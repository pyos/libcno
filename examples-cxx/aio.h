#ifndef AIO_H
#define AIO_H

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <vector>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <unordered_map>


namespace aio
{
    static const int ONE = 1;  // used as parameter to setsockopt(2)


    struct stringview
    {
        const char * base; size_t size;
        stringview() : base(NULL), size(0) {}
        stringview(const char *b) : base(b), size(strlen(b)) {}
        stringview(const char *b, size_t s) : base(b), size(s) {}
        stringview(const std::string& s) : stringview(s.data(), s.size()) {}

        bool operator == (const char *a) const
        {
            const char  *b = base;
            for (size_t s = size; s; s--)
                if (*a++ != *b++) return false;
            return *a == 0;
        }

        std::string as_string() const
        {
            return std::string(base, base + size);
        }
    };


    template <typename ret, typename... args> struct event
    {
        typedef std::function<ret(args...)> callback;

        std::vector<const callback *> cs;

        void operator += (const callback *c)
        {
            if (std::find(cs.begin(), cs.end(), c) == cs.end()) cs.push_back(c);
        }

        void operator -= (const callback *c)
        {
            auto i = std::find(cs.begin(), cs.end(), c);
            if (i != cs.end()) cs.erase(i);
        }

        bool operator ! () const
        {
            return cs.empty();
        }

        void emit(args... xs)
        {
            for (const callback *c : std::vector<const callback *>(cs)) (*c)(xs...);
        }

        void once(args... xs)
        {
            std::vector<const callback *> cq;
            std::swap(cq, cs);
            for (const callback *c : cq) (*c)(xs...);
        }
    };


    struct evloop
    {
        int running;
        int wakeup_fd[2];
        event<int> call_soon, on_exit;
        std::unordered_map<int, event<int>> io_events[2];
        std::unordered_map<int, event<int>> &read  = io_events[0];
        std::unordered_map<int, event<int>> &write = io_events[1];
        typedef event<int>::callback callback;

        evloop()
        {
            ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, wakeup_fd);
            read[wakeup_fd[0]] += &on_wakeup;
        }

       ~evloop()
        {
            on_exit.once();
            ::close(wakeup_fd[0]);
            ::close(wakeup_fd[1]);
        }

        int run()
        {
            fd_set fds[2];

            for (running = 1; running;) {
                for (fd_set &fd : fds)
                    FD_ZERO(&fd);

                while (!!call_soon)
                    call_soon.once();

                int max_fd = 0;
                for (int i = 0; i < 2; i++)
                    for (auto it = io_events[i].cbegin(); it != io_events[i].cend(); ) {
                        if (!!it->second) {
                            FD_SET(it->first, &fds[i]);
                            if (max_fd < it->first + 1)
                                max_fd = it->first + 1;
                            ++it;
                        } else
                            it = io_events[i].erase(it);
                    }

                while (-1 == select(max_fd, &fds[0], &fds[1], NULL, NULL))
                    if (errno != EINTR)
                        return -1;

                for (int i = 0; i < 2; i++)
                    for (auto &fd_ev : io_events[i])
                        if (FD_ISSET(fd_ev.first, &fds[i]))
                            fd_ev.second.emit();
            }

            return 0;
        }

        int stop()
        {
            running = 0;
            return wakeup();
        }

        int wakeup()
        {
            return ::write(wakeup_fd[1], "\0", 1) == 1 ? 0 : -1;
        }

        const callback on_wakeup = [this]()
        {
            char p[1024]; return ::read(wakeup_fd[0], &p, 1024) > 0 ? 0 : -1;
        };
    };


    struct transport;
    struct protocol
    {
        aio::transport * const transport;
        /* A partial copy of the Protocol from Python's asyncio. Does not support flow control.
         *
         *    ctor --------------+---> destructor
         *             ^         v
         *            data_received
         */
        protocol(struct transport *t) : transport(t) {}
        virtual ~protocol() {}
        virtual int data_received(const stringview) = 0;
        typedef std::function<protocol*(struct transport*)> factory;
    };


    struct transport
    {
        evloop        * const loop;
        aio::protocol *       protocol;

        aio::event<int> on_drain;
        std::string buffer;
        /* A transport actually interfaces between a Protocol and low-level I/O.
         *
         *            write event
         *             v      ^
         *     ctor ----------+-----> close ----> destructor
         *             ^      v         ^
         *            read event ----> EOF
         */
        transport(evloop *loop) : loop(loop) { loop->on_exit += &close_now; }
        virtual ~transport() { delete protocol; loop->on_exit -= &close_now; }
        virtual void write(const stringview) = 0;

        const evloop::callback close = [this]()
        {
            loop->call_soon += &close_now;
            return 0;
        };

        const evloop::callback close_now = [this]()
        {
            delete this;
            return 0;
        };

        const evloop::callback close_on_drain = [this]()
        {
            if (!buffer.size())
                return close();

            on_drain += &close;
            return 0;
        };
    };


    struct unix_file_transport : transport
    {
        int const fd;

        unix_file_transport(evloop *loop, int fd) : transport(loop), fd(fd)
        {
            loop->read[fd] += &on_read;
        }

       ~unix_file_transport() override
        {
            loop->read [fd] -= &on_read;
            loop->write[fd] -= &on_write;
            ::close(fd);
        }

        void write(const stringview data) override
        {
            if (buffer.append(data.base, data.size).size() == data.size)
                // avoid busy-waiting for data to send by only connecting on_write
                // while the buffer is non-empty.
                loop->write[fd] += &on_write;
        }

        const evloop::callback on_read = [this]()
        {
            char buffer[4096];
            auto read = ::read(fd, buffer, sizeof(buffer));

            if (read < 0) return -1;
            if (read > 0) return protocol->data_received({ buffer, static_cast<size_t>(read) });
            close();  // :(( < aww it's gone
            return 0;
        };

        const evloop::callback on_write = [this]()
        {
            auto written = ::write(fd, buffer.data(), buffer.size());

            if (written < 0)
                return -1;
            if (buffer.erase(0, written).empty()) {
                loop->write[fd] -= &on_write;
                on_drain.once();
            }
            return 0;
        };
    };


    struct socket
    {
        int fd;
       ~socket() { if (fd >= 0) ::close(fd); }
        socket(int fd) : fd(fd) {}
        socket(socket const &) = delete;
        socket(socket && s) : fd(0) { std::swap(fd, s.fd); }
        socket& operator = (socket const &) = delete;
        socket& operator = (socket && s) { std::swap(fd, s.fd); return *this; }
        operator int() { return fd; }

        static socket ipv4_server(uint32_t iface, uint32_t port)
        {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port        = htons(port);
            addr.sin_addr.s_addr = htons(iface);
            int fd;

            if (-1 == (fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0))
            ||  -1 == setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &aio::ONE, sizeof(aio::ONE))
            ||  -1 == bind       (fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr))
            ||  -1 == listen     (fd, 127))
            {
                if (fd != -1) ::close(fd);
                throw std::runtime_error(strerror(errno));
            }

            return aio::socket { fd };
        }
    };


    struct server
    {
        int const fd;
        evloop *          const loop;
        protocol::factory const new_proto;

        server(int fd, evloop *loop, protocol::factory pf) : fd(fd), loop(loop), new_proto(pf)
        {
            loop->read[fd] += &on_accept;
        }

       ~server()
        {
            loop->read[fd] -= &on_accept;
        }

        const evloop::callback on_accept = [this]()
        {
            struct sockaddr_in addr;
            socklen_t size = sizeof(addr);

            int fd;
            if (-1 == (fd = accept4(this->fd, reinterpret_cast<struct sockaddr *>(&addr), &size, SOCK_NONBLOCK))
            ||  -1 == setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &ONE, sizeof(ONE))
            ||  fd > 1023 /* max. supported by select */)
            {
                if (fd != -1) close(fd);
                return -1;
            }

            auto t = new unix_file_transport(loop, fd);
            t->protocol = new_proto(t);
            return 0;
        };
    };
};

#endif
