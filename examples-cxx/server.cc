/*
 * A simple async I/O web server that responds to all requests with a "hello, world".
 * Requests with more than 10 MB of data are rejected with error 400.
 *
 *   $ make obj/examples-cxx/server
 *   $ server &
 *   [0] ready
 *   [1] ready
 *   $ nghttp http://127.0.0.1:8000/ -d - <<< 'test'
 *   Hello, World! (5 bytes)
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <thread>

#include "cno.h"

#define PORT    8000
#define THREADS 2


struct stream : cno::stream
{
    bool is_201   = false;
    bool is_head  = false;
    bool rejected = false;
    size_t payload_size = 0;

    using cno::stream::stream;

    int on_message(const cno::message msg)
    {
        is_201   = false;
        is_head  = msg.method == "HEAD";
        rejected = false;
        payload_size = 0;

        for (const cno::header &h : msg)
            if (h.name == "x-respond-with-201")
                is_201 = true;

        return CNO_OK;
    }

    int on_data(const aio::stringview buf)
    {
        if (rejected)
            return CNO_OK;

        if ((payload_size += buf.size) > 9999999) {
            rejected = true;

            if (write_message(400, { { "content-length", "0" } }))
                return CNO_ERROR_UP();

            if (write_eof())
                return CNO_ERROR_UP();
        }

        return CNO_OK;
    }

    int on_end()
    {
        if (rejected)
            return CNO_OK;

        char len[64];
        char buf[64];
        snprintf(len, sizeof(len), "%d",
            snprintf(buf, sizeof(buf), "Hello, World! (%zu bytes)\n", payload_size));

        if (write_message(is_201 ? 201 : 200,
              { { "server",         "hello-world-cxx/1.0" },
                { "cache-control",  "no-cache"            },
                { "content-length", len                   } }))
            return CNO_ERROR_UP();

        if (!is_head)
            if (write_data(buf))
                return CNO_ERROR_UP();

        return write_eof();
    }
};


static void run(int thread, int socket, aio::evloop *loop, aio::protocol::factory pf)
{
    aio::server _(socket, loop, pf);
    fprintf(stderr, "[%d] ready\n", thread);
    if (loop->run())
    fprintf(stderr, "[%d] error: %s [%d]\n", thread, strerror(errno), errno);
    fprintf(stderr, "[%d] stopped\n", thread);
}


static void sigcatch(int signum)
{
    signal(signum, SIG_DFL);
}


int main(void)
{
    aio::socket socket = aio::socket::ipv4_server(0, PORT);
    aio::evloop evloops[THREADS];
    std::thread threads[THREADS];

    for (unsigned long i = 0; i < THREADS; i++)
        threads[i] = std::thread(&run, i, int(socket), &evloops[i],
            [](aio::transport *t) { return new cno::protocol<stream, CNO_SERVER>(t); });

    signal(SIGINT, &sigcatch);
    signal(SIGPIPE, SIG_IGN);
    pause();

    for (auto &e : evloops) e.stop();
    for (auto &t : threads) t.join();
    return 0;
}
