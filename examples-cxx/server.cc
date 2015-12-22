/*
 * A simple async I/O web server that responds to all requests with a "hello, world".
 * Requests with more than 10 MB of data are rejected with error 400.
 *
 *   $ make obj/examples-cxx/server STRICT=1
 *   $ server -t 2
 *   [0] ready
 *   [1] ready
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <thread>

#include "cno.h"


struct stream : cno::stream
{
    bool is_head  = false;
    bool rejected = false;
    size_t payload_size = 0;

    using cno::stream::stream;

    int on_message(const struct cno_message_t *msg)
    {
        is_head = cno_buffer_eq(&msg->method, CNO_BUFFER_CONST("HEAD"));
        return CNO_OK;
    }

    int on_data(const struct cno_buffer_t *buf)
    {
        if (rejected)
            return CNO_OK;

        if ((payload_size += buf->size) > 9999999) {
            rejected = true;

            struct cno_header_t  h = { CNO_BUFFER_CONST("content-length"), CNO_BUFFER_CONST("0") };
            struct cno_message_t m = { 400, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, &h, 1 };
            if (write_message(m) || write_eof())
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

        struct cno_header_t headers[] = {
            { CNO_BUFFER_CONST("server"),         CNO_BUFFER_CONST("hello-world-cxx/1.0") },
            { CNO_BUFFER_CONST("cache-control"),  CNO_BUFFER_CONST("no-cache") },
            { CNO_BUFFER_CONST("content-length"), CNO_BUFFER_STRING(len) },
        };

        struct cno_message_t message = { 200, CNO_BUFFER_EMPTY, CNO_BUFFER_EMPTY, headers,
                                         sizeof(headers) / sizeof(struct cno_header_t) };

        if (write_message(message))
            return CNO_ERROR_UP();

        if (!is_head)
            if (write_data(CNO_BUFFER_STRING(buf)))
                return CNO_ERROR_UP();

        return write_eof();
    }
};


template <typename T, T f(const char *, char **, int)> static bool parse_int(const char *c, T *x)
{
    return *c && ((*x = f(c, (char **) &c, 10)), !*c);
}


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


int main(int argc, char *const *argv)
{
    unsigned long parallel = 1  /* thread */;
    unsigned long port     = 8000;

    for (int ch; (ch = getopt(argc, argv, "-:hp:t:")) != -1; ) switch (ch) {
        default:
            fprintf(stderr, "fatal: unknown option -%c\n", optopt);
            return 2;

        case 1:
            fprintf(stderr, "fatal: stray argument %s\n", optarg);
            return 2;

        case ':':
            fprintf(stderr, "fatal: missing argument to -%c\n", optopt);
            return 2;

        case 'h':
            fprintf(stdout,
                "usage: %s [options]\n"
                "    -h         display this message\n"
                "    -t <num>   run in <num> parallel threads [default: 1]\n"
                "    -p <port>  listen on this TCP port [default: 8000]\n", argv[0]);
            return 0;

        case 'p':
            if (parse_int<unsigned long, strtoul>(optarg, &port) && port) break;
            goto non_integer_argument;

        case 't':
            if (parse_int<unsigned long, strtoul>(optarg, &parallel) && parallel) break;

        non_integer_argument:
            fprintf(stderr, "fatal: -%c expected a positive integer\n", ch);
            return 2;
    }

    aio::socket socket = aio::socket::ipv4_server(0, port);
    aio::evloop * const evloops = new aio::evloop[parallel];
    std::thread * const threads = new std::thread[parallel];

    for (unsigned long i = 0; i < parallel; i++)
        threads[i] = std::thread(&run, i, int(socket), &evloops[i],
            [](aio::transport *t) { return new cno::protocol<stream, CNO_SERVER>(t); });

    signal(SIGINT, &sigcatch);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    pause();

    for (unsigned long i = 0; i < parallel; i++) {
        evloops[i].stop();
        threads[i].join();
    }

    delete[] threads;
    delete[] evloops;
    return 0;
}
