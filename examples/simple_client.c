/* A basic POSIX plaintext client.
 *
 * Building with GCC (for example):
 *
 *     gcc -std=c11 -I.. ../cno{,-common,-hpack}.c ../picohttpparser/picohttpparser.c simple_client.c -o client
 *
 * Usage:
 *
 *        ./client http://example.com/
 *   e.g. ./client http://ec2-52-0-206-26.compute-1.amazonaws.com/
 *                 ^---- Deuterium test server: http://robbysimpson.com/deuterium/
 *
 * (Only plain-text HTTP 2, i.e. h2c, over port 80 is supported. Upgrading is done via
 *  prior knowledge. So don't try to connect to Twitter or Google -- these require TLS.)
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include "cno.h"
#include "urlparse.h"
// See this file for callbacks:
#include "simple_common.h"


int disconnect(cno_connection_t *conn, void *fd, size_t stream)
{
    log_recv_message_end(conn, (int *) fd, stream);

    if (cno_connection_stop(conn)) {
        return CNO_PROPAGATE;
    }

    close(*(int *) fd);
    return CNO_OK;
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <address>\n", argv[0]);
        return 1;
    }

    struct parsed_url *url = parse_url(argv[1]);
    struct hostent *server_host;

    int fd, i, found = 0;
    int port = url->port ? atoi(url->port) : 80;

    char  root[] = "/";
    char *path = root;

    if (url->path) {
        path = malloc(url->path ? strlen(url->path) + 2 : 1);
        path[0] = '/';
        strcpy(path + 1, url->path);
    }

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "error: could not open socket: %s\n", strerror(errno));
        return 1;
    }

    if ((server_host = gethostbyname(url->host)) != NULL) {
        struct sockaddr_in server;
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port   = htons(port);

        for (i = 0; !found && server_host->h_addr_list[i]; ++i) {
            memcpy(&server.sin_addr.s_addr, server_host->h_addr_list[i], server_host->h_length);

            if (connect(fd, (struct sockaddr *) &server, sizeof(server)) >= 0) {
                found = 1;
            }
        }
    }

    if (!found) {
        fprintf(stderr, "error: %s\n", strerror(errno));
        return 1;
    }

    cno_connection_t *client = cno_connection_new(CNO_HTTP2_CLIENT);

    if (client == NULL) {
        goto error;
    }

    cno_settings_t settings;
    cno_settings_copy(client, &settings);
    settings.enable_push = 0;
    settings.max_concurrent_streams = 1024;
    cno_settings_apply(client, &settings);

    client->cb_data          = &fd;
    client->on_write         = &write_to_fd;
    client->on_frame         = &log_recv_frame;
    client->on_frame_send    = &log_sent_frame;
    client->on_message_start = &log_recv_message;
    client->on_message_data  = &log_recv_message_data;
    client->on_message_end   = &disconnect;

    cno_header_t headers[] = {
        { CNO_IO_VECTOR_CONST(":scheme"),    CNO_IO_VECTOR_CONST("http") },
        { CNO_IO_VECTOR_CONST(":authority"), CNO_IO_VECTOR_STRING(url->host) },
    };

    cno_message_t message = { 0, CNO_IO_VECTOR_CONST("GET"), CNO_IO_VECTOR_STRING(path), headers, 2 };
    size_t stream = cno_stream_next_id(client);

    if (cno_connection_made(client)
     || cno_write_message(client, stream, &message, 1)) goto error;

    char buf[8196];
    ssize_t ln;

    while ((ln = recv(fd, buf, 8196, 0)) > 0) {
        if (cno_connection_data_received(client, buf, ln)) {
            goto error;
        }
    }

    if (cno_connection_lost(client)) {
        goto error;
    }

    close(fd);
    cno_connection_destroy(client);
    return 0;

error:
    close(fd);
    fprintf(stderr, "%s: %s at line %d in %s\n",
        cno_error_name(), cno_error_text(),
        cno_error_line(), cno_error_file());

    if (client) cno_connection_destroy(client);
    return 1;
}
