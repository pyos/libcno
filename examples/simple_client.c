/* A basic POSIX plaintext client.
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
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#include "examples/urlparse.h"
// See this file for callbacks:
#include "examples/simple_common.h"


int disconnect(void *data, size_t stream)
{
    log_recv_message_end(data, stream);

    struct cbdata_t *cbdata = data;

    if (cno_connection_stop(&cbdata->conn))
        return CNO_ERROR_UP();

    shutdown(cbdata->fd, SHUT_RD);
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

    struct cbdata_t client;
    client.fd = fd;
    cno_connection_init(&client.conn, CNO_CLIENT);

    struct cno_settings_t settings;
    cno_settings_copy(&client.conn, &settings);
    settings.enable_push = 0;
    settings.max_concurrent_streams = 1024;
    cno_settings_apply(&client.conn, &settings);

    client.conn.cb_data          = &client;
    client.conn.on_write         = &write_to_fd;
    client.conn.on_frame         = &log_recv_frame;
    client.conn.on_frame_send    = &log_sent_frame;
    client.conn.on_message_start = &log_recv_message;
    client.conn.on_message_data  = &log_recv_message_data;
    client.conn.on_message_end   = &disconnect;

    struct cno_header_t headers[] = {
        { CNO_BUFFER_CONST(":scheme"),    CNO_BUFFER_CONST("http") },
        { CNO_BUFFER_CONST(":authority"), CNO_BUFFER_STRING(url->host) },
    };

    struct cno_message_t message = { 0, CNO_BUFFER_CONST("GET"), CNO_BUFFER_STRING(path), headers, 2 };
    size_t stream = cno_stream_next_id(&client.conn);

    if (cno_connection_made(&client.conn, CNO_HTTP2)
    ||  cno_write_message(&client.conn, stream, &message, 1))
            goto error;

    char buf[8196];
    ssize_t ln;

    while ((ln = recv(fd, buf, 8196, 0)) > 0)
        if (cno_connection_data_received(&client.conn, buf, ln))
            goto error;

    if (cno_connection_lost(&client.conn))
        goto error;

    close(fd);
    cno_connection_reset(&client.conn);
    return 0;

error:
    print_traceback();
    close(fd);
    cno_connection_reset(&client.conn);
    return 1;
}
