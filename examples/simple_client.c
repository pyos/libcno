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


int on_message_end(cno_connection_t *conn, int *fd, size_t stream, int disconnect)
{
    log_recv_message_end(conn, fd, stream, disconnect);

    if (cno_connection_stop(conn)) {
        return CNO_PROPAGATE;
    }

    close(*fd);
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

    if ((server_host = gethostbyname2(url->host, AF_INET6)) != NULL) {
        struct sockaddr_in6 server6;
        memset(&server6, 0, sizeof(server6));
        server6.sin6_family = AF_INET6;
        server6.sin6_port   = htons(port);

        for (i = 0; !found && server_host->h_addr_list[i]; ++i) {
            memcpy(&server6.sin6_addr.s6_addr, server_host->h_addr_list[i], server_host->h_length);

            if (connect(fd, (struct sockaddr *) &server6, sizeof(server6)) >= 0) {
                found = 1;
            }
        }
    }

    if ((server_host = gethostbyname2(url->host, AF_INET)) != NULL) {
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

    client->cb_data          = &fd;
    client->on_write         = &write_to_fd;
    client->on_frame         = &log_recv_frame;
    client->on_frame_send    = &log_sent_frame;
    client->on_message_start = &log_recv_message;
    client->on_message_data  = &log_recv_message_data;
    client->on_message_end   = &on_message_end;

    cno_message_t message;
    CNO_ZERO(&message);
    message.path.data = path;
    message.path.size = strlen(path);
    message.method.data = "GET";
    message.method.size = 3;

    cno_header_t headers[] = {
        { { ":scheme", 7 }, { "http", 4 } },
        { { ":authority", 10 }, { "localhost", 9 } },
    };

    message.headers_len = sizeof(headers) / sizeof(cno_header_t);
    message.headers = headers;

    if (
        cno_connection_made(client)
     || cno_write_message(client, 1, &message)
     || cno_write_end(client, 1, 0)) goto error;

    char buf[2048];
    ssize_t ln;

    while ((ln = recv(fd, buf, 2048, 0)) > 0) {
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
