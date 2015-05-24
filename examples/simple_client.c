#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <ctype.h>

#include "cno.h"
#include "urlparse.h"


int write_cb(cno_connection_t *conn, int *fd, const char *data, size_t length)
{
    size_t wrote = 0;

    do {
        wrote += write(*fd, data + wrote, length - wrote);
    } while (wrote < length);

    return CNO_OK;
}


int on_message_start(cno_connection_t *conn, int *fd, size_t stream, cno_message_t *msg)
{
    fprintf(stdout, "recv message: HTTP/%d.%d %d, method = ", msg->major, msg->minor, msg->code);
    fwrite(msg->method.data, msg->method.size, 1, stdout);
    fprintf(stdout, ", path = ");
    fwrite(msg->path.data, msg->path.size, 1, stdout);
    fprintf(stdout, ", headers:\n");

    size_t k = 0;

    for (; k < msg->headers_len; ++k) {
        printf("    (%lu) ", msg->headers[k].name.size);
        fwrite(msg->headers[k].name.data, msg->headers[k].name.size, 1, stdout);
        printf(" = (%lu) ", msg->headers[k].value.size);
        fwrite(msg->headers[k].value.data, msg->headers[k].value.size, 1, stdout);
        printf("\n");
    }
    return CNO_OK;
}


int on_message_data(cno_connection_t *conn, int *fd, size_t stream, const char *data, size_t length)
{
    if (length) {
        printf("recv data: ");
        fwrite(data, length, 1, stdout);
        printf("\n");
    }
    return CNO_OK;
}


int on_message_end(cno_connection_t *conn, int *fd, size_t stream)
{
    printf("recv message end\n");

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
    struct sockaddr_in server;
    struct hostent *server_host;

    int fd;
    int port = url->port ? atoi(url->port) : 80;

    char  root[] = "/";
    char *path = root;

    if (url->path) {
        path = malloc(url->path ? strlen(url->path) + 2 : 1);
        path[0] = '/';
        strcpy(path + 1, url->path);
    }

    if ((server_host = gethostbyname(url->host)) == NULL) {
        fprintf(stderr, "error: hostname not found\n");
        return 1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port   = htons(port);
    memcpy(server_host->h_addr, &server.sin_addr.s_addr, server_host->h_length);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "error: could not open socket\n");
        return 1;
    }

    if (connect(fd, (struct sockaddr *) &server, sizeof(server)) < 0) {
        fprintf(stderr, "error: could not connect to server\n");
        return 1;
    }

    cno_connection_t *client = cno_connection_new(CNO_HTTP2_CLIENT);

    if (client == NULL) {
        goto error;
    }

    client->cb_data          = &fd;
    client->on_write         = &write_cb;
    client->on_message_start = &on_message_start;
    client->on_message_data  = &on_message_data;
    client->on_message_end   = &on_message_end;

    cno_message_t message;
    CNO_ZERO(&message);
    message.path.data = path;
    message.path.size = strlen(path);
    message.method.data = "POST";
    message.method.size = 4;

    cno_header_t headers[] = {
        { { ":scheme", 7 }, { "http", 4 } },
        { { ":authority", 10 }, { "localhost", 9 } },
    };

    message.headers_len = sizeof(headers) / sizeof(cno_header_t);
    message.headers = headers;

    if (
        cno_connection_made(client)
     || cno_write_message(client, 1, &message)
     || cno_write_data(client, 1, "Hello, World!\n", 14, 0)
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
