/*
 * proxy.c of netloop
 * Copyright (C) 2021-2021  hxdyxd <hxdyxd@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "netutils.h"

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8086


static void connect_task(void *ud);


static void transfer_task(struct tcp_connect_t *conn, char *buffer, int len)
{
    ASSERT(conn);
    int r;
    struct tcp_connect_t *peer = (struct tcp_connect_t *)conn->data;
    ASSERT(peer);
    int rfd = conn->fd;
    int wfd = peer->fd;

    NONE_PRINTF("transfer %d to %d\n", rfd, wfd);

    while (conn->data) {
        r = read(rfd, buffer, len);
        if (r <= 0) {
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ERROR_PRINTF("read(fd = %d) %s\n", rfd, strerror(errno));
            }
            shutdown(wfd, SHUT_RDWR);
            break;
        }

        if (!conn->data) {
            INFO_PRINTF("connection closed [%d, ]!\n", rfd);
            break;
        }

        NONE_PRINTF("new %u msg from %d:\n", r, rfd);

        r = write(wfd, buffer, r);
        if (r <= 0) {
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ERROR_PRINTF("write(fd = %d) %s\n", wfd, strerror(errno));
            }
            shutdown(rfd, SHUT_RDWR);
            break;
        }
    }

    if (conn->data) {
        conn->data = NULL;
        peer->data = NULL;
    } else {
        NONE_PRINTF("close socket []!\n");
        close(rfd);
        close(wfd);
    }
    free(conn);
    NONE_PRINTF("task exit []!\n");
}

static void proxy_http_parse(struct tcp_connect_t *conn, char *buffer, int len)
{
    int r;
    int rlen;

    r = read(conn->fd, buffer, len);
    if (r <= 0) {
        if (r < 0) {
            ERROR_PRINTF("read(fd = %d) %s\n", conn->fd, strerror(errno));
        }
        return;
    }
    rlen = r;

    NONE_PRINTF("new %u msg from %d!\n", rlen, conn->fd);

    struct tcp_connect_t *remote = malloc(sizeof(struct tcp_connect_t));
    if (!remote) {
        return;
    }
    memset(remote, 0, sizeof(struct tcp_connect_t));

    r = parse_addr_in_http(&remote->addrinfo, buffer, rlen);
    if (r < 0) {
        ERROR_PRINTF("parse addr fail!\n");
        ERROR_PRINTF("dump %u msg from %d: \n", rlen, conn->fd);
        msg_dump(buffer, rlen);
        free(remote);
        return;
    }

    remote->fd = tcp_socket_create(0, remote->addrinfo.host, remote->addrinfo.port);
    if (remote->fd < 0) {
        free(remote);
        return;
    }

    if (strncmp("CONNECT", buffer, 7) == 0) {
        char *connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        r = write(conn->fd, connect_msg, strlen(connect_msg));
        if (r <= 0) {
            close(remote->fd);
            free(remote);
            return;
        }
    } else {
        r = write(remote->fd, buffer, rlen);
        if (r <= 0) {
            close(remote->fd);
            free(remote);
            return;
        }
    }

    r = netutils_run_task(&(struct netutils_task_t){
        .ontask = connect_task,
        .ud = remote,
        .name = remote->addrinfo.host,
    });
    if (r < 0) {
        ERROR_PRINTF("netutils_run_task() error\n");
        close(remote->fd);
        free(remote);
        return;
    }

    conn->data = remote;
    remote->data = conn;
}

static void connect_task(void *ud)
{
    ASSERT(ud);
    struct tcp_connect_t *conn = (struct tcp_connect_t *)ud;
    int r;
    char buffer[1024];

    if (!conn->data) {
        NONE_PRINTF("new connect = %d\n", conn->fd);

        proxy_http_parse(conn, buffer, sizeof(buffer));
        if (!conn->data) {
            close(conn->fd);
            free(conn);
            return;
        }

        r = netutils_ntop(&conn->addrinfo, &conn->sockinfo);
        if (r < 0) {
            ERROR_PRINTF("netutils_ntop: error\n");
            close(conn->fd);
            free(conn);
            return;
        }

        char *name = NULL;
        r = asprintf(&name, "%s_%s:%u", __FUNCTION__, conn->addrinfo.host, conn->addrinfo.port);
        if (r < 0) {
            ERROR_PRINTF("asprintf() %s\n", strerror(errno));
        }

        netutils_task_setname(name);
        free(name);
    }

    transfer_task(conn, buffer, sizeof(buffer));
}

int module_main(int argc, char **argv)
{
    int r;
    const char *host = EXAMPLE_ADDR;
    uint16_t port = EXAMPLE_PORT;

    if (argc >= 2)
        host = argv[1];

    if (argc >= 3)
        port = atoi(argv[2]);

    if (argc < 3) {
        PRINTF("proxy usage:\n");
        PRINTF("\tproxy [addr] [port]\n");
        return -1;
    }

    r = tcp_server_init(host, port, connect_task);
    if (r < 0) {
        ERROR_PRINTF("tcp_server_init() error\n");
        return -1;
    }

    INFO_PRINTF("proxy server at %s:%d\n", host, port);
    return 0;
}
