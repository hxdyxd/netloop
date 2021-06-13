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

#include <netloop.h>
#include <netutils.h>

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8086


#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

static void connect_task(struct netloop_obj_t *ctx, void *ud);


static void transfer_task(struct netloop_obj_t *ctx, struct tcp_connect_t *conn, char *buffer, int len)
{
    ASSERT(conn);
    int r;
    struct tcp_connect_t *peer = (struct tcp_connect_t *)conn->data;
    ASSERT(peer);
    int rfd = conn->fd;
    int wfd = peer->fd;

    NONE_PRINTF("transfer %d to %d\n", rfd, wfd);

    while (conn->data) {
        r = netloop_read(ctx, rfd, buffer, len);
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
            DEBUG_PRINTF("connection closed [%d, %s]!\n", rfd, ctx->name);
            break;
        }

        NONE_PRINTF("new %u msg from %d:\n", r, rfd);

        r = netloop_write(ctx, wfd, buffer, r);
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
        NONE_PRINTF("close socket [%s]!\n", ctx->name);
        close(rfd);
        close(wfd);
    }
    free(conn);
    NONE_PRINTF("task exit [%s]!\n", ctx->name);
}

static void proxy_http_parse(struct netloop_obj_t *ctx, struct tcp_connect_t *conn, char *buffer, int len)
{
    int r;
    int rlen;

    r = netloop_read(ctx, conn->fd, buffer, len);
    if (r <= 0) {
        ERROR_PRINTF("read(fd = %d) %s\n", conn->fd, strerror(errno));
        return;
    }
    rlen = r;

    NONE_PRINTF("new %u msg from %d: %.*s\n", rlen, conn->fd, rlen, (char *)buffer);

    struct tcp_connect_t *remote = malloc(sizeof(struct tcp_connect_t));
    if (!remote) {
        return;
    }
    memset(remote, 0, sizeof(struct tcp_connect_t));

    r = parse_addr_in_http(&remote->addrinfo, buffer, rlen);
    if (r < 0) {
        ERROR_PRINTF("parse addr fail!\n");
        free(remote);
        return;
    }

    remote->fd = tcp_socket_create(ctx, 0, remote->addrinfo.host, remote->addrinfo.port);
    if (remote->fd < 0) {
        free(remote);
        return;
    }

    if (strncmp("CONNECT", buffer, 7) == 0) {
        char *connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        r = netloop_write(ctx, conn->fd, connect_msg, strlen(connect_msg));
        if (r <= 0) {
            close(remote->fd);
            free(remote);
            return;
        }
    } else {
        r = netloop_write(ctx, remote->fd, buffer, rlen);
        if (r <= 0) {
            close(remote->fd);
            free(remote);
            return;
        }
    }

    struct netloop_obj_t *task;
    task = netloop_run_task(ctx->nm, &(struct netloop_task_t){
        .task_cb = connect_task,
        .ud = remote,
        .name = remote->addrinfo.host,
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task() error\n");
        close(remote->fd);
        free(remote);
        return;
    }

    conn->data = remote;
    remote->data = conn;
}

static void connect_task(struct netloop_obj_t *ctx, void *ud)
{
    ASSERT(ud);
    struct tcp_connect_t *conn = (struct tcp_connect_t *)ud;
    char buffer[512];

    if (!conn->data) {
        NONE_PRINTF("new connect = %d\n", conn->fd);

        proxy_http_parse(ctx, conn, buffer, sizeof(buffer));
        if (!conn->data) {
            close(conn->fd);
            free(conn);
            return;
        }

        if (ctx->name) {
            free(ctx->name);
            ctx->name = strdup("transfer_task");
        }
    }

    transfer_task(ctx, conn, buffer, sizeof(buffer));
}

int main(int argc, char **argv)
{
    int r;
    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);
#ifdef MTRAVE_PATH 
    mtrace_init(MTRAVE_PATH);
#endif

    signal(SIGPIPE, SIG_IGN);

    struct netloop_main_t *nm = netloop_init();
    if (!nm) {
        return -1;
    }

    r = command_init(nm);
    if (r < 0) {
        ERROR_PRINTF("command_init() error\n");
        return -1;
    }

    r = tcp_server_init(nm, EXAMPLE_ADDR, EXAMPLE_PORT, connect_task);
    if (r < 0) {
        ERROR_PRINTF("tcp_server_init() error\n");
        return -1;
    }

    r = tcp_server_init(nm, EXAMPLE_ADDR, EXAMPLE_PORT + 1, connect_task);
    if (r < 0) {
        ERROR_PRINTF("tcp_server_init() error\n");
        return -1;
    }

    r = netloop_start(nm);
    if (r < 0) {
        return -1;
    }

    while(1) {
        sleep(9999);
    }

    DEBUG_PRINTF("exit\n");
    return 0;
}
