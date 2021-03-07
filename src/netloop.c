/*
 * netloop.c of netloop
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>

#include <netloop.h>
#include <loop.h>

#define LOG_NAME   "netloop"
#define DEBUG_PRINTF(...)     printf("\033[0;32m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ERROR_PRINTF(...)     printf("\033[1;31m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static int sock_setblocking(int sock, int if_block)
{
    int flags, r;

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }

    if (if_block)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    r = fcntl(sock, F_SETFL, flags);
    if (r < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


static int tcp_socket_create(int if_bind, const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    r = getaddrinfo(host, NULL, &hints, &res);
    if (0 != r) {
        ERROR_PRINTF("getaddrinfo: %s\n", gai_strerror(r));
        return -1;
    }

    if (res->ai_family == AF_INET)
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
    else if (res->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
    else {
        ERROR_PRINTF("unknown ai_family %d\n", res->ai_family);
        goto exit;
    }

    sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ERROR_PRINTF("socket: %s\n", strerror(errno));
        goto exit;
    }

    r = sock_setblocking(sock, 0);
    if (r < 0) {
        goto exit1;
    }

    if (if_bind) {
        int opt = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (r < 0) {
            ERROR_PRINTF("setsockopt: %s\n", strerror(errno));
            goto exit1;
        }

        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("bind %s:%d : %s\n", host, port, strerror(errno));
            goto exit1;
        }

        r = listen(sock, 512);
        if (r < 0) {
            ERROR_PRINTF("listen: %s\n", strerror(errno));
            goto exit1;
        }
    }

    freeaddrinfo(res);
    DEBUG_PRINTF("%s %s:%d\n", if_bind ? "listen" : "connect", host, port);
    return sock;

exit1:
    close(sock);
exit:
    freeaddrinfo(res);
    return -1;
}


static void netloop_dump_list(struct netloop_conn_t *head)
{
    struct netloop_conn_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &head->list, list) {
        printf("idx: %d, fd: %d, ", ctx->idx,  ctx->fd);
        printf("events: %c%c, ", (ctx->events & POLLIN) ? 'I' : ' ', (ctx->events & POLLOUT) ? 'O' : ' ' );
        printf("\n");
    }
}


static struct netloop_conn_t *netloop_conn_new(void)
{
    struct netloop_conn_t *conn;
    conn = malloc(sizeof(struct netloop_conn_t));
    if (!conn) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(struct netloop_conn_t));
    conn->magic = NETLOOP_MAGIC;
    return conn;
}

static void netloop_conn_free(struct netloop_conn_t *conn)
{
    ASSERT(NETLOOP_MAGIC == conn->magic);
    conn->fd = -1;
    conn->magic = 0;
    free(conn);
}


static void __netloop_receive(struct netloop_conn_t *ctx)
{
    int r;
    char buffer[512];
    ASSERT(NETLOOP_STATE_STREAM == ctx->state);

    r = read(ctx->fd, buffer, 512);
    if (r == 0) {
        ctx->state = NETLOOP_STATE_CLOSED;
        ASSERT(ctx->close_cb);
        ctx->close_cb(ctx);
        return;
    } else if (r < 0) {
        if (EINTR == errno)
            return;
        ERROR_PRINTF("read: %s\n", strerror(errno));
        ctx->state = NETLOOP_STATE_CLOSED;
        ASSERT(ctx->close_cb);
        ctx->close_cb(ctx);
        return;
    }

    ASSERT(ctx->recv_cb);
    ctx->recv_cb(ctx, buffer, r);
}

static void __netloop_accept(struct netloop_conn_t *ctx)
{
    int r;
    struct netloop_conn_t *newconn;

    newconn = netloop_conn_new();
    if (!newconn) {
        return;
    }

    newconn->peer.addrlen = sizeof(struct sockaddr_in6);
    newconn->fd = accept(ctx->fd, &newconn->peer.addr, &newconn->peer.addrlen);
    if (newconn->fd < 0) {
        ERROR_PRINTF("accept: %s\n", strerror(errno));
        netloop_conn_free(newconn);
        return;
    }

    r = sock_setblocking(newconn->fd, 0);
    if (r < 0) {
        close(newconn->fd);
        netloop_conn_free(newconn);
        return;
    }

    newconn->type = NETLOOP_TYPE_SERVER;
    newconn->state = NETLOOP_STATE_STREAM;
    newconn->events = POLLIN;
    newconn->head = ctx->head;
    newconn->in = __netloop_receive;

    newconn->connect_cb = ctx->connect_cb;
    newconn->recv_cb = ctx->recv_cb;
    newconn->close_cb = ctx->close_cb;
    newconn->data = ctx->data;
    list_add(&newconn->list, &newconn->head->list);
    ASSERT(newconn->connect_cb);
    newconn->connect_cb(newconn);
}


static void __netloop_prepare(void *opaque)
{
    struct netloop_server_t *server = (struct netloop_server_t *)opaque;
    struct netloop_conn_t *ctx;

    DEBUG_PRINTF("__netloop_prepare\n");
    list_for_each_entry(ctx, &server->head.list, list) {
        ASSERT(ctx->fd >= 0);
        ctx->idx = loop_add_poll(&server->loop, ctx->fd, ctx->events);
    }

    netloop_dump_list(&server->head);
}

static void __netloop_poll(void *opaque)
{
    struct netloop_server_t *server = (struct netloop_server_t *)opaque;
    struct netloop_conn_t *ctx, *tmp;

    DEBUG_PRINTF("__netloop_poll\n");
    list_for_each_entry_safe(ctx, tmp, &server->head.list, list) {
        int revents = loop_get_revents(&server->loop, ctx->idx);
        if (revents & POLLIN) {
            ASSERT(ctx->in);
            ctx->in(ctx);
        }
        if (revents & POLLOUT) {
            ASSERT(ctx->out)
            ctx->out(ctx);
        }
        if (NETLOOP_STATE_CLOSED == ctx->state) {
            close(ctx->fd);
            list_del(&ctx->list);
            netloop_conn_free(ctx);
        }
    }
}




struct netloop_server_t *netloop_init(void)
{
    int r;
    struct netloop_server_t *server;

    server =  malloc(sizeof(struct netloop_server_t));
    if (!server) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(server, 0, sizeof(struct netloop_server_t));
    INIT_LIST_HEAD(&server->head.list);
    server->head.fd = -1;

    r = loop_init(&server->loop);
    if (r < 0) {
        ERROR_PRINTF("loop_init: %s\n", strerror(errno));
        free(server);
        return NULL;
    }

    return server;
}


int netloop_new_server(struct netloop_server_t *server, const struct netloop_opt_t *opt)
{
    int sock;
    struct netloop_conn_t *listener;
    ASSERT(server && opt);

    sock = tcp_socket_create(1, opt->host, opt->port);
    if (sock < 0) {
        return -1;
    }

    listener = netloop_conn_new();
    if (!listener) {
        close(sock);
        return -1;
    }

    listener->fd = sock;
    listener->type = NETLOOP_TYPE_LISTENER;
    listener->events |= POLLIN;
    listener->head = &server->head;
    listener->in = __netloop_accept;

    listener->connect_cb = opt->connect_cb;
    listener->recv_cb = opt->recv_cb;
    listener->close_cb = opt->close_cb;
    listener->data = opt->data;
    list_add(&listener->list, &server->head.list);
    return 0;
}


int netloop_start(struct netloop_server_t *server)
{
    struct loopcb_t loop_cb;

    ASSERT(server);

    netloop_dump_list(&server->head);

    loop_cb.poll = __netloop_poll;
    loop_cb.prepare = __netloop_prepare;
    loop_cb.timer = NULL;
    loop_cb.opaque = server;
    loop_register(&server->loop, loop_cb);
    return loop_start(&server->loop);
}
