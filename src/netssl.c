/*
 * ssl.c of netloop
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
#include <errno.h>
#include <netssl.h>

#include <log.h>
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static inline void do_callback(void (*cb)(struct netloop_conn_t *),
                               struct netloop_conn_t *ctx)
{
    if (cb) {
        cb(ctx);
    }
}


static void __ssl_receive(struct netloop_conn_t *ctx)
{
    int r;
    char buffer[512];
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);
    ASSERT(NETLOOP_SSL_STATE_STREAM == conn->state);

    r = SSL_read(conn->ssl, buffer, 512);
    if (r <= 0) {
        r = SSL_get_error(conn->ssl, r);
        switch(r) {
        case SSL_ERROR_WANT_READ:
            ctx->events |= POLLIN;
            return;
        case SSL_ERROR_ZERO_RETURN:
            ctx->close(ctx);
            return;
        case SSL_ERROR_SYSCALL:
            if (0 != errno) {
                ERROR_PRINTF("SSL_read(fd = %d) %s\n", ctx->fd, strerror(errno));
            }
            ctx->close(ctx);
            return;
        default:
            ERROR_PRINTF("SSL_read() %d\n", r);
            ctx->close(ctx);
            return;
        }
    }
    if (conn->recv_cb)
        conn->recv_cb(ctx, buffer, r);
}

static void __ssl_send(struct netloop_conn_t *ctx)
{
    int r;
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);
    ASSERT(NETLOOP_SSL_STATE_STREAM == conn->state);
    ASSERT(ctx->extra_send_buf);

    r = SSL_write(conn->ssl, ctx->extra_send_buf->data, ctx->extra_send_buf->len);
    if (r <= 0) {
        r = SSL_get_error(conn->ssl, r);
        switch(r) {
        case SSL_ERROR_SYSCALL:
            ERROR_PRINTF("SSL_write(fd = %d) %s\n", ctx->fd, strerror(errno));
            ctx->close(ctx);
            break;
        default:
            ERROR_PRINTF("SSL_write() %d\n", r);
            ctx->close(ctx);
            break;
        }
    } else if (r < ctx->extra_send_buf->len) {
        DEBUG_PRINTF("write: %d/%d\n", r, ctx->extra_send_buf->len);
        ASSERT(0);
    }

    buffer_free(ctx->extra_send_buf);
    ctx->extra_send_buf = NULL;
    ctx->events &= ~POLLOUT;
    do_callback(ctx->drain_cb, ctx);
}

static void __ssl_connect_deal(struct netloop_conn_t *ctx)
{
    int r;
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);
    ASSERT(NETLOOP_SSL_STATE_CONNECT == conn->state);

    r = SSL_connect(conn->ssl);
    if (1 != r) {
        r = SSL_get_error(conn->ssl, r);
        switch(r) {
        case SSL_ERROR_WANT_READ:
            ctx->events = POLLIN;
            DEBUG_PRINTF("SSL_connect() %d\n", r);
            break;
        case SSL_ERROR_WANT_WRITE:
            ctx->events = POLLOUT;
            DEBUG_PRINTF("SSL_connect() %d\n", r);
            break;
        case SSL_ERROR_SYSCALL:
            ERROR_PRINTF("SSL_connect(fd = %d) %s\n", ctx->fd, strerror(errno));
            ctx->close(ctx);
            break;
        default:
            ERROR_PRINTF("SSL_connect() %d\n", r);
            ctx->close(ctx);
            break;
        }
    } else {
        conn->state = NETLOOP_SSL_STATE_STREAM;
        ctx->in     = __ssl_receive;
        ctx->out    = __ssl_send;
        ctx->events = POLLIN;
        if (ctx->extra_send_buf) {
            ctx->events |= POLLOUT;
        }
        DEBUG_PRINTF("SSL_connect() ok!\n");
        do_callback(conn->connect_cb, ctx);
    }
}

static void __ssl_connect(struct netloop_conn_t *ctx)
{
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    struct netloop_ssl_server_t *server = (struct netloop_ssl_server_t *)ctx->head;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);

    DEBUG_PRINTF("ssl __ssl_connect\n");
    ctx->in  = __ssl_connect_deal;
    ctx->out = __ssl_connect_deal;
    conn->state = NETLOOP_SSL_STATE_CONNECT;
    conn->ssl = SSL_new(server->ctx);
    SSL_set_fd(conn->ssl, ctx->fd);
    __ssl_connect_deal(ctx);
}

static void __ssl_unused(struct netloop_conn_t *ctx)
{
    ERROR_PRINTF("__ssl_unused()!\n");
}

static void __ssl_unused_data(struct netloop_conn_t *ctx, void *buf, int len)
{
    ERROR_PRINTF("__ssl_unused()!\n");
}

static int ssl_send(struct netloop_conn_t *ctx, void *buf, int len)
{
    int r;
    ASSERT(NULL != ctx);
    ASSERT(NETLOOP_MAGIC == ctx->magic);
    ASSERT(NULL != buf);
    ASSERT(0 != len);
    ASSERT(ctx->fd >= 0);
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);

    if (NETLOOP_SSL_STATE_CLOSED == conn->state) {
        WARN_PRINTF("connection already closed\n");
        return -1;
    }
    if (ctx->extra_send_buf) {
        ASSERT(ctx->extra_send_buf->len < ctx->max_extra_send_buf_size);
    }

    if (NETLOOP_SSL_STATE_STREAM != conn->state || ctx->extra_send_buf) {
        ctx->extra_send_buf = buffer_append(ctx->extra_send_buf, buf, len);
        if (!ctx->extra_send_buf) {
            return -1;
        }
        if (ctx->extra_send_buf->len >= ctx->max_extra_send_buf_size) {
            do_callback(ctx->full_cb, ctx);
        }
        return len;
    }

    r = SSL_write(conn->ssl, buf, len);
    if (r <= 0) {
        r = SSL_get_error(conn->ssl, r);
        switch(r) {
        case SSL_ERROR_SYSCALL:
            ERROR_PRINTF("SSL_write(fd = %d) %s\n", ctx->fd, strerror(errno));
            ctx->close(ctx);
            break;
        default:
            ERROR_PRINTF("SSL_write() %d\n", r);
            ctx->close(ctx);
            break;
        }
    } else if (r < len) {
        DEBUG_PRINTF("write: %d/%d\n", r, len);
        //todo...
    }
    return 0;
}

static int ssl_close(struct netloop_conn_t *ctx)
{
    ASSERT(NULL != ctx);
    ASSERT(NETLOOP_MAGIC == ctx->magic);
    struct netloop_ssl_conn_t *conn = (struct netloop_ssl_conn_t *)ctx;
    struct netloop_server_t *server = (struct netloop_server_t *)ctx->head;
    ASSERT(NETLOOP_SSL_MAGIC == conn->magic);

    DEBUG_PRINTF("ssl ssl_close\n");
    if (NETLOOP_STATE_CLOSED != ctx->state) {
        ctx->state  = NETLOOP_STATE_CLOSED;
        conn->state = NETLOOP_SSL_STATE_CLOSED;
        do_callback(conn->close_cb, ctx);
        SSL_free(conn->ssl);
        conn->magic = 0;
        ++server->need_free_conn;
    }
    return 0;
}

static int ssl_start(struct netloop_ssl_server_t *server)
{
    struct netloop_server_t *raw_server = &server->tcp;
    return raw_server->start(raw_server);
}

static int ssl_new_server(struct netloop_ssl_server_t *server, const struct netloop_ssl_opt_t *opt)
{
    ASSERT(server);
    struct netloop_server_t *tcp = &server->tcp;
    const struct netloop_opt_t *tcp_opt = &opt->tcp;

    return -1;
}

static struct netloop_conn_t *ssl_new_remote(struct netloop_ssl_server_t *server, const struct netloop_ssl_opt_t *opt)
{
    ASSERT(server);
    struct netloop_server_t *tcp = &server->tcp;
    const struct netloop_opt_t *tcp_opt = &opt->tcp;
    struct netloop_ssl_conn_t *remote;

    remote = (struct netloop_ssl_conn_t *)tcp->new_remote(tcp, tcp_opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return NULL;
    }
    remote->magic      = NETLOOP_SSL_MAGIC;
    remote->tcp.proto  = NETLOOP_PROTO_SSL;
    remote->state      = NETLOOP_SSL_STATE_TCPCONNECT;
    remote->connect_cb = remote->tcp.connect_cb;
    remote->recv_cb    = remote->tcp.recv_cb;
    remote->close_cb   = remote->tcp.close_cb;
    //remote->full_cb    = remote->tcp.full_cb;
    //remote->drain_cb   = remote->tcp.drain_cb;
    remote->error_cb   = remote->tcp.error_cb;
    //remote->send       = ssl_send;
    //remote->close      = ssl_close;

    //from tcp layer
    remote->tcp.connect_cb = __ssl_connect;
    remote->tcp.recv_cb    = __ssl_unused_data;
    remote->tcp.close_cb   = __ssl_unused;

    //from user
    remote->tcp.send       = ssl_send;
    remote->tcp.close      = ssl_close;
    return &remote->tcp;
}

struct netloop_ssl_server_t *netloop_ssl_init_by_server(struct netloop_server_t *tcp)
{
    ASSERT(tcp);
    struct netloop_ssl_server_t *server = (struct netloop_ssl_server_t *)tcp;
    const SSL_METHOD *method;

    if (0 != server->magic) {
        ERROR_PRINTF("magic fail!\n");
        return NULL;
    }
    server->magic = NETLOOP_SSL_MAGIC;

    method = TLS_method();
    server->ctx = SSL_CTX_new(method);
    if (!server->ctx) {
        perror("unable to create SSL context\n");
        server->magic = 0;
        return NULL;
    }
    server->start      = ssl_start;
    server->new_server = ssl_new_server;
    server->new_remote = ssl_new_remote;

    return server;
}
