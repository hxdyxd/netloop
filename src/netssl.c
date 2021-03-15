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
#include <netssl.h>

#define LOG_NAME   __FILE__
#define DEBUG_PRINTF(fmt, ...) \
    printf("\033[0;32m" LOG_NAME " %s:%d\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ERROR_PRINTF(fmt, ...) \
    printf("\033[1;31m" LOG_NAME " %s:%d\033\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

/*
struct netloop_ssl_priv_t {
    struct netloop_conn_t *conn;
    SSL *ssl;

    void (*connect_cb)(struct netloop_conn_t *ctx);
    void (*recv_cb)(struct netloop_conn_t *ctx, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *ctx);
    void (*full_cb)(struct netloop_conn_t *ctx);
    void (*drain_cb)(struct netloop_conn_t *ctx);
    void (*error_cb)(struct netloop_conn_t *ctx);

    int (*send)(struct netloop_conn_t *ctx, void *buf, int len);
    int (*close)(struct netloop_conn_t *ctx);
    void *(*get_priv)(struct netloop_conn_t *ctx);
};


static struct netloop_ssl_conn_t *netloop_ssl_conn_new(void)
{
    struct netloop_ssl_conn_t *conn;
    conn = malloc(sizeof(struct netloop_ssl_conn_t));
    if (!conn) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(struct netloop_ssl_conn_t));
    conn->magic = NETLOOP_SSL_MAGIC;
    conn->ssl = SSL_new(conn->ctx);
    return conn;
}
*/


static void __ssl_connect(struct netloop_conn_t *ctx)
{
    int r;
    struct netloop_ssl_server_t *server = (struct netloop_ssl_server_t *)ctx->head;
    DEBUG_PRINTF("ssl __ssl_connect\n");
    /*ctx->ssl = SSL_new(server->ctx);
    SSL_set_fd(ctx->ssl, ctx->tcp.fd);
    r = SSL_connect(ctx->ssl);
    if (r < 0) {
        DEBUG_PRINTF("", SSL_get_error());
    }*/
}

static void __ssl_recv(struct netloop_conn_t *ctx, void *buf, int len)
{
    DEBUG_PRINTF("ssl __ssl_recv\n");
}

static void __ssl_close_cb(struct netloop_conn_t *ctx)
{
    DEBUG_PRINTF("ssl __ssl_close_cb\n");
}


static int ssl_send(struct netloop_conn_t *ctx, void *buf, int len)
{
    DEBUG_PRINTF("ssl ssl_send\n");
}

static int ssl_close(struct netloop_conn_t *ctx)
{
    DEBUG_PRINTF("ssl ssl_close\n");
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
    struct netloop_opt_t *tcp_opt = &opt->tcp;
    return -1;
}

static struct netloop_ssl_conn_t *ssl_new_remote(struct netloop_ssl_server_t *server, const struct netloop_ssl_opt_t *opt)
{
    ASSERT(server);
    struct netloop_server_t *tcp = &server->tcp;
    struct netloop_opt_t *tcp_opt = &opt->tcp;
    struct netloop_ssl_conn_t *remote;

    remote = (struct netloop_ssl_conn_t *)tcp->new_remote(tcp, tcp_opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return NULL;
    }
    remote->connect_cb = remote->tcp.connect_cb;
    remote->recv_cb    = remote->tcp.recv_cb;
    remote->close_cb   = remote->tcp.close_cb;
    remote->full_cb    = remote->tcp.full_cb;
    remote->drain_cb   = remote->tcp.drain_cb;
    remote->error_cb   = remote->tcp.error_cb;
    remote->tcp.connect_cb = __ssl_connect;
    remote->tcp.recv_cb    = __ssl_recv;
    remote->tcp.close_cb   = __ssl_close_cb;
    remote->send           = ssl_send;
    remote->close          = ssl_close;

    return remote;
}

struct netloop_ssl_server_t *netloop_ssl_init_by_server(struct netloop_server_t *tcp)
{
    ASSERT(tcp);
    struct netloop_ssl_server_t *server = tcp;
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

/*
static void __netloop_ssl_connect(struct netloop_conn_t *ctx)
{
    ASSERT(ctx);
    struct netloop_ssl_priv_t *nssl = ctx->get_priv(ctx);
    ASSERT(nssl);
    DEBUG_PRINTF("ssl connect\n");
}

static void __netloop_ssl_receive(struct netloop_conn_t *ctx, void *buf, int len)
{
    ASSERT(ctx);
    struct netloop_ssl_priv_t *nssl = (struct netloop_ssl_priv_t *)netloop_priv(ctx);
    ASSERT(nssl);
    DEBUG_PRINTF("ssl receive\n");
}

static void __netloop_ssl_close(struct netloop_conn_t *ctx)
{
    ASSERT(ctx);
    struct netloop_ssl_priv_t *nssl = (struct netloop_ssl_priv_t *)netloop_priv(ctx);
    ASSERT(nssl);
    DEBUG_PRINTF("ssl close\n");
}

static void __netloop_ssl_free(struct netloop_conn_t *ctx)
{
    ASSERT(ctx);
    struct netloop_ssl_priv_t *nssl = (struct netloop_ssl_priv_t *)netloop_priv(ctx);
    ASSERT(nssl);
    free(nssl);
    DEBUG_PRINTF("ssl free\n");
}

static void __netloop_ssl_get_priv(struct netloop_conn_t *ctx)
{
    ASSERT(ctx);
    struct netloop_ssl_priv_t *nssl = (struct netloop_ssl_priv_t *)ctx->get_priv(ctx);
    ASSERT(nssl);
    if (nssl->get_next_priv)
        return nssl->get_next_priv;
    return nssl->data;
}

int netloop_set_ssl(struct netloop_conn_t *conn)
{
    struct netloop_ssl_priv_t *nssl;
    ASSERT(conn);

    nssl = malloc(sizeof(struct netloop_ssl_priv_t));
    if (!nssl) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(nssl, 0, sizeof(struct netloop_ssl_priv_t));
    nssl->conn = conn;
    nssl->connect_cb  = conn->connect_cb;
    nssl->recv_cb  = conn->recv_cb;
    nssl->close_cb = conn->close_cb;
    nssl->error_cb = conn->error_cb;
    nssl->send = conn->send;
    nssl->close = conn->close;
    conn->connect_cb = __netloop_ssl_connect;
    conn->recv_cb = __netloop_ssl_receive;
    conn->close_cb =  __netloop_ssl_close;
    conn->free = __netloop_ssl_free;
    conn->get_next_priv = __netloop_ssl_get_priv;
}
*/
