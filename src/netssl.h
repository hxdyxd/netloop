/*
 * ssl.h of netloop
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
#ifndef _NETLOOP_SSL_H_
#define _NETLOOP_SSL_H_

#include <openssl/ssl.h>
#include <netloop.h>

#define NETLOOP_SSL_MAGIC   0xbabadada

struct netloop_ssl_conn_t {
    struct netloop_conn_t tcp;
    uint32_t magic;
    SSL *ssl;

    void (*connect_cb)(struct netloop_conn_t *ctx);
    void (*recv_cb)(struct netloop_conn_t *ctx, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *ctx);
    void (*full_cb)(struct netloop_conn_t *ctx);
    void (*drain_cb)(struct netloop_conn_t *ctx);
    void (*error_cb)(struct netloop_conn_t *ctx);

    int (*send)(struct netloop_ssl_conn_t *ctx, void *buf, int len);
    void (*pause_recv)(struct netloop_ssl_conn_t *ctx);
    void (*resume_recv)(struct netloop_ssl_conn_t *ctx);
    int (*close)(struct netloop_ssl_conn_t *ctx);

    void *data;
};

struct netloop_ssl_opt_t {
    struct netloop_opt_t tcp;
};

struct netloop_ssl_server_t {
    struct netloop_server_t tcp;
    uint32_t magic;
    SSL_CTX *ctx;

    int (*start)(struct netloop_ssl_server_t *server);
    int (*new_server)(struct netloop_ssl_server_t *server, const struct netloop_ssl_opt_t *opt);
    struct netloop_conn_t *(*new_remote)(struct netloop_ssl_server_t *server, const struct netloop_ssl_opt_t *opt);
};

int netloop_set_ssl(struct netloop_conn_t *conn);
struct netloop_ssl_server_t *netloop_ssl_init_by_server(struct netloop_server_t *raw_server);

#endif