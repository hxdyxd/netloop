/*
 * netloop.h of netloop
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
#ifndef _NETLOOP_H_
#define _NETLOOP_H_


#include <stdint.h>
#include <loop.h>
#include <ares.h>
#include <list.h>
#include <sys/types.h>
#include <sys/socket.h>

#define NETLOOP_MAX_RECV_BUF_SIZE       512
#define NETLOOP_MAX_SEND_BUF_SIZE      2048

#define NETLOOP_TYPE_LISTENER     'L'
#define NETLOOP_TYPE_SERVER       'S'
#define NETLOOP_TYPE_REMOTE       'R'
#define NETLOOP_TYPE_DNS          'D'

#define  NETLOOP_STATE_INIT       '0'
#define  NETLOOP_STATE_RESOLV     '1'
#define  NETLOOP_STATE_CONNECT    '2'
#define  NETLOOP_STATE_STREAM     '3'
#define  NETLOOP_STATE_CLOSED     '4'

#define NETLOOP_PROTO_TCP         'T'
#define NETLOOP_PROTO_SSL         'S'
#define NETLOOP_PROTO_USR         'U'

#define NETLOOP_MAGIC   0xcafecafe
#define NETLOOP_RESERVED_MEM        (512)

struct sockaddr_t {
    //from sys
    socklen_t addrlen;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr_v4;
        struct sockaddr_in6 addr_v6;
    };
    //from user
    char *host;
    uint16_t port;
};

struct netloop_buffer_t {
    int idx;
    int len;
    char *data;
};

struct netloop_conn_t {
    uint32_t magic;
    struct list_head list;
    struct netloop_conn_t *head;
    struct sockaddr_t peer;
    int fd;
    int events;
    int idx;
    char type;
    char proto;
    char state;
    int max_extra_send_buf_size;
    struct netloop_buffer_t *recvbuf;
    struct netloop_buffer_t *extra_send_buf;
    void (*in)(struct netloop_conn_t *ctx);
    void (*out)(struct netloop_conn_t *ctx);
    void (*free)(struct netloop_conn_t *ctx);

    void (*connect_cb)(struct netloop_conn_t *ctx);
    void (*recv_cb)(struct netloop_conn_t *ctx, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *ctx);
    void (*full_cb)(struct netloop_conn_t *ctx);
    void (*drain_cb)(struct netloop_conn_t *ctx);
    void (*error_cb)(struct netloop_conn_t *ctx);

    int (*send)(struct netloop_conn_t *ctx, void *buf, int len);
    void (*pause_recv)(struct netloop_conn_t *ctx);
    void (*resume_recv)(struct netloop_conn_t *ctx);
    int (*close)(struct netloop_conn_t *ctx);
    void *(*get_priv)(struct netloop_conn_t *ctx);

    void *data;
};

struct netloop_opt_t {
    char *host;
    uint16_t port;
    void *data;
    void (*connect_cb)(struct netloop_conn_t *ctx);
    void (*recv_cb)(struct netloop_conn_t *ctx, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *ctx);
    void (*full_cb)(struct netloop_conn_t *ctx);
    void (*drain_cb)(struct netloop_conn_t *ctx);
    void (*error_cb)(struct netloop_conn_t *ctx);
};

struct netloop_server_t {
    struct netloop_conn_t head;
    struct loop_t loop;
    ares_channel dns_channel;
    int need_free_conn;
    struct netloop_buffer_t *recvbuf;

    int (*start)(struct netloop_server_t *server);
    struct netloop_conn_t *(*new_server)(struct netloop_server_t *server, const struct netloop_opt_t *opt);
    struct netloop_conn_t *(*new_remote)(struct netloop_server_t *server, const struct netloop_opt_t *opt);
};

#define  netloop_priv(ctx)  (ctx)->get_priv(ctx)
struct netloop_server_t *netloop_init(void);

struct netloop_buffer_t *buffer_append(struct netloop_buffer_t *buf, char *data, int len);
void buffer_free(struct netloop_buffer_t *buf);

#endif
