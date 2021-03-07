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
#include <list.h>
#include <sys/types.h>
#include <sys/socket.h>

#define NETLOOP_TYPE_LISTENER     'L'
#define NETLOOP_TYPE_SERVER       'S'
#define NETLOOP_TYPE_REMOTE       'R'

#define  NETLOOP_STATE_INIT       '0'
#define  NETLOOP_STATE_RESOLV     '1'
#define  NETLOOP_STATE_CONNECT    '2'
#define  NETLOOP_STATE_STREAM     '3'
#define  NETLOOP_STATE_CLOSED     '4'

#define NETLOOP_MAGIC   0xcafecafe

struct sockaddr_t {
    socklen_t addrlen;
    union {
        struct sockaddr addr;
    };
};

struct netloop_conn_t {
    struct list_head list;
    struct netloop_conn_t *head;
    uint32_t magic;
    struct sockaddr_t peer;
    int fd;
    int events;
    int idx;
    char type;
    char state;
    void (*in)(struct netloop_conn_t *);
    void (*out)(struct netloop_conn_t *);

    void (*connect_cb)(struct netloop_conn_t *);
    void (*recv_cb)(struct netloop_conn_t *, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *);
    void *data;
};

struct netloop_server_t {
    struct netloop_conn_t head;
    struct loop_t loop;
};

struct netloop_opt_t {
    char *host;
    uint16_t port;
    void *data;
    void (*connect_cb)(struct netloop_conn_t *);
    void (*recv_cb)(struct netloop_conn_t *, void *buf, int len);
    void (*close_cb)(struct netloop_conn_t *);
};


int netloop_new_server(struct netloop_server_t *server, const struct netloop_opt_t *opt);
int netloop_start(struct netloop_server_t *server);
struct netloop_server_t *netloop_init(void);

#endif
