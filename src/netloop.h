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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>

#include "coroutine.h"
#include "list.h"
#include "loop.h"


#define NETLOOP_MAGIC     0xcafecafe

struct netloop_obj_t {
    uint32_t magic;
    struct list_head list;
    struct list_head timer;
    struct netloop_main_t *nm;
    int idx;
    int fd;
    int events;
    int revents;
    int co;
    char *name;
    int expires;
    int time;
    const char *caller;

    void (*task_cb)(struct netloop_obj_t *, void *ud);
    void *data;
};

typedef void (*task_func)(struct netloop_obj_t *, void *ud);

struct netloop_main_t {
    struct netloop_obj_t head;
    struct netloop_obj_t ready;
    struct netloop_obj_t timer;
    struct schedule *s;
    struct loop_t loop;
};

struct netloop_task_t {
    task_func task_cb;
    void *ud;
    char *name;
};

#define netloop_yield(ctx)              \
    do {                                \
        (ctx)->caller = __FUNCTION__;   \
        coroutine_yield((ctx)->nm->s);  \
    } while(0)

struct netloop_obj_t *netloop_run_task(struct netloop_main_t *nm, struct netloop_task_t *task);
void netloop_dump_task(struct netloop_main_t *nm);

int netloop_accept(struct netloop_obj_t *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int netloop_connect(struct netloop_obj_t *ctx, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t netloop_read(struct netloop_obj_t *ctx, int fd, void *buf, size_t count);
ssize_t netloop_write(struct netloop_obj_t *ctx, int fd, void *buf, size_t count);
unsigned int netloop_sleep(struct netloop_obj_t *ctx, unsigned int seconds);

struct netloop_main_t *netloop_init(void);
int netloop_start(struct netloop_main_t *nm);

#endif
