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
#include <string.h>
#include <fcntl.h>
#include "netloop.h"

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static void netloop_prepare(void *opaque);
static void netloop_timer(void *opaque);
static void netloop_poll(void *opaque);
static int debug_obj_cnt = 0;

void netloop_dump_task(struct netloop_main_t *nm)
{
    struct netloop_obj_t *ctx;
    int cur = time(NULL);
    int item = 0;

    printf("------------------total_obj: %u------------------\n", debug_obj_cnt);
    list_for_each_entry(ctx, &nm->head.list, list) {
        printf("%s: ", ctx->caller);
        printf("co: %d, fd: %d, ", ctx->co,  ctx->fd);
        printf("events: %c%c, ", (ctx->events & POLLIN) ? 'I' : ' ', (ctx->events & POLLOUT) ? 'O' : ' ' );
        printf("run: %u, ", cur - ctx->time);
        if (ctx->name) {
            printf("name: %s", ctx->name);
        }
        printf("\n");
        item++;
    }
    printf("------------------total_obj: %u/%u------------------\n", item, debug_obj_cnt);
    item = 0;

    if (list_empty(&nm->timer.list)) {
        return;
    }
    list_for_each_entry(ctx, &nm->timer.list, list) {
        int diff = ctx->expires - cur;
        printf("%s: ", ctx->caller);
        printf("co: %d, ", ctx->co);
        printf("run: %u, ", cur - ctx->time);
        printf("tm: %u, ", diff);
        if (ctx->name) {
            printf("name: %s", ctx->name);
        }
        printf("\n");
        item++;
    }
    printf("---------------total_timer_obj: %u/%u---------------\n", item, debug_obj_cnt);
}

struct netloop_main_t *netloop_init(void)
{
    int r;
    struct netloop_main_t *nm;
    nm = malloc(sizeof(struct netloop_main_t));
    if (!nm) {
        return NULL;
    }
    memset(nm, 0, sizeof(struct netloop_main_t));
    INIT_LIST_HEAD(&nm->head.list);
    INIT_LIST_HEAD(&nm->ready.list);
    INIT_LIST_HEAD(&nm->timer.list);

    nm->s = coroutine_open();
    if (!nm->s) {
        ERROR_PRINTF("coroutine_open() %s\n", strerror(errno));
        free(nm);
        return NULL;
    }

    r = loop_init(&nm->loop);
    if (r < 0) {
        ERROR_PRINTF("loop_init() %s\n", strerror(errno));
        coroutine_close(nm->s);
        free(nm);
        return NULL;
    }

    return nm;
}

int netloop_start(struct netloop_main_t *nm)
{
    struct loopcb_t loop_cb;
    ASSERT(nm);

    loop_cb.poll = netloop_poll;
    loop_cb.prepare = netloop_prepare;
    loop_cb.timer = netloop_timer;
    loop_cb.opaque = nm;
    loop_register(&nm->loop, loop_cb);
    return loop_start(&nm->loop);
}


static struct netloop_obj_t *netloop_obj_new(void)
{
    struct netloop_obj_t *conn;
    conn = malloc(sizeof(struct netloop_obj_t));
    if (!conn) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(struct netloop_obj_t));
    conn->magic = NETLOOP_MAGIC;
    debug_obj_cnt++;
    return conn;
}

static void netloop_obj_free(struct netloop_obj_t *conn)
{
    ASSERT(NETLOOP_MAGIC == conn->magic);
    conn->fd = -1;
    conn->magic = 0;
    if (conn->name) {
        free(conn->name);
        conn->name = NULL;
    }
    free(conn);
    debug_obj_cnt--;
    NONE_PRINTF("conn: %d\n", debug_obj_cnt);
}

static void netloop_process(struct schedule *s, void *ud)
{
    struct netloop_obj_t *ctx = (struct netloop_obj_t *)ud;
    if (ctx->task_cb) {
        ctx->task_cb(ctx, ctx->data);
    }
    list_del(&ctx->list);
    netloop_obj_free(ctx);
}

static void netloop_prepare(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &nm->ready.list, list) {
        list_del(&ctx->list);
        ctx->co = coroutine_new(ctx->nm->s, netloop_process, ctx);
        list_add(&ctx->list, &nm->head.list);
        coroutine_resume(nm->s, ctx->co);
    }

    list_for_each_entry(ctx, &nm->head.list, list) {
        ASSERT(ctx->fd >= 0);
        ctx->idx = loop_add_poll(&nm->loop, ctx->fd, ctx->events);
        ctx->revents = 0;
    }

    if (list_empty(&nm->timer.list)) {
        return;
    }
    int cur = time(NULL);
    list_for_each_entry(ctx, &nm->timer.list, list) {
        int diff = ctx->expires - cur;
        if (diff > 0) {
            loop_set_timeout(&nm->loop, 1000 * diff);
        }
    }
}

static void netloop_timer(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    if (list_empty(&nm->timer.list)) {
        return;
    }
    int cur = time(NULL);
    list_for_each_entry_safe(ctx, tmp, &nm->timer.list, list) {
        int diff = ctx->expires - cur;
        if (diff <= 0) {
            coroutine_resume(nm->s, ctx->co);
        }
    }
}

static void netloop_poll(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &nm->head.list, list) {
        ctx->revents = loop_get_revents(&nm->loop, ctx->idx);
        if ((ctx->revents & POLLIN) || (ctx->revents & POLLOUT)) {
            coroutine_resume(nm->s, ctx->co);
        }
    }

    if (list_empty(&nm->timer.list)) {
        return;
    }
    int cur = time(NULL);
    list_for_each_entry_safe(ctx, tmp, &nm->timer.list, list) {
        int diff = ctx->expires - cur;
        if (diff <= 0) {
            coroutine_resume(nm->s, ctx->co);
        }
    }
}


struct netloop_obj_t *netloop_run_task(struct netloop_main_t *nm, struct netloop_task_t *task)
{
    ASSERT(nm && task);
    struct netloop_obj_t *ctx;

    ctx = netloop_obj_new();
    if (!ctx) {
        return NULL;
    }
    ctx->fd = -1;
    ctx->nm = nm;
    ctx->name = strdup(task->name);
    ctx->data = task->ud;
    ctx->task_cb = task->task_cb;
    ctx->time = time(NULL);
    list_add_tail(&ctx->list, &nm->ready.list);
    return ctx;
}


int netloop_accept(struct netloop_obj_t *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    while (1) {
        int r = accept(sockfd, addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = sockfd;
            ctx->events = POLLIN;
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}

int netloop_connect(struct netloop_obj_t *ctx, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int r;
    int val;
    socklen_t optlen = sizeof(int);

    r = connect(sockfd, addr, addrlen);
    if (r < 0 && EINPROGRESS == errno) {
        ctx->fd = sockfd;
        ctx->events = POLLOUT;
        netloop_yield(ctx);
    } else {
        return r;
    }

    r = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &val, &optlen);
    if (r < 0) {
        ERROR_PRINTF("getsockopt(fd = %d) %s\n", sockfd, strerror(errno));
        return r;
    }
    if (val < 0) {
        ERROR_PRINTF("connect(fd = %d) %s\n", sockfd, strerror(val));
        return val;
    }
    return 0;
}

ssize_t netloop_read(struct netloop_obj_t *ctx, int fd, void *buf, size_t count)
{
    while (1) {
        int r = read(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = fd;
            ctx->events = POLLIN;
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}

ssize_t netloop_write(struct netloop_obj_t *ctx, int fd, void *buf, size_t count)
{
    char *pos = buf;
    while (1) {
        int r = write(fd, pos, count);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = fd;
            ctx->events = POLLOUT;
            netloop_yield(ctx);
        } else if (0 < r && r < count) {
            ctx->fd = fd;
            ctx->events = POLLOUT;
            netloop_yield(ctx);
            pos += r;
            count -= r;
        } else {
            return r;
        }
    }
}

unsigned int netloop_sleep(struct netloop_obj_t *ctx, unsigned int seconds)
{
    ctx->expires = time(NULL) + seconds;
    list_del(&ctx->list);
    list_add(&ctx->list, &ctx->nm->timer.list);
    netloop_yield(ctx);
    list_del(&ctx->list);
    list_add(&ctx->list, &ctx->nm->head.list);
    return 0;
}
