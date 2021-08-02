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
#include <sys/eventfd.h>
#include "netloop.h"
#include "garray.h"
#include "coroutine.h"
#include "list.h"
#include "loop.h"
#include "netclock.h"

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


#define NETLOOP_MAGIC          0xcafecafe
#define NETLOOP_MAIN_MAGIC     0xaffec000
#define NETLOOP_TASK_NAME      "--"

struct netloop_obj_t {
    uint32_t magic;
    struct list_head list;
    struct list_head timer;
    struct netloop_main_t *nm;
    GArray *idxs;
    struct pollfd *fds;
    int nfds;
    int rnfds;
    int co;
    int pco;
    char *name;
    uint32_t expires;
    int exitfd;
    int exit_waiting;
    uint32_t time;
    uint32_t ctxswitch;
    const char *caller;

    task_func task_cb;
    void *data;
};

struct netloop_main_t {
    uint32_t magic;
    struct netloop_obj_t head;
    struct netloop_obj_t ready;
    struct netloop_obj_t timer;
    struct schedule *s;
    struct loop_t loop;
    struct netloop_obj_t *current;
    int task_cnt;
};

static void __netloop_prepare(void *opaque);
static void __netloop_timer(void *opaque);
static void __netloop_poll(void *opaque);


void netloop_dump_task(struct netloop_main_t *nm)
{
    struct netloop_obj_t *ctx;
    uint32_t cur = get_time_ms();
    int item = 0;
    int i;

    printf("------------------total_obj: %u------------------\n", nm->task_cnt);
    printf("%24s | %5s | %5s | %5s | %6s | %8s | %8s | %30s\n",
            "caller", "tid", "ptid", "fd", "status", "uptime", "sw", "name");
    list_for_each_entry(ctx, &nm->head.list, list) {
        int nfds = ctx->nfds;
        if (!nfds) {
            nfds = 1;
        }
        for (i = 0; i < nfds; i++) {
            char events[5];
            int fd_events = ctx->fds ? ctx->fds[i].events : 0;
            int fd = ctx->fds ? ctx->fds[i].fd : -1;
            int status = coroutine_status(ctx->nm->s, ctx->co);
            printf("%24s   ", ctx->caller);
            printf("%5d   %5d   ", ctx->co,  ctx->pco);
            printf("%5d   ", fd);
            memset(events, ' ', sizeof(events));
            if (COROUTINE_RUNNING == status)
                events[0] = 'R';
            else if (COROUTINE_SUSPEND == status)
                events[0] = 'S';
            if (fd_events & POLLIN)
                events[1] = 'I';
            if (fd_events & POLLOUT)
                events[2] = 'O';
            events[3] = 0;
            printf("%6s   ", events);
            printf("%8u   ", (cur - ctx->time) / 1000);
            printf("%8u   ", ctx->ctxswitch);
            printf("%30s   ", ctx->name);
            printf("\n");
        }
        item++;
    }
    printf("------------------total_obj: %u/%u------------------\n", item, nm->task_cnt);
    item = 0;

    if (list_empty(&nm->timer.list)) {
        return;
    }
    printf("%24s | %5s | %5s | %10s | %8s | %8s | %30s\n",
            "caller", "tid", "ptid", "timeout", "uptime", "sw", "name");
    list_for_each_entry(ctx, &nm->timer.list, timer) {
        int diff = ctx->expires - cur;
        printf("%24s   ", ctx->caller);
        printf("%5d   %5d   ", ctx->co,  ctx->pco);
        printf("%10.3f   ", diff / 1000.0);
        printf("%8u   ", (cur - ctx->time) / 1000);
        printf("%8u   ", ctx->ctxswitch);
        printf("%30s   ", ctx->name);
        printf("\n");
        item++;
    }
    printf("---------------total_timer_obj: %u/%u---------------\n", item, nm->task_cnt);
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
    nm->magic = NETLOOP_MAIN_MAGIC;

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
    if (NETLOOP_MAIN_MAGIC != nm->magic) {
        return -1;
    }

    loop_cb.poll = __netloop_poll;
    loop_cb.prepare = __netloop_prepare;
    loop_cb.timer = __netloop_timer;
    loop_cb.opaque = nm;
    loop_register(&nm->loop, loop_cb);
    return loop_start(&nm->loop);
}

int netloop_stop(struct netloop_main_t *nm)
{
    //todo...
    DEBUG_PRINTF("stop...\n");
    exit(0);
    return 0;
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
    return conn;
}

static void netloop_obj_free(struct netloop_obj_t *conn)
{
    ASSERT(NETLOOP_MAGIC == conn->magic);
    conn->magic = 0;
    conn->nm->task_cnt--;
    if (conn->name) {
        free(conn->name);
        conn->name = NULL;
    }
    if (conn->idxs) {
        g_array_free(conn->idxs, TRUE);
        conn->idxs = NULL;
    }
    free(conn);
}

static void netloop_process(struct schedule *s, void *ud)
{
    struct netloop_obj_t *ctx = (struct netloop_obj_t *)ud;
    if (ctx->task_cb) {
        ctx->task_cb(ctx->data);
    }

    if (ctx->exit_waiting) {
        uint64_t val = 1;
        netloop_write(ctx->nm, ctx->exitfd, &val, sizeof(val));
    } else {
        close(ctx->exitfd);
    }

    list_del(&ctx->list);
    netloop_obj_free(ctx);
}

static inline void __netloop_resume(struct netloop_obj_t *ctx)
{
    ctx->nm->current = ctx;
    coroutine_resume(ctx->nm->s, ctx->co);
    ctx->nm->current = NULL;
}

static inline void __netloop_yield(struct netloop_obj_t *ctx, int timeout, const char *caller)
{
    if (timeout >= 0) {
        ctx->expires = get_time_ms() + timeout;
        list_add(&ctx->timer, &ctx->nm->timer.list);
    }
    ctx->caller = caller;
    coroutine_yield(ctx->nm->s);
    ctx->caller = "--";
    ctx->ctxswitch++;
    if (timeout >= 0) {
        list_del(&ctx->timer);
    }
}

#define netloop_yield_timeout(ctx,tm)            \
    __netloop_yield(ctx,(tm),__FUNCTION__)

static void __netloop_prepare(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

retry:
    list_for_each_entry_safe(ctx, tmp, &nm->ready.list, list) {
        list_del(&ctx->list);
        list_add(&ctx->list, &nm->head.list);
        __netloop_resume(ctx);
    }
    if (!list_empty(&nm->ready.list)) {
        goto retry;
    }

    list_for_each_entry(ctx, &nm->head.list, list) {
        int i;
        g_array_set_size(ctx->idxs, 0);
        for (i = 0; i < ctx->nfds; i++) {
            ASSERT(ctx->fds[i].fd >= 0);
            int idx = loop_add_poll(&nm->loop, ctx->fds[i].fd, ctx->fds[i].events);
            g_array_append_val(ctx->idxs, idx);
            ctx->fds[i].revents = 0;
        }
    }

    if (list_empty(&nm->timer.list)) {
        return;
    }
    uint32_t cur = get_time_ms();
    list_for_each_entry(ctx, &nm->timer.list, timer) {
        int diff = ctx->expires - cur;
        if (diff < 0) {
            diff = 0;
        }
        loop_set_timeout(&nm->loop, diff);
    }
}

static void __netloop_timer(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    if (list_empty(&nm->timer.list)) {
        return;
    }
    uint32_t cur = get_time_ms();
    list_for_each_entry_safe(ctx, tmp, &nm->timer.list, timer) {
        int diff = ctx->expires - cur;
        if (diff <= 0) {
            __netloop_resume(ctx);
        }
    }
}

static void __netloop_poll(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &nm->head.list, list) {
        int i;
        int rnfds = 0;
        ASSERT(ctx->nfds == ctx->idxs->len);
        for (i = 0; i < ctx->nfds; i++) {
            int idx = g_array_index(ctx->idxs, int, i);
            ctx->fds[i].revents = loop_get_revents(&nm->loop, idx);
            if (ctx->fds[i].revents) {
                rnfds++;
            }
        }
        if (rnfds) {
            ctx->rnfds = rnfds;
            __netloop_resume(ctx);
        }
    }

    __netloop_timer(opaque);
}


int netloop_run_task(struct netloop_main_t *nm, struct netloop_task_t *task)
{
    struct netloop_obj_t *ctx;

    ctx = netloop_obj_new();
    if (!ctx) {
        return -1;
    }
    ctx->idxs = g_array_new(FALSE, FALSE, sizeof(int));
    if (!ctx->idxs) {
        ERROR_PRINTF("g_array_new: %s\n", strerror(errno));
        netloop_obj_free(ctx);
        return -1;
    }
    ctx->exitfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (ctx->exitfd < 0) {
        ERROR_PRINTF("eventfd: %s\n", strerror(errno));
        netloop_obj_free(ctx);
        return -1;
    }
    ctx->fds = NULL;
    ctx->nfds = 0;
    ctx->rnfds = 0;
    ctx->nm = nm;
    if (task->name) {
        ctx->name = strdup(task->name);
    } else {
        ctx->name = strdup(NETLOOP_TASK_NAME);
    }
    ctx->data = task->ud;
    ctx->task_cb = task->task_cb;
    ctx->time = get_time_ms();
    ctx->pco = netloop_gettid(nm);
    ctx->co = coroutine_new(ctx->nm->s, netloop_process, ctx);
    list_add(&ctx->list, &nm->ready.list);
    nm->task_cnt++;
    return ctx->co;
}

//todo...
//id conflict
int netloop_join_task(struct netloop_main_t *nm, int id)
{
    struct netloop_obj_t *ctx;
    if (!nm || !nm->current) {
        return -1;
    }
    if (netloop_gettid(nm) == id) {
        return -1;
    }

    list_for_each_entry(ctx, &nm->head.list, list) {
        if (id == ctx->co)
            goto find;
    }

    list_for_each_entry(ctx, &nm->ready.list, list) {
        if (id == ctx->co)
            goto find;
    }

find:
    if (ctx->exitfd > 0) {
        uint64_t val = 0;
        ctx->exit_waiting = 1;
        if (netloop_read(nm, ctx->exitfd, &val, sizeof(val)) > 0) {
            NONE_PRINTF("task %d exit %lu\n", id, val);
        }
        close(ctx->exitfd);
    }
    return 0;
}

pid_t netloop_gettid(struct netloop_main_t *nm)
{
    if (!nm || !nm->current) {
        return -1;
    }
    return nm->current->co;
}

char *netloop_getname(struct netloop_main_t *nm)
{
    if (!nm || !nm->current) {
        return NETLOOP_TASK_NAME;
    }
    return nm->current->name;
}

int netloop_setname(struct netloop_main_t *nm, const char *name)
{
    if (!nm || !nm->current) {
        return -1;
    }
    if (nm->current->name) {
        free(nm->current->name);
    }
    nm->current->name = strdup(name);
    if (!nm->current->name) {
        return -1;
    }
    return 0;
}

int netloop_poll_c(struct netloop_main_t *nm, struct pollfd *fds,
                         nfds_t nfds, int timeout, const char *caller)
{
    ASSERT(nm);
    struct netloop_obj_t *ctx = nm->current;
    if (!ctx || !timeout) {
        return poll(fds, nfds, timeout);
    }

    ctx->fds = fds;
    ctx->nfds = nfds;
    ctx->rnfds = 0;
    __netloop_yield(ctx, timeout, caller);
    ctx->fds = NULL;
    ctx->nfds = 0;
    return ctx->rnfds;
}

int netloop_accept(struct netloop_main_t *nm, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    do {
        int r = accept(sockfd, addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            ASSERT(1 == r);
        } else {
            return r;
        }
    } while (1);
}

int netloop_connect(struct netloop_main_t *nm, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int r;
    int val;
    socklen_t optlen = sizeof(int);

    r = connect(sockfd, addr, addrlen);
    if (r < 0 && EINPROGRESS == errno) {
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLOUT | POLLERR | POLLHUP;
        r = netloop_poll_f(nm, &pfd, 1, -1);
        ASSERT(1 == r);
    } else {
        return r;
    }

    r = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &val, &optlen);
    if (r < 0) {
        ERROR_PRINTF("getsockopt(fd = %d) %s\n", sockfd, strerror(errno));
        return r;
    }
    if (val != 0) {
        errno = val;
        return -1;
    }
    return 0;
}

ssize_t netloop_read_timeout(struct netloop_main_t *nm, int fd, void *buf, size_t count, int timeout)
{
    do {
        int r = read(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, timeout);
            if (0 == r) {
                return read(fd, buf, count);
            }
        } else {
            return r;
        }
    } while (1);
}

ssize_t netloop_write(struct netloop_main_t *nm, int fd, void *buf, size_t count)
{
    char *pos = buf;
    do {
        int r = write(fd, pos, count);
        if ((r < 0 && EAGAIN == errno) || (r > 0 && r < count)) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            ASSERT(1 == r);

            pos += r;
            count -= r;
        } else {
            return r;
        }
    } while (1);
}

unsigned int netloop_sleep(struct netloop_main_t *nm, unsigned int seconds)
{
    int r;
    r = netloop_poll_f(nm, NULL, 0, seconds * 1000);
    ASSERT(0 == r);

    return 0;
}


ssize_t netloop_recvfrom_timeout(struct netloop_main_t *nm, int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen, int timeout)
{
    do {
        int r = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, timeout);
            if (0 == r) {
                return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
            }
        } else {
            return r;
        }
    } while (1);
}

ssize_t netloop_sendto(struct netloop_main_t *nm, int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
    do {
        int r = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            ASSERT(1 == r);
        } else {
            return r;
        }
    } while (1);
}
