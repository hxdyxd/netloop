/*
 * netutils_task.c of netloop
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <signal.h>
#include <pthread.h>
#ifdef USE_PRCTL_SET_THREAD_NAME
#include <sys/prctl.h>
#endif

#include "list.h"
#include "netutils.h"

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define NETUTILS_TASK_MAGIC          0xcafecafe

struct netutils_obj_t {
    uint32_t magic;
    struct list_head list;
    pthread_t tid;
    char *name;
    void (*ontask) (void *);
    void *ud;
};


void netutils_task_setname(const char *name)
{
#ifdef USE_PRCTL_SET_THREAD_NAME
    prctl(PR_SET_NAME, name);
#endif
}

char *netutils_task_getname(void)
{
    return "--";
}

static void netutils_task_free(struct netutils_obj_t *ctx)
{
    if (!ctx || NETUTILS_TASK_MAGIC != ctx->magic) {
        ERROR_PRINTF("parameter error\n");
        return;
    }
    if (ctx->name) {
        free(ctx->name);
    }
    ctx->magic = 0;
    free(ctx);
}

static void *netutils_process(void *ud)
{
    struct netutils_obj_t *ctx = (struct netutils_obj_t *)ud;
    ASSERT(ctx);

    netutils_task_setname(ctx->name);

    if (ctx->ontask) {
        ctx->ontask(ctx->ud);
    }

    netutils_task_free(ctx);
    return NULL;
}

int netutils_run_task(struct netutils_task_t *task)
{
    int r;
    struct netutils_obj_t *ctx;

    ctx = malloc(sizeof(struct netutils_obj_t));
    if (!ctx) {
        ERROR_PRINTF("malloc() %s\n", strerror(errno));
        return -1;
    }
    ctx->magic = NETUTILS_TASK_MAGIC;
    ctx->name = strdup(task->name);
    ctx->ontask = task->ontask;
    ctx->ud = task->ud;

    r = pthread_create(&ctx->tid, NULL, netutils_process, ctx);
    if (r < 0) {
        ERROR_PRINTF("pthread_create(%s) error\n", task->name);
        netutils_task_free(ctx);
        return r;
    }
    return 0;
}

int netutils_stop_task(void)
{
    kill(0, SIGINT);
    return 0;
}
