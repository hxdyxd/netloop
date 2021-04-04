/*
 * netdns_cares.c of netloop
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
#include "netdns_cares.h"
#include <ares.h>

#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static int inited = 0;


struct netdns_priv_t {
    ares_channel   channel;
    struct netloop_obj_t *ctx;
    struct addrinfo *ai;
    int fd;
    int events;
    int ret;
    const char *host;
};

static void netdns_sock_state_cb(void *data, int fd, int readable, int writeable)
{
    ASSERT(data);
    struct netdns_priv_t *np = (struct netdns_priv_t *)data;
    np->fd = fd;
    np->events = 0;
    if (readable)
        np->events |= POLLIN;
    if (writeable)
        np->events |= POLLOUT;
}

static void netdns_addrinfo_cb(void *arg, int status, int timeouts, struct ares_addrinfo *res)
{
    ASSERT(arg);
    struct netdns_priv_t *np = (struct netdns_priv_t *)arg;

    if (ARES_SUCCESS != status) {
        DEBUG_PRINTF("addrinfo_cb: %s, %s\n", np->host, ares_strerror(status));
        np->ret = -1;
        return;
    }

    ASSERT(NULL != res);
    if (NULL == res->nodes) {
        ERROR_PRINTF("addrinfo nodes is null\n");
        ares_freeaddrinfo(res);
        np->ret = -1;
        return;
    }

    np->ai = malloc(sizeof(struct addrinfo));
    if (!np->ai) {
        ares_freeaddrinfo(res);
        np->ret = -2;
        return;
    }
    memset(np->ai, 0, sizeof(struct addrinfo));

    np->ai->ai_flags    = res->nodes->ai_flags;
    np->ai->ai_family   = res->nodes->ai_family;
    np->ai->ai_socktype = res->nodes->ai_socktype;
    np->ai->ai_protocol = res->nodes->ai_protocol;
    np->ai->ai_addrlen  = res->nodes->ai_addrlen;
    np->ai->ai_addr    = malloc(np->ai->ai_addrlen);
    if (!np->ai->ai_addr) {
        ares_freeaddrinfo(res);
        np->ret = -2;
        return;
    }
    memcpy(np->ai->ai_addr, res->nodes->ai_addr, np->ai->ai_addrlen);
    ares_freeaddrinfo(res);
    np->ret = 0;
}

int netdns_getaddrinfo(struct netloop_obj_t *ctx, const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res)
{
    int r;
    struct ares_options options;
    struct ares_addrinfo_hints areshints;
    struct netdns_priv_t np;

    memset(&np, 0, sizeof(struct netdns_priv_t));
    if (!inited) {
        r = ares_library_init(ARES_LIB_INIT_ALL);
        if (ARES_SUCCESS != r) {
            ERROR_PRINTF("ares_library_init\n");
            return -1;
        }
        inited = 1;
    }

    np.ctx = ctx;
    np.host = node;
    np.ret = 1;
    memset(&options, 0, sizeof(struct ares_options));
    options.sock_state_cb_data = &np;
    options.sock_state_cb      = netdns_sock_state_cb;
    options.timeout            = 3000;
    options.tries              = 2;
    r = ares_init_options(&np.channel, &options, 
        ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB);
    if (ARES_SUCCESS != r) {
        ERROR_PRINTF("ares_init_options\n");
        return -1;
    }

    memset(&areshints, 0, sizeof(areshints));
    areshints.ai_flags    = hints->ai_flags;
    areshints.ai_family   = hints->ai_family;
    areshints.ai_socktype = hints->ai_socktype;
    areshints.ai_protocol = hints->ai_protocol;
    ares_getaddrinfo(np.channel, node, service, &areshints, netdns_addrinfo_cb, &np);

    while (1 == np.ret || np.events) {
        NONE_PRINTF("ret = %d, events = %x\n", np.ret, np.events);
        int rfd = -1;
        int wfd = -1;
        ctx->fd = np.fd;
        ctx->events = np.events;
        list_add(&ctx->list, &ctx->head->list);
        coroutine_yield(ctx->s);
        list_del(&ctx->list);
        if (ctx->revents & POLLIN)
            rfd = ctx->fd;
        if (ctx->revents & POLLOUT)
            wfd = ctx->fd;
        ares_process_fd(np.channel, rfd, wfd);
    }
    ASSERT(1 != np.ret);
    ASSERT(!np.events);

    ares_destroy(np.channel);
    *res = np.ai;
    return np.ret;
}
