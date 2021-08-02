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

typedef void (*task_func)(void *ud);

struct netloop_obj_t;
struct netloop_main_t;

struct netloop_task_t {
    task_func task_cb;
    void *ud;
    char *name;
};

int netloop_run_task(struct netloop_main_t *nm, struct netloop_task_t *task);
int netloop_join_task(struct netloop_main_t *nm, int id);
void netloop_dump_task(struct netloop_main_t *nm);

int netloop_poll_c(struct netloop_main_t *nm, struct pollfd *fds, nfds_t nfds, int timeout, const char *caller);
int netloop_accept(struct netloop_main_t *nm, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int netloop_connect(struct netloop_main_t *nm, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t netloop_read_timeout(struct netloop_main_t *nm, int fd, void *buf, size_t count, int timeout);
ssize_t netloop_write(struct netloop_main_t *nm, int fd, void *buf, size_t count);
unsigned int netloop_sleep(struct netloop_main_t *nm, unsigned int seconds);
ssize_t netloop_recvfrom_timeout(struct netloop_main_t *nm, int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen, int timeout);
ssize_t netloop_sendto(struct netloop_main_t *nm, int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);

struct netloop_main_t *netloop_init(void);
int netloop_start(struct netloop_main_t *nm);
int netloop_stop(struct netloop_main_t *nm);
pid_t netloop_gettid(struct netloop_main_t *nm);
char *netloop_getname(struct netloop_main_t *nm);
int netloop_setname(struct netloop_main_t *nm, const char *name);

#define netloop_read(n,f,b,l) \
    netloop_read_timeout(n,f,b,l,-1)

#define netloop_recvfrom(n,s,b,l,f,a,al) \
    netloop_recvfrom_timeout(n,s,b,l,f,a,al,-1)

#define netloop_poll_f(n,f,s,t) \
    netloop_poll_c(n,f,s,t,__FUNCTION__)

#define netloop_poll(n,f,s,t) \
    netloop_poll_c(n,f,s,t,"netloop_poll")

#endif
