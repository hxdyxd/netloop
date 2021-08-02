/*
 * wrapper.h of netloop
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
#ifndef _WRAPPER_H_
#define _WRAPPER_H_

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#ifdef USE_PRCTL_SET_THREAD_NAME
#include <sys/prctl.h>
#endif
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#include "netloop.h"
#include "netdns_cares.h"

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_NONE
#define INFO_PRINTF   LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

struct func_list_t {
    int (*printf)(const char *format, ...);
    unsigned int (*sleep)(unsigned int seconds);
    int (*usleep)(useconds_t usec);
    int (*open)(const char *pathname, int flags, ...);
    int (*close)(int fd);
    ssize_t (*write)(int fd, const void *buf, size_t count);
    ssize_t (*read)(int fd, void *buf, size_t count);
    int (*pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);
    int (*pthread_join)(pthread_t thread, void **retval);
    int (*pthread_mutex_lock)(pthread_mutex_t *mutex);
    int (*pthread_mutex_trylock)(pthread_mutex_t *mutex);
    int (*pthread_mutex_unlock)(pthread_mutex_t *mutex);
    int (*prctl)(int option, ...);
    int (*poll)(struct pollfd *fds, nfds_t nfds, int timeout);
    int (*fcntl)(int fd, int cmd, ... /* arg */ );
    int (*socket)(int domain, int type, int protocol);
    int (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int (*accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    ssize_t (*sendto)(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t (*recvfrom)(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);
    int (*setsockopt)(int sockfd, int level, int optname,
                const void *optval, socklen_t optlen);
    int (*getaddrinfo)(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);
    void (*freeaddrinfo)(struct addrinfo *res);
    const char *(*gai_strerror)(int errcode);
    ssize_t (*send)(int sockfd, const void *buf, size_t len, int flags);
    ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags);
};

struct fdinfo_t {
    int inuse;
    char *name;
    int rcvtimeo;
    int sndtimeo;
};

struct fdtable_t {
    struct fdinfo_t *head;
    size_t max_fds;
    size_t inused_fds;
};

struct main_parameter_t {
    int argc;
    char **argv;
    char **envp;
};

#endif
