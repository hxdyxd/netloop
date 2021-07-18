/*
 * wrapper.c of netloop
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
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <poll.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef USE_PRCTL_SET_THREAD_NAME
#include <sys/prctl.h>
#endif
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#include "netloop.h"

struct func_list_t {
    int (*printf)(const char *format, ...);
    unsigned int (*sleep)(unsigned int seconds);
    int (*usleep)(useconds_t usec);
    int (*open)(const char *pathname, int flags, ...);
    ssize_t (*write)(int fd, const void *buf, size_t count);
    ssize_t (*read)(int fd, void *buf, size_t count);
    int (*pthread_create)(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);
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
};

static __attribute__((constructor)) void wrapper_init(void);


static struct func_list_t wrapper_sys_func;
static struct netloop_main_t *nm = NULL;
static int netloop_run = 0;
static __thread pid_t sys_main_tid = 0;

#define wrapper_set_function(fp, f)  \
    __wrapper_set_function(fp, #f)

static int __wrapper_set_function(void **fptr, const char *name)
{
    void *fp = dlsym(RTLD_NEXT, name);
    if (fp && fptr) {
        *fptr = fp;
        // printf("find symbol %s at %p\n", name, fp);
        return 0;
    }
    printf("not find symbol %s\n", name);
    return -1;
}

void wrapper_init(void)
{
    int r = 0;
    printf("%s build: %s, %s\n", __FILE__, __DATE__, __TIME__);
    sys_main_tid = gettid();
    memset(&wrapper_sys_func, 0, sizeof(wrapper_sys_func));

    r |= wrapper_set_function( (void **)&wrapper_sys_func.printf, printf);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.sleep, sleep);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.usleep, usleep);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.open, open);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.write, write);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.read, read);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.pthread_create, pthread_create);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.prctl, prctl);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.poll, poll);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.fcntl, fcntl);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.socket, socket);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.connect, connect);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.accept, accept);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.sendto, sendto);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.recvfrom, recvfrom);
    r |= wrapper_set_function( (void **)&wrapper_sys_func.setsockopt, setsockopt);
    assert(!r);

    nm = netloop_init();
    assert(nm);

    printf("tid = %d, nm = %p\n", sys_main_tid, nm);
}

static inline int in_loop(void)
{
    return (0 == sys_main_tid);
}

int printf(const char *format, ...)
{
    int r;
    va_list args;
    // assert(wrapper_sys_func.printf);

    va_start(args, format);
    r = vprintf(format, args);
    va_end(args);

    return r;
}

unsigned int sleep(unsigned int seconds)
{
    assert(nm);
    assert(wrapper_sys_func.sleep);
    // printf("sleep(%u)\n", seconds);

    if (!in_loop()) {
        if (!netloop_run) {
            netloop_run = 1;
            assert(netloop_start(nm) >= 0);
        }
        return wrapper_sys_func.sleep(seconds);
    }

    return netloop_poll_f(nm, NULL, 0, seconds * 1000);
}

int usleep(useconds_t usec)
{
    assert(nm);
    assert(wrapper_sys_func.usleep);

    if (!in_loop()) {
        return wrapper_sys_func.usleep(usec);
    }

    int msec = usec / 1000;
    if (0 == msec) {
        msec = 1;
    }

    return netloop_poll_f(nm, NULL, 0, msec);
}

int open(const char *pathname, int flags, ...)
{
    assert(wrapper_sys_func.open);
    int r;
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    // printf("open(%s, %d, %d)\n", pathname, flags, mode);

    r = wrapper_sys_func.open(pathname, flags | O_NONBLOCK, mode);
    va_end(args);
    return r;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    assert(nm);
    assert(wrapper_sys_func.write);
    // printf("This is the write(%d, %p, %d)\n", fd, buf, count);

    if (-1 == fd && !buf && !count) {
        netloop_dump_task(nm);
    }

    const char *pos = buf;
    do {
        int r = wrapper_sys_func.write(fd, pos, count);
        if ((r < 0 && EAGAIN == errno) || (r > 0 && r < count)) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            assert(1 == r);
            pos += r;
            count -= r;
        } else {
            return r;
        }
    } while (1);
}

ssize_t read(int fd, void *buf, size_t count)
{
    assert(nm);
    assert(wrapper_sys_func.read);
    // printf("This is the read(%d, %p, %d)\n", fd, buf, count);

    do {
        int r = wrapper_sys_func.read(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            assert(1 == r);
        } else {
            return r;
        }
    } while (1);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                    void *(*start_routine) (void *), void *arg)
{
    assert(nm);
    assert(wrapper_sys_func.pthread_create);
    // printf("pthread_create(%p, %p, %p, %p) wrapper!\n", thread, attr, start_routine, arg);

    if (netloop_run && !in_loop()) {
        printf("create pthread: %p\n", start_routine);
        return wrapper_sys_func.pthread_create(thread, attr, start_routine, arg);
    }

    struct netloop_task_t tconf = {
        .task_cb = (task_func)start_routine,
        .ud = arg,
    };

    return (netloop_run_task(nm, &tconf) != NULL) ? 0 : -1;
}

int prctl(int option, ...)
{
    assert(nm);
    assert(wrapper_sys_func.prctl);
    int r = -1;
    va_list args;

    va_start(args, option);

    switch(option)
    {
        case PR_SET_KEEPCAPS:
        case PR_SET_NAME:
        case PR_GET_NAME:
        {
            unsigned long arg2 = va_arg(args, unsigned long);
            if (PR_SET_NAME == option && netloop_gettid(nm) >= 0) {
                r = netloop_setname(nm, (const char *)arg2);
            } else {
                r = wrapper_sys_func.prctl(option, arg2);
            }
            break;
        }
        default:
        {
            printf("undefined option = %d\n", option);
            r = -1;
            break;
        }
    }

    va_end(args);
    return r;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    assert(nm);
    assert(wrapper_sys_func.poll);

    if (!in_loop()) {
        return wrapper_sys_func.poll(fds, nfds, timeout);
    } else if (netloop_gettid(nm) < 0 || !timeout) {
        return wrapper_sys_func.poll(fds, nfds, timeout);
    }

    // printf("poll(%d)\n", nfds);
    return netloop_poll_f(nm, fds, nfds, timeout);
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
    assert(nm);
    assert(wrapper_sys_func.fcntl);

    int r;
    va_list args;

    va_start(args, cmd);

    switch (cmd) {
        case F_DUPFD:
        {
            int param = va_arg(args, int);
            r = wrapper_sys_func.fcntl(fd, cmd, param);
            break;
        }
        case F_GETFD:
        {
            r = wrapper_sys_func.fcntl(fd, cmd);
            break;
        }
        case F_SETFD:
        {
            int param = va_arg(args, int);
            r = wrapper_sys_func.fcntl(fd, cmd, param);
            break;
        }
        case F_GETFL:
        {
            r = wrapper_sys_func.fcntl(fd, cmd);
            r = r & (~O_NONBLOCK);
            break;
        }
        case F_SETFL:
        {
            int flag = va_arg(args, int);
            flag |= O_NONBLOCK;
            r = wrapper_sys_func.fcntl(fd, cmd, flag);
            break;
        }
        default:
        {
            r = -1;
            break;
        }
    }

    va_end(args);

    return r;
}

int socket(int domain, int type, int protocol)
{
    assert(nm);
    assert(wrapper_sys_func.socket);
    // printf("socket(%d, %d, %d)\n", domain, type, protocol);

    int sockfd = wrapper_sys_func.socket(domain, type, protocol);
    if (sockfd < 0) {
        return sockfd;
    }

    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL));
    return sockfd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    assert(nm);
    assert(wrapper_sys_func.connect);
    // printf("connect(%d, %p, %p)\n", sockfd, addr, addrlen);

    int r;
    int val;
    socklen_t optlen = sizeof(int);

    r = wrapper_sys_func.connect(sockfd, addr, addrlen);
    if (r < 0 && EINPROGRESS == errno) {
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLOUT | POLLERR | POLLHUP;
        r = netloop_poll_f(nm, &pfd, 1, -1);
        assert(1 == r);
    } else {
        return r;
    }

    r = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &val, &optlen);
    if (r < 0) {
        return r;
    } else if (val != 0) {
        errno = val;
        return -1;
    }
    errno = 0;
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    assert(nm);
    assert(wrapper_sys_func.accept);
    // printf("accept(%d, %p, %p)\n", sockfd, addr, addrlen);

    do {
        int r = wrapper_sys_func.accept(sockfd, addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            assert(1 == r);
        } else {
            fcntl(r, F_SETFL, fcntl(sockfd, F_GETFL));
            return r;
        }
    } while (1);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen)
{
    assert(nm);
    assert(wrapper_sys_func.sendto);

    do {
        int r = wrapper_sys_func.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            assert(1 == r);
        } else {
            return r;
        }
    } while (1);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    assert(nm);
    assert(wrapper_sys_func.recvfrom);

    do {
        int r = wrapper_sys_func.recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            if (0 == r) {
                return wrapper_sys_func.recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
            }
        } else {
            return r;
        }
    } while (1);
}

int setsockopt(int sockfd, int level, int optname,
                const void *optval, socklen_t optlen)
{
    assert(wrapper_sys_func.setsockopt);
    //todo...

    return wrapper_sys_func.setsockopt(sockfd, level, optname, optval, optlen);
}

