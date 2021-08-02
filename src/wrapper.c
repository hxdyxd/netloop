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
#include "wrapper.h"


static void *init_task(void *ud);


static struct func_list_t wrapper_sys_func;
static struct netloop_main_t *nm = NULL;
static int netloop_run = 0;
static __thread pid_t sys_main_tid = 0;
static struct fdtable_t sys_fdt;

#define wrapper_set_function(fp, f)  \
    __wrapper_set_function((void **)&(fp.f), #f)

static int __wrapper_set_function(void **fptr, const char *name)
{
    void *fp = dlsym(RTLD_NEXT, name);
    if (fp && fptr) {
        *fptr = fp;
        DEBUG_PRINTF("find symbol %s at %p\n", name, fp);
        return 0;
    }
    WARN_PRINTF("not find symbol %s\n", name);
    return -1;
}

static void wrapper_init(int argc, char **argv, char **envp) __attribute__((constructor));
static void wrapper_init(int argc, char **argv, char **envp)
{
    int r = 0;
    INFO_PRINTF("%s build: %s, %s\n", __FILE__, __DATE__, __TIME__);
    sys_main_tid = gettid();
    memset(&wrapper_sys_func, 0, sizeof(wrapper_sys_func));

    r |= wrapper_set_function(wrapper_sys_func, accept);
    r |= wrapper_set_function(wrapper_sys_func, close);
    r |= wrapper_set_function(wrapper_sys_func, connect);
    r |= wrapper_set_function(wrapper_sys_func, fcntl);
    r |= wrapper_set_function(wrapper_sys_func, freeaddrinfo);
    r |= wrapper_set_function(wrapper_sys_func, gai_strerror);
    r |= wrapper_set_function(wrapper_sys_func, getaddrinfo);
    r |= wrapper_set_function(wrapper_sys_func, open);
    r |= wrapper_set_function(wrapper_sys_func, poll);
    r |= wrapper_set_function(wrapper_sys_func, prctl);
    r |= wrapper_set_function(wrapper_sys_func, printf);
    r |= wrapper_set_function(wrapper_sys_func, pthread_create);
    r |= wrapper_set_function(wrapper_sys_func, pthread_join);
    r |= wrapper_set_function(wrapper_sys_func, pthread_mutex_lock);
    r |= wrapper_set_function(wrapper_sys_func, pthread_mutex_trylock);
    r |= wrapper_set_function(wrapper_sys_func, pthread_mutex_unlock);
    r |= wrapper_set_function(wrapper_sys_func, read);
    r |= wrapper_set_function(wrapper_sys_func, recv);
    r |= wrapper_set_function(wrapper_sys_func, recvfrom);
    r |= wrapper_set_function(wrapper_sys_func, send);
    r |= wrapper_set_function(wrapper_sys_func, sendto);
    r |= wrapper_set_function(wrapper_sys_func, setsockopt);
    r |= wrapper_set_function(wrapper_sys_func, sleep);
    r |= wrapper_set_function(wrapper_sys_func, socket);
    r |= wrapper_set_function(wrapper_sys_func, usleep);
    r |= wrapper_set_function(wrapper_sys_func, write);
    ASSERT(!r);

    nm = netloop_init();
    ASSERT(nm);

    INFO_PRINTF("tid = %d, nm = %p\n", sys_main_tid, nm);

    pthread_t init_tid;
    struct main_parameter_t mp;
    mp.argc = argc;
    mp.argv = argv;
    mp.envp = envp;
    r = pthread_create(&init_tid, NULL, init_task, &mp);
    ASSERT(!r);

    while (1) {
        sleep(9999);
    }
}

int main(int argc, char **argv, char **envp);
static void *init_task(void *ud)
{
    int r;
    struct main_parameter_t *mp = (struct main_parameter_t *)ud;
    prctl(PR_SET_NAME, "init_task");
    r = main(mp->argc, mp->argv, mp->envp);
    exit(r);
    return NULL;
}


#define fdt_append(f,d)  \
__fdt_append(f,d,"unknown")

#define fdt_append_name(f,d,n)  \
__fdt_append(f,d,n)

static int __fdt_append(struct fdtable_t *fdt, int fd, const char *pname)
{
    ASSERT(fdt);
    ASSERT(pname);
    if (fd < 0) {
        return -1;
    }
    while (fd >= fdt->max_fds) {
        size_t new_size = fdt->max_fds;
        if (!new_size)
            new_size = 1;
        fdt->max_fds += new_size;
        fdt->head = realloc(fdt->head, sizeof(struct fdinfo_t) * fdt->max_fds);
        ASSERT(fdt->head);
        memset(fdt->head + fdt->max_fds - new_size, 0, sizeof(struct fdinfo_t) * new_size);
        DEBUG_PRINTF("max_fds = %lu\n",  fdt->max_fds);
    }

    if (!fdt->head[fd].inuse) {
        NONE_PRINTF("append %d %s\n", fd, pname);
        fdt->head[fd].inuse = 1;
        fdt->inused_fds++;
        fdt->head[fd].rcvtimeo = -1;
        fdt->head[fd].sndtimeo = -1;
        if (pname) {
            fdt->head[fd].name = strdup(pname);
        }
    }
    return 0;
}

static inline int fdt_delete(struct fdtable_t *fdt, int fd)
{
    ASSERT(fdt);
    if (fd < 0) {
        return -1;
    }
    if (fd < fdt->max_fds) {
        if (fdt->head[fd].inuse) {
            fdt->head[fd].inuse = 0;
            fdt->inused_fds--;
            fdt->head[fd].name[0] = '\0';
            NONE_PRINTF("delete %d %s\n", fd, fdt->head[fd].name);
            if (fdt->head[fd].name) {
                free(fdt->head[fd].name);
            }
        }
    }
    return 0;
}

static inline int fdt_dump(struct fdtable_t *fdt)
{
    int i;
    PRINTF("%10s | %16s | %8s | %8s \n", "fd", "name", "sndtimeo", "rcvtimeo");
    for (i = 0; i < fdt->max_fds; i++) {
        if (fdt->head[i].inuse) {
            PRINTF("%10d   ", i);
            PRINTF("%16s   ", fdt->head[i].name);
            PRINTF("%8d   ", fdt->head[i].sndtimeo);
            PRINTF("%8d   ", fdt->head[i].rcvtimeo);
            PRINTF("\n");
        }
    }
    INFO_PRINTF("find file descriptors %lu\n", fdt->inused_fds);
    return 0;
}

static inline int in_loop(void)
{
    return (0 == sys_main_tid);
}

static inline int in_task(void)
{
    return (in_loop() && netloop_gettid(nm) >= 0);
}

int printf(const char *format, ...)
{
    int r;
    va_list args;
    // ASSERT(wrapper_sys_func.printf);

    va_start(args, format);
    r = vprintf(format, args);
    va_end(args);

    return r;
}

unsigned int sleep(unsigned int seconds)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.sleep);
    NONE_PRINTF("sleep(%u)\n", seconds);

    if (!in_loop()) {
        if (!netloop_run) {
            netloop_run = 1;
            ASSERT(netloop_start(nm) >= 0);
        }
        return wrapper_sys_func.sleep(seconds);
    }

    return netloop_poll_f(nm, NULL, 0, seconds * 1000);
}

int usleep(useconds_t usec)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.usleep);

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
    ASSERT(wrapper_sys_func.open);
    int r;
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    NONE_PRINTF("open(%s, %d, %d)\n", pathname, flags, mode);

    r = wrapper_sys_func.open(pathname, flags | O_NONBLOCK, mode);
    va_end(args);

    fdt_append_name(&sys_fdt, r, pathname);
    if (flags & O_NONBLOCK) {
        sys_fdt.head[r].sndtimeo = 0;
        sys_fdt.head[r].rcvtimeo = 0;
    }
    return r;
}

int close(int fd)
{
    ASSERT(wrapper_sys_func.close);

    fdt_delete(&sys_fdt, fd);
    return wrapper_sys_func.close(fd);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.write);
    fdt_append(&sys_fdt, fd);
    NONE_PRINTF("write(%d, %p, %d)\n", fd, buf, count);

    if (-1 == fd && !buf && !count) {
        netloop_dump_task(nm);
    }

    if (-2 == fd && !buf && !count) {
        fdt_dump(&sys_fdt);
    }

    const char *pos = buf;
    do {
        int r = wrapper_sys_func.write(fd, pos, count);
        if ((r < 0 && EAGAIN == errno) || (r > 0 && r < count)) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;

            pos += r;
            count -= r;
            r = netloop_poll_f(nm, &pfd, 1, sys_fdt.head[fd].sndtimeo);
            if (0 == r) {
                return wrapper_sys_func.write(fd, pos, count);
            }
        } else {
            return r;
        }
    } while (1);
}

ssize_t read(int fd, void *buf, size_t count)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.read);
    fdt_append(&sys_fdt, fd);
    NONE_PRINTF("read(%d, %p, %d)\n", fd, buf, count);

    do {
        int r = wrapper_sys_func.read(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, sys_fdt.head[fd].rcvtimeo);
            if (0 == r) {
                return wrapper_sys_func.read(fd, buf, count);
            }
        } else {
            return r;
        }
    } while (1);
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                    void *(*start_routine) (void *), void *arg)
{
    int r;
    ASSERT(nm);
    ASSERT(wrapper_sys_func.pthread_create);
    NONE_PRINTF("pthread_create(%p, %p, %p, %p)\n", thread, attr, start_routine, arg);

    if (netloop_run && !in_loop()) {
        INFO_PRINTF("create pthread: %p\n", start_routine);
        return wrapper_sys_func.pthread_create(thread, attr, start_routine, arg);
    }

    struct netloop_task_t tconf = {
        .task_cb = (task_func)start_routine,
        .ud = arg,
    };

    r = netloop_run_task(nm, &tconf);
    if (r < 0) {
        return -1;
    }
    *thread = r;
    return 0;
}

int pthread_join(pthread_t thread, void **retval)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.pthread_join);
    NONE_PRINTF("pthread_join(%lu, %p)\n", thread, retval);

    if (netloop_run && !in_loop()) {
        return wrapper_sys_func.pthread_join(thread, retval);
    }

    return netloop_join_task(nm, (int)thread);
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    ASSERT(wrapper_sys_func.pthread_mutex_lock);

    if (!in_task()) {
        return wrapper_sys_func.pthread_mutex_lock(mutex);
    }
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    ASSERT(wrapper_sys_func.pthread_mutex_trylock);

    if (!in_task()) {
        return wrapper_sys_func.pthread_mutex_trylock(mutex);
    }
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    ASSERT(wrapper_sys_func.pthread_mutex_unlock);

    if (!in_task()) {
        return wrapper_sys_func.pthread_mutex_unlock(mutex);
    }
    return 0;
}

int prctl(int option, ...)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.prctl);
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
            if (PR_SET_NAME == option && in_task()) {
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
    ASSERT(nm);
    ASSERT(wrapper_sys_func.poll);

    if (!in_task() || !timeout) {
        return wrapper_sys_func.poll(fds, nfds, timeout);
    }

    NONE_PRINTF("poll(%d)\n", nfds);
    return netloop_poll_f(nm, fds, nfds, timeout);
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.fcntl);
    int r;
    va_list args;

    fdt_append(&sys_fdt, fd);
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
            if (flag & O_NONBLOCK) {
                sys_fdt.head[fd].sndtimeo = 0;
                sys_fdt.head[fd].rcvtimeo = 0;
            }
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
    ASSERT(nm);
    ASSERT(wrapper_sys_func.socket);
    NONE_PRINTF("socket(%d, %d, %d)\n", domain, type, protocol);

    int sockfd = wrapper_sys_func.socket(domain, type, protocol);
    if (sockfd < 0) {
        return sockfd;
    }

    fdt_append_name(&sys_fdt, sockfd, "socket");
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL));
    return sockfd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.connect);
    NONE_PRINTF("connect(%d, %p, %p)\n", sockfd, addr, addrlen);

    int r;
    int val;
    socklen_t optlen = sizeof(int);

    r = wrapper_sys_func.connect(sockfd, addr, addrlen);
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
    ASSERT(nm);
    ASSERT(wrapper_sys_func.accept);
    NONE_PRINTF("accept(%d, %p, %p)\n", sockfd, addr, addrlen);

    do {
        int r = wrapper_sys_func.accept(sockfd, addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
            ASSERT(1 == r);
        } else {
            fdt_append_name(&sys_fdt, r, "socket:accept");
            fcntl(r, F_SETFL, fcntl(sockfd, F_GETFL));
            return r;
        }
    } while (1);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.sendto);
    fdt_append(&sys_fdt, sockfd);

    do {
        int r = wrapper_sys_func.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLOUT | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, sys_fdt.head[sockfd].sndtimeo);
            if (0 == r) {
                return wrapper_sys_func.sendto(sockfd, buf, len, flags, dest_addr, addrlen);
            }
        } else {
            return r;
        }
    } while (1);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.recvfrom);
    fdt_append(&sys_fdt, sockfd);

    do {
        int r = wrapper_sys_func.recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, sys_fdt.head[sockfd].rcvtimeo);
            if (0 == r) {
                return wrapper_sys_func.recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
            }
        } else {
            return r;
        }
    } while (1);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.send);
    fdt_append(&sys_fdt, sockfd);
    NONE_PRINTF("send(%d, %p, %lu, %x)\n", sockfd, buf, len, flags);

    return write(sockfd, buf, len);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    ASSERT(nm);
    ASSERT(wrapper_sys_func.recv);
    fdt_append(&sys_fdt, sockfd);
    NONE_PRINTF("recv(%d, %p, %lu, %x)\n", sockfd, buf, len, flags);

    return read(sockfd, buf, len);
}

int setsockopt(int sockfd, int level, int optname,
                const void *optval, socklen_t optlen)
{
    ASSERT(wrapper_sys_func.setsockopt);
    fdt_append(&sys_fdt, sockfd);
    //todo...
    if (SOL_SOCKET == level) {
        if (SO_RCVTIMEO == optname) {
            const struct timeval *tv = optval;
            if (optlen >= sizeof(struct timeval)) {
                sys_fdt.head[sockfd].rcvtimeo = tv->tv_sec * 1000 + tv->tv_usec / 1000;
                return 0;
            }
        } else if (SO_SNDTIMEO == optname) {
            const struct timeval *tv = optval;
            if (optlen >= sizeof(struct timeval)) {
                sys_fdt.head[sockfd].sndtimeo = tv->tv_sec * 1000 + tv->tv_usec / 1000;
                return 0;
            }
        }
    }

    return wrapper_sys_func.setsockopt(sockfd, level, optname, optval, optlen);
}

int getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints,
                   struct addrinfo **res)
{
    ASSERT(wrapper_sys_func.getaddrinfo);

#ifndef LIBCARES
    return wrapper_sys_func.getaddrinfo(node, service, hints, res);
#endif

    return netdns_getaddrinfo(nm, node, service, hints, res);
}

void freeaddrinfo(struct addrinfo *res)
{
    ASSERT(wrapper_sys_func.freeaddrinfo);

#ifndef LIBCARES
    return wrapper_sys_func.freeaddrinfo(res);
#endif

    return netdns_freeaddrinfo(res);
}

const char *gai_strerror(int errcode)
{
    ASSERT(wrapper_sys_func.gai_strerror);

#ifndef LIBCARES
    return wrapper_sys_func.gai_strerror(errcode);
#endif

    return netdns_strerror(errcode);
}

