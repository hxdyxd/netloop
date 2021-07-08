/*
 * netutils_tcp.c of netloop
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
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "netutils.h"

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

int sock_setblocking(int sock, int if_block)
{
    int flags, r;

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }

    if (if_block)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    r = fcntl(sock, F_SETFL, flags);
    if (r < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int netutils_ntop(struct addrinfo_t *addr_info, struct sockinfo_t *sock_addr)
{
    if (!addr_info || !sock_addr) {
        return -1;
    }

    memset(addr_info, 0, sizeof(struct addrinfo_t));
    if (AF_INET == sock_addr->addr.sa_family) {
        inet_ntop(AF_INET, &sock_addr->addr_v4.sin_addr,
                        addr_info->host, MAX_HOST_NAME_LEN);
        addr_info->port = ntohs(sock_addr->addr_v4.sin_port);
    } else if (AF_INET6 == sock_addr->addr.sa_family) {
        inet_ntop(AF_INET6, &sock_addr->addr_v6.sin6_addr,
                         addr_info->host, MAX_HOST_NAME_LEN);
        addr_info->port = ntohs(sock_addr->addr_v6.sin6_port);
    } else {
        return -1;
    }
    return 0;
}

int netutils_getaddrinfo(struct sockinfo_t *sock_addr, const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int r;
    if (!sock_addr || !host) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    r = getaddrinfo(host, NULL, &hints, &res);
    if (0 != r) {
        ERROR_PRINTF("getaddrinfo(%s) %s\n", host, gai_strerror(r));
        return -1;
    }

    if (res->ai_family == AF_INET)
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
    else if (res->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
    else {
        ERROR_PRINTF("unknown ai_family %d\n", res->ai_family);
        freeaddrinfo(res);
        return -1;
    }

    memcpy(&sock_addr->addr, res->ai_addr, res->ai_addrlen);
    sock_addr->addrlen = res->ai_addrlen;
    
    freeaddrinfo(res);
    return 0;
}

int sock_set_recv_timeout(int sock, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = timeout * 1000;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int tcp_get_state(int sockfd)
{
    int r;
    struct tcp_info info;
    socklen_t len = sizeof(info);
    r = getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, &len);
    if (r < 0) {
        ERROR_PRINTF("setsockopt: %s\n", strerror(errno));
        return -1;
    }
    return info.tcpi_state;
}

int tcp_socket_create(int if_bind, const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    r = getaddrinfo(host, NULL, &hints, &res);
    if (0 != r) {
        ERROR_PRINTF("getaddrinfo(%s) %s\n", host, gai_strerror(r));
        return -1;
    }

    if (res->ai_family == AF_INET)
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
    else if (res->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
    else {
        ERROR_PRINTF("unknown ai_family %d\n", res->ai_family);
        goto exit;
    }

    sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ERROR_PRINTF("socket: %s\n", strerror(errno));
        goto exit;
    }

    // r = sock_setblocking(sock, 0);
    // if (r < 0) {
    //     goto exit1;
    // }

    if (if_bind) {
        int opt = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (r < 0) {
            ERROR_PRINTF("setsockopt: %s\n", strerror(errno));
            goto exit1;
        }

        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("bind(fd = %d, %s:%d): %s\n", sock, host, port, strerror(errno));
            goto exit1;
        }

        r = listen(sock, 512);
        if (r < 0) {
            ERROR_PRINTF("listen(fd = %d, %s:%d): %s\n", sock, host, port, strerror(errno));
            goto exit1;
        }
    } else {
        r = connect(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("connect(fd = %d, %s:%d): %s\n", sock, host, port, strerror(errno));
            close(sock);
            return -1;
        }
    }

    freeaddrinfo(res);
    NONE_PRINTF("%s(fd = %d, %s:%d)\n", if_bind ? "listen" : "connect", sock, host, port);
    return sock;

exit1:
    close(sock);
exit:
    freeaddrinfo(res);
    return -1;
}


struct tcp_listen_t {
    const char *host;
    uint16_t port;
    void (*conntask) (void *);
};

static void tcp_listen_task(void *ud)
{
    int r;
    struct tcp_listen_t *tl = (struct tcp_listen_t *)ud;
    int sockfd;
    sockfd = tcp_socket_create(1, tl->host, tl->port);
    if (sockfd < 0) {
        return;
    }

    while (1) {
        struct tcp_connect_t *conn = malloc(sizeof(struct tcp_connect_t));
        if (!conn) {
            break;
        }
        memset(conn, 0, sizeof(struct tcp_connect_t));

        conn->sockinfo.addrlen = sizeof(struct sockaddr_in6);
        conn->fd = accept(sockfd, &conn->sockinfo.addr, &conn->sockinfo.addrlen);
        if (conn->fd < 0) {
            ERROR_PRINTF("accept(fd = %d) %s\n", sockfd, strerror(errno));
            free(conn);
            break;
        }

        // r = sock_setblocking(conn->fd, 0);
        // if (r < 0) {
        //     ERROR_PRINTF("sock_setblocking(fd = %d) %s\n", conn->fd, strerror(errno));
        //     close(conn->fd);
        //     free(conn);
        //     break;
        // }

        r = netutils_run_task(&(struct netutils_task_t){
            .ontask = tl->conntask,
            .ud = conn,
            .name = "connect_task",
        });
        if (r < 0) {
            ERROR_PRINTF("netutils_run_task(connect_task) error\n");
            close(conn->fd);
            free(conn);
            break;
        }
    }
    close(sockfd);
    free(tl);
    DEBUG_PRINTF("task exit!\n");
}

int tcp_server_init(const char *host, uint16_t port, void (*conntask) (void *))
{
    int r;
    char *name;

    r = asprintf(&name, "tcp_listen_task_%s:%u", host, port);
    if (r < 0) {
        ERROR_PRINTF("asprintf() %s\n", strerror(errno));
        return -1;
    }

    struct tcp_listen_t *tl = memdup(
        &(struct tcp_listen_t) {
            .host = host,
            .port = port,
            .conntask = conntask,
        }, 
        sizeof(struct tcp_listen_t)
    );
    if (!tl) {
        ERROR_PRINTF("malloc() %s\n", strerror(errno));
        free(name);
        return -1;
    }

    r = netutils_run_task(&(struct netutils_task_t){
        .ontask = tcp_listen_task,
        .ud = tl,
        .name = "tcp_listen_task",
    });
    if (r < 0) {
        ERROR_PRINTF("netutils_run_task(tcp_listen_task) error\n");
        free(tl);
        free(name);
        return -1;
    }

    free(name);
    return 0;
}
