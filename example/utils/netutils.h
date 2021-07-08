/*
 * netutils.h of netloop
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
#ifndef _NETUTILS_H_
#define _NETUTILS_H_

#include <stdint.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

//netutils.c
void msg_dump(void *buf, int len);
void *memdup(const void *src, size_t n);
void mtrace_init(const char *filename);
int command_init(void);

//netutils_tcp.c
#define MAX_HOST_NAME_LEN   (128)

struct sockinfo_t {
    socklen_t addrlen;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr_v4;
        struct sockaddr_in6 addr_v6;
    };
};

struct addrinfo_t {
    char host[MAX_HOST_NAME_LEN];
    uint16_t port;
};

struct tcp_connect_t {
    int fd;
    pthread_t tid;
    struct addrinfo_t addrinfo;
    struct sockinfo_t sockinfo;
    void *data;
};

int sock_setblocking(int sock, int if_block);
int netutils_ntop(struct addrinfo_t *addr_info, struct sockinfo_t *sock_addr);
int netutils_getaddrinfo(struct sockinfo_t *sock_addr, const char *host, uint16_t port);
int sock_set_recv_timeout(int sock, int timeout);
int tcp_get_state(int sockfd);
int tcp_socket_create(int if_bind, const char *host, int port);
int tcp_server_init(const char *host, uint16_t port, void (*conntask) (void *));

#ifdef NETSSL
//netutils_ssl.c
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#define SSL_DUMP_ERRORS()                                    \
    do {                                                     \
        unsigned long r;                                     \
        while ((r = ERR_get_error()) != 0) {                 \
            ERROR_PRINTF("%s\n", ERR_error_string(r, NULL)); \
        }                                                    \
    } while(0)

struct ssl_connect_t {
    struct tcp_connect_t tcp;
    SSL *ssl;
    void *data;
};

struct ssl_cert_t {
    EVP_PKEY  *pkey;
    X509      *x509;
};

int ssl_library_init(void);
int import_x509_pem(struct ssl_cert_t *pem, const char *cert, const char *key);
int free_x509_pem(struct ssl_cert_t *pem);
SSL_CTX *create_ssl_ctx(const char *cert, const char *key);
SSL_CTX *create_ssl_self_ctx(struct ssl_cert_t *ca, const char *domain, const char *key);
SSL_CTX *create_ssl_self_ca_ctx(const char *domain, const char *ca, const char *key);
SSL *create_ssl_by_fd(SSL_CTX *ctx, int sockfd);
SSL *create_ssl(SSL_CTX *ctx, int if_bind, const char *host, int port);
void close_ssl(SSL *ssl);
#endif

//netutils_http.c
int parse_addr_in_http(struct addrinfo_t *addr, char *buf, int len);

//netutils_udp.c
int udp_socket_create(int if_bind, const char *host, int port);
int udp_socket_create_family(int family);

//netutils_task.c
struct netutils_task_t {
    void (*ontask) (void *);
    void *ud;
    char *name;
};

void netutils_task_setname(const char *name);
char *netutils_task_getname(void);
int netutils_run_task(struct netutils_task_t *task);
int netutils_stop_task(void);

#endif
