/*
 * sslproxy.c of netloop
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
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <netutils.h>

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8086

#define CERT_FILE     "server.crt"
#define KEY_FILE      "server.key"


#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


#define PROTO_TYPE_TCP    'T'
#define PROTO_TYPE_SSL    'S'

#define TRANSFER_OBJ_MAGIC  0xbeef1997

struct transfer_obj_t {
    uint32_t magic;
    char type;
    int fd;
    SSL *ssl;
    SSL_CTX *sslctx;
    int end;
    void *data;
};


static void connect_task(void *ud);
static void to_connect(void *ud);


static struct transfer_obj_t *new_transfer(int fd)
{
    struct transfer_obj_t *to;

    to = malloc(sizeof(struct transfer_obj_t));
    if (!to) {
        return NULL;
    }
    memset(to, 0, sizeof(struct transfer_obj_t));
    to->magic = TRANSFER_OBJ_MAGIC;
    to->type = PROTO_TYPE_TCP;
    to->fd = fd;
    return to;
}

static void free_transfer(struct transfer_obj_t * to)
{
    ASSERT(TRANSFER_OBJ_MAGIC == to->magic);
    if (PROTO_TYPE_SSL == to->type) {
        ASSERT(to->ssl);
        SSL_free(to->ssl);
        to->ssl = NULL;
        ASSERT(to->sslctx);
        SSL_CTX_free(to->sslctx);
        to->sslctx = NULL;
    }
    close(to->fd);
    to->magic = 0;
    to->fd = -1;
    free(to);
}

static int transfer_read(struct transfer_obj_t *conn, void *buf, int len)
{
    int r;
    if (PROTO_TYPE_TCP == conn->type) {
        do {
            r = read(conn->fd, buf, len);
        } while(r < 0 && errno == EINTR);
        if (r < 0 && errno) {
            ERROR_PRINTF("read(fd = %d) %s\n", conn->fd, strerror(errno));
        }
    } else if (PROTO_TYPE_SSL == conn->type) {
        r = SSL_read(conn->ssl, buf, len);
        if (r <= 0) {
            SSL_DUMP_ERRORS();
        }
    } else {
        r = -3;
    }
    return r;
}

static int transfer_write(struct transfer_obj_t *conn, void *buf, int len)
{
    int r;
    if (PROTO_TYPE_TCP == conn->type) {
        do {
            r = write(conn->fd, buf, len);
        } while(r < 0 && errno == EINTR);
        if (r < 0 && errno) {
            ERROR_PRINTF("write(fd = %d) %s\n", conn->fd, strerror(errno));
        }
    } else if (PROTO_TYPE_SSL == conn->type) {
        r = SSL_write(conn->ssl, buf, len);
        if (r <= 0) {
            SSL_DUMP_ERRORS();
        }
    } else {
        r = -3;
    }
    return r;
}

#define transfer_ssl_wrap(conn, sslctx, server)  \
  __transfer_ssl_wrap(conn, sslctx, server, NULL)
#define transfer_ssl_connect_wrap_hostname(conn, sslctx, hostname)  \
  __transfer_ssl_wrap(conn, sslctx, 0, hostname)

static int __transfer_ssl_wrap(struct transfer_obj_t *conn, SSL_CTX *sslctx, int server, const char *hostname)
{
    ASSERT(conn);
    ASSERT(0 != conn->fd);
    int r;
    if (PROTO_TYPE_TCP != conn->type) {
        ERROR_PRINTF("connection not tcp\n");
        return -1;
    }

    SSL *ssl = create_ssl_by_fd(sslctx, conn->fd);
    if (!ssl) {
        return -1;
    }

    if (server) {
        r = SSL_accept(ssl);
    } else {
        if (hostname) {
            SSL_set_tlsext_host_name(ssl, hostname);
        }
        r = SSL_connect(ssl);
    }
    if (1 != r) {
        SSL_DUMP_ERRORS();
        SSL_free(ssl);
        return -1;
    }
    conn->type = PROTO_TYPE_SSL;
    conn->ssl = ssl;
    conn->sslctx = sslctx;
    return 0;
}

static void transfer_task(struct transfer_obj_t *conn, char *buffer, int len)
{
    ASSERT(conn);
    int r;
    struct transfer_obj_t *peer = (struct transfer_obj_t *)conn->data;
    ASSERT(peer);

    NONE_PRINTF("transfer %d to %d\n", conn->fd, peer->fd);

    while (!conn->end) {
        r = transfer_read(conn, buffer, len);
        if (r <= 0) {
            shutdown(peer->fd, SHUT_RDWR);
            break;
        }

        if (conn->end) {
            DEBUG_PRINTF("connection closed [%d, %s]!\n", conn->fd, netutils_task_getname());
            break;
        }

        NONE_PRINTF("new %u msg from %d:\n", r, conn->fd);

        r = transfer_write(peer, buffer, r);
        if (r <= 0) {
            shutdown(conn->fd, SHUT_RDWR);
            break;
        }
    }

    ASSERT(conn && peer);
    if (!conn->end) {
        conn->end = 1;
        peer->end = 1;
    } else {
        NONE_PRINTF("close socket [%s]!\n", netutils_task_getname());
        free_transfer(conn);
        free_transfer(peer);
    }
    NONE_PRINTF("task exit [%s]!\n", netutils_task_getname());
}

struct ssl_alpn_t {
    const unsigned char *data;
    unsigned int len;
};

static int ssl_server_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
 const unsigned char *in, unsigned int inlen, void *arg)
{
    struct ssl_alpn_t *alpn = (struct ssl_alpn_t *)arg;
    ASSERT(alpn);
    NONE_PRINTF("client report alpn: %.*s\n", inlen, in);
    if (alpn->data) {
        *out = alpn->data;
        *outlen = alpn->len;
        NONE_PRINTF("selected %d = %.*s\n", alpn->len, alpn->len, alpn->data);
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static void proxy_http_parse(struct transfer_obj_t *conn, char *buffer, int len)
{
    int r;
    int rlen;
    int rmtfd;
    struct addrinfo_t addrinfo;
    char *connect_msg = NULL;

    rlen = transfer_read(conn, buffer, len);
    if (rlen <= 0) {
        return;
    }

    NONE_PRINTF("new %u msg from %d!\n", rlen, conn->fd);

    r = parse_addr_in_http(&addrinfo, buffer, rlen);
    if (r < 0) {
        ERROR_PRINTF("parse addr fail!\n");
        ERROR_PRINTF("dump %u msg from %d: \n", rlen, conn->fd);
        msg_dump(buffer, rlen);
        return;
    }

    rmtfd = tcp_socket_create(0, addrinfo.host, addrinfo.port);
    if (rmtfd < 0) {
        connect_msg = "HTTP/1.1 408 Request Timeout\r\n\r\n";
        transfer_write(conn, connect_msg, strlen(connect_msg));
        return;
    }

    struct transfer_obj_t *remote;
    remote = new_transfer(rmtfd);
    if (!remote) {
        close(rmtfd);
        return;
    }
    remote->type = PROTO_TYPE_TCP;

    if (strncmp("CONNECT", buffer, 7) == 0) {
        SSL_CTX *sslctx;

        //start connect to ssl server
        sslctx = SSL_CTX_new(TLS_method());
        if (!sslctx) {
            goto out_free_remote;
        }

        const unsigned char *alpn_list = (unsigned char *)"\x2h2\x8http/1.1";
        r = SSL_CTX_set_alpn_protos(sslctx, alpn_list, 2 + 8 + 2);
        if (0 != r) {
            ERROR_PRINTF("SSL_set_alpn_protos(%s) %d\n", alpn_list, r);
            SSL_CTX_free(sslctx);
            goto out_free_remote;
        }

        r = transfer_ssl_connect_wrap_hostname(remote, sslctx, addrinfo.host);
        if (r < 0) {
            connect_msg = "HTTP/1.1 408 Request Timeout\r\n\r\n";
            transfer_write(conn, connect_msg, strlen(connect_msg));
            goto out_free_remote;
        }

        struct ssl_alpn_t alpn_rmt;
        SSL_get0_alpn_selected(remote->ssl, &alpn_rmt.data, &alpn_rmt.len);

        connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        r = transfer_write(conn, connect_msg, strlen(connect_msg));
        if (r <= 0) {
            goto out_free_remote;
        }

        //start connect to ssl client
        sslctx = create_ssl_self_ca_ctx(addrinfo.host, CERT_FILE, KEY_FILE);
        if (!sslctx) {
            goto out_free_remote;
        }

        SSL_CTX_set_alpn_select_cb(sslctx, ssl_server_alpn_select_cb, &alpn_rmt);

        r = transfer_ssl_wrap(conn, sslctx, 1);
        if (r < 0) {
            goto out_free_remote;
        }

    } else {
        r = transfer_write(remote, buffer, rlen);
        if (r <= 0) {
            goto out_free_remote;
        }
    }

    conn->data = remote;
    remote->data = conn;
    r = netutils_run_task(&(struct netutils_task_t){
        .ontask = to_connect,
        .ud = remote,
        .name = addrinfo.host,
    });
    if (r < 0) {
        ERROR_PRINTF("netutils_run_task() error\n");
        goto out_free_remote;
    }

    return;

out_free_remote:
    free_transfer(remote);
}

static void to_connect(void *ud)
{
    ASSERT(ud);
    struct transfer_obj_t *conn = (struct transfer_obj_t *)ud;
    char buffer[1024];

    if (!conn->data) {
        NONE_PRINTF("new connect = %d\n", conn->fd);

        proxy_http_parse(conn, buffer, sizeof(buffer));
        if (!conn->data) {
            free_transfer(conn);
            return;
        }
    }

    transfer_task(conn, buffer, sizeof(buffer));
}

static void connect_task(void *ud)
{
    ASSERT(ud);
    struct tcp_connect_t *tcpcon = (struct tcp_connect_t *)ud;
    struct transfer_obj_t *conn;
    int r;

    r = netutils_ntop(&tcpcon->addrinfo, &tcpcon->sockinfo);
    if (r < 0) {
        ERROR_PRINTF("netutils_ntop: error\n");
        close(tcpcon->fd);
        free(tcpcon);
        return;
    }

    char *name = NULL;
    r = asprintf(&name, "%s_%s:%u", __FUNCTION__, tcpcon->addrinfo.host, tcpcon->addrinfo.port);
    if (r < 0) {
        ERROR_PRINTF("asprintf() %s\n", strerror(errno));
    }

    netutils_task_setname(name);
    free(name);

    conn = new_transfer(tcpcon->fd);
    if (!conn) {
        ERROR_PRINTF("new_transfer() error\n");
        close(tcpcon->fd);
        free(tcpcon);
        return;
    }
    free(tcpcon);
    conn->type = PROTO_TYPE_TCP;
    to_connect(conn);
}

int main(int argc, char **argv)
{
    int r;
    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);
#ifdef MTRAVE_PATH 
    mtrace_init(MTRAVE_PATH);
#endif

    signal(SIGPIPE, SIG_IGN);

    ssl_library_init();

    r = command_init();
    if (r < 0) {
        ERROR_PRINTF("command_init() error\n");
        return -1;
    }

    r = tcp_server_init(EXAMPLE_ADDR, EXAMPLE_PORT, connect_task);
    if (r < 0) {
        ERROR_PRINTF("tcp_server_init() error\n");
        return -1;
    }

    r = tcp_server_init(EXAMPLE_ADDR, EXAMPLE_PORT + 1, connect_task);
    if (r < 0) {
        ERROR_PRINTF("tcp_server_init() error\n");
        return -1;
    }

    while(1) {
        sleep(9999);
    }

    DEBUG_PRINTF("exit\n");
    return 0;
}
