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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>

#include <netloop.h>

#define LOG_NAME   __FILE__
#define DEBUG_PRINTF(fmt, ...) \
    printf("\033[0;32m" LOG_NAME " %s:%d\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ERROR_PRINTF(fmt, ...) \
    printf("\033[1;31m" LOG_NAME " %s:%d\033\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static void __netloop_conn_add_method(struct netloop_conn_t *ctx);


static inline void do_callback(void (*cb)(struct netloop_conn_t *),
                               struct netloop_conn_t *ctx)
{
    if (cb) {
        cb(ctx);
    }
}


static struct netloop_buffer_t *buffer_append(struct netloop_buffer_t *buf, char *data, int len)
{
    if (!buf) {
        buf = malloc(sizeof(struct netloop_buffer_t));
        if (!buf) {
            return NULL;
        }
        memset(buf, 0, sizeof(struct netloop_buffer_t));
    }
    buf->data = realloc(buf->data, buf->len + len);
    if (!buf->data) {
        free(buf);
        return NULL;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return buf;
}


static void buffer_free(struct netloop_buffer_t *buf)
{
    if (buf) {
        if (buf->data) {
            free(buf->data);
            buf->data = NULL;
        }
        free(buf);
    }
}




static int sock_setblocking(int sock, int if_block)
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


static int tcp_socket_create(int if_bind, const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    r = getaddrinfo(host, NULL, &hints, &res);
    if (0 != r) {
        ERROR_PRINTF("getaddrinfo: %s\n", gai_strerror(r));
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

    r = sock_setblocking(sock, 0);
    if (r < 0) {
        goto exit1;
    }

    if (if_bind) {
        int opt = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (r < 0) {
            ERROR_PRINTF("setsockopt: %s\n", strerror(errno));
            goto exit1;
        }

        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("bind %s:%d : %s\n", host, port, strerror(errno));
            goto exit1;
        }

        r = listen(sock, 512);
        if (r < 0) {
            ERROR_PRINTF("listen: %s\n", strerror(errno));
            goto exit1;
        }
    }

    freeaddrinfo(res);
    DEBUG_PRINTF("%s %s:%d\n", if_bind ? "listen" : "connect", host, port);
    return sock;

exit1:
    close(sock);
exit:
    freeaddrinfo(res);
    return -1;
}


static int tcp_socket_connect(struct ares_addrinfo_node *nodes, uint16_t port)
{
    int sock, r;

    if (nodes->ai_family == AF_INET)
        ((struct sockaddr_in *)nodes->ai_addr)->sin_port = htons(port);
    else if (nodes->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)nodes->ai_addr)->sin6_port = htons(port);
    else {
        ERROR_PRINTF("unknown ai_family %d\n", nodes->ai_family);
        return -1;
    }

    sock = socket(nodes->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ERROR_PRINTF("socket: %s\n", strerror(errno));
        return -1;
    }

    r = sock_setblocking(sock, 0);
    if (r < 0) {
        close(sock);
        return -1;
    }

    r = connect(sock, nodes->ai_addr, nodes->ai_addrlen);
    if (r < 0) {
        if (EINPROGRESS == errno) {
            return sock;
        }
        ERROR_PRINTF("connect: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}


static void netloop_dump_list(struct netloop_conn_t *head)
{
    struct netloop_conn_t *ctx, *tmp;

    printf("------------------\n");
    list_for_each_entry_safe(ctx, tmp, &head->list, list) {
        printf("idx: %d, fd: %d t:%c, s:%c, ", ctx->idx,  ctx->fd, ctx->type, ctx->state);
        printf("events: %c%c, ", (ctx->events & POLLIN) ? 'I' : ' ', (ctx->events & POLLOUT) ? 'O' : ' ' );
        if (ctx->extra_send_buf) {
            printf("extra: %d, ", ctx->extra_send_buf ? ctx->extra_send_buf->len : 0 );
        }
        if (ctx->peer.host) {
            printf("peer: %s:%d, ", ctx->peer.host, ctx->peer.port);
        }
        printf("\n");
    }
}


static int debug_conn_cnt = 0;

static struct netloop_conn_t *netloop_conn_new(void)
{
    struct netloop_conn_t *conn;
    conn = malloc(sizeof(struct netloop_conn_t) + NETLOOP_RESERVED_MEM);
    if (!conn) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(struct netloop_conn_t) + NETLOOP_RESERVED_MEM);
    conn->magic = NETLOOP_MAGIC;
    debug_conn_cnt++;
    return conn;
}

static void netloop_conn_free(struct netloop_conn_t *conn)
{
    ASSERT(NETLOOP_MAGIC == conn->magic);
    conn->fd = -1;
    conn->magic = 0;
    if (conn->peer.host) {
        free(conn->peer.host);
        conn->peer.host = NULL;
    }
    if (conn->extra_send_buf) {
        buffer_free(conn->extra_send_buf);
        conn->extra_send_buf = NULL;
    }
    free(conn);
    debug_conn_cnt--;
    //DEBUG_PRINTF("conn: %d\n", debug_conn_cnt);
}


static void __netloop_send(struct netloop_conn_t *ctx)
{
    int r;
    ASSERT(NETLOOP_STATE_STREAM == ctx->state);
    ASSERT(ctx->extra_send_buf);

    r = write(ctx->fd, ctx->extra_send_buf->data, ctx->extra_send_buf->len);
    if (r == 0) {
        ctx->close(ctx);
        return;
    } else if (r < 0) {
        switch(errno) {
        case EINTR:
            return;
        case EAGAIN:
            ASSERT(0);
            break;
        default:
            ERROR_PRINTF("write: %s\n", strerror(errno));
            ctx->close(ctx);
            return;
        }
    } else if (r < ctx->extra_send_buf->len) {
        ASSERT(0);
    }

    buffer_free(ctx->extra_send_buf);
    ctx->extra_send_buf = NULL;
    ctx->events &= ~POLLOUT;
    do_callback(ctx->drain_cb, ctx);
}

static void __netloop_receive(struct netloop_conn_t *ctx)
{
    int r;
    char buffer[512];
    ASSERT(NETLOOP_STATE_STREAM == ctx->state);

    r = read(ctx->fd, buffer, 512);
    if (r == 0) {
        ctx->close(ctx);
        return;
    } else if (r < 0) {
        if (EINTR == errno)
            return;
        ERROR_PRINTF("read: %s\n", strerror(errno));
        ctx->close(ctx);
        return;
    }

    ctx->recv_cb(ctx, buffer, r);
}

static void __netloop_connect(struct netloop_conn_t *ctx)
{
    int r;
    int val;
    socklen_t optlen = sizeof(int);
    ASSERT(NETLOOP_STATE_CONNECT == ctx->state);

    r = getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, &val, &optlen);
    if (r < 0) {
        ERROR_PRINTF("getsockopt: %s\n", strerror(errno));
        ctx->close(ctx);
        return;
    }
    if (val < 0) {
        ERROR_PRINTF("connect: %s\n", strerror(val));
        ctx->close(ctx);
        return;
    }
    ctx->state = NETLOOP_STATE_STREAM;
    ctx->events = POLLIN;
    if (ctx->extra_send_buf) {
        ctx->events |= POLLOUT;
    }
    ctx->in = __netloop_receive;
    ctx->out = __netloop_send;
    do_callback(ctx->connect_cb, ctx);
}

static void __netloop_accept(struct netloop_conn_t *ctx)
{
    int r;
    struct netloop_conn_t *newconn;

    newconn = netloop_conn_new();
    if (!newconn) {
        return;
    }

    newconn->peer.addrlen = sizeof(struct sockaddr_in6);
    newconn->fd = accept(ctx->fd, &newconn->peer.addr, &newconn->peer.addrlen);
    if (newconn->fd < 0) {
        ERROR_PRINTF("accept: %s\n", strerror(errno));
        netloop_conn_free(newconn);
        return;
    }

    r = sock_setblocking(newconn->fd, 0);
    if (r < 0) {
        close(newconn->fd);
        netloop_conn_free(newconn);
        return;
    }

    newconn->proto = NETLOOP_PROTO_TCP;
    newconn->type = NETLOOP_TYPE_SERVER;
    newconn->state = NETLOOP_STATE_STREAM;
    newconn->events = POLLIN;
    newconn->head = ctx->head;
    newconn->in = __netloop_receive;
    newconn->out = __netloop_send;

    newconn->connect_cb = ctx->connect_cb;
    newconn->recv_cb = ctx->recv_cb;
    newconn->close_cb = ctx->close_cb;
    newconn->full_cb = ctx->full_cb;
    newconn->drain_cb = ctx->drain_cb;
    newconn->data = ctx->data;
    __netloop_conn_add_method(newconn);
    list_add(&newconn->list, &newconn->head->list);
    do_callback(newconn->connect_cb, newconn);
}


static void __netloop_prepare(void *opaque)
{
    struct netloop_server_t *server = (struct netloop_server_t *)opaque;
    struct netloop_conn_t *ctx;

    //DEBUG_PRINTF("__netloop_prepare\n");
    list_for_each_entry(ctx, &server->head.list, list) {
        ASSERT(ctx->fd >= 0);
        ctx->idx = loop_add_poll(&server->loop, ctx->fd, ctx->events);
    }

    //netloop_dump_list(&server->head);
}


static void __netloop_close_free(struct netloop_server_t *server)
{
    struct netloop_conn_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &server->head.list, list) {
        if (NETLOOP_STATE_CLOSED == ctx->state) {
            do_callback(ctx->free, ctx);
            close(ctx->fd);
            list_del(&ctx->list);
            netloop_conn_free(ctx);
        }
    }
    //netloop_dump_list(&server->head);
}

static void __netloop_poll(void *opaque)
{
    struct netloop_server_t *server = (struct netloop_server_t *)opaque;
    struct netloop_conn_t *ctx;

    //DEBUG_PRINTF("__netloop_poll\n");
    server->need_free_conn = 0;
    list_for_each_entry(ctx, &server->head.list, list) {
        int revents = loop_get_revents(&server->loop, ctx->idx);
        if (server->need_free_conn)
            goto close_free;
        if (revents & POLLIN) {
            do_callback(ctx->in, ctx);
        }
        if (server->need_free_conn)
            goto close_free;
        if (revents & POLLOUT) {
            do_callback(ctx->out, ctx);
        }
        if (server->need_free_conn)
            goto close_free;
    }
    return;

close_free:
    __netloop_close_free(server);
    return;
}


static void __netloop_addrinfo_cb(void *arg, int status, int timeouts, struct ares_addrinfo *res)
{
    struct netloop_conn_t *ctx = (struct netloop_conn_t *)arg;
    ASSERT(ctx);
    ASSERT(NETLOOP_MAGIC == ctx->magic);

    if (ARES_SUCCESS != status) {
        DEBUG_PRINTF("addrinfo_cb: %s (%c) %s\n", ctx->peer.host ? ctx->peer.host : "",
                    ctx->state, ares_strerror(status));
        if (NETLOOP_STATE_INIT == ctx->state) {
            ctx->state = NETLOOP_STATE_CLOSED;
            return;
        }
        ctx->close(ctx);
        netloop_conn_free(ctx);
        return;
    }
    ASSERT(NULL != res);
    if (NULL == res->nodes) {
        ERROR_PRINTF("addrinfo nodes is null\n");
        ctx->close(ctx);
        ares_freeaddrinfo(res);
        netloop_conn_free(ctx);
        return;
    }

    if (NETLOOP_STATE_RESOLV != ctx->state) {
        ERROR_PRINTF("connection state is %c\n", ctx->state);
        ctx->close(ctx);
        ares_freeaddrinfo(res);
        netloop_conn_free(ctx);
        return;
    }

    ctx->fd = tcp_socket_connect(res->nodes, ctx->peer.port);
    if (ctx->fd < 0) {
        ctx->close(ctx);
        ares_freeaddrinfo(res);
        netloop_conn_free(ctx);
        return;
    }

    if (EINPROGRESS == errno) {
        ctx->state = NETLOOP_STATE_CONNECT;
        ctx->events |= POLLOUT;
        ctx->out = __netloop_connect;
    } else {
        ctx->state = NETLOOP_STATE_STREAM;
        ctx->events |= POLLIN;
        ctx->in = __netloop_receive;
        ctx->out = __netloop_send;
    }
    list_add(&ctx->list, &ctx->head->list);

    ares_freeaddrinfo(res);
}


static void __netloop_ares_readable(struct netloop_conn_t *ctx)
{
    //DEBUG_PRINTF("ares_readable start\n");
    ares_process_fd( *((ares_channel *)ctx->data), ctx->fd, -1);
    //DEBUG_PRINTF("ares_readable end\n");
}

static void __netloop_ares_writeable(struct netloop_conn_t *ctx)
{
    ares_process_fd( *((ares_channel *)ctx->data), -1, ctx->fd);
}

static void __netloop_sock_state_cb(void *data, int fd, int readable, int writeable)
{
    int events = 0;
    struct netloop_server_t *server = (struct netloop_server_t *)data;
    struct netloop_conn_t *dns_ctx;
    if (readable)
        events |= POLLIN;
    if (writeable)
        events |= POLLOUT;

    //DEBUG_PRINTF("__netloop_sock_state_cb: fd: %d  %d%d\n", fd, readable, writeable);
    if (events) {
        dns_ctx = netloop_conn_new();
        if (!dns_ctx) {
            return;
        }
        dns_ctx->fd = fd;
        dns_ctx->type = NETLOOP_TYPE_DNS;
        dns_ctx->events = events;
        dns_ctx->head = &server->head;
        dns_ctx->in = __netloop_ares_readable;
        dns_ctx->out = __netloop_ares_writeable;

        dns_ctx->data = &server->dns_channel;
        list_add(&dns_ctx->list, &server->head.list);
    } else {
        list_for_each_entry(dns_ctx, &server->head.list, list) {
            if (fd == dns_ctx->fd) {
                dns_ctx->state = NETLOOP_STATE_CLOSED;
                ++server->need_free_conn;
            }
        }
    }
}


static int __netloop_ares_init(struct netloop_server_t *server)
{
    int r;
    struct ares_options options;
    r = ares_library_init(ARES_LIB_INIT_ALL);
    if (ARES_SUCCESS != r) {
        ERROR_PRINTF("ares_library_init\n");
        return -1;
    }

    memset(&options, 0, sizeof(struct ares_options));
    options.sock_state_cb_data = server;
    options.sock_state_cb      = __netloop_sock_state_cb;
    options.timeout            = 3000;
    options.tries              = 2;
    r = ares_init_options(&server->dns_channel, &options, 
        ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB);
    if (ARES_SUCCESS != r) {
        ERROR_PRINTF("ares_init_options\n");
        return -1;
    }

    return 0;
}


static int netloop_send(struct netloop_conn_t *ctx, void *buf, int len)
{
    int r;
    ASSERT(NULL != ctx);
    ASSERT(NETLOOP_MAGIC == ctx->magic);
    ASSERT(NULL != buf);
    ASSERT(0 != len);
    ASSERT(ctx->fd >= 0);
    if (NETLOOP_STATE_CLOSED == ctx->state) {
        ERROR_PRINTF("connection already closed\n");
        return -1;
    }
    if (ctx->extra_send_buf) {
        ASSERT(ctx->extra_send_buf->len < ctx->max_extra_send_buf_size);
    }

    if (NETLOOP_STATE_STREAM != ctx->state || ctx->extra_send_buf) {
        ctx->extra_send_buf = buffer_append(ctx->extra_send_buf, buf, len);
        if (!ctx->extra_send_buf) {
            return -1;
        }
        if (ctx->extra_send_buf->len >= ctx->max_extra_send_buf_size) {
            do_callback(ctx->full_cb, ctx);
        }
        return len;
    }

    r = write(ctx->fd, buf, len);
    if (r == 0) {
        ctx->close(ctx);
        return -1;
    } else if (r < 0) {
        switch(errno) {
        case EINTR:
            return -1;
        case EAGAIN:
            ctx->extra_send_buf = buffer_append(ctx->extra_send_buf, buf, len);
            if (!ctx->extra_send_buf) {
                return -1;
            }
            ctx->events |= POLLOUT;
            if (ctx->extra_send_buf->len >= ctx->max_extra_send_buf_size) {
                do_callback(ctx->full_cb, ctx);
            }
            return len;
        default:
            ERROR_PRINTF("write: %s\n", strerror(errno));
            ctx->close(ctx);
            return -1;
        }
    } else if (r < len) {
        DEBUG_PRINTF("write: %d/%d\n", r, len);
        ctx->extra_send_buf = buffer_append(ctx->extra_send_buf, (char *)buf + r, len - r);
        if (!ctx->extra_send_buf) {
            return -1;
        }
        ctx->events |= POLLOUT;
        if (ctx->extra_send_buf->len >= ctx->max_extra_send_buf_size) {
            do_callback(ctx->full_cb, ctx);
        }
        return len;
    }
    return r;
}

static int netloop_close(struct netloop_conn_t *ctx)
{
    ASSERT(NULL != ctx);
    ASSERT(NETLOOP_MAGIC == ctx->magic);
    struct netloop_server_t *server = (struct netloop_server_t *)ctx->head;
    if (NETLOOP_STATE_CLOSED != ctx->state) {
        ctx->state = NETLOOP_STATE_CLOSED;
        do_callback(ctx->close_cb, ctx);
        ++server->need_free_conn;
    }
    return 0;
}

static void netloop_pause_recv(struct netloop_conn_t *ctx)
{
    ctx->events &= ~POLLIN;
}

static void netloop_resume_recv(struct netloop_conn_t *ctx)
{
    ctx->events |= POLLIN;
}

static void *netloop_get_priv(struct netloop_conn_t *ctx)
{
    return ctx->data;
}

static void __netloop_conn_add_method(struct netloop_conn_t *ctx)
{
    ctx->send         = netloop_send;
    ctx->pause_recv   = netloop_pause_recv;
    ctx->resume_recv  = netloop_resume_recv;
    ctx->close        = netloop_close;
    ctx->get_priv     = netloop_get_priv;
}



static int netloop_start(struct netloop_server_t *server)
{
    struct loopcb_t loop_cb;
    ASSERT(server);

    netloop_dump_list(&server->head);

    loop_cb.poll = __netloop_poll;
    loop_cb.prepare = __netloop_prepare;
    loop_cb.timer = NULL;
    loop_cb.opaque = server;
    loop_register(&server->loop, loop_cb);
    return loop_start(&server->loop);
}


static int netloop_new_server(struct netloop_server_t *server, const struct netloop_opt_t *opt)
{
    int sock;
    struct netloop_conn_t *listener;
    ASSERT(server && opt);

    sock = tcp_socket_create(1, opt->host, opt->port);
    if (sock < 0) {
        return -1;
    }

    listener = netloop_conn_new();
    if (!listener) {
        close(sock);
        return -1;
    }

    listener->fd = sock;
    listener->type = NETLOOP_TYPE_LISTENER;
    listener->events |= POLLIN;
    listener->head = &server->head;
    listener->in = __netloop_accept;

    listener->connect_cb = opt->connect_cb;
    listener->recv_cb = opt->recv_cb;
    listener->close_cb = opt->close_cb;
    listener->full_cb = opt->full_cb;
    listener->drain_cb = opt->drain_cb;
    listener->data = opt->data;
    listener->max_extra_send_buf_size = NETLOOP_MAX_SEND_BUF_SIZE;
    list_add(&listener->list, &server->head.list);
    return 0;
}


static struct netloop_conn_t *netloop_new_remote(struct netloop_server_t *server,
                                                 const struct netloop_opt_t *opt)
{
    struct netloop_conn_t *newconn;
    struct ares_addrinfo_hints hints;
    ASSERT(server && opt);

    newconn = netloop_conn_new();
    if (!newconn) {
        return NULL;
    }

    newconn->peer.host = strdup(opt->host);
    newconn->peer.port = opt->port;
    newconn->fd = 0;
    newconn->proto = NETLOOP_PROTO_TCP;
    newconn->type = NETLOOP_TYPE_REMOTE;
    newconn->state = NETLOOP_STATE_INIT;
    newconn->events = 0;
    newconn->head = &server->head;

    newconn->connect_cb = opt->connect_cb;
    newconn->recv_cb = opt->recv_cb;
    newconn->close_cb = opt->close_cb;
    newconn->full_cb = opt->full_cb;
    newconn->drain_cb = opt->drain_cb;
    newconn->data = opt->data;
    newconn->max_extra_send_buf_size = NETLOOP_MAX_SEND_BUF_SIZE;
    __netloop_conn_add_method(newconn);
    //list_add(&newconn->list, &server->head.list);

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ares_getaddrinfo(server->dns_channel, opt->host, NULL, &hints, __netloop_addrinfo_cb, newconn);
    if (NETLOOP_STATE_CLOSED == newconn->state) {
        netloop_conn_free(newconn);
        return NULL;
    }
    newconn->state = NETLOOP_STATE_RESOLV;
    return newconn;
}


struct netloop_server_t *netloop_init(void)
{
    int r;
    struct netloop_server_t *server;

    server =  malloc(sizeof(struct netloop_server_t) + NETLOOP_RESERVED_MEM);
    if (!server) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(server, 0, sizeof(struct netloop_server_t) + NETLOOP_RESERVED_MEM);
    INIT_LIST_HEAD(&server->head.list);
    server->head.fd = -1;

    r = loop_init(&server->loop);
    if (r < 0) {
        ERROR_PRINTF("loop_init: %s\n", strerror(errno));
        free(server);
        return NULL;
    }

    r = __netloop_ares_init(server);
    if (r < 0) {
        ERROR_PRINTF("failed to initialize c-ares\n");
        loop_exit(&server->loop);
        free(server);
        return NULL;
    }

    server->start      = netloop_start;
    server->new_server = netloop_new_server;
    server->new_remote = netloop_new_remote;

    return server;
}
