/*
 * proxy.c of netloop
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
#include <unistd.h>
#include <netloop.h>


#define LOG_NAME   "proxy"
#define DEBUG_PRINTF(...)     printf("\033[0;32m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ERROR_PRINTF(...)     printf("\033[1;31m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};



#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8088

#define MAX_HOST_NAME_LEN   (128)

struct addrinfo_t {
    char host[MAX_HOST_NAME_LEN];
    uint16_t port;
};

static int parse_addr_in_http(struct addrinfo_t *addr, char *buf, int len)
{
    char *method, *method_d;
    char *url, *url_d;
    char tmp[512];
    strncpy(tmp, buf, sizeof(tmp) - 1);

    method = tmp;
    method_d = strstr(tmp, " ");
    if (!method_d) {
        goto exit;
    }
    *method_d = 0;

    url = method_d + 1;
    url_d = strstr(method_d + 1, " ");
    if (!url_d) {
        goto exit;
    }
    *url_d = 0;

    DEBUG_PRINTF("parse: %s %s\n", method, url);

    if (strncmp(url, "http://", 7) == 0) {
        addr->port = 80;
    } else {
        addr->port = 443;
    }

    char *host = strstr(url, "://");
    if (host) {
        host += 3;
    } else {
        host = url;
    }

    char *host_d = strstr(host, ":");
    if (host_d) {
        int port = strtoul(host_d + 1, NULL, 10);
        if (port) {
            addr->port = port;
        }
    } else {
        host_d = strstr(host, "/");
    }

    if (host_d) {
        *host_d = 0;
    }

    strncpy(addr->host, host, MAX_HOST_NAME_LEN - 1);
    DEBUG_PRINTF("parse: %s:%d\n", addr->host, addr->port);
    return 0;
exit:
    return -1;
}

static void tcp_connect_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)conn->data;

    if (peer) {
        DEBUG_PRINTF("new connect peer fd: %d --> %d\n", peer->fd, conn->fd);
    }
}

static void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)conn->data;
    ASSERT(peer);

    netloop_send(peer, buf, len);
    //DEBUG_PRINTF("new data %d\n", len);
}

static void tcp_close_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)conn->data;
    if (!peer) {
        ERROR_PRINTF("peer is null, fd: %d, type: %c\n", conn->fd, conn->type);
    } else {
        netloop_close(peer);
    }
    DEBUG_PRINTF("close connect\n");
}

static void tcp_full_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)conn->data;
    ASSERT(peer);

    peer->events &= ~POLLIN;
    DEBUG_PRINTF("full\n");
}

static void tcp_drain_callback(struct netloop_conn_t *conn)
{
    struct netloop_conn_t *peer = (struct netloop_conn_t *)conn->data;
    ASSERT(peer);

    peer->events |= POLLIN;
    DEBUG_PRINTF("drain\n");
}

static void tcp_pre_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    int r;
    struct netloop_opt_t opt;
    struct netloop_conn_t *remote;
    struct addrinfo_t addr;

    //DEBUG_PRINTF("new data %d\n", len);

    r = parse_addr_in_http(&addr, buf, len);
    if (r < 0) {
        ERROR_PRINTF("parse_addr_by_http\n");
        netloop_close(conn);
        return;
    }

    opt.host = addr.host;
    opt.port = addr.port;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_remote( (struct netloop_server_t *)conn->head, &opt, &remote);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_remote\n");
        netloop_close(conn);
        return;
    }

    conn->recv_cb = tcp_recv_callback;
    conn->data = remote;
    remote->data = conn;

    if (strncmp("CONNECT", buf, 7) == 0) {
        char *connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        netloop_send(conn, connect_msg, strlen(connect_msg));
    } else {
        netloop_send(remote, buf, len);
    }
}


int main(int argc, char **argv)
{
    int r;
    struct netloop_server_t *server;
    struct netloop_opt_t opt;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    server = netloop_init();
    if (!server) {
        ERROR_PRINTF("netloop_init\n");
        return -1;
    }

    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_pre_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_server(server, &opt);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_server\n");
        return -1;
    }

    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT + 1;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_pre_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_server(server, &opt);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_server\n");
        return -1;
    }

    r = netloop_start(server);
    if (r < 0) {
        ERROR_PRINTF("netloop_start\n");
        return -1;
    }
    DEBUG_PRINTF("netloop init ok!\n");

    while(1) {
        sleep(9999);
    }
    
    return 0;
}
