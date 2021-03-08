/*
 * server.c of netloop
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

#define   REMOTE

#define LOG_NAME   "server"
#define DEBUG_PRINTF(...)     printf("\033[0;32m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ERROR_PRINTF(...)     printf("\033[1;31m" LOG_NAME "\033[0m: " __VA_ARGS__)


#ifdef REMOTE
#define EXAMPLE_ADDR    "cloud.sococos.com"
#define EXAMPLE_PORT    9999

#define EXAMPLE_ADDR2    "www.google.com"
#define EXAMPLE_PORT2    80

void tcp_connect_callback(struct netloop_conn_t *conn)
{
    char *msg;
    DEBUG_PRINTF("new connect\n");
    msg = "GET / HTTP/1.1\r\nHost: www.qq.com\r\nConnection: keep-alive\r\n\r\n";
    netloop_send(conn, msg, strlen(msg));
}

void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    ((char *)buf)[len - 1] = 0;
    DEBUG_PRINTF("new data %d %s\n", len, (char *)buf);
}

void tcp_close_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("close connect\n");
}

void tcp_full_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("full\n");
}

void tcp_drain_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("drain\n");
}

#else

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8088

void tcp_connect_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("new connect\n");
}

void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    char *msg;
    DEBUG_PRINTF("new data %d\n", len);

    msg = "HTTP/1.1 200 OK\r\n";
    netloop_send(conn, msg, strlen(msg));
    msg = "Content-Length: 5\r\n";
    netloop_send(conn, msg, strlen(msg));
    msg = "\r\n";
    netloop_send(conn, msg, strlen(msg));
    msg = "hello";
    netloop_send(conn, msg, strlen(msg));
}

void tcp_close_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("close connect\n");
}

void tcp_full_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("full\n");
}

void tcp_drain_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("drain\n");
}
#endif


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

#ifdef REMOTE
    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_remote(server, &opt, NULL);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_remote\n");
        return -1;
    }

    opt.host = EXAMPLE_ADDR2;
    opt.port = EXAMPLE_PORT2;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_remote(server, &opt, NULL);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_remote\n");
        return -1;
    }
#else
    struct netloop_opt_t opt;
    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
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
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = netloop_new_server(server, &opt);
    if (r < 0) {
        ERROR_PRINTF("netloop_new_server\n");
        return -1;
    }
#endif

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
