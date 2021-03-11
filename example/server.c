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
#include <signal.h>


#define LOG_NAME   "server"
#define DEBUG_PRINTF(...)     printf("\033[0;32m" LOG_NAME "\033[0m: " __VA_ARGS__)
#define ERROR_PRINTF(...)     printf("\033[1;31m" LOG_NAME "\033[0m: " __VA_ARGS__)


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
    conn->send(conn, msg, strlen(msg));
    msg = "Content-Length: 5\r\n";
    conn->send(conn, msg, strlen(msg));
    msg = "\r\n";
    conn->send(conn, msg, strlen(msg));
    msg = "hello";
    conn->send(conn, msg, strlen(msg));
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


int main(int argc, char **argv)
{
    int r;
    struct netloop_server_t *server;
    struct netloop_opt_t opt;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    server = netloop_init();
    if (!server) {
        ERROR_PRINTF("netloop init fail!\n");
        return -1;
    }

    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.full_cb = tcp_full_callback;
    opt.drain_cb = tcp_drain_callback;
    opt.data = NULL;
    r = server->new_server(server, &opt);
    if (r < 0) {
        ERROR_PRINTF("new_server fail!\n");
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
    r = server->new_server(server, &opt);
    if (r < 0) {
        ERROR_PRINTF("new_server fail!\n");
        return -1;
    }

    r = server->start(server);
    if (r < 0) {
        ERROR_PRINTF("netloop start fail!\n");
        return -1;
    }
    DEBUG_PRINTF("netloop init ok!\n");

    while(1) {
        sleep(9999);
    }
    
    return 0;
}
