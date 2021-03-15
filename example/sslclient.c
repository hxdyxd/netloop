/*
 * sslclient.c of netloop
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
#include <netssl.h>
#include <signal.h>


#define LOG_NAME   __FILE__
#define DEBUG_PRINTF(fmt, ...) \
    printf("\033[0;32m" LOG_NAME " %s:%d\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ERROR_PRINTF(fmt, ...) \
    printf("\033[1;31m" LOG_NAME " %s:%d\033\033[0m: " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define EXAMPLE_ADDR    "www.qq.com"
#define EXAMPLE_PORT    443

#define EXAMPLE_ADDR2    "google.com"
#define EXAMPLE_PORT2    443

void ssl_connect_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("new connect, %s:%d\n", conn->peer.host, conn->peer.port);
}

void ssl_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    ((char *)buf)[len - 1] = 0;
    DEBUG_PRINTF("new %d bytes data from %s:%d: %s\n",
     len, conn->peer.host,  conn->peer.port, (char *)buf);
}

void ssl_close_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("close connect\n");
}

int main(int argc, char **argv)
{
    int r;
    char *msg;
    struct netloop_server_t *server;
    struct netloop_ssl_server_t *ssl_server;
    struct netloop_ssl_conn_t *remote;
    struct netloop_ssl_opt_t opt;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    server = netloop_init();
    if (!server) {
        ERROR_PRINTF("netloop init fail!\n");
        return -1;
    }

    ssl_server = netloop_ssl_init_by_server(server);
    if (!ssl_server) {
        ERROR_PRINTF("netloop ssl init fail!\n");
        return -1;
    }

    opt.tcp.host = EXAMPLE_ADDR;
    opt.tcp.port = EXAMPLE_PORT;
    opt.tcp.connect_cb = ssl_connect_callback;
    opt.tcp.recv_cb = ssl_recv_callback;
    opt.tcp.close_cb = ssl_close_callback;
    opt.tcp.data = NULL;
    remote = ssl_server->new_remote(ssl_server, &opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return -1;
    }

    msg = "GET / HTTP/1.1\r\nHost: " EXAMPLE_ADDR "\r\nConnection: keep-alive\r\n\r\n";
    remote->send(remote, msg, strlen(msg));

    opt.tcp.host = EXAMPLE_ADDR2;
    opt.tcp.port = EXAMPLE_PORT2;
    opt.tcp.connect_cb = ssl_connect_callback;
    opt.tcp.recv_cb = ssl_recv_callback;
    opt.tcp.close_cb = ssl_close_callback;
    opt.tcp.data = NULL;
    remote = ssl_server->new_remote(ssl_server, &opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return -1;
    }

    msg = "GET / HTTP/1.1\r\nHost: " EXAMPLE_ADDR2 "\r\nConnection: keep-alive\r\n\r\n";
    remote->send(remote, msg, strlen(msg));

    r = ssl_server->start(ssl_server);
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
