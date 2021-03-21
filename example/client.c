/*
 * client.c of netloop
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


#include <log.h>
#define DEBUG_PRINTF  LOG_DEBUG
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define EXAMPLE_ADDR    "www.qq.com"
#define EXAMPLE_PORT    80

#define EXAMPLE_ADDR2    "google.com"
#define EXAMPLE_PORT2    80

void tcp_connect_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("new connect, %s:%d\n", conn->peer.host, conn->peer.port);
}

void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    ((char *)buf)[len - 1] = 0;
    DEBUG_PRINTF("new %d bytes data from %s:%d: %s\n",
     len, conn->peer.host,  conn->peer.port, (char *)buf);
}

void tcp_close_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("close connect\n");
}

int main(int argc, char **argv)
{
    int r;
    char *msg;
    struct netloop_conn_t *remote;
    struct netloop_server_t *server;
    struct netloop_opt_t opt;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    server = netloop_init();
    if (!server) {
        ERROR_PRINTF("netloop init fail!\n");
        return -1;
    }

    memset(&opt, 0, sizeof(opt));
    opt.host = EXAMPLE_ADDR;
    opt.port = EXAMPLE_PORT;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.data = NULL;
    remote = server->new_remote(server, &opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return -1;
    }

    msg = "GET / HTTP/1.1\r\nHost: " EXAMPLE_ADDR "\r\nConnection: keep-alive\r\n\r\n";
    remote->send(remote, msg, strlen(msg));

    memset(&opt, 0, sizeof(opt));
    opt.host = EXAMPLE_ADDR2;
    opt.port = EXAMPLE_PORT2;
    opt.connect_cb = tcp_connect_callback;
    opt.recv_cb = tcp_recv_callback;
    opt.close_cb = tcp_close_callback;
    opt.data = NULL;
    remote = server->new_remote(server, &opt);
    if (!remote) {
        ERROR_PRINTF("new_remote fail!\n");
        return -1;
    }

    msg = "GET / HTTP/1.1\r\nHost: " EXAMPLE_ADDR2 "\r\nConnection: keep-alive\r\n\r\n";
    remote->send(remote, msg, strlen(msg));

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
