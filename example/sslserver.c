/*
 * sslserver.c of netloop
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


#include <log.h>
#define DEBUG_PRINTF  LOG_DEBUG
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8088

#define CERT_FILE     "server.crt"
#define KEY_FILE      "server.key"


void tcp_connect_callback(struct netloop_conn_t *conn)
{
    DEBUG_PRINTF("new connect\n");
}

void tcp_recv_callback(struct netloop_conn_t *conn, void *buf, int len)
{
    char *msg;
    DEBUG_PRINTF("new %d bytes data: \n", len);
    //DEBUG_PRINTF("%.*s\n",  len, (char *)buf);

    if (strstr(buf, "GET") != NULL && strstr(buf, "HTTP/1.1") != NULL) {
        msg = "HTTP/1.1 200 OK\r\n";
        conn->send(conn, msg, strlen(msg));
        msg = "Content-Length: 5\r\n";
        conn->send(conn, msg, strlen(msg));
        msg = "\r\n";
        conn->send(conn, msg, strlen(msg));
        msg = "hello";
        conn->send(conn, msg, strlen(msg));
        DEBUG_PRINTF("new response\n");
    }
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

/* Set the key and cert */
static SSL_CTX *create_ssl_ctx(const char *cert, const char *key)
{
    int r;
    SSL_CTX *sslctx;
    sslctx = SSL_CTX_new(TLS_method());
    if (!sslctx) {
        ERROR_PRINTF("SSL_CTX_new() fail!\n");
        return NULL;
    }

    r = SSL_CTX_use_certificate_file(sslctx, cert, SSL_FILETYPE_PEM);
    if (r <= 0) {
        ERROR_PRINTF("SSL_CTX_use_certificate_file() fail!\n");
        return NULL;
    }

    r = SSL_CTX_use_PrivateKey_file(sslctx, key, SSL_FILETYPE_PEM);
    if (r <= 0) {
        ERROR_PRINTF("SSL_CTX_use_PrivateKey_file() fail!\n");
        return NULL;
    }
    return sslctx;
}


int main(int argc, char **argv)
{
    int r;
    struct netloop_server_t *server;
    struct netloop_ssl_server_t *ssl_server;
    struct netloop_ssl_conn_t *listener;
    struct netloop_ssl_opt_t opt;
    SSL_CTX *sslctx;

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

    sslctx = create_ssl_ctx(CERT_FILE, KEY_FILE);
    if (!sslctx) {
        ERROR_PRINTF("create_ssl_ctx() fail!\n");
        return -1;
    }

    memset(&opt, 0, sizeof(opt));
    opt.tcp.host = EXAMPLE_ADDR;
    opt.tcp.port = EXAMPLE_PORT;
    opt.tcp.connect_cb = tcp_connect_callback;
    opt.tcp.recv_cb = tcp_recv_callback;
    opt.tcp.close_cb = tcp_close_callback;
    opt.tcp.full_cb = tcp_full_callback;
    opt.tcp.drain_cb = tcp_drain_callback;
    opt.tcp.data = NULL;
    opt.ctx = sslctx;
    listener = (struct netloop_ssl_conn_t *)ssl_server->new_server(ssl_server, &opt);
    if (!listener) {
        ERROR_PRINTF("new_server fail!\n");
        return -1;
    }

    memset(&opt, 0, sizeof(opt));
    opt.tcp.host = EXAMPLE_ADDR;
    opt.tcp.port = EXAMPLE_PORT + 1;
    opt.tcp.connect_cb = tcp_connect_callback;
    opt.tcp.recv_cb = tcp_recv_callback;
    opt.tcp.close_cb = tcp_close_callback;
    opt.tcp.full_cb = tcp_full_callback;
    opt.tcp.drain_cb = tcp_drain_callback;
    opt.tcp.data = NULL;
    opt.ctx = sslctx;
    listener = (struct netloop_ssl_conn_t *)ssl_server->new_server(ssl_server, &opt);
    if (!listener) {
        ERROR_PRINTF("new_server fail!\n");
        return -1;
    }

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
