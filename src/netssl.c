/*
 * netssl.c of netloop
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
#include "netssl.h"

int netssl_SSL_read(struct netloop_obj_t *ctx, SSL *ssl, void *buf, int num)
{
    while (1) {
        int r = SSL_read(ssl, buf, num);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                ctx->events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                ctx->events = POLLOUT;
                break;
            default:
                return r;
            }
            ctx->fd = SSL_get_fd(ssl);
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}

int netssl_SSL_write(struct netloop_obj_t *ctx, SSL *ssl, const void *buf, int num)
{
    while (1) {
        int r = SSL_write(ssl, buf, num);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                ctx->events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                ctx->events = POLLOUT;
                break;
            default:
                return r;
            }
            ctx->fd = SSL_get_fd(ssl);
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}

int netssl_SSL_accept(struct netloop_obj_t *ctx, SSL *ssl)
{
    while (1) {
        int r = SSL_accept(ssl);
        if (1 != r) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                ctx->events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                ctx->events = POLLOUT;
                break;
            default:
                return r;
            }
            ctx->fd = SSL_get_fd(ssl);
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}

int netssl_SSL_connect(struct netloop_obj_t *ctx, SSL *ssl)
{
    while (1) {
        int r = SSL_connect(ssl);
        if (1 != r) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                ctx->events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                ctx->events = POLLOUT;
                break;
            default:
                return r;
            }
            ctx->fd = SSL_get_fd(ssl);
            netloop_yield(ctx);
        } else {
            return r;
        }
    }
}
