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

int netssl_SSL_read(struct netloop_main_t *nm, SSL *ssl, void *buf, int num)
{
    while (1) {
        int events = 0;
        int r = SSL_read(ssl, buf, num);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                events = POLLOUT;
                break;
            default:
                return r;
            }
            struct pollfd pfd;
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = events | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
        } else {
            return r;
        }
    }
}

int netssl_SSL_write(struct netloop_main_t *nm, SSL *ssl, const void *buf, int num)
{
    while (1) {
        int events = 0;
        int r = SSL_write(ssl, buf, num);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                events = POLLOUT;
                break;
            default:
                return r;
            }
            struct pollfd pfd;
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = events | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
        } else {
            return r;
        }
    }
}

int netssl_SSL_accept(struct netloop_main_t *nm, SSL *ssl)
{
    while (1) {
        int events = 0;
        int r = SSL_accept(ssl);
        if (1 != r) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                events = POLLOUT;
                break;
            default:
                return r;
            }
            struct pollfd pfd;
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = events | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
        } else {
            return r;
        }
    }
}

int netssl_SSL_connect(struct netloop_main_t *nm, SSL *ssl)
{
    while (1) {
        int events = 0;
        int r = SSL_connect(ssl);
        if (1 != r) {
            int err = SSL_get_error(ssl, r);
            switch(err) {
            case SSL_ERROR_WANT_READ:
                events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                events = POLLOUT;
                break;
            default:
                return r;
            }
            struct pollfd pfd;
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = events | POLLERR | POLLHUP;
            r = netloop_poll_f(nm, &pfd, 1, -1);
        } else {
            return r;
        }
    }
}
