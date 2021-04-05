/*
 * netssl.h of netloop
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
#ifndef _NETSSL_H_
#define _NETSSL_H_

#include "netloop.h"
#include <openssl/ssl.h>

int netssl_SSL_read(struct netloop_obj_t *ctx, SSL *ssl, void *buf, int num);
int netssl_SSL_write(struct netloop_obj_t *ctx, SSL *ssl, const void *buf, int num);
int netssl_SSL_accept(struct netloop_obj_t *ctx, SSL *ssl);
int netssl_SSL_connect(struct netloop_obj_t *ctx, SSL *ssl);

#endif
