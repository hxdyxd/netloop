/*
 * netdns_cares.h of netloop
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
#ifndef _NETDNS_CARES_H_
#define _NETDNS_CARES_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "netloop.h"

#ifdef LIBCARES
int netdns_getaddrinfo(struct netloop_main_t *nm, const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res);
void netdns_freeaddrinfo(struct addrinfo *res);
const char *netdns_strerror(int code);
#else
#define netdns_getaddrinfo(c,n,s,h,r) getaddrinfo(n,s,h,r)
#define netdns_freeaddrinfo(r)        freeaddrinfo(r)
#define netdns_strerror(c)            gai_strerror(c)
#endif

#endif
