/*
 * netutils_http.c of netloop
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
#include <string.h>
#include "netutils.h"


int parse_addr_in_http(struct addrinfo_t *addr, char *buf, int len)
{
    char *method, *method_d;
    char *url, *url_d;
    char *tmp;
    tmp = malloc(len + 1);
    if(!tmp) {
        return -1;
    }
    memcpy(tmp, buf, len);
    tmp[len] = 0;

    method = tmp;
    method_d = strstr(method, " ");
    if (!method_d) {
        goto exit;
    }
    *method_d = 0;

    url = method_d + 1;
    url_d = strstr(url, " ");
    if (!url_d) {
        goto exit;
    }
    *url_d = 0;

    DEBUG_PRINTF("parse addr \"%s %s\"\n", method, url);

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
    free(tmp);
    return 0;
exit:
    free(tmp);
    return -1;
}
