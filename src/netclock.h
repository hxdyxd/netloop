/*
 * netclock.h of netloop
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
#ifndef _NETCLOCK_H_
#define _NETCLOCK_H_

#include <sys/time.h>

static inline uint32_t get_time_ms(void)
{
    int r;

#ifdef NO_CLOCK_MONOTONIC
    struct timeval tv;

    r = gettimeofday(&tv, NULL);
    if (r < 0) {
        ERROR_PRINTF("gettimeofday() %s\n", strerror(errno));
        return 0;
    }
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
    struct timespec tv;

    r = clock_gettime(
#ifdef CLOCK_MONOTONIC_RAW
        CLOCK_MONOTONIC_RAW,
#else
        CLOCK_MONOTONIC,
#endif
        &tv);
    if (r < 0) {
        return 0;
    }
    return tv.tv_sec * 1000 + tv.tv_nsec / 1000 / 1000;
#endif
}

#endif
