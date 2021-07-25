/*
 * log.h of netloop
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
#ifndef _LOG_H
#define _LOG_H

int log_write(int level, int have_prefix, const char *func,
              const char *file, int line, char *fmt, ...);
int log_setlevel(int level);
int log_swapfd(int fd);
int log_setlock(int lock);
int log_test(void);

#define PRINTF(...)  \
    log_write(-1, 0, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define PRINTF_DEBUG(...)  \
    log_write(3, 0, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_NONE(...)

#define LOG_ERROR(...)  \
    log_write(0, 1, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_WARN(...)  \
    log_write(1, 1, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_INFO(...)  \
    log_write(2, 1, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#define LOG_DEBUG(...)  \
    log_write(3, 1, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)

#endif
