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

#include <stdio.h>
#include <time.h>

#define BLUE_FONT "\033[40;34m%s\033[0m "
#define RED_FONT "\033[40;31m%s\033[0m "
#define GREEN_FONT "\033[40;32m%s\033[0m "
#define YELLOW_FONT "\033[40;33m%s\033[0m "
#define PURPLE_FONT "\033[40;35m%s\033[0m "
#define DGREEN_FONT "\033[40;36m%s\033[0m "
#define WHITE_FONT "\033[40;37m%s\033[0m "

#define TIME_FORMAT "%m-%d %H:%M:%S"


#define PRINTF(...) printf(__VA_ARGS__);
#define LOG_NONE(...)

#define LOG_ERROR(...)                                        \
    do {                                                      \
        time_t now = time(NULL);                              \
        char timestr[20];                                     \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));  \
        printf("\033[40;32m[%s]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
            timestr, __FUNCTION__, __LINE__);                 \
        printf("\033[1;40;31mERROR\033[0m ");                 \
        printf(__VA_ARGS__);                                  \
    } while(0)

#define LOG_WARN(...)                                         \
    do {                                                      \
        time_t now = time(NULL);                              \
        char timestr[20];                                     \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));  \
        printf("\033[40;32m[%s]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
            timestr, __FUNCTION__, __LINE__);                 \
        printf("\033[1;40;33mWARN\033[0m ");                  \
        printf(__VA_ARGS__);                                  \
    } while(0)

#define LOG_DEBUG(...)                                        \
    do {                                                      \
        time_t now = time(NULL);                              \
        char timestr[20];                                     \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));  \
        printf("\033[40;32m[%s]\033[0m \033[2;40;33m%s(%d)\033[0m: ",\
            timestr, __FUNCTION__, __LINE__);                 \
        printf(__VA_ARGS__);                                  \
    } while(0)

#endif
