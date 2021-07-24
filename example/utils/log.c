/*
 * log.c of netloop
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
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#include "list.h"
#include "log.h"

#include <unistd.h>
#include <sys/syscall.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

#define BLUE_FONT "\033[40;34m%s\033[0m "
#define RED_FONT "\033[40;31m%s\033[0m "
#define GREEN_FONT "\033[40;32m%s\033[0m "
#define YELLOW_FONT "\033[40;33m%s\033[0m "
#define PURPLE_FONT "\033[40;35m%s\033[0m "
#define DGREEN_FONT "\033[40;36m%s\033[0m "
#define WHITE_FONT "\033[40;37m%s\033[0m "
#define NONE_FONT "\033[0m"

#ifdef LOG_MONTH
#define TIME_FORMAT "%m-%d %H:%M:%S"
#else
#define TIME_FORMAT "%H:%M:%S"
#endif

struct log_opt_t {
    struct list_head list;
    int level;
    int fd;
    int tid;
};

static int global_log_level = 2;
static int global_log_fd = STDOUT_FILENO;
static int global_log_lock = 0;

static int log_format_levelstr(int level, char **levelstr)
{
    if (!levelstr)
        return -1;
    switch(level) {
        case 0:
        {
            *levelstr = "\033[1;40;31m" "ERROR" NONE_FONT " ";
            break;
        }
        case 1:
        {
            *levelstr = "\033[1;40;33m" "WARN" NONE_FONT " ";
            break;
        }
        case 2:
        {
            *levelstr = "";
            break;
        }
        case 3:
        {
            *levelstr = "D" " ";
            break;
        }
        default:
        {
            *levelstr = "";
            break;
        }
    }
    return 0;
}

int log_write(int level, const char *func,
              const char *file, int line, char *fmt, ...)
{
    int r;
    int ecode = errno;
    int have_prefix = 1;
    va_list args;
    time_t now;
    pid_t tid;
    char timestr[20];
    char *levelstr = "";
    char *vbuf = NULL;
    int msglen = 0;

    if (level > global_log_level)
        return 0;

    if (level < 0)
        have_prefix = 0;

    vbuf = malloc(512);
    if (!vbuf) {
        printf("malloc failed!\n");
        return 0;
    }

    if (have_prefix) {
        now = time(NULL);
        tid = gettid();

        strftime(timestr, 20, TIME_FORMAT, localtime(&now));

        log_format_levelstr(level, &levelstr);
        msglen += snprintf(vbuf + msglen, 512 - msglen,
            "%s" /* color */
            "[%s] " /* time */
            "%s" /* color */
            "%s(%d) %u %s" /* file(line) tid func */
            "%s"  /* NONE_FONT */
            ": "
            "%s", "\033[40;32m", timestr, "\033[2;40;33m", file, line, tid, func, NONE_FONT, levelstr);
    }

    va_start(args, fmt);
    msglen += vsnprintf(vbuf + msglen, 512 - msglen, fmt, args);
    va_end(args);

    r = write(global_log_fd, vbuf, msglen);
    if (r < 0) {
        printf("write(fd = %d) %s\n", global_log_fd, strerror(errno));
        r = -1;
    }

    free(vbuf);
    errno = ecode;
    return r;
}

int log_setlevel(int level)
{
    global_log_level = level;
    return 0;
}

int log_swapfd(int fd)
{
    int ofd = global_log_fd;
    if (!global_log_lock)
        global_log_fd = fd;
    return ofd;
}

int log_setlock(int lock)
{
    global_log_lock = lock;
    return lock;
}

int log_test(void)
{
    PRINTF("test PRINTF message\n");
    LOG_ERROR("test LOG_ERROR message\n");
    LOG_WARN("test LOG_WARN message\n");
    LOG_INFO("test LOG_INFO message\n");
    LOG_DEBUG("test LOG_DEBUG message\n");
    log_write(4, __FUNCTION__, __FILE__, __LINE__, "test default message\n");
    return 0;
}

