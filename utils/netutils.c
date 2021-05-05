/*
 * netutils.c of netloop
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
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "netutils.h"


#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


void *memdup(const void *src, size_t n)
{
    void *dest = malloc(n);
    if (dest && src)
        memcpy(dest, src, n);
    return dest;
}


static struct termios stdin_orig_termios;
static int conio_oldf;

static void disable_raw_mode(void)
{
    tcsetattr(STDIN_FILENO, TCSANOW, &stdin_orig_termios);
    fcntl(STDIN_FILENO, F_SETFL, conio_oldf);
}

static void enable_raw_mode(void)
{
    tcgetattr(STDIN_FILENO, &stdin_orig_termios);
    struct termios term = stdin_orig_termios;
    term.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                         | INLCR | IGNCR | ICRNL | IXON);
    term.c_oflag |= OPOST;
    term.c_lflag &= ~(ICANON | ECHONL | ECHO | IEXTEN); // Disable echo as well
    term.c_cflag &= ~(CSIZE | PARENB);
    term.c_cflag |= CS8;
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    term.c_lflag &= ~ISIG;
    if(tcsetattr(STDIN_FILENO, TCSANOW, &term) < 0) {
        ERROR_PRINTF("set attr err\n");
        return;
    }

    conio_oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, conio_oldf | O_NONBLOCK);
}

static void command_task(struct netloop_obj_t *ctx, void *ud)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)ud;
    int in = STDIN_FILENO;
    int out = STDOUT_FILENO;
    char ch;

    enable_raw_mode();
    atexit(disable_raw_mode);
    while (1) {
        int r = netloop_read(ctx, in, &ch, 1);
        if (r < 0) {
            ERROR_PRINTF("read(fd = %d) %s\n", in, strerror(errno));
            return;
        }

        netloop_write(ctx, out, &ch, 1);
        netloop_write(ctx, out, "\n", 1);
        fflush(stdout);
        switch(ch) {
        case 'q':
            DEBUG_PRINTF("exit\n");
            exit(0);
            break;
        case 'd':
            netloop_dump_task(nm);
            break;
        case '?':
        case 'h':
            DEBUG_PRINTF("press 'q' to exit\n");
            break;
        }
    }
}

int command_init(struct netloop_main_t *nm)
{
    struct netloop_obj_t *task;
    task = netloop_run_task(nm, &(struct netloop_task_t){
        .task_cb = command_task, .ud = nm, .name = "command_task",
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task(command_task) error\n");
        return -1;
    }
    return 0;
}
