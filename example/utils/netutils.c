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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>

#include "list.h"
#include "netutils.h"


void msg_dump(void *buf, int len)
{
    int i, j;
    unsigned char *ch = buf;
    for (i = 0; i < len; i = j) {
        for (j = i; j < i + 16; j++) {
            if (j < len) {
                PRINTF("%02x ", ch[j]);
            } else {
                PRINTF("   ");
            }
        }
        PRINTF("  ");
        for (j = i; j < len && j < i + 16; j++) {
            if (0x20 <= ch[j] && ch[j] <= 0x7e) {
                PRINTF("%c", ch[j]);
            } else {
                PRINTF(".");
            }
        }

        PRINTF("\n");
    }
}

void *memdup(const void *src, size_t n)
{
    void *dest = malloc(n);
    if (dest && src)
        memcpy(dest, src, n);
    return dest;
}

#ifdef MTRAVE_PATH
#include <mcheck.h>

static void mtrace_exit(void)
{
    muntrace();
    unsetenv("MALLOC_TRACE");
    INFO_PRINTF("mtrace end\n");
}

void mtrace_init(const char *filename)
{
    setenv("MALLOC_TRACE", filename, 1);
    mtrace();
    atexit(mtrace_exit);
    INFO_PRINTF("mtrace start, log: %s\n", filename);
}
#endif

struct command_t {
    struct list_head list;
    char *cmd;
    int (*process)(int, char **);
};


static struct termios stdin_orig_termios;
static int conio_oldf;
static struct command_t global_cmd_table;

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
    fcntl(STDIN_FILENO, F_SETFL, conio_oldf /*| O_NONBLOCK*/);
}

static int command_process(char *cmd, int len)
{
    int i;
    int argc;
    char *argv[16];
    struct command_t *item;

    memset(argv, 0, sizeof(argv));
    argc = 0;
    argv[argc++] = cmd;
    for (i = 0; i < len && argc < 16; i++) {
        if (' ' == cmd[i]) {
            cmd[i] = 0;
            if (i + 1 < len && ' ' != cmd[i + 1]) {
                argv[argc++] = &cmd[i + 1];
            }
        }
    }

    DEBUG_PRINTF("find %d\n", argc);
    for (i = 0; i < argc; i++) {
        DEBUG_PRINTF("%d: %s\n", i, argv[i]);
    }

    list_for_each_entry(item, &global_cmd_table.list, list) {
        if (!strcmp(argv[0], item->cmd) && item->process) {
            DEBUG_PRINTF("do command \'%s\'\n", item->cmd);
            return item->process(argc, argv);
        }
    }
    INFO_PRINTF("\'%s\' command not found\n", argv[0]);
    return -1;
}

struct command_task_opt_t {
    int in;
    int out;
};



static void command_task(void *ud)
{
    ASSERT(ud);
    struct command_task_opt_t *opt = (struct command_task_opt_t *)ud;
    int in = opt->in;
    int out = opt->out;
    int ofd;
    char ch = 0, och = 0;
    int pos = 0;
    char vbuf[64];

    if (STDIN_FILENO == in) {
        enable_raw_mode();
        atexit(disable_raw_mode);
    }

    INFO_PRINTF("command task enter, in = %d, out = %d\n", in, out);

    while (1) {
        int r = read(in, &ch, 1);
        if (r <= 0) {
            ERROR_PRINTF("read(fd = %d) %s\n", in, strerror(errno));
            break;
        }

        if (ch == '\n' && och == '\r')
            continue;
        if (ch == '\r' && och == '\n')
            continue;
        och = ch;

        ofd = log_swapfd(out);
        switch(ch) {
            case '\r':
            {
                PRINTF("\n");
                /* miss break */
            }
            case '\n':
            {
                vbuf[pos] = 0;
                if (pos) {
                    DEBUG_PRINTF("new cmd: %s\n", vbuf);
                    // msg_dump(vbuf, pos);
                    command_process(vbuf, pos);
                }
                pos = 0;
                break;
            }
            case 3: /* ctrl+c */
            {
                PRINTF("\n");
                INFO_PRINTF("exit, ctrl+c\n");
                exit(0);
                break;
            }
            case 9:  /* tab */
            {
                break;
            }
            case 0x7f:
            {
                INFO_PRINTF("\b");
                fflush(stdout);
                break;
            }
            case 033:
            {
                break;
            }
            default:
            {
                if (pos >= sizeof(vbuf) - 1)
                    break;
                vbuf[pos] = ch;
                pos++;
                break;
            }
        }

        vbuf[pos] = 0;
        PRINTF("\rcommand > %s", vbuf);
        fflush(stdout);
        log_swapfd(ofd);
    }
    INFO_PRINTF("command task exit, in = %d, out = %d\n", in, out);
}

static int __dump_command(int argc, char **argv)
{
    write(-1, NULL, 0);
    return 0;
}

static int __echo_command(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        PRINTF("%s ", argv[i]);
    }
    PRINTF("\n");
    return 0;
}

static int __quit_command(int argc, char **argv)
{
    INFO_PRINTF("exit, quit\n");
    exit(0);
    return 0;
}

static int __log_command(int argc, char **argv)
{
    if (2 == argc && !strcmp(argv[1], "test")) {
        return log_test();
    } else if (3 == argc && !strcmp(argv[1], "level")) {
        int l = atoi(argv[2]);
        if (l > 3)
            l = 3;
        if (l < 0)
            l = 0;
        PRINTF("set log level to %d\n", l);
        return log_setlevel(l);
    } else if (2 == argc && !strcmp(argv[1], "get")) {
        return log_setlock(1);
    } else if (2 == argc && !strcmp(argv[1], "put")) {
        return log_setlock(0);
    } else {
        PRINTF("log usage:\n");
        PRINTF("\tlog test\n");
        PRINTF("\tlog level [0-3]\n");
        PRINTF("\tlog get\n");
        PRINTF("\tlog put\n");
    }
    return 0;
}

static int __help_command(int argc, char **argv)
{
    struct command_t *item;
    int total = 0;

    list_for_each_entry(item, &global_cmd_table.list, list) {
        if (item->cmd && item->process) {
            INFO_PRINTF("command \'%s\', process %p\n", item->cmd, item->process);
            total++;
        }
    }

    INFO_PRINTF("find %d command\n", total);
    return 0;
}

int command_init(void)
{
    int r;
    struct command_task_opt_t *opt;

    opt = malloc(sizeof(struct command_task_opt_t));
    if (!opt) {
        ERROR_PRINTF("malloc(%d) %s\n", sizeof(struct command_task_opt_t), strerror(errno));
        return -1;
    }
    opt->in = STDIN_FILENO;
    opt->out = STDOUT_FILENO;

    r = netutils_run_task(&(struct netutils_task_t){
        .ontask = command_task,
        .ud = opt,
        .name = "command_task",
    });
    if (r < 0) {
        ERROR_PRINTF("netutils_run_task(command_task) error\n");
        free(opt);
        return -1;
    }
    INIT_LIST_HEAD(&global_cmd_table.list);

    r |= command_attach("help", __help_command);
    r |= command_attach("?", __help_command);
    r |= command_attach("log", __log_command);
    r |= command_attach("quit", __quit_command);
    r |= command_attach("echo", __echo_command);
    r |= command_attach("dump", __dump_command);

    return 0;
}

static void telnetd_connect_task(void *ud)
{
    ASSERT(ud);
    struct tcp_connect_t *tcpcon = (struct tcp_connect_t *)ud;
    int r;
    struct command_task_opt_t opt;

    opt.in = tcpcon->fd;
    opt.out = tcpcon->fd;
    netutils_task_setname(__FUNCTION__);
    command_task(&opt);
    close(tcpcon->fd);
    free(tcpcon);
    INFO_PRINTF("exit\n");
}

int telnetd_command_init(const char *host, uint16_t port)
{
    return tcp_server_init(host, port, telnetd_connect_task);
}

int command_attach(const char *cmd, int (*process)(int, char **))
{
    struct command_t *item;
    ASSERT(cmd);
    ASSERT(process);

    item = malloc(sizeof(struct command_t));
    if (!item) {
        ERROR_PRINTF("malloc(%d) %s\n", sizeof(struct command_t), strerror(errno));
        return -1;
    }

    item->cmd = strdup(cmd);
    if (!item->cmd) {
        free(item);
        return -1;
    }
    item->process = process;
    list_add_tail(&item->list, &global_cmd_table.list);
    return 0;
}
