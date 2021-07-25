/*
 * command.c of netloop
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

#include "netutils.h"


static int attach_command(int argc, char **argv)
{
    int r = 0;
    void *dl;
    char *cmd = NULL;
    char *dlpath = NULL;
    int (*cmd_process)(int, char **) = NULL;

    if (argc >= 2)
        cmd = argv[1];

    if (argc >= 3)
        dlpath = argv[2];

    if (!cmd || !dlpath) {
        PRINTF("attach usage:\n");
        PRINTF("\tattach [cmd] [library]\n");
        return -1;
    }

    dl = dlopen(dlpath, RTLD_GLOBAL | RTLD_NOW | RTLD_NODELETE);
    if (!dl) {
        ERROR_PRINTF("load %s failed, %s\n", dlpath, dlerror());
        return -1;
    }

    cmd_process = dlsym(dl, "module_main");
    if (!cmd_process) {
        ERROR_PRINTF("load symbol failed\n");
        dlclose(dl);
        return -1;
    }

    r = command_attach(cmd, cmd_process);
    if (r < 0) {
        ERROR_PRINTF("attach command \'%s\' failed\n", cmd);
        dlclose(dl);
        return -1;
    }

    dlclose(dl);
    return 0;
}

static int detach_command(int argc, char **argv)
{
    char *cmd = NULL;

    if (argc >= 2)
        cmd = argv[1];

    if (!cmd) {
        PRINTF("detach usage:\n");
        PRINTF("\tdetach [cmd]\n");
        return -1;
    }

    return command_detach(cmd);
}

int module_main(int argc, char **argv)
{
    int r;
    r = command_init();
    if (r < 0) {
        ERROR_PRINTF("command_init() error\n");
        return -1;
    }

    r = telnetd_command_init("::", 2323);
    if (r < 0) {
        ERROR_PRINTF("command_init_telnetd() error\n");
        return -1;
    }

    r |= command_attach("attach", attach_command);
    r |= command_attach("detach", detach_command);
    if (r < 0) {
        ERROR_PRINTF("command_attach() error\n");
        return -1;
    }
    return 0;
}
