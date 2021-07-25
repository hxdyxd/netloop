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

#include "netutils.h"

int module_main(int argc, char **argv);

int main(int argc, char **argv)
{
    int r;
    INFO_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);
#ifdef MTRAVE_PATH 
    mtrace_init(MTRAVE_PATH);
#endif

    signal(SIGPIPE, SIG_IGN);
    r = module_main(argc, argv);
    if (r < 0) {
        return r;
    }

    while(1) {
        sleep(9999);
    }

    INFO_PRINTF("exit\n");
    return 0;
}
