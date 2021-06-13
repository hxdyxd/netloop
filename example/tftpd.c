/*
 * tftpd.c of netloop
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
#include <sys/stat.h>

#include <netloop.h>
#include <netutils.h>

#define TFTPD_ADDR    "::"
#define TFTPD_PORT    69


#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

/* tftp opcode mnemonic */
enum tftp_opcode {
     TFTP_OP_RRQ=1,
     TFTP_OP_WRQ,
     TFTP_OP_DATA,
     TFTP_OP_ACK,
     TFTP_OP_ERROR,
     TFTP_OP_OACK
};

/* tftp message structure */
typedef union {
     uint16_t opcode;
     struct {
          uint16_t opcode; /* RRQ or WRQ */
          char filename_and_mode[514];
     } request;     
     struct {
          uint16_t opcode; /* DATA */
          uint16_t block_number;
          uint8_t data[0];
     } data;
     struct {
          uint16_t opcode; /* ACK */
          uint16_t block_number;
     } ack;
     struct {
          uint16_t opcode; /* ERROR */
          uint16_t error_code;
          char error_string[512];
     } error;
     struct {
          uint16_t opcode; /* OACK */
          char option[512];
     } oack;
} tftp_message;


typedef struct {
    struct sockinfo_t addr;
    char filename[512];
    uint8_t is_write;
    uint8_t option;
    int tsize;
    uint16_t blksize;
    uint8_t windowsize;
    uint16_t port;
} tftp_chat;


static void msg_dump(void *buf, int len)
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
            if ('0' <= ch[j] && ch[j] <= 'z') {
                PRINTF("%c", ch[j]);
            } else {
                PRINTF(".");
            }
        }

        PRINTF("\n");
    }
}


static int tftp_send_message(struct netloop_obj_t *ctx, int fd, tftp_message *msg, int len,
                             tftp_message *rmsg, struct sockinfo_t *addr, int try_count)
{
    int r = 0;

    //PRINTF("-------------------------start send message-------------------------\n");

    do {
        NONE_PRINTF("send msg %d bytes, op = %d\n", len, ntohs(msg->opcode));
        //msg_dump(msg, len);
        r = netloop_sendto(ctx, fd, msg, len, 0, &addr->addr, addr->addrlen);
        if (r < 0) {
            ERROR_PRINTF("netloop_sendto(fd = %d) %s\n", fd, strerror(errno));
            break;
        }

        if (ntohs(msg->opcode) == TFTP_OP_ERROR) {
            return r;
        }

        r = netloop_recvfrom_timeout(ctx, fd, rmsg, sizeof(tftp_message), 0, &addr->addr, &addr->addrlen, 2);
        if (r < 0) {
            ERROR_PRINTF("netloop_recvfrom(fd = %d) %s\n", fd, strerror(errno));
        }
    } while (r < 0 && EAGAIN == errno && --try_count);

    if (r > 0) {
        NONE_PRINTF("recv msg %d bytes, op = %d\n", r, ntohs(rmsg->opcode));
        //msg_dump(rmsg, r);
    }

    //PRINTF("-------------------------end send message-------------------------\n");
    return r;
}

static void tftp_read_task(struct netloop_obj_t *ctx, void *ud)
{
    tftp_message *msg, *rmsg;
    tftp_chat *chat;
    int r;
    int i;
    int filesize;
    int opcode = 0;
    uint16_t block_number = 0;
    uint16_t blocksize = 512;
    ASSERT(ud);

    chat = (tftp_chat *)ud;

    if (chat->blksize) {
        blocksize = chat->blksize;
    }

    msg = malloc(sizeof(tftp_message) + blocksize);
    if (!msg) {
        ERROR_PRINTF("malloc() error\n");
        goto exit;
    }

    rmsg = malloc(sizeof(tftp_message) + blocksize);
    if (!rmsg) {
        ERROR_PRINTF("malloc() error\n");
        goto exit1;
    }

    int tftp_fd = udp_socket_create_family(ctx, chat->addr.addr.sa_family);
    if (tftp_fd < 0) {
        ERROR_PRINTF("udp_socket_create() error\n");
        goto exit2;
    }

    int file_fd = open(chat->filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (file_fd < 0) {
        ERROR_PRINTF("open(%s) %s\n", chat->filename, strerror(errno));

        msg->opcode = htons(TFTP_OP_ERROR);
        msg->error.error_code = htons(0);
        strcpy(msg->error.error_string, strerror(errno));

        tftp_send_message(ctx, tftp_fd, msg, 4 + strlen(msg->error.error_string) + 1, rmsg, &chat->addr, 5);

        goto exit3;
    }

    filesize = lseek(file_fd, 0, SEEK_END);

    DEBUG_PRINTF("filesize: %d\n", filesize);


    if (chat->option) {
        msg->opcode = htons(TFTP_OP_OACK);

        char *option = msg->oack.option;

        option += sprintf(option, "tsize") + 1;
        option += sprintf(option, "%d", filesize) + 1;

        option += sprintf(option, "blksize") + 1;
        option += sprintf(option, "%d", blocksize) + 1;

        r = tftp_send_message(ctx, tftp_fd, msg, option - (char *)msg, rmsg, &chat->addr, 5);
        if (r < 0) {
            ERROR_PRINTF("receive timeout\n");
            goto exit4;
        }

        opcode = ntohs(rmsg->opcode);
        block_number = ntohs(rmsg->ack.block_number);

        if (TFTP_OP_ACK != opcode) {
            ERROR_PRINTF("received opcode=%d\n", opcode);
            goto exit4;
        }

        if (0 != block_number) {
            ERROR_PRINTF("received block_number=%d\n", block_number);
            goto exit4;
        }
    }


    int blocknum = filesize / blocksize + 1;
    int pos = 0;

    DEBUG_PRINTF("block num is %d\n", blocknum);
    int time_start = time(NULL);

    int sent_percent = 0;
    int prev_sent_percent = 100;

    for (i = 1; i <= blocknum; i++) {

        int sent_size = filesize - pos < blocksize ? filesize - pos : blocksize;

        lseek(file_fd, pos, SEEK_SET);

        sent_percent = i * 100 / blocknum;
        if (sent_percent != prev_sent_percent) {
            DEBUG_PRINTF("sent %s: %d/%d (%d%%)\n", chat->filename, i, blocknum, sent_percent);
        }
        prev_sent_percent = sent_percent;

        msg->opcode = htons(TFTP_OP_DATA);
        msg->data.block_number = htons(i & 0xffff);

        r = netloop_read(ctx, file_fd, msg->data.data, sent_size);
        if (r < 0 || r != sent_size) {
            ERROR_PRINTF("netloop_read(fd=%d, file=%s) %s\n", file_fd, chat->filename, strerror(errno));
            goto exit4;
        }

        int try_count = 5;
        while (--try_count) {

            r = tftp_send_message(ctx, tftp_fd, msg, 4 + sent_size, rmsg, &chat->addr, 5);
            if (r < 0) {
                ERROR_PRINTF("receive timeout\n");
                goto exit4;
            }

            opcode = ntohs(rmsg->opcode);
            block_number = ntohs(rmsg->ack.block_number);

            if (TFTP_OP_ACK != opcode) {
                ERROR_PRINTF("received opcode=%d\n", opcode);
                continue;
            }

            if ( (i & 0xffff) != block_number) {
                ERROR_PRINTF("sent block_number=%d, received block_number=%d\n", (i & 0xffff), block_number);
                continue;
            }
            break;
        }
        

        pos += sent_size;
    }

    int cost_time = (int)time(NULL) - time_start;

    DEBUG_PRINTF("sent %s complate, size=%d block=%d cost=%ds\n", chat->filename, filesize, blocknum, cost_time);

exit4:
    close(file_fd);
exit3:
    close(tftp_fd);
exit2:
    free(rmsg);
exit1:
    free(msg);
exit:
    free(chat);
}

static void tftp_server_task(struct netloop_obj_t *ctx, void *ud)
{
    tftp_message msg;
    int r;

    int tftp_fd = udp_socket_create(ctx, 1, TFTPD_ADDR, TFTPD_PORT);
    if (tftp_fd < 0) {
        ERROR_PRINTF("udp_socket_create(%s:%d) error\n", TFTPD_ADDR, TFTPD_PORT);
        return;
    }

    while (1) {
        tftp_chat *chat;
        uint16_t opcode;
        char *mode_s = NULL;

        chat = malloc(sizeof(tftp_chat));
        if (!chat) {
            ERROR_PRINTF("malloc() %s\n", strerror(errno));
            break;
        }
        memset(chat, 0, sizeof(tftp_chat));

        chat->addr.addrlen = sizeof(struct sockaddr_in6);
        r = netloop_recvfrom(ctx, tftp_fd, &msg, sizeof(msg), 0, &chat->addr.addr, &chat->addr.addrlen);
        if (r < 0) {
            ERROR_PRINTF("netloop_recvfrom(fd = %d) %s\n", tftp_fd, strerror(errno));
            free(chat);
            break;
        }

        DEBUG_PRINTF("recv msg %d bytes, op = %d\n", r, ntohs(msg.opcode));
        msg_dump(&msg, r);

        opcode = ntohs(msg.opcode);

        if (TFTP_OP_RRQ != opcode && TFTP_OP_WRQ != opcode) {
            free(chat);
            break;
        }

        if (TFTP_OP_WRQ == opcode) {
            chat->is_write = 1;
        }

        char *opt = NULL;
        char *cur = msg.request.filename_and_mode;
        char *end = (char *)&msg + r;
        char num = 0;
        while (cur < end) {
            if (num == 0) {
                strcpy(chat->filename, cur);
            } else if (num == 1) {
                mode_s = cur;
            } else {
                if (strcmp(opt, "tsize") == 0) {
                    chat->tsize = atoi(cur);
                    DEBUG_PRINTF("tsize=%d\n", chat->tsize);
                } else if (strcmp(opt, "blksize") == 0) {
                    chat->blksize = atoi(cur);
                    DEBUG_PRINTF("blksize=%d\n", chat->blksize);
                } else if (strcmp(opt, "windowsize") == 0) {
                    chat->windowsize = atoi(cur);
                    DEBUG_PRINTF("windowsize=%d\n", chat->windowsize);
                }
                chat->option = 1;
            }

            opt = cur;
            cur = strlen(cur) + cur + 1;
            num++;
        }

        DEBUG_PRINTF("received %s, filename=%s, mode=%s, tsize=%d\n", chat->is_write ? "WRQ" : "RRQ",
         chat->filename, mode_s, chat->tsize);

        if (chat->is_write) {
            DEBUG_PRINTF("unsupported\n");
            free(chat);
        } else {
            netloop_run_task(ctx->nm, &(struct netloop_task_t){
                .task_cb = tftp_read_task, .ud = chat, .name = "tftp_read_task",
            });
        }

    }
}

int main(int argc, char **argv)
{
    int r;
    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);
#ifdef MTRAVE_PATH 
    mtrace_init(MTRAVE_PATH);
#endif

    signal(SIGPIPE, SIG_IGN);

    struct netloop_main_t *nm = netloop_init();
    if (!nm) {
        return -1;
    }

    r = command_init(nm);
    if (r < 0) {
        ERROR_PRINTF("command_init() error\n");
        return -1;
    }

    struct netloop_obj_t *task;
    task = netloop_run_task(nm, &(struct netloop_task_t){
        .task_cb = tftp_server_task, .ud = NULL, .name = "tftp_server_task",
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task() error\n");
        return -1;
    }

    r = netloop_start(nm);
    if (r < 0) {
        return -1;
    }

    while(1) {
        sleep(9999);
    }

    DEBUG_PRINTF("exit\n");
    return 0;
}
