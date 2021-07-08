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
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "netutils.h"

#define TFTPD_ADDR    "::"
#define TFTPD_PORT    69


#include "log.h"
#define NONE_PRINTF   LOG_NONE
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
    pthread_t tid;
    struct sockinfo_t addr;
    char filename[512];
    uint8_t is_write;
    uint8_t option;
    unsigned long tsize;
    uint16_t blksize;
    uint8_t windowsize;
    uint16_t port;
    uint16_t timeout;
} tftp_chat;


static int tftp_send_message(int fd, tftp_message *msg, int len,
                             tftp_message *rmsg, int rlen, struct sockinfo_t *addr, int try_count)
{
    int r = 0;

    r = sock_set_recv_timeout(fd, 2000);
    if (r < 0) {
        ERROR_PRINTF("sock_set_recv_timeout(fd = %d) %s\n", fd, strerror(errno));
        return r;
    }

    NONE_PRINTF("-------------------------start send message-------------------------\n");

    do {
        NONE_PRINTF("send msg %d bytes, op=%d, blk=%d\n", len, ntohs(msg->opcode), ntohs(msg->data.block_number));
        //msg_dump(msg, len);
        r = sendto(fd, msg, len, 0, &addr->addr, addr->addrlen);
        if (r < 0) {
            ERROR_PRINTF("sendto(fd = %d) %s\n", fd, strerror(errno));
            break;
        }

        if (ntohs(msg->opcode) == TFTP_OP_ERROR || 0 == try_count) {
            return r;
        }

        r = recvfrom(fd, rmsg, rlen, 0, &addr->addr, &addr->addrlen);
        if (r < 0) {
            ERROR_PRINTF("recvfrom(fd = %d) %s\n", fd, strerror(errno));
        }
    } while (r < 0 && EAGAIN == errno && --try_count);

    if (r > 0) {
        NONE_PRINTF("recv msg %d bytes, op=%d, blk=%d\n", r, ntohs(rmsg->opcode), ntohs(rmsg->data.block_number));
        //msg_dump(rmsg, r);
    }

    NONE_PRINTF("-------------------------end send message-------------------------\n");
    return r;
}

static void *tftp_read_task(void *ud)
{
    tftp_message *msg, *rmsg;
    tftp_chat *chat;
    int r;
    int i;
    unsigned long filesize;
    int opcode = 0;
    uint16_t block_number = 0;
    uint16_t blocksize = 512;
    int rlen = 0;
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

    rlen = sizeof(tftp_message) + blocksize;

    int tftp_fd = udp_socket_create_family(chat->addr.addr.sa_family);
    if (tftp_fd < 0) {
        ERROR_PRINTF("udp_socket_create() error\n");
        goto exit2;
    }

    int file_fd = open(chat->filename, O_RDONLY | O_NOFOLLOW);
    if (file_fd < 0) {
        ERROR_PRINTF("open(%s) %s\n", chat->filename, strerror(errno));

        msg->opcode = htons(TFTP_OP_ERROR);
        msg->error.error_code = htons(0);
        strcpy(msg->error.error_string, strerror(errno));

        tftp_send_message(tftp_fd, msg, 4 + strlen(msg->error.error_string) + 1, rmsg, rlen, &chat->addr, 5);

        goto exit3;
    }

    filesize = lseek(file_fd, 0, SEEK_END);

    DEBUG_PRINTF("filesize: %lu\n", filesize);


    if (chat->option) {
        msg->opcode = htons(TFTP_OP_OACK);

        char *option = msg->oack.option;

        option += sprintf(option, "tsize") + 1;
        option += sprintf(option, "%lu", filesize) + 1;

        option += sprintf(option, "blksize") + 1;
        option += sprintf(option, "%d", blocksize) + 1;

        r = tftp_send_message(tftp_fd, msg, option - (char *)msg, rmsg, rlen, &chat->addr, 5);
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
    unsigned long pos = 0;

    DEBUG_PRINTF("block num is %d\n", blocknum);
    int time_start = time(NULL);

    int sent_percent = 0;
    int prev_sent_percent = 100;

    for (i = 1; i <= blocknum; i++) {

        int sent_size = filesize - pos < blocksize ? filesize - pos : blocksize;

        lseek(file_fd, pos, SEEK_SET);

        msg->opcode = htons(TFTP_OP_DATA);
        msg->data.block_number = htons(i & 0xffff);

        r = read(file_fd, msg->data.data, sent_size);
        if (r < 0 || r != sent_size) {
            ERROR_PRINTF("read(fd=%d, file=%s) %s\n", file_fd, chat->filename, strerror(errno));
            goto exit4;
        }

        int try_count = 5;
        while (--try_count) {

            r = tftp_send_message(tftp_fd, msg, 4 + sent_size, rmsg, rlen, &chat->addr, 5);
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

        sent_percent = i * 100 / blocknum;
        if (sent_percent != prev_sent_percent) {
            DEBUG_PRINTF("sent %s: %d/%d (%d%%)\n", chat->filename, i, blocknum, sent_percent);
        }
        prev_sent_percent = sent_percent;
    }

    int cost_time = (int)time(NULL) - time_start;

    DEBUG_PRINTF("sent %s complate, size=%lu block=%d cost=%ds\n", chat->filename, filesize, blocknum, cost_time);

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
    return NULL;
}

static void *tftp_write_task(void *ud)
{
    tftp_message *msg, *rmsg;
    tftp_chat *chat;
    int r;
    unsigned long filesize = 0;
    int opcode = 0;
    uint16_t block_number = 0;
    uint16_t blocksize = 512;
    int rlen = 0;
    ASSERT(ud);

    chat = (tftp_chat *)ud;

    if (chat->blksize) {
        blocksize = chat->blksize;
    }

    if (chat->tsize) {
        filesize = chat->tsize;
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

    rlen = sizeof(tftp_message) + blocksize;

    int tftp_fd = udp_socket_create_family(chat->addr.addr.sa_family);
    if (tftp_fd < 0) {
        ERROR_PRINTF("udp_socket_create() error\n");
        goto exit2;
    }

    int file_fd = open(chat->filename, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0777);
    if (file_fd < 0) {
        ERROR_PRINTF("open(%s) %s\n", chat->filename, strerror(errno));

        msg->opcode = htons(TFTP_OP_ERROR);
        msg->error.error_code = htons(0);
        strcpy(msg->error.error_string, strerror(errno));

        tftp_send_message(tftp_fd, msg, 4 + strlen(msg->error.error_string) + 1, rmsg, rlen, &chat->addr, 5);

        goto exit3;
    }

    if (chat->option) {
        msg->opcode = htons(TFTP_OP_OACK);

        char *option = msg->oack.option;

        if (chat->timeout) {
            option += sprintf(option, "timeout") + 1;
            option += sprintf(option, "%u", chat->timeout) + 1;
        }

        option += sprintf(option, "blksize") + 1;
        option += sprintf(option, "%d", blocksize) + 1;

        option += sprintf(option, "tsize") + 1;
        option += sprintf(option, "%lu", filesize) + 1;

        r = option - (char *)msg;
    } else {
        msg->opcode = htons(TFTP_OP_ACK);
        msg->ack.block_number = htons(0);

        r = 4;
    }

    r = tftp_send_message(tftp_fd, msg, r, rmsg, rlen, &chat->addr, 5);
    if (r < 0) {
        ERROR_PRINTF("receive timeout\n");
        goto exit4;
    }

    opcode = ntohs(rmsg->opcode);
    block_number = ntohs(rmsg->ack.block_number);

    if (TFTP_OP_DATA != opcode) {
        ERROR_PRINTF("received opcode=%d\n", opcode);
        goto exit4;
    }

    if (1 != block_number) {
        ERROR_PRINTF("received block_number=%d\n", block_number);
        goto exit4;
    }

    int rsize = r - 4;
    if (rsize <= 0) {
        ERROR_PRINTF("rsize is %d\n", rsize);
        goto exit4;
    }

    lseek(file_fd, 0, SEEK_SET);

    r = write(file_fd, rmsg->data.data, rsize);
    if (r < 0 || r != rsize) {
        ERROR_PRINTF("read(fd=%d, file=%s) %s\n", file_fd, chat->filename, strerror(errno));
        goto exit4;
    }

    int blocknum = 1;
    unsigned long pos = rsize;
    int time_start = time(NULL);

    int received_percent = 0;
    int prev_received_percent = 100;

    while (rsize == blocksize) {

        lseek(file_fd, pos, SEEK_SET);

        msg->opcode = htons(TFTP_OP_ACK);
        msg->data.block_number = htons(block_number);

        int try_count = 5;
        while (--try_count) {

            r = tftp_send_message(tftp_fd, msg, 4, rmsg, rlen, &chat->addr, 5);
            if (r < 0) {
                ERROR_PRINTF("receive timeout\n");
                goto exit4;
            }

            opcode = ntohs(rmsg->opcode);
            block_number = ntohs(rmsg->data.block_number);

            if (TFTP_OP_DATA != opcode) {
                ERROR_PRINTF("received opcode=%d\n", opcode);
                continue;
            }

            if (((ntohs(msg->data.block_number) + 1) & 0xffff) != block_number) {
                ERROR_PRINTF("expected block_number=%d, received block_number=%d\n",
                     ((ntohs(msg->data.block_number) + 1) & 0xffff), block_number);
                continue;
            }
            break;
        }
        
        rsize = r - 4;
        if (rsize < 0) {
            ERROR_PRINTF("rsize is %d\n", rsize);
            goto exit4;
        }

        if (rsize) {
            r = write(file_fd, rmsg->data.data, rsize);
            if (r < 0 || r != rsize) {
                ERROR_PRINTF("write(fd=%d, file=%s) %s\n", file_fd, chat->filename, strerror(errno));
                goto exit4;
            }
        }

        pos += rsize;
        blocknum++;

        if (filesize) {
            received_percent = pos * 100 / filesize;
            if (received_percent != prev_received_percent) {
                DEBUG_PRINTF("received %s: %lu/%lu (%d%%)\n", chat->filename, pos, filesize, received_percent);
            }
            prev_received_percent = received_percent;
        }
    }

    msg->opcode = htons(TFTP_OP_ACK);
    msg->data.block_number = htons(block_number);
    r = tftp_send_message(tftp_fd, msg, 4, rmsg, rlen, &chat->addr, 0);

    int cost_time = (int)time(NULL) - time_start;

    DEBUG_PRINTF("received %s complate, size=%lu block=%d cost=%ds\n", chat->filename, pos, blocknum, cost_time);

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
    return NULL;
}

static void *tftp_server_task(void *ud)
{
    tftp_message msg;
    int r;

    int tftp_fd = udp_socket_create(1, TFTPD_ADDR, TFTPD_PORT);
    if (tftp_fd < 0) {
        ERROR_PRINTF("udp_socket_create(%s:%d) error\n", TFTPD_ADDR, TFTPD_PORT);
        return NULL;
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
        r = recvfrom(tftp_fd, &msg, sizeof(msg), 0, &chat->addr.addr, &chat->addr.addrlen);
        if (r < 0) {
            ERROR_PRINTF("recvfrom(fd = %d) %s\n", tftp_fd, strerror(errno));
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
                    DEBUG_PRINTF("tsize=%lu\n", chat->tsize);
                } else if (strcmp(opt, "blksize") == 0) {
                    chat->blksize = atoi(cur);
                    DEBUG_PRINTF("blksize=%d\n", chat->blksize);
                } else if (strcmp(opt, "windowsize") == 0) {
                    chat->windowsize = atoi(cur);
                    DEBUG_PRINTF("windowsize=%d\n", chat->windowsize);
                } else if (strcmp(opt, "timeout") == 0) {
                    chat->timeout = atoi(cur);
                    DEBUG_PRINTF("timeout=%d\n", chat->timeout);
                }
                chat->option = 1;
            }

            opt = cur;
            cur = strlen(cur) + cur + 1;
            num++;
        }

        DEBUG_PRINTF("received %s, filename=%s, mode=%s, tsize=%lu\n", chat->is_write ? "WRQ" : "RRQ",
         chat->filename, mode_s, chat->tsize);

        if (chat->is_write) {
            r = pthread_create(&chat->tid, NULL, tftp_write_task, chat);
            if (r < 0) {
                continue;
            }
        } else {
            r = pthread_create(&chat->tid, NULL, tftp_read_task, chat);
            if (r < 0) {
                continue;
            }
        }

    }

    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t tid;
    int r;
    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);

    signal(SIGPIPE, SIG_IGN);

    r = command_init();
    if (r < 0) {
        ERROR_PRINTF("command_init() error\n");
        return -1;
    }

    r = pthread_create(&tid, NULL, tftp_server_task, NULL);
    if (r < 0) {
        ERROR_PRINTF("pthread_create() error\n");
        return -1;
    }

    while (1) {
        sleep(9999);
    }

    DEBUG_PRINTF("exit\n");
    return 0;
}
