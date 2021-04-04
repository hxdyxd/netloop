
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include "netloop.h"
#include "netdns_cares.h"

#define EXAMPLE_ADDR    "::"
#define EXAMPLE_PORT    8086


#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static int sock_setblocking(int sock, int if_block)
{
    int flags, r;

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }

    if (if_block)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    r = fcntl(sock, F_SETFL, flags);
    if (r < 0) {
        ERROR_PRINTF("fcntl: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}


static int tcp_socket_create(struct netloop_obj_t *ctx, int if_bind, const char *host, int port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    r = netdns_getaddrinfo(ctx, host, NULL, &hints, &res);
    if (0 != r) {
        ERROR_PRINTF("getaddrinfo: %d\n", r);
        return -1;
    }

    if (res->ai_family == AF_INET)
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(port);
    else if (res->ai_family == AF_INET6)
        ((struct sockaddr_in6 *)res->ai_addr)->sin6_port = htons(port);
    else {
        ERROR_PRINTF("unknown ai_family %d\n", res->ai_family);
        goto exit;
    }

    sock = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ERROR_PRINTF("socket: %s\n", strerror(errno));
        goto exit;
    }

    r = sock_setblocking(sock, 0);
    if (r < 0) {
        goto exit1;
    }

    if (if_bind) {
        int opt = 1;
        r = setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        if (r < 0) {
            ERROR_PRINTF("setsockopt: %s\n", strerror(errno));
            goto exit1;
        }

        r = bind(sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("bind %s:%d : %s\n", host, port, strerror(errno));
            goto exit1;
        }

        r = listen(sock, 512);
        if (r < 0) {
            ERROR_PRINTF("listen: %s\n", strerror(errno));
            goto exit1;
        }
    } else {
        r = netloop_connect(ctx, sock, res->ai_addr, res->ai_addrlen);
        if (r < 0) {
            ERROR_PRINTF("connect: %s\n", strerror(errno));
            close(sock);
            return -1;
        }
    }

    freeaddrinfo(res);
    DEBUG_PRINTF("%s %s:%d\n", if_bind ? "listen" : "connect", host, port);
    return sock;

exit1:
    close(sock);
exit:
    freeaddrinfo(res);
    return -1;
}



#define MAX_HOST_NAME_LEN   (128)

struct addrinfo_t {
    char host[MAX_HOST_NAME_LEN];
    uint16_t port;
};

static int parse_addr_in_http(struct addrinfo_t *addr, char *buf, int len)
{
    char *method, *method_d;
    char *url, *url_d;
    char *tmp;
    tmp = malloc(len + 1);
    if(!tmp) {
        return -1;
    }
    memcpy(tmp, buf, len);
    tmp[len] = 0;

    method = tmp;
    method_d = strstr(method, " ");
    if (!method_d) {
        goto exit;
    }
    *method_d = 0;

    url = method_d + 1;
    url_d = strstr(url, " ");
    if (!url_d) {
        goto exit;
    }
    *url_d = 0;

    NONE_PRINTF("parse addr \"%s %s\"\n", method, url);

    if (strncmp(url, "http://", 7) == 0) {
        addr->port = 80;
    } else {
        addr->port = 443;
    }

    char *host = strstr(url, "://");
    if (host) {
        host += 3;
    } else {
        host = url;
    }

    char *host_d = strstr(host, ":");
    if (host_d) {
        int port = strtoul(host_d + 1, NULL, 10);
        if (port) {
            addr->port = port;
        }
    } else {
        host_d = strstr(host, "/");
    }

    if (host_d) {
        *host_d = 0;
    }

    strncpy(addr->host, host, MAX_HOST_NAME_LEN - 1);
    free(tmp);
    return 0;
exit:
    free(tmp);
    return -1;
}


struct tcp_connect_t {
    int fd;
    int peerfd;
    struct netloop_main_t *nm;
    struct netloop_obj_t *ctx;
    int run;
};


void transfer_task(struct netloop_obj_t *ctx, void *ud)
{
    ASSERT(ud);
    int r;
    struct tcp_connect_t *conn = (struct tcp_connect_t *)ud;
    char buffer[512];
    int rfd = conn->fd;
    int wfd = conn->peerfd;
    if (ctx != conn->ctx) {
        //run in transfer_task
        rfd = conn->peerfd;
        wfd = conn->fd;
    }

    NONE_PRINTF("transfer %d to %d\n", rfd, wfd);

    while (conn->run >= 2) {
        r = netloop_read(ctx, rfd, buffer, sizeof(buffer));
        if (r <= 0) {
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                ERROR_PRINTF("read(fd = %d) %s\n", rfd, strerror(errno));
            }
            break;
        }

        NONE_PRINTF("new %u msg from %d:\n", r, rfd);

        char *pos = buffer;
        int len = r;
        do {
            r = netloop_write(ctx, wfd, pos, len);
            if (r <= 0) {
                if (r < 0) {
                    if (errno == EINTR)
                        continue;
                    ERROR_PRINTF("write(fd = %d) %s\n", wfd, strerror(errno));
                }
                goto out;
            }
            if (r < len) {
                DEBUG_PRINTF("%u/%u \n", r, len);
            }
            len -= r;
            pos += r;
        } while (len);
    }

out:
    conn->run--;
    if (conn->run <= 0) {
        DEBUG_PRINTF("free [%s]!\n", ctx->name);
        close(rfd);
        close(wfd);
        free(conn);
    }
    NONE_PRINTF("task exit [%s]!\n", ctx->name);
}

void connect_task(struct netloop_obj_t *ctx, void *ud)
{
    ASSERT(ud);
    int r;
    int len;
    struct addrinfo_t addr;
    struct tcp_connect_t *conn = (struct tcp_connect_t *)ud;
    char buffer[512];

    r = sock_setblocking(conn->fd, 0);
    if (r < 0) {
        ERROR_PRINTF("sock_setblocking(fd = %d) %s\n", conn->fd, strerror(errno));
        goto exit;
    }

    NONE_PRINTF("new connect = %d\n", conn->fd);

    r = netloop_read(ctx, conn->fd, buffer, sizeof(buffer));
    if (0 == r) {
        goto exit;
    } else if (r < 0) {
        ERROR_PRINTF("read(fd = %d) %s\n", conn->fd, strerror(errno));
        goto exit;
    }
    len = r;

    NONE_PRINTF("new %u msg from %d: %.*s\n", len, conn->fd, len, (char *)buffer);

    r = parse_addr_in_http(&addr, buffer, len);
    if (r < 0) {
        ERROR_PRINTF("parse addr fail!\n");
        goto exit;
    }

    conn->peerfd = tcp_socket_create(ctx, 0, addr.host, addr.port);
    if (conn->peerfd < 0) {
        ERROR_PRINTF("tcp_socket_create fail!\n");
        goto exit;
    }

    if (strncmp("CONNECT", buffer, 7) == 0) {
        char *connect_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        r = netloop_write(ctx, conn->fd, connect_msg, strlen(connect_msg));
        if (r <= 0)
            goto exit2;
    } else {
        r = netloop_write(ctx, conn->peerfd, buffer, len);
        if (r <= 0)
            goto exit2;
    }

    conn->ctx = ctx;
    conn->run = 2;
    struct netloop_obj_t *task;
    task = netloop_run_task(conn->nm, &(struct netloop_task_t){
        .task_cb = transfer_task,
        .ud = conn,
        .name = addr.host,
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task() error\n");
        goto exit2;
    }
    transfer_task(ctx, conn);
    return;
exit2:
    close(conn->peerfd);
exit:
    close(conn->fd);
    conn->run = 0;
    free(conn);
    DEBUG_PRINTF("task exit!\n");
}


struct tcp_listen_t {
    char *host;
    uint16_t port;
    struct netloop_main_t *nm;
};

void tcp_listen_task(struct netloop_obj_t *ctx, void *ud)
{
    struct tcp_listen_t *tl = (struct tcp_listen_t *)ud;
    struct netloop_obj_t *task;
    int sockfd;
    sockfd = tcp_socket_create(ctx, 1, tl->host, tl->port);
    if (sockfd < 0) {
        return;
    }

    while (1) {
        struct tcp_connect_t *conn = malloc(sizeof(struct tcp_connect_t));
        if (!conn) {
            break;
        }
        memset(conn, 0, sizeof(struct tcp_connect_t));

        conn->fd = netloop_accept(ctx, sockfd, NULL, NULL);
        if (conn->fd < 0) {
            ERROR_PRINTF("accept(fd = %d) %s\n", sockfd, strerror(errno));
            break;
        }

        conn->nm = tl->nm;
        task = netloop_run_task(tl->nm, &(struct netloop_task_t){
            .task_cb = connect_task, .ud = conn, .name = "connect_task",
        });
        if (!task) {
            ERROR_PRINTF("netloop_run_task() error\n");
            close(conn->fd);
            break;
        }
    }
    close(sockfd);
    DEBUG_PRINTF("task exit!\n");
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


void stdin_task(struct netloop_obj_t *ctx, void *ud)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)ud;
    int in = STDIN_FILENO;
    char ch;

    enable_raw_mode();
    atexit(disable_raw_mode);
    while (1) {
        int r = netloop_read(ctx, in, &ch, 1);
        if (r < 0) {
            ERROR_PRINTF("read(fd = %d) %s\n", in, strerror(errno));
            return;
        }

        if ('q' == ch) {
            DEBUG_PRINTF("exit\n");
            exit(0);
        } else if ('d' == ch) {
            netloop_dump_task(nm);
        } else {
            DEBUG_PRINTF("press 'q' to exit\n");
        }
    }
}


int main(int argc, char **argv)
{
    int r;
    struct netloop_obj_t *task;

    DEBUG_PRINTF("%s build: %s, %s\n", argv[0], __DATE__, __TIME__);
    signal(SIGPIPE, SIG_IGN);

    struct netloop_main_t *nm = netloop_init();
    if (!nm) {
        return -1;
    }

    task = netloop_run_task(nm, &(struct netloop_task_t){
        .name = "tcp_listen_task",
        .task_cb = tcp_listen_task,
        .ud = &(struct tcp_listen_t){
            .nm = nm,
            .host = EXAMPLE_ADDR,
            .port = EXAMPLE_PORT,
        },
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task() error\n");
        return -1;
    }

    task = netloop_run_task(nm, &(struct netloop_task_t){
        .name = "tcp_listen_task",
        .task_cb = tcp_listen_task,
        .ud = &(struct tcp_listen_t){
            .nm = nm,
            .host = EXAMPLE_ADDR,
            .port = EXAMPLE_PORT + 1,
        },
    });
    if (!task) {
        ERROR_PRINTF("netloop_run_task() error\n");
        return -1;
    }

    task = netloop_run_task(nm, &(struct netloop_task_t){
        .task_cb = stdin_task, .ud = nm, .name = "stdin_task",
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
