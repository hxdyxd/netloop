#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "netloop.h"

#include "log.h"
#define NONE_PRINTF    LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};


static void netloop_prepare(void *opaque);
static void netloop_poll(void *opaque);
static int debug_obj_cnt = 0;

void netloop_dump_task(struct netloop_main_t *nm)
{
    struct netloop_obj_t *ctx, *tmp;
    uint32_t cur = time(NULL);
    int item = 0;

    printf("------------------total_obj: %u------------------\n", debug_obj_cnt);
    list_for_each_entry_safe(ctx, tmp, &nm->head.list, list) {
        printf("co: %d, fd: %d, ", ctx->co,  ctx->fd);
        printf("events: %c%c, ", (ctx->events & POLLIN) ? 'I' : ' ', (ctx->events & POLLOUT) ? 'O' : ' ' );
        printf("t: %u, ", cur - ctx->time);
        if (ctx->name) {
            printf("name: %s", ctx->name);
        }
        printf("\n");
        item++;
    }
    printf("------------------total_obj: %u/%u------------------\n", item, debug_obj_cnt);
}

struct netloop_main_t *netloop_init(void)
{
    int r;
    struct netloop_main_t *nm;
    nm = malloc(sizeof(struct netloop_main_t));
    if (!nm) {
        return NULL;
    }
    memset(nm, 0, sizeof(struct netloop_main_t));
    INIT_LIST_HEAD(&nm->head.list);
    nm->head.fd = -1;
    INIT_LIST_HEAD(&nm->ready.list);
    nm->ready.fd = -1;

    nm->s = coroutine_open();
    if (!nm->s) {
        ERROR_PRINTF("coroutine_open() %s\n", strerror(errno));
        free(nm);
        return NULL;
    }

    r = loop_init(&nm->loop);
    if (r < 0) {
        ERROR_PRINTF("loop_init() %s\n", strerror(errno));
        coroutine_close(nm->s);
        free(nm);
        return NULL;
    }

    return nm;
}

int netloop_start(struct netloop_main_t *nm)
{
    struct loopcb_t loop_cb;
    ASSERT(nm);

    loop_cb.poll = netloop_poll;
    loop_cb.prepare = netloop_prepare;
    loop_cb.timer = NULL;
    loop_cb.opaque = nm;
    loop_register(&nm->loop, loop_cb);
    return loop_start(&nm->loop);
}


static struct netloop_obj_t *netloop_obj_new(void)
{
    struct netloop_obj_t *conn;
    conn = malloc(sizeof(struct netloop_obj_t));
    if (!conn) {
        ERROR_PRINTF("malloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(conn, 0, sizeof(struct netloop_obj_t));
    conn->magic = NETLOOP_MAGIC;
    debug_obj_cnt++;
    return conn;
}

static void netloop_obj_free(struct netloop_obj_t *conn)
{
    ASSERT(NETLOOP_MAGIC == conn->magic);
    conn->fd = -1;
    conn->magic = 0;
    free(conn);
    debug_obj_cnt--;
    NONE_PRINTF("conn: %d\n", debug_obj_cnt);
}

static void netloop_process(struct schedule *s, void *ud)
{
    struct netloop_obj_t *ctx = (struct netloop_obj_t *)ud;
    if (ctx->task_cb) {
        ctx->task_cb(ctx, ctx->data);
    }
    if (ctx->name) {
        free(ctx->name);
        ctx->name = NULL;
    }
    netloop_obj_free(ctx);
}

static void netloop_prepare(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &nm->ready.list, ready) {
        list_del(&ctx->ready);
        ctx->co = coroutine_new(ctx->s, netloop_process, ctx);
        coroutine_resume(ctx->s, ctx->co);
    }

    list_for_each_entry_safe(ctx, tmp, &nm->head.list, list) {
        ASSERT(ctx->fd >= 0);
        ctx->idx = loop_add_poll(&nm->loop, ctx->fd, ctx->events);
    }
}

static void netloop_poll(void *opaque)
{
    struct netloop_main_t *nm = (struct netloop_main_t *)opaque;
    struct netloop_obj_t *ctx, *tmp;

    list_for_each_entry_safe(ctx, tmp, &nm->head.list, list) {
        ctx->revents = loop_get_revents(&nm->loop, ctx->idx);
        if ((ctx->revents & POLLIN) || (ctx->revents & POLLOUT)) {
            coroutine_resume(ctx->s, ctx->co);
        }
    }
}


struct netloop_obj_t *netloop_run_task(struct netloop_main_t *nm, struct netloop_task_t *task)
{
    ASSERT(nm && task);
    struct netloop_obj_t *ctx;

    ctx = netloop_obj_new();
    if (!ctx) {
        return NULL;
    }
    ctx->fd = -1;
    ctx->head = &nm->head;
    ctx->s = nm->s;
    ctx->name = strdup(task->name);
    ctx->data = task->ud;
    ctx->task_cb = task->task_cb;
    ctx->time = time(NULL);
    list_add_tail(&ctx->ready, &nm->ready.list);
    return ctx;
}


int netloop_accept(struct netloop_obj_t *ctx, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    while (1) {
        int r = accept(sockfd, addr, addrlen);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = sockfd;
            ctx->events = POLLIN;
            list_add(&ctx->list, &ctx->head->list);
            coroutine_yield(ctx->s);
            list_del(&ctx->list);
        } else {
            return r;
        }
    }
}

int netloop_connect(struct netloop_obj_t *ctx, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int r;
    int val;
    socklen_t optlen = sizeof(int);

    r = connect(sockfd, addr, addrlen);
    if (r < 0 && EINPROGRESS == errno) {
        ctx->fd = sockfd;
        ctx->events = POLLOUT;
        list_add(&ctx->list, &ctx->head->list);
        coroutine_yield(ctx->s);
        list_del(&ctx->list);
    } else {
        return r;
    }

    r = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &val, &optlen);
    if (r < 0) {
        ERROR_PRINTF("getsockopt(fd = %d) %s\n", sockfd, strerror(errno));
        return r;
    }
    if (val < 0) {
        ERROR_PRINTF("connect(fd = %d) %s\n", sockfd, strerror(val));
        return val;
    }
    return 0;
}

ssize_t netloop_read(struct netloop_obj_t *ctx, int fd, void *buf, size_t count)
{
    while (1) {
        int r = read(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = fd;
            ctx->events = POLLIN;
            list_add(&ctx->list, &ctx->head->list);
            coroutine_yield(ctx->s);
            list_del(&ctx->list);
        } else {
            return r;
        }
    }
}

ssize_t netloop_write(struct netloop_obj_t *ctx, int fd, void *buf, size_t count)
{
    while (1) {
        int r = write(fd, buf, count);
        if (r < 0 && EAGAIN == errno) {
            ctx->fd = fd;
            ctx->events = POLLOUT;
            list_add(&ctx->list, &ctx->head->list);
            coroutine_yield(ctx->s);
            list_del(&ctx->list);
        } else {
            return r;
        }
    }
}
