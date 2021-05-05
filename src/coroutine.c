#include "coroutine.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <libucontext/libucontext.h>

#include "log.h"
#define NONE_PRINTF   LOG_NONE
#define DEBUG_PRINTF  LOG_DEBUG
#define WARN_PRINTF   LOG_WARN
#define ERROR_PRINTF  LOG_ERROR
#define ASSERT(if_true)     while(!(if_true)) {  \
    ERROR_PRINTF("assert(%s) failed at %s, %s:%d\n",  \
     #if_true, __FILE__, __FUNCTION__, __LINE__); exit(-1);};

#define getcontext     libucontext_getcontext
#define makecontext    libucontext_makecontext
#define setcontext     libucontext_setcontext
#define swapcontext    libucontext_swapcontext
#define ucontext_t     libucontext_ucontext_t

#define STACK_SIZE            (1024*32)
#define STACK_PROTECT_SIZE    (1024*1)
#if STACK_SIZE <= STACK_PROTECT_SIZE
#error The STACK_SIZE is less then STACK_PROTECT_SIZE!
#endif

#define DEFAULT_COROUTINE  16

struct coroutine;

struct schedule {
    ucontext_t main;
    int nco;
    int cap;
    int running;
    struct coroutine **co;
};

struct coroutine {
    coroutine_func func;
    void *ud;
    ucontext_t ctx;
    struct schedule *sch;
    int size;
    int status;
    char *stack;
};

static struct coroutine *_co_new(struct schedule *S , coroutine_func func, void *ud)
{
    struct coroutine * co = malloc(sizeof(*co));
    ASSERT(co);
    co->func = func;
    co->ud = ud;
    co->sch = S;
    co->size = STACK_SIZE;
    co->status = COROUTINE_READY;
    co->stack = NULL;
    return co;
}

static void _co_delete(struct coroutine *co)
{
    ASSERT(co && co->stack);
    free(co->stack);
    co->stack = NULL;
    free(co);
}

struct schedule *coroutine_open(void)
{
    struct schedule *S = malloc(sizeof(*S));
    S->nco = 0;
    S->cap = DEFAULT_COROUTINE;
    S->running = -1;
    S->co = malloc(sizeof(struct coroutine *) * S->cap);
    memset(S->co, 0, sizeof(struct coroutine *) * S->cap);
    return S;
}

void coroutine_close(struct schedule *S)
{
    int i;
    for (i=0;i<S->cap;i++) {
        struct coroutine * co = S->co[i];
        if (co) {
            _co_delete(co);
        }
    }
    free(S->co);
    S->co = NULL;
    free(S);
}

int coroutine_new(struct schedule *S, coroutine_func func, void *ud)
{
    struct coroutine *co = _co_new(S, func , ud);
    if (S->nco >= S->cap) {
        int id = S->cap;
        S->co = realloc(S->co, S->cap * 2 * sizeof(struct coroutine *));
        memset(S->co + S->cap , 0 , sizeof(struct coroutine *) * S->cap);
        S->co[S->cap] = co;
        S->cap *= 2;
        ++S->nco;
        return id;
    } else {
        int i;
        for (i = 0; i < S->cap; i++) {
            int id = (i+S->nco) % S->cap;
            if (S->co[id] == NULL) {
                S->co[id] = co;
                ++S->nco;
                return id;
            }
        }
    }
    ASSERT(0);
    return -1;
}

static void mainfunc(struct schedule *S)
{
    int id = S->running;
    struct coroutine *C = S->co[id];
    C->func(S, C->ud);
    C->status = COROUTINE_DEAD;
    S->co[id] = NULL;
    --S->nco;
    S->running = -1;
}

static void stack_detect(const char *stack)
{
    for (int i = 0; i < STACK_PROTECT_SIZE; i++) {
        if(stack[i] != 0x55) {
            WARN_PRINTF("stack overflow at %d %x\n", i, stack[i]);
            break;
        }
    }
}

void coroutine_resume(struct schedule *S, int id)
{
    ASSERT(S->running == -1);
    ASSERT(id >=0 && id < S->cap);
    struct coroutine *C = S->co[id];
    if (C == NULL)
        return;
    int status = C->status;
    switch(status) {
    case COROUTINE_READY:
        C->stack = malloc(C->size);
        ASSERT(C->stack);
        memset(C->stack, 0x55, STACK_PROTECT_SIZE);
        getcontext(&C->ctx);
        C->ctx.uc_stack.ss_sp = C->stack;
        C->ctx.uc_stack.ss_size = C->size;
        C->ctx.uc_link = &S->main;
        S->running = id;
        C->status = COROUTINE_RUNNING;
        makecontext(&C->ctx, (void (*)(void))mainfunc, 1, S);
        swapcontext(&S->main, &C->ctx);
        break;
    case COROUTINE_SUSPEND:
        S->running = id;
        C->status = COROUTINE_RUNNING;
        swapcontext(&S->main, &C->ctx);
        break;
    default:
        ASSERT(0);
    }
    if (COROUTINE_DEAD == C->status) {
        stack_detect(C->stack);
        _co_delete(C);
    }
}

void coroutine_yield(struct schedule * S)
{
    int id = S->running;
    ASSERT(id >= 0);
    struct coroutine * C = S->co[id];
    stack_detect(C->stack);
    C->status = COROUTINE_SUSPEND;
    S->running = -1;
    swapcontext(&C->ctx , &S->main);
}

int coroutine_status(struct schedule * S, int id)
{
    ASSERT(id>=0 && id < S->cap);
    if (S->co[id] == NULL) {
        return COROUTINE_DEAD;
    }
    return S->co[id]->status;
}

int coroutine_running(struct schedule * S)
{
    return S->running;
}

