# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET ?= libnetloop.so
TARGET_STATIC ?= libnetloop.a

ifeq ($(LIBUCONTEXT), 1)
SUBMODS += $(shell pwd)/../netloop/libucontext
endif
SUBMODS += $(shell pwd)/../netloop/src

LIBSUBMODS += $(shell pwd)/../netloop/src/lib.a

OBJS += wrapper.o

C_INCLUDES += -I $(shell pwd)/../netloop/src

CFLAGS :=
CFLAGS += -fPIC
CFLAGS += -O3 -Wall -g $(C_DEFS)
CFLAGS += -DUSE_PRCTL_SET_THREAD_NAME
CFLAGS += -D_GNU_SOURCE


ifeq ($(LIBUCONTEXT), 1)
LIBSUBMODS += $(shell pwd)/../netloop/libucontext/libucontext.a
C_INCLUDES += -I $(shell pwd)/../netloop/libucontext/include
CFLAGS += -DLIBUCONTEXT
endif

ifeq ($(LIBCARES), 1)
LDFLAGS += -lcares
CFLAGS += -DLIBCARES
endif

LDFLAGS += -lpthread -lrt -ldl


quiet_CC  =      @echo "  CC      $@"; $(CC)
quiet_LD  =      @echo "  LD      $@"; $(LD)
quiet_AR  =      @echo "  AR      $@"; $(AR)
quiet_INSTALL  = @echo "  INSTALL $?"; $(INSTALL)
quiet_MAKE     = @echo "  MAKE    $@"; $(MAKE)

V = 0
ifeq ($(V), 0)
	quiet = quiet_
else
	quiet =
endif

CFLAGS += $(C_INCLUDES)
export CROSS_COMPILE CFLAGS V CC AR LD ARCH

CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET) $(TARGET_STATIC)

.PHONY: $(TARGET)
$(TARGET): $(OBJS) $(LIBSUBMODS)
	-$($(quiet)CC) -fPIC -shared -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

.PHONY: $(TARGET_STATIC)
$(TARGET_STATIC): $(OBJS) $(LIBSUBMODS)
	$($(quiet)AR) -rcsT $@ $< $(LIBSUBMODS)

%.o: %.c 
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

$(LIBSUBMODS): $(SUBMODS)

.PHONY: $(SUBMODS)
$(SUBMODS):
	+$($(quiet)MAKE) -C $@

.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET)
	-$(RM) -f $(TARGET_STATIC)
	-$(RM) -f $(OBJS)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	+$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean
