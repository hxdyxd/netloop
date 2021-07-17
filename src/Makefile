# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET ?= lib.a

OBJS += netloop.o
OBJS += netdns_cares.o
OBJS += coroutine.o
OBJS += loop.o

ifeq ($(SSL), 1)
OBJS += netssl.o
endif

CFLAGS += -I.
CFLAGS += -DUSE_PRCTL_SET_THREAD_NAME


quiet_CC  =      @echo "  CC      $@"; $(CC)
quiet_LD  =      @echo "  LD      $@"; $(LD)
quiet_AR  =      @echo "  AR      $@"; $(AR)
quiet_INSTALL  = @echo "  INSTALL $?"; $(INSTALL)
quiet_MAKE     = @+$(MAKE)

V = 0
ifeq ($(V), 0)
	quiet = quiet_
else
	quiet =
endif

all: $(TARGET)

.PHONY: $(TARGET)
$(TARGET): $(OBJS)
	$($(quiet)AR) -rcs $@ $^

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	-$(RM) -f $(TARGET) $(OBJS)
