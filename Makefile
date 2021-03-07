# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config

TARGET = netloop_example

OBJS += \
src/netloop.o \
src/loop.o \
example/example.o

C_INCLUDES += -I .
C_INCLUDES += -I src


CFLAGS += -O0 -Wall -std=gnu99 -g $(C_DEFS)
CFLAGS += -DNO_GLIB

LDFLAGS += -lpthread
#LDFLAGS += -rdynamic


quiet_CC  =      @echo "  CC      $@"; $(CC)
quiet_LD  =      @echo "  LD      $@"; $(LD)
quiet_INSTALL  = @echo "  INSTALL $?"; $(INSTALL)
quiet_MAKE     = @+$(MAKE)

V = 0
ifeq ($(V), 0)
	quiet = quiet_
else
	quiet =
endif

STATIC = 0
ifeq ($(STATIC), 1)
	LDFLAGS += -static
endif
CFLAGS += $(C_INCLUDES)


all: $(TARGET)

$(TARGET): $(OBJS)
	$($(quiet)LD) -o $(TARGET)   $(OBJS) $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<


.PHONY: clean
clean:
	$(RM) -f $(TARGET) $(OBJS)

install: $(TARGET)
	$($(quiet)INSTALL) -D $< /usr/local/bin/$<

uninstall:
	$(RM) -f /usr/local/bin/$(TARGET)
