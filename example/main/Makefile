# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET ?= lib.a

OBJS += main.o

CFLAGS += -I.

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
	-$(RM) -f $(TARGET)
	-$(RM) -f $(OBJS)
