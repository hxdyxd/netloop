# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET += example/server_example
TARGET += example/proxy_example

OBJS += \
src/netloop.o \
src/loop.o

EXAMPLE_OBJ += example/*.o


C_INCLUDES += -I .
C_INCLUDES += -I src
C_INCLUDES += -I cares/include

CFLAGS += -O3 -Wall -std=gnu99 -g $(C_DEFS)
CFLAGS += -DNO_GLIB

LDFLAGS += -lpthread -lcares_static -lrt
LDFLAGS += -L cares/lib
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

#$(TARGET): $(OBJS) 
#	$($(quiet)LD) -o $(TARGET)   $(OBJS) $(LDFLAGS)

%_example: %.o $(OBJS)
	$($(quiet)LD) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<


.PHONY: clean
clean:
	-$(RM) -f $(TARGET) $(OBJS) $(EXAMPLE_OBJ)

install: $(TARGET)
	$($(quiet)INSTALL) -D $< /usr/local/bin/$<

uninstall:
	-$(RM) -f /usr/local/bin/$(TARGET)
