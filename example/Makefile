# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET += command_ex
TARGET += tftpd_ex
TARGET += proxy_ex

LIBEX += libcommand.so
LIBEX += libtftpd.so
LIBEX += libproxy.so

SUBMODS += $(shell pwd)/../src
SUBMODS += $(shell pwd)/utils
SUBMODS += $(shell pwd)/main

LIBSUBMODS += $(shell pwd)/utils/lib.a

LIBSUBMODS_MAIN := $(LIBSUBMODS)
LIBSUBMODS_MAIN += $(shell pwd)/../src/libnetloop.a
LIBSUBMODS_MAIN += $(shell pwd)/main/lib.a

OBJS += tftpd.o

C_INCLUDES += -I $(shell pwd)/utils

CFLAGS += -fPIC -O3 -Wall -g $(C_DEFS)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -I.
CFLAGS += -DUSE_PRCTL_SET_THREAD_NAME

ifeq ($(SSL), 1)
TARGET += sslproxy_ex
LIBEX += libsslproxy.so
C_INCLUDES += -I $(shell pwd)/libopenssl/include
CFLAGS += -DNETSSL
LDFLAGS += -lssl -lcrypto
LDFLAGS += -L $(shell pwd)/libopenssl/lib
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

STATIC = 0
ifeq ($(STATIC), 1)
	LDFLAGS += -static
endif
CFLAGS += $(C_INCLUDES)
export CROSS_COMPILE CFLAGS V CC AR LD SSL LIBCARES ARCH

OBJSTARGET = $(patsubst %_ex, %.o, $(TARGET))
CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET) $(LIBEX)

%_ex: %.o $(LIBSUBMODS_MAIN)
	$($(quiet)LD) -o $@ $< $(LIBSUBMODS_MAIN) $(LDFLAGS) -Wl,-export-dynamic

lib%.so: %.o $(LIBSUBMODS)
	-$($(quiet)CC) -fPIC -shared -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

$(LIBSUBMODS): $(SUBMODS)
$(LIBSUBMODS_MAIN): $(SUBMODS)

.PHONY: $(SUBMODS)
$(SUBMODS):
	+$($(quiet)MAKE) -C $@

.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET)
	-$(RM) -f $(OBJSTARGET)
	-$(RM) -f $(LIBEX)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	+$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean
