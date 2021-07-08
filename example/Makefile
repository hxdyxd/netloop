# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET += tftpd_ex
TARGET += proxy_ex

SUBMODS += $(shell pwd)/utils

OBJS += tftpd.o

C_INCLUDES += -I $(shell pwd)/utils

CFLAGS += -O3 -Wall -g $(C_DEFS)
CFLAGS += -D_GNU_SOURCE
CFLAGS += -I.
CFLAGS += -DUSE_PRCTL_SET_THREAD_NAME

ifeq ($(SSL), 1)
TARGET += sslproxy_ex
C_INCLUDES += -I $(shell pwd)/libopenssl/include
CFLAGS += -DNETSSL
LDFLAGS += -lssl -lcrypto
LDFLAGS += -L $(shell pwd)/libopenssl/lib
endif

LDFLAGS += -lpthread -lrt


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
export CROSS_COMPILE CFLAGS V CC AR LD SSL ARCH

OBJSTARGET = $(patsubst %_ex, %.o, $(TARGET))
LIBSUBMODS = $(patsubst %, %/lib.a, $(SUBMODS))
CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET)

%_ex: %.o $(SUBMODS)
	$($(quiet)LD) -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

.PHONY: $(SUBMODS)
$(SUBMODS):
	+$($(quiet)MAKE) -C $@

.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET) $(OBJSTARGET)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	+$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean
