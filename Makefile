# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET += example/proxy_example
TARGET += example/tftpd_example

ifeq ($(LIBUCONTEXT), 1)
SUBMODS += $(shell pwd)/libucontext
endif
SUBMODS += $(shell pwd)/src
SUBMODS += $(shell pwd)/utils

LIBSUBMODS += $(shell pwd)/utils/lib.a
LIBSUBMODS += $(shell pwd)/src/lib.a

C_INCLUDES += -I $(shell pwd)/src
C_INCLUDES += -I $(shell pwd)/utils

CFLAGS += -O3 -Wall -g $(C_DEFS)
CFLAGS += -D_GNU_SOURCE

ifeq ($(LIBUCONTEXT), 1)
LIBSUBMODS += $(shell pwd)/libucontext/libucontext.a
C_INCLUDES += -I $(shell pwd)/libucontext/include
CFLAGS += -DLIBUCONTEXT
endif
ifeq ($(LIBCARES), 1)
C_INCLUDES += -I $(shell pwd)/cares/include
CFLAGS += -DLIBCARES
LDFLAGS += -lcares_static
LDFLAGS += -L $(shell pwd)/cares/lib
endif

ifeq ($(SSL), 1)
TARGET += example/sslproxy_example
C_INCLUDES += -I $(shell pwd)/libopenssl/include
CFLAGS += -DNETSSL
LDFLAGS += -lssl -lcrypto
LDFLAGS += -L $(shell pwd)/libopenssl/lib
endif

LDFLAGS += -lpthread -lrt -ldl

quiet_CC  =      @echo "  CC      $@"; $(CC)
quiet_LD  =      @echo "  LD      $@"; $(LD)
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
export CROSS_COMPILE CFLAGS V CC AR LD SSL ARCH

OBJSTARGET = $(patsubst %_example, %.o, $(TARGET))
CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET)
	@echo "build success!"

%_example: %.o $(LIBSUBMODS)
	$($(quiet)LD) -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

$(LIBSUBMODS): $(SUBMODS)

.PHONY: $(SUBMODS)
$(SUBMODS):
	+$($(quiet)MAKE) -C $@

.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET) 
	-$(RM) -f $(OBJSTARGET)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	+$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean

install: $(TARGET)
	$($(quiet)INSTALL) -D $< /usr/local/bin/$<

uninstall:
	-$(RM) -f /usr/local/bin/$(TARGET)
