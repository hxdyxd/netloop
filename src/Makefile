# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET ?= libnetloop.so

SUBMODS += $(shell pwd)/../netloop/libucontext
SUBMODS += $(shell pwd)/../netloop/src

LIBSUBMODS += $(shell pwd)/../netloop/src/lib.a
LIBSUBMODS += $(shell pwd)/../netloop/libucontext/libucontext.a

OBJS += wrapper.o

C_INCLUDES += -I $(shell pwd)/../netloop/libucontext/include
C_INCLUDES += -I $(shell pwd)/../netloop/src

CFLAGS += -fPIC
CFLAGS += -I.
CFLAGS += -DUSE_PRCTL_SET_THREAD_NAME

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
export CROSS_COMPILE CFLAGS V CC AR LD SSL ARCH

CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET)

.PHONY: $(TARGET)
$(TARGET): $(OBJS) $(LIBSUBMODS)
	$($(quiet)CC) -fPIC -shared -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

%.o: %.c 
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

$(LIBSUBMODS): $(SUBMODS)

.PHONY: $(SUBMODS)
$(SUBMODS):
	+$($(quiet)MAKE) -C $@

.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET) $(OBJS)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	+$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean
