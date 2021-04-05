# Makefile of netloop
# Copyright (C) 2019-2020  hxdyxd <hxdyxd@gmail.com>
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CC)
INSTALL = install
RM = rm
PKG_CONFIG ?= pkg-config


TARGET += example/proxy_example
TARGET += example/sslproxy_example


SUBMODS += $(shell pwd)/utils
SUBMODS += $(shell pwd)/src

C_INCLUDES += -I $(shell pwd)/cares/include
C_INCLUDES += -I $(shell pwd)/libopenssl/include
C_INCLUDES += -I /usr/include
C_INCLUDES += -I $(shell pwd)/utils
C_INCLUDES += -I $(shell pwd)/src

CFLAGS += -O3 -Wall -g $(C_DEFS)
CFLAGS += -D_GNU_SOURCE

LDFLAGS += -lcares_static -lrt
LDFLAGS += -lssl -lcrypto -ldl
LDFLAGS += -lpthread
LDFLAGS += -L $(shell pwd)/cares/lib
LDFLAGS += -L $(shell pwd)/libopenssl/lib


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
export CROSS_COMPILE CFLAGS V

OBJSTARGET = $(patsubst %_example, %.o, $(TARGET))
LIBSUBMODS = $(patsubst %, %/lib.a, $(SUBMODS))
CLEANSUBMODS = $(patsubst %, %_clean, $(SUBMODS))

all: $(TARGET)
	@echo "build success!"

#$(TARGET): $(OBJS) 
#	$($(quiet)LD) -o $(TARGET)   $(OBJS) $(LDFLAGS)

%_example: %.o $(SUBMODS)
	$($(quiet)LD) -o $@ $< $(LIBSUBMODS) $(LDFLAGS)

%.o: %.c
	$($(quiet)CC) $(CFLAGS) -o $@ -c $<

.PHONY: $(SUBMODS)
$(SUBMODS):
	$($(quiet)MAKE) -C $@


.PHONY: clean
clean: $(CLEANSUBMODS)
	-$(RM) -f $(TARGET) $(OBJSTARGET)

.PHONY: $(CLEANSUBMODS)
$(CLEANSUBMODS):
	$($(quiet)MAKE) -C $(patsubst %_clean, %, $@) clean

install: $(TARGET)
	$($(quiet)INSTALL) -D $< /usr/local/bin/$<

uninstall:
	-$(RM) -f /usr/local/bin/$(TARGET)
