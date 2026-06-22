# Builds the C reference implementation (parallel_pipe_suw) used only for the
# interop test. It links the same XKCP static library the Rust crate builds.

CC      ?= cc
CFLAGS  ?= -O2 -fomit-frame-pointer -Wall
LDLIBS  ?= -lpthread

# Repo root is three levels up from tests/interop/cref.
ROOT        := ../../..
XKCP_DIR    ?= $(ROOT)/third_party/xkcp
XKCP_TARGET ?= x86-64
XKCP_LIBDIR := $(XKCP_DIR)/bin/$(XKCP_TARGET)
XKCP_LIB    := $(XKCP_LIBDIR)/libXKCP.a
XKCP_HDRS   := $(XKCP_LIBDIR)/libXKCP.a.headers

BIN  := cref
SRCS := ShakeUpWrap.c suw.c

all: $(BIN)

$(XKCP_LIB):
	$(MAKE) -C $(XKCP_DIR) $(XKCP_TARGET)/libXKCP.a

$(BIN): $(SRCS) $(XKCP_LIB)
	$(CC) $(CFLAGS) -I . -I $(XKCP_HDRS) $(SRCS) $(XKCP_LIB) $(LDLIBS) -o $@

clean:
	rm -f $(BIN)

.PHONY: all clean
