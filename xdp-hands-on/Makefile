# Simple Makefile for building BPF .c -> .o and C++ .cpp -> binaries in bin/

CLANG   := clang
CLANGXX := clang++

CFLAGS_BPF := -O2 -g -target bpf
LDLIBS_CPP := -lbpf -lxdp

BIN_DIR := bin

C_SRCS   := $(wildcard *.c)
CPP_SRCS := $(wildcard *.cpp)

BPF_OBJS := $(C_SRCS:.c=.o)

# Put C++ executables under bin/
CPP_BINS := $(patsubst %.cpp,$(BIN_DIR)/%,$(CPP_SRCS))

.PHONY: all bpf cpp clean

all: bpf cpp

bpf: $(BPF_OBJS)

cpp: $(CPP_BINS)

# Ensure bin/ exists
$(BIN_DIR):
	mkdir -p $@

# Build BPF object files from C
%.o: %.c
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# Build C++ executables into bin/
$(BIN_DIR)/%: %.cpp | $(BIN_DIR)
	$(CLANGXX) $< $(LDLIBS_CPP) -o $@

clean:
	rm -f $(BPF_OBJS) $(CPP_BINS)
	rmdir $(BIN_DIR) 2>/dev/null || true
