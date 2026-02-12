# Simple Makefile for building BPF .c -> .o and C++ .cpp -> binaries

CLANG   := clang
CLANGXX := clang++

CFLAGS_BPF := -O2 -g -target bpf
LDLIBS_CPP := -lbpf -lxdp

C_SRCS   := $(wildcard *.c)
CPP_SRCS := $(wildcard *.cpp)

BPF_OBJS := $(C_SRCS:.c=.o)
CPP_BINS := $(CPP_SRCS:.cpp=)

.PHONY: all bpf cpp clean

all: bpf cpp

bpf: $(BPF_OBJS)

cpp: $(CPP_BINS)

# Build BPF object files from C
%.o: %.c
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# Build C++ executables
%: %.cpp
	$(CLANGXX) $< $(LDLIBS_CPP) -o $@

clean:
	rm -f $(BPF_OBJS) $(CPP_BINS)

