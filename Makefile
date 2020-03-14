# Assumptions:
# - kernel headers for approximately the same build as is running are in place
# - LLVM/clang/bcc are available

COMMONOBJS = bpf.o

TESTPROG= bpf_mapper_sync
TESTOBJS = $(TESTPROG).o

PROGS= $(TESTPROG)

OBJS= $(COMMONOBJS) $(TESTOBJS)

linuxhdrs ?= /usr/src/linux-headers-5.3.0-40

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/arch/x86/include/generated/uapi \
                -I$(linuxhdrs)/include/generated/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include

prefix ?= /usr/local

LDLIBS = -lelf

all: $(TESTPROG)
	
debug: all
	
.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)

%.o: %.c
	$(CC) $(DEBUG_FLAGS) -g -Wno-unused-variable -I../include $(LINUXINCLUDE) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJS)
	$(CC) -g -o $@ $(@).o $(COMMONOBJS) $(CFLAGS) $(LDLIBS)
