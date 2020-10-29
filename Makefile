HDRS=runtime.h

LOADER_SRCS=loader.c runtime.c
LOADER_OBJS=$(patsubst %.c,%.o,$(LOADER_SRCS))
LOADER_BIN=loader

ELFPADDER_SRCS=elfpadder.c runtime.c
ELFPADDER_OBJS=$(patsubst %.c,%.o,$(ELFPADDER_SRCS))
ELFPADDER_BIN=elfpadder

OBJS=$(LOADER_OBJS) $(ELFPADDER_OBJS)
BINS=$(LOADER_BIN) $(ELFPADDER_BIN)


CFLAGS=-Wall -Wextra -ansi -pedantic -DVERBOSE=1 -ggdb3
LDFLAGS=

.PHONY: all
all: $(BINS)

$(LOADER_BIN): $(LOADER_OBJS) Makefile
	gcc -o $@ $(LOADER_OBJS) $(LDFLAGS)

$(ELFPADDER_BIN): $(ELFPADDER_OBJS) Makefile
	gcc -o $@ $(ELFPADDER_OBJS) $(LDFLAGS)

%.o: %.c $(HDRS) Makefile
	gcc -o $@ -c $< $(CFLAGS)


.PHONY: clean
clean:
	rm -f $(OBJS)

.PHONY: mrproper
mrproper: clean
	rm -f $(BINS)
