HDRS=runtime.h

LOADER_SRCS=loader.c runtime.c
LOADER_OBJS=$(patsubst %.c,%.o,$(LOADER_SRCS))
LOADER_BIN=loader

OBJS=$(LOADER_OBJS)
BINS=$(LOADER_BIN)


CFLAGS=-Wall -Wextra -ansi -pedantic -DVERBOSE=1 -ggdb3
LDFLAGS=

.PHONY: all
all: $(BINS)

$(LOADER_BIN): $(LOADER_OBJS) Makefile
	gcc -o $@ $(LOADER_OBJS) $(LDFLAGS)


%.o: %.c $(HDRS) Makefile
	gcc -o $@ -c $< $(CFLAGS)


.PHONY: clean
clean:
	rm -f $(OBJS)

.PHONY: mrproper
mrproper: clean
	rm -f $(BINS)
