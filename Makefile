SRCS=loader.c runtime.c
HDRS=runtime.h
OBJS=$(patsubst %.c,%.o,$(SRCS))
BIN=loader


CFLAGS=-Wall -Wextra -ansi -pedantic -DVERBOSE=1 -ggdb3
LDFLAGS=

.PHONY: all
all: $(BIN)

$(BIN): $(OBJS) Makefile
	gcc -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c $(HDRS) Makefile
	gcc -o $@ -c $< $(CFLAGS)


.PHONY: clean
clean:
	rm -f $(OBJS)

.PHONY: mrproper
mrproper: clean
	rm -f $(BIN)
