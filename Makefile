SRCS=unpacker.c
OBJS=$(patsubst %.c,%.o,$(SRCS))
BIN=$(patsubst %.c,%,$(SRCS))


CFLAGS=-Wall -Wextra -ansi -pedantic -ggdb3
LDFLAGS=

.PHONY: all
all: $(BIN)

$(BIN): $(OBJS) Makefile
	gcc -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c Makefile
	gcc -o $@ -c $< $(CFLAGS)


.PHONY: clean
clean:
	rm -f $(OBJS)

.PHONY: mrproper
mrproper: clean
	rm -f $(BIN)
