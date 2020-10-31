HDRS=runtime.h

LOADER_SRCS=loader.c runtime.c
LOADER_OBJS=$(patsubst %.c,%.o,$(LOADER_SRCS))
LOADER_BIN=loader

ELFPADDER_SRCS=elfpadder.c runtime.c
ELFPADDER_OBJS=$(patsubst %.c,%.o,$(ELFPADDER_SRCS))
ELFPADDER_BIN=elfpadder

ENCRYPTER_SRCS=encrypter.c runtime.c
ENCRYPTER_OBJS=$(patsubst %.c,%.o,$(ENCRYPTER_SRCS))
ENCRYPTER_BIN=encrypter

RUNMAIN_SRCS=runmain.c runtime.c
RUNMAIN_OBJS=$(patsubst %.c,%.o,$(RUNMAIN_SRCS))

OBJS=$(LOADER_OBJS) $(ELFPADDER_OBJS) $(ENCRYPTER_OBJS) $(RUNMAIN_OBJS)
BINS=$(LOADER_BIN) $(ELFPADDER_BIN) $(ENCRYPTER_BIN)


CFLAGS=-Wall -Wextra -ansi -pedantic -DVERBOSE=1 -ggdb3
LDFLAGS=

.PHONY: all
all: $(BINS)

$(LOADER_BIN): $(LOADER_OBJS) Makefile
	gcc -o $@ $(LOADER_OBJS) $(LDFLAGS)

$(ELFPADDER_BIN): $(ELFPADDER_OBJS) Makefile
	gcc -o $@ $(ELFPADDER_OBJS) $(LDFLAGS)

$(ENCRYPTER_BIN): $(ENCRYPTER_OBJS) Makefile
	gcc -o $@ $(ENCRYPTER_OBJS) $(LDFLAGS)

# Remove implicit rule
%: %.o

.SECONDARY: $(RUNMAIN_OBJS)
%.packed: $(RUNMAIN_OBJS) %.o Makefile
	gcc -o $@ $(RUNMAIN_OBJS) $*.o $(LDFLAGS)

%.o: %.c $(HDRS) Makefile
	gcc -o $@ -c $< $(CFLAGS)

%.o: %.enc Makefile
	objcopy -I binary -O elf64-x86-64 --strip-all --add-symbol embedded_elf=.data:0 $< $@

%.enc: %.pad $(ENCRYPTER_BIN) Makefile
	cp $< $@
	./$(ENCRYPTER_BIN) $@

%.pad: % $(ELFPADDER_BIN) Makefile
	cp $< $@
	./$(ELFPADDER_BIN) $@


.PHONY: clean
clean:
	rm -f $(OBJS)

.PHONY: mrproper
mrproper: clean
	rm -f $(BINS)
