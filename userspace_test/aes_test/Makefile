CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../../userspace_lib

LINKFLAGS = -static -lcrypto -ldl -lz -static-libgcc

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=aes_test

all: $(EXECUTABLE) cppcheck

cppcheck:
	if [ -x "`which cppcheck`" ]; then cppcheck --enable=all -I ../../userspace_lib/ $(SOURCES); fi

$(EXECUTABLE): $(OBJECTS) $(LIBPATHS)
	$(CC) $(OBJECTS) -o $@ $(LINKFLAGS)

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

depend: .depend

.depend: $(SOURCES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend;

include .depend

