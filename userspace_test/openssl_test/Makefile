CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99

LINKFLAGS =

SOURCES=$(wildcard *.c)
ASM=$(wildcard *.s)
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=openssl_test

all: check $(EXECUTABLE)

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I ../../userspace_lib/ $(SOURCES); fi
	@if [ -x "`which sparse 2> /dev/null`" ]; then sparse -I ../../userspace_lib/ -Wsparse-all $(SOURCES); fi

$(EXECUTABLE): $(OBJECTS) $(LIBPATHS)
	$(CC) $(OBJECTS) $(ASM) -o $@ $(LINKFLAGS)

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

depend: .depend

.depend: $(SOURCES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend;

include .depend

