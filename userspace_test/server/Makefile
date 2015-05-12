CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../../userspace_lib

LINKFLAGS = -lsendfile_aes -L../../userspace_lib
LIBPATHS = ../../userspace_lib/libsendfile_aes.a

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=server

all: check $(EXECUTABLE)

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I ../../userspace_lib/ $(SOURCES) || echo "cppcheck failed"; fi
	@if [ -x "`which sparse 2> /dev/null`" ]; then sparse -I ../../userspace_lib/ -Wsparse-all $(SOURCES) || echo "sparse failed"; fi

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

