CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../include
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
LIBRARY=libsendfile_aes

all: check $(LIBRARY)

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I ../include/ $(SOURCES); fi
	@if [ -x "`which sparse 2> /dev/null`" ]; then sparse -I ../include -Wsparse-all $(SOURCES); fi

$(LIBRARY): $(OBJECTS) $(HEADERS)
	$(AR) $(ARFLAGS) $@.a $(OBJECTS)

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

depend: .depend

.depend: $(SOURCES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend;

include .depend

