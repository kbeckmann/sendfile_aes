CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../include
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
LIBRARY=libsendfile_aes

all: $(LIBRARY) cppcheck

cppcheck:
	if [ -x "`which cppcheck`" ]; then cppcheck $(SOURCES); fi

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

