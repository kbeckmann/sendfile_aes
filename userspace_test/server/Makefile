CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../../userspace_lib
LDFLAGS+=-lsendfile_aes -L../../userspace_lib
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=server

all: $(EXECUTABLE) cppcheck

cppcheck:
	if [ -x "`which cppcheck`" ]; then cppcheck $(SOURCES); fi

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

