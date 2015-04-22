CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../../userspace_lib
LDFLAGS+=
SOURCES=$(wildcard *.c) ../../userspace_lib/sendfile_aes_client.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=basic

all: $(EXECUTABLE) cppcheck

cppcheck:
	if [ -x "`which cppcheck`" ]; then cppcheck $(SOURCES); fi 
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS)

