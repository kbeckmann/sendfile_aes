CC=gcc
CFLAGS+=-g -Wall -Wextra -std=c99 -I../include
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
LIBRARY=libsendfile_aes

all: $(LIBRARY)

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I ../include/ $(SOURCES) || echo "cppcheck failed"; fi
	@if [ -x "`which sparse 2> /dev/null`" ]; then sparse -I ../include -I /usr/include/linux -Wsparse-all $(SOURCES) || echo "Sparse failed"; fi

$(LIBRARY): $(OBJECTS) $(HEADERS)
	$(AR) $(ARFLAGS) $@.a $(OBJECTS)
	@echo Built userspace_lib

clean:
	rm -f $(LIBRARY).a $(OBJECTS)
	@echo Cleaned userspace_lib

depend: .depend

.depend: $(SOURCES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend;

include .depend

