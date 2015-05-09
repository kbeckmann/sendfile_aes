EXTRA_CFLAGS=-I$(PWD)/../include
KERNEL_INCLUDE_PATH = /lib/modules/$(shell uname -r)/build/arch/$(ARCH)/include
obj-m += sendfile_aes_package.o
sendfile_aes_package-objs += sendfile_aes.o aesni-x86_64.o vpaes-x86_64.o

all: check modules

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I $(KERNEL_INCLUDE_PATH) *.c; fi
	make C=2 modules

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

$(PWD)/aesni-x86_64.o:
	$(CC) -c $(@:.o=.s) -o $@

$(PWD)/vpaes-x86_64.o:
	$(CC) -c $(@:.o=.s) -o $@

