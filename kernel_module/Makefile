EXTRA_CFLAGS=-I$(PWD)/../include
KERNEL_INCLUDE_PATH = /lib/modules/$(shell uname -r)/build/arch/$(ARCH)/include
ASSEMBLY = \
	aes-x86_64.o \
	aesni-x86_64.o \
	vpaes-x86_64.o \
	x86_64cpuid.o

obj-m += sendfile_aes_package.o

sendfile_aes_package-objs += $(ASSEMBLY) \
	aes.o \
	sendfile_aes.o

all: modules

check_and_build: check all

check:
	@if [ -x "`which cppcheck 2> /dev/null`" ]; then cppcheck --enable=all -I $(KERNEL_INCLUDE_PATH) *.c; fi
	make C=2 modules

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

$(addprefix $(PWD)/, $(ASSEMBLY)):
	$(CC) -c $(@:.o=.s) -o $@
