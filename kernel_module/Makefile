EXTRA_CFLAGS=-I$(PWD)/../include
obj-m += sendfile_aes_package.o
sendfile_aes_package-objs += sendfile_aes.o aesni-x86_64.o vpaes-x86_64.o

all: cppcheck
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


$(PWD)/aesni-x86_64.o:
	$(CC) -c $(@:.o=.s) -o $@

$(PWD)/vpaes-x86_64.o:
	$(CC) -c $(@:.o=.s) -o $@

cppcheck:
	cppcheck --enable=all -I ../include/ *.c

