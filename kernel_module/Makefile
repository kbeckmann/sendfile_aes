EXTRA_CFLAGS=-I$(PWD)/../include
obj-m += sendfile_aes.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
