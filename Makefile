.PHONY: all kernel_module userspace_lib userspace_test test clean

all: kernel_module userspace_lib userspace_test

kernel_module:
	$(MAKE) -C kernel_module

userspace_lib:
	$(MAKE) -C userspace_lib

userspace_test:
	$(MAKE) -C userspace_test

# sendfile_aes_package.ko must be loaded and installed in /dev/sendfile_aes
test: all
	$(MAKE) -C test

clean:
	cd kernel_module && $(BASH) ./clean.sh && cd -
	$(MAKE) -C userspace_lib clean
	$(MAKE) -C userspace_test clean
	$(MAKE) -C test clean
