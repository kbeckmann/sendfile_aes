.PHONY: all kernel_module userspace_lib userspace_test test clean

all: kernel_module userspace_lib userspace_test

kernel_module:
	@cd kernel_module && make -s && cd ..
#Why doesn't this work?
#$(MAKE) -C kernel_module


userspace_lib:
	@$(MAKE) -s -C userspace_lib

userspace_test:
	@$(MAKE) -s -C userspace_test

# Must be root
install_module:
	@lsmod | grep sendfile_aes_package &> /dev/null && rmmod sendfile_aes_package.ko || true
	@rm -f /dev/sendfile_aes
	@insmod kernel_module/sendfile_aes_package.ko
	@dmesg | grep sendfile_aes | tail -n 1 | grep -o /dev/sendfile_aes.* | xargs mknod
	@chmod 777 /dev/sendfile_aes

remove_module:
	@rmmod sendfile_aes_package

# sendfile_aes_package.ko must be loaded and installed in /dev/sendfile_aes
test:
	@lsmod | grep sendfile_aes_package &> /dev/null || (echo "Run 'sudo make install_module' first" && false)
	$(MAKE) -s -C test

clean:
	@cd kernel_module && make -s clean && cd ..
	@$(MAKE) -s -C userspace_lib clean
	@$(MAKE) -s -C userspace_test clean
	@$(MAKE) -s -C test clean
