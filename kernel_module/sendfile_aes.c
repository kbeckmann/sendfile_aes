#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>

#define MY_MACIG 'G'
#define READ_IOCTL _IOR(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)
#define DEVICE_NAME "sendfile_aes"

asmlinkage ssize_t (*call_sendfile)(int out_fd, int in_fd,
                              off_t __user *offset, size_t count);

 
static int major; 
static int message_err = -1;
static int num_open_files = 0;

struct t_data {
	size_t aes_key_length;
	char *aes_key_data;
	int message;
};

struct t_message {
	int out_fd;
	int in_fd;
	off_t *offset;
	size_t count;	
};

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
	struct t_data* key_data;

	if (!(file && file->private_data)) {
		printk(DEVICE_NAME " unexpected call to read()\n");
		return simple_read_from_buffer(buffer, len, offset,
			&message_err, sizeof(message_err));
	}

	key_data = (struct t_data*)file->private_data;
	printk(DEVICE_NAME " read(%d)\n", key_data->message);
	return simple_read_from_buffer(buffer, len, offset,
		&key_data->message, sizeof(key_data->message));
}

static ssize_t device_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
	struct t_data* key_data;
	if (!(file && file->private_data)) {
		printk(DEVICE_NAME " unexpected call to write()\n");
		return -1;
	}

	key_data = (struct t_data*)file->private_data;

	if (key_data->aes_key_length == 0) {
		// First call to write(), read the key. write() will be called with the following:
		// size_t aes_key_length 
		// char aes_key_data[]
		if (len <= 0 || len > 1024) {
			printk(DEVICE_NAME " length out of bounds, %ld\n", len);
			key_data->message = -1;
			return -1;
		}

		key_data->aes_key_length = len - sizeof(size_t);
		key_data->aes_key_data = kmalloc(key_data->aes_key_length, GFP_KERNEL);
		if (!key_data->aes_key_data) {
			printk(DEVICE_NAME " kmalloc failed\n");
			key_data->message = -1;
			return -1;
		}

		copy_from_user(key_data->aes_key_data, buff + sizeof(size_t),
			key_data->aes_key_length);
		printk(DEVICE_NAME " copy_from_user copied %ld bytes\n", key_data->aes_key_length);
		key_data->message = 0;
		return 0;
	} else {
		// Second+ call to write(), handle sendfile-stuff
		struct t_message message = {0};
		if (len != sizeof(struct t_message)) {
			printk(DEVICE_NAME " size mismatch %ld should be %ld\n", 
				len, sizeof(struct t_message));
			key_data->message = -1;
			return -1;
		}

		copy_from_user(&message, buff, sizeof(struct t_message));
		printk(DEVICE_NAME " message received (%d, %d, %p, %ld)\n", 
			message.out_fd,
			message.in_fd,
			message.offset,
			message.count);

		if (!message.offset) {
			key_data->message = -1;
			return -1;
		}

		printk(DEVICE_NAME " message received (*offset=%ld)\n", 
			*message.offset);

		// Dang, sys_sendfile is not exported. Not a big deal later, but it would have been nice to test with...
		//sys_sendfile(message.out_fd, message.in_fd,
		//	message.offset, message.count);
//		sys_call_table[__NR_sendfile](message.out_fd, message.in_fd,
//                            message.offset, message.count);
//		{
//			call_sendfile = sys_call_table[__NR_sendfile];
//			call_sendfile(message.out_fd, message.in_fd,
//                           message.offset, message.count);
//		}

		key_data->message = message.count - *message.offset;
		return key_data->message;
	}
}

static int device_open(struct inode *inode, struct file *file)
{
	printk(DEVICE_NAME " open\n");
	if (file) {
		struct t_data* data = (struct t_data*) kmalloc(sizeof(struct t_data), GFP_KERNEL);

		printk(DEVICE_NAME " private_data: %p\n", file->private_data);
		data->aes_key_length = 0;
		data->message = 0;
		file->private_data = data;

		num_open_files++;
		printk(DEVICE_NAME " open files: %d\n", num_open_files);
	}
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	if (file) {
		printk(DEVICE_NAME " private_data: %p\n", file->private_data);
		if (file->private_data) {
		        struct t_data* key_data = (struct t_data*)file->private_data;
			if (key_data->aes_key_data) {
				printk(DEVICE_NAME " freeing key_data->aes_key_data\n");
				kfree(key_data->aes_key_data);
				key_data->aes_key_data = 0;
			}
			printk(DEVICE_NAME " freeing key_data\n");
			kfree(file->private_data);
			file->private_data = 0;
		}
	}
	num_open_files--;
	printk(DEVICE_NAME " release\n");
	printk(DEVICE_NAME " open files: %d\n", num_open_files);
	return 0;
}

/*
//char buf[200];
//int device_ioctl(struct inode *inode, struct file *filep, unsigned int cmd, unsigned long arg)
long device_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int len = 200;
	printk(DEVICE_NAME " device_compat_ioctl\n");
	switch(cmd) {
	case READ_IOCTL:	
		printk(DEVICE_NAME " READ_IOCTL\n");
		copy_to_user((char *)arg, buf, 200);
		break;
	
	case WRITE_IOCTL:
		printk(DEVICE_NAME " WRITE_IOCTL\n");
		copy_from_user(buf, (char *)arg, len);
		break;

	default:
		return -ENOTTY;
	}
	return len;

}
*/

static struct file_operations fops = {
	.read = device_read, 
	.write = device_write,
	.open = device_open,
	.release = device_release,
	//.ioctl = device_ioctl,
	//.compat_ioctl = device_compat_ioctl,
};

static int __init sendfile_aes_init(void)
{
	printk(DEVICE_NAME " init\n");
	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
     		printk ("Registering the character device failed with %d\n", major);
	     	return major;
	}
	printk("sendfile_aes: assigned major: %d\n", major);
	printk("create node with mknod /dev/sendfile_aes c %d 0\n", major);
 	return 0;
}

static void __exit sendfile_aes_exit(void)
{
	printk(DEVICE_NAME " exit\n");
	unregister_chrdev(major, DEVICE_NAME);
}  

module_init(sendfile_aes_init);
module_exit(sendfile_aes_exit);
MODULE_LICENSE("GPL");
