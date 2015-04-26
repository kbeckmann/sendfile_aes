#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include "sendfile_aes.h"

#define DEVICE_NAME "sendfile_aes"

static int major;
static int message_err = -1;
static int num_open_files = 0;

struct t_data {
	struct T_SENDFILE_AES_SET_KEY *key;
	int message;
};

static int file_write(struct file* file, unsigned char* data, size_t size, loff_t *offset)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(file, data, size, offset);

	set_fs(oldfs);
	return ret;
}

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
	struct t_data* this;

	if (!(file && file->private_data)) {
		printk(DEVICE_NAME " unexpected call to read()\n");
		return simple_read_from_buffer(buffer, len, offset,
			&message_err, sizeof(message_err));
	}

	this = (struct t_data*)file->private_data;
	printk(DEVICE_NAME " read(%d)\n", this->message);
	return simple_read_from_buffer(buffer, len, offset,
		&this->message, sizeof(this->message));
}

static ssize_t message_set_key(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SET_KEY set_key;
	if (len < sizeof(set_key)) {
		printk(DEVICE_NAME " write(): message too short (1)\n");
		return -1;
	}

	if (len > 4096 + sizeof(set_key)) {
		printk(DEVICE_NAME " write(): message too long\n");
		return -1;
	}

	this->key = kmalloc(len, GFP_KERNEL);
	copy_from_user(this->key, buff, len);

	if (len > this->key->key_length + 31) {
		printk(DEVICE_NAME " write(): key_length != len; %d != %ld\n",
			this->key->key_length,
			len);
		return -1;
	}

	{
		int i;
		printk(DEVICE_NAME " write(): key: [");
		for (i = 0; i < this->key->key_length; i++)
			printk("%02x", this->key->key_data[i]);
		printk("]\n");
	}
	
	this->message = 0;
	return 0;
}

static ssize_t message_sendfile(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SENDFILE message;
	char tmp_buf[100];
	ssize_t n;
	struct file *file_in;
	struct file *file_out;

	printk(DEVICE_NAME " enum: %ld, int: %ld, off_t*: %ld, size_t: %ld, "
		"T_SENDFILE_AES_SENDFILE:%ld\n",
		sizeof(enum e_message_type),
		sizeof(int),
		sizeof(off_t*),
		sizeof(size_t),
		sizeof(message));

	if (len < sizeof(message)) {
		printk(DEVICE_NAME " size mismatch %ld should be %ld\n",
			   len, sizeof(message));
		this->message = -1;
		return -1;
	}

	copy_from_user(&message, buff, sizeof(message));
	printk(DEVICE_NAME " message received (%d, %d, %p, %ld)\n",
		   message.out_fd,
		   message.in_fd,
		   message.offset,
		   message.count);

	if (!message.offset) {
		this->message = -1;
		return -1;
	}

	printk(DEVICE_NAME " message received (*offset=%ld)\n",
		   *message.offset);

	file_in = fget(message.in_fd);
	file_out = fget(message.out_fd);
	while ((n = file_in->f_op->read(file_in, tmp_buf,
		sizeof(tmp_buf), &file_in->f_pos)) > 0) {
		loff_t offset = 0;

		// "encrypt"
		ssize_t i;

		printk(DEVICE_NAME " message_sendfile(): f_op->read()\n");
		for (i = 0; i < n; i++) {
			// mostly harmless scrambling
			if (tmp_buf[i] == 'A') tmp_buf[i] = 'B';
		}

		// write to out_fd
		file_write(file_out, tmp_buf, n, &offset);
		tmp_buf[sizeof(tmp_buf) - 1] = '\0';
		printk(DEVICE_NAME " message_sendfile(): [%s]\n", tmp_buf);
	}
	printk(DEVICE_NAME " n= %d\n", n);
	this->message = message.count;
	printk(DEVICE_NAME " message: %d\n", this->message);
	return this->message;
}

static ssize_t device_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
	struct t_data* this;
	enum e_message_type message_type;

	if (!(file && file->private_data)) {
		printk(DEVICE_NAME " write(): invalid stuff\n");
		return -1;
	}
	this = (struct t_data*)file->private_data;

	if (!off) {
		printk(DEVICE_NAME " write() warning: off is null\n");
	} else {
		printk(DEVICE_NAME " write() *off: %lld\n", *off);
	}

	if (len < sizeof(enum e_message_type)) {
		printk(DEVICE_NAME " write(): message too short\n");
		return -1;
	}

	if (!buff) {
		printk(DEVICE_NAME " write(): buff is NULL\n");
		return -1;
	}

	if (*off == 0) {
		// First time write() is called, assume we want to set the key.
		// This allows us to skip one call to copy_from_user()
		// TODO: Decide if message_type should be sent or not
		buff += sizeof(message_type);
		len -= sizeof(message_type);
		return message_set_key(this, buff, len);
	}

	copy_from_user(&message_type, buff, sizeof(message_type));
	buff += sizeof(message_type);
	len -= sizeof(message_type);

	printk(DEVICE_NAME " write(): message_type: %d\n", message_type);
	switch (message_type) {
		case MESSAGE_TYPE_SET_KEY:
			return message_set_key(this, buff, len);
		case MESSAGE_TYPE_GET_KEY:
			return 0;
		case MESSAGE_TYPE_SENDFILE:
			return message_sendfile(this, buff, len);
		default:
			printk(DEVICE_NAME " write() invalid message_type\n");
	}

	return -1;
}

static int device_open(struct inode *inode, struct file *file)
{
	printk(DEVICE_NAME " open\n");
	if (file) {
		struct t_data* data = (struct t_data*) kmalloc(sizeof(struct t_data), GFP_KERNEL);

		printk(DEVICE_NAME " private_data: %p\n", file->private_data);
		data->key = 0;
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
			struct t_data* this = (struct t_data*)file->private_data;
			if (this->key) {
				printk(DEVICE_NAME " freeing this->key: %p\n", this->key);
				kfree(this->key);
				this->key = 0;
			}
			printk(DEVICE_NAME " freeing this\n");
			kfree(file->private_data);
			file->private_data = 0;
		}
	}
	num_open_files--;
	printk(DEVICE_NAME " release\n");
	printk(DEVICE_NAME " open files: %d\n", num_open_files);
	return 0;
}

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release,
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

MODULE_AUTHOR("Konrad Beckmann <konrad.beckmann@gmail.com>");
MODULE_DESCRIPTION("Sendfile with on-the-fly encryption");
MODULE_LICENSE("GPL");
