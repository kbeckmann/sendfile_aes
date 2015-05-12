#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "sendfile_aes.h"
#include "aes.h"

//#define _DEBUG_

#define DBG_PRINT(...) printk(__VA_ARGS__)

#define LOGLEVEL 1

#if LOGLEVEL == 0
#  define INF_HEX(...)
#  define INF(...) 
#  define DBG(...)
#  define ERR(...) DBG_PRINT(__VA_ARGS__)
#elif LOGLEVEL == 1
#  define INF_HEX(...)
#  define INF(...) 
#  define DBG(...) DBG_PRINT(__VA_ARGS__)
#  define ERR(...) DBG_PRINT(__VA_ARGS__)
#elif LOGLEVEL == 2
#  define INF_HEX(...) print_hex_dump(__VA_ARGS__)
#  define INF(...) DBG_PRINT(__VA_ARGS__) 
#  define DBG(...) DBG_PRINT(__VA_ARGS__)
#  define ERR(...) DBG_PRINT(__VA_ARGS__)
#endif


#define DEVICE_NAME "sendfile_aes"

#define CHUNK_SIZE 1024 * 10
#define MAX_PADDING 32

static int major;
static int message_err = -1;
static int message_ok = 0;
atomic_t num_open_files = ATOMIC_INIT(0);

struct t_data {
	struct T_SENDFILE_AES_SET_KEY *key;
	int message;
	char tmp_buf[CHUNK_SIZE];
	char dst_buf[CHUNK_SIZE + MAX_PADDING];
	AES_KEY aes_key;
};

static int file_read(struct file* file, loff_t *offset, unsigned char* data, unsigned int size) {
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	/* The cast to a user pointer is valid due to the set_fs() */
	ret = vfs_read(file, (void __user *)data, size, offset);

	set_fs(oldfs);
	return ret;
}

static int file_write(struct file* file, unsigned char* data, size_t size, loff_t *offset)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(get_ds());

	/* The cast to a user pointer is valid due to the set_fs() */
	ret = vfs_write(file, (void __user *)data, size, offset);

	set_fs(oldfs);
	return ret;
}

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
	struct t_data* this;

	if (!(file && file->private_data)) {
		INF(DEVICE_NAME " unexpected call to read()\n");
		return simple_read_from_buffer(buffer, len, offset,
			&message_err, sizeof(message_err));
	}

	this = (struct t_data*)file->private_data;
	INF(DEVICE_NAME " read(%d)\n", this->message);
	return simple_read_from_buffer(buffer, len, offset,
		&this->message, sizeof(this->message));
}

static ssize_t message_set_key(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SET_KEY set_key;

	if (len < sizeof(set_key)) {
		ERR(DEVICE_NAME " write(): message too short\n");
		return -1;
	}

	if (len > 4096 + sizeof(set_key)) {
		ERR(DEVICE_NAME " write(): message too long\n");
		return -1;
	}

	this->key = kmalloc(len, GFP_KERNEL);
	copy_from_user(this->key, buff, len);

	if (len > this->key->key_length + 31) {
		ERR(DEVICE_NAME " write(): key_length != len; %d != %ld\n",
			this->key->key_length,
			len);
		return -1;
	}

	INF_HEX(KERN_ERR, " key: ", DUMP_PREFIX_NONE, 16, 1,
				  this->key->key_data, this->key->key_length, 1);
	INF_HEX(KERN_ERR, " iv : ", DUMP_PREFIX_NONE, 16, 1,
				  this->key->iv_data, this->key->iv_length, 1);

	if (this->key->encrypt) {
		aes_auto_set_encrypt_key(this->key->key_data, this->key->key_length * 8, &this->aes_key);
	} else {
		aes_auto_set_decrypt_key(this->key->key_data, this->key->key_length * 8, &this->aes_key);
	}

	this->message = 0;
	return 0;
}

static ssize_t do_sendfile_null_cipher(struct t_data *this, struct T_SENDFILE_AES_SENDFILE *message)
{
	int out_fd = message->out_fd;
	int in_fd = message->in_fd;
	loff_t *ppos = NULL;
	size_t count = message->count;
	loff_t max = 0;
	struct fd in, out;
	struct inode *in_inode, *out_inode;
	loff_t pos;
	loff_t out_pos;
	ssize_t retval;
	int fl;

	/*
	 * Get input file, and verify that it is ok..
	 */
	retval = -EBADF;
	in = fdget(in_fd);
	if (!in.file)
		goto out;
	if (!(in.file->f_mode & FMODE_READ))
		goto fput_in;
	retval = -ESPIPE;
	if (!ppos) {
		pos = in.file->f_pos;
	} else {
		pos = *ppos;
		if (!(in.file->f_mode & FMODE_PREAD))
			goto fput_in;
	}
	//retval = rw_verify_area(READ, in.file, &pos, count);
	//if (retval < 0)
	//	goto fput_in;
	//count = retval;

	/*
	 * Get output file, and verify that it is ok..
	 */
	retval = -EBADF;
	out = fdget(out_fd);
	if (!out.file)
		goto fput_in;
	if (!(out.file->f_mode & FMODE_WRITE))
		goto fput_out;
	retval = -EINVAL;
	in_inode = file_inode(in.file);
	out_inode = file_inode(out.file);
	out_pos = out.file->f_pos;
	//retval = rw_verify_area(WRITE, out.file, &out_pos, count);
	//if (retval < 0)
	//	goto fput_out;
	//count = retval;

	if (!max)
		max = min(in_inode->i_sb->s_maxbytes, out_inode->i_sb->s_maxbytes);

	if (unlikely(pos + count > max)) {
		retval = -EOVERFLOW;
		if (pos >= max)
			goto fput_out;
		count = max - pos;
	}

	fl = 0;
#if 0
	/*
	 * We need to debate whether we can enable this or not. The
	 * man page documents EAGAIN return for the output at least,
	 * and the application is arguably buggy if it doesn't expect
	 * EAGAIN on a non-blocking file descriptor.
	 */
	if (in.file->f_flags & O_NONBLOCK)
		fl = SPLICE_F_NONBLOCK;
#endif
	file_start_write(out.file);
	retval = do_splice_direct(in.file, &pos, out.file, &out_pos, count, fl);
	file_end_write(out.file);

	if (retval > 0) {
		add_rchar(current, retval);
		add_wchar(current, retval);
		fsnotify_access(in.file);
		fsnotify_modify(out.file);
		out.file->f_pos = out_pos;
		if (ppos)
			*ppos = pos;
		else
			in.file->f_pos = pos;
	}

	inc_syscr(current);
	inc_syscw(current);
	if (pos > max)
		retval = -EOVERFLOW;

fput_out:
	fdput(out);
fput_in:
	fdput(in);
out:
	return retval;
}

static ssize_t do_sendfile_aes_encrypt(struct t_data *this, struct T_SENDFILE_AES_SENDFILE *message)
{
	ssize_t n;
	struct file *file_in;
	struct file *file_out;
	size_t dst_len_value = 0;
	size_t *dst_len = &dst_len_value;
	loff_t in_off = 0;
	loff_t out_off = 0;
	char pad[16];
	size_t padding = (0x10 - (message->count & 0x0f));

	INF(DEVICE_NAME " do_sendfile_aes_encrypt:\n\t"
		"out_fd: %d\n\t"
		"in_fd: %d\n\t"
		"count: %ld\n\t"
		"encrypt: %d\n",
		message->out_fd, message->in_fd, message->count, this->key->encrypt);

	file_in = fget(message->in_fd);
	file_out = fget(message->out_fd);

	//TODO: handle error on file_in and file_out

	int n2 = 0;
	int last_n = 0;
	while ((n = file_read(file_in, &in_off, this->tmp_buf, sizeof(this->tmp_buf)))) {
		// Encrypt!
		last_n = n;
		n2 = n & (~0xf);
		if (likely(n2)) {
			aes_auto_cbc_encrypt(this->tmp_buf, this->dst_buf, n2, &this->aes_key, this->key->iv_data, this->key->encrypt);
		}

		*dst_len += n2;
		file_write(file_out, this->dst_buf, n2, &out_off);
	}

	// Always write trailing padding
	int n_trailing = last_n & 0xf;
	INF("Trailing bytes: %d, last_n: %d\n", n_trailing, last_n);
	memcpy(pad, this->tmp_buf + n2, n_trailing);
	memset(pad + n_trailing, padding, padding);

	aes_auto_cbc_encrypt(pad, this->dst_buf + n2, sizeof(pad), &this->aes_key, this->key->iv_data, this->key->encrypt);
	file_write(file_out, this->dst_buf + n2, sizeof(pad), &out_off);
	*dst_len += sizeof(pad);

	this->message = message->count;
	INF(DEVICE_NAME " read: %d, wrote: %d\n", this->message, *dst_len);

	// "close" the files
	fput(file_out);
	fput(file_in);

	// clean up temp buffers so we don't leave plaintext in RAM
	memset(this->tmp_buf, 0, sizeof(this->tmp_buf));
	memset(this->dst_buf, 0, sizeof(this->dst_buf));
	return this->message;
}

static ssize_t message_sendfile(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SENDFILE message;
	ssize_t ret = 0;

	if (len < sizeof(message)) {
		INF(DEVICE_NAME " size mismatch %ld should be %ld\n",
			   len, sizeof(message));
		this->message = -1;
		return -1;
	}

	copy_from_user(&message, buff, sizeof(message));
	INF(DEVICE_NAME " message received (%d, %d, %p, %ld)\n",
		   message.out_fd,
		   message.in_fd,
		   message.offset,
		   message.count);

	if (!message.offset) {
		this->message = -1;
		return -1;
	}

	INF(DEVICE_NAME " message received (*offset=%ld)\n",
		   *message.offset);

	// TODO: Add support for null_cipher in message
	if (1) {
		ret = do_sendfile_aes_encrypt(this, &message);
	} else {
		ret = do_sendfile_null_cipher(this, &message);
	}

	return ret;
}

static ssize_t device_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
	struct t_data* this;
	enum e_message_type message_type;

	if (!(file && file->private_data)) {
		ERR(DEVICE_NAME " write(): invalid stuff\n");
		return -1;
	}
	this = (struct t_data*)file->private_data;

	if (!off) {
		ERR(DEVICE_NAME " write() warning: off is null\n");
	} else {
		INF(DEVICE_NAME " write() *off: %lld\n", *off);
	}

	if (len < sizeof(enum e_message_type)) {
		ERR(DEVICE_NAME " write(): message too short\n");
		return -1;
	}

	if (!buff) {
		ERR(DEVICE_NAME " write(): buff is NULL\n");
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

	INF(DEVICE_NAME " write(): message_type: %d\n", message_type);
	switch (message_type) {
		case MESSAGE_TYPE_SET_KEY:
			return message_set_key(this, buff, len);
		case MESSAGE_TYPE_GET_KEY:
			return 0;
		case MESSAGE_TYPE_SENDFILE:
			return message_sendfile(this, buff, len);
		default:
			ERR(DEVICE_NAME " write() invalid message_type\n");
	}

	return -1;
}

static int device_open(struct inode *inode, struct file *file)
{
	INF(DEVICE_NAME " open\n");
	if (likely(file)) {
		struct t_data* data = (struct t_data*) kmalloc(sizeof(struct t_data), GFP_KERNEL);

		INF(DEVICE_NAME " private_data: %p\n", file->private_data);
		data->key = NULL;
		data->message = message_ok;
		file->private_data = data;

		// Note: This code is only called if DBG is defined
		DBG(DEVICE_NAME " open, open files: %d\n", atomic_inc_return(&num_open_files));
	}
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	if (likely(file)) {
		INF(DEVICE_NAME " private_data: %p\n", file->private_data);
		if (file->private_data) {
			struct t_data* this = (struct t_data*)file->private_data;
			if (this->key) {
				INF(DEVICE_NAME " freeing this->key: %p\n", this->key);
				kfree(this->key);
				this->key = NULL;
			}
			INF(DEVICE_NAME " freeing this\n");
			kfree(file->private_data);
			file->private_data = NULL;
		}
	}

	// Note: This code is only called if DBG is defined
	DBG(DEVICE_NAME " release, open files: %d\n", atomic_dec_return(&num_open_files));
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
	INF(DEVICE_NAME " init\n");
	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
		INF("Registering the character device failed with %d\n", major);
		return major;
	}
	INF("sendfile_aes: assigned major: %d\n", major);
	ERR(DEVICE_NAME " create a node with mknod /dev/sendfile_aes c %d 0\n", major);

	OPENSSL_cpuid_setup();

	return 0;
}

static void __exit sendfile_aes_exit(void)
{
	INF(DEVICE_NAME " exit\n");
	unregister_chrdev(major, DEVICE_NAME);
}

module_init(sendfile_aes_init);
module_exit(sendfile_aes_exit);

MODULE_AUTHOR("Konrad Beckmann <konrad.beckmann@gmail.com>");
MODULE_DESCRIPTION("Sendfile with on-the-fly encryption");
MODULE_LICENSE("GPL");
