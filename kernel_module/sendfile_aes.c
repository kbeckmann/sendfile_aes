#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "sendfile_aes.h"

//#define _DEBUG_

#ifdef _DEBUG_
#define DBG_PRINT(...) printk(__VA_ARGS__)
#define DBG_PRINT_HEX(...) print_hex_dump(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#define DBG_PRINT_HEX(...)
#endif
#define DEVICE_NAME "sendfile_aes"

#define CHUNK_SIZE 1024 * 10
#define MAX_PADDING 32

# define AES_MAXNR 14
# define AES_BLOCK_SIZE 16

struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;



// TODO use cpuid
#define HAS_AESNI

#ifdef HAS_AESNI
#define AES_SET_ENCRYPT_KEY(...) aesni_set_encrypt_key(__VA_ARGS__)
#define AES_SET_DECRYPT_KEY(...) aesni_set_decrypt_key(__VA_ARGS__)
#define AES_CBC_ENCRYPT(...) aesni_cbc_encrypt(__VA_ARGS__)
#else
#define AES_SET_ENCRYPT_KEY(...) vpaes_set_encrypt_key(__VA_ARGS__)
#define AES_SET_DECRYPT_KEY(...) vpaes_set_decrypt_key(__VA_ARGS__)
#define AES_CBC_ENCRYPT(...) vpaes_cbc_encrypt(__VA_ARGS__)
#endif


// VP-AES
int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

// AES-NI
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void aesni_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

int OPENSSL_ia32cap_P[128];



static int major;
static int message_err = -1;
static int num_open_files = 0;

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

	ret = vfs_read(file, data, size, offset);

	set_fs(oldfs);
	return ret;
}

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
		DBG_PRINT(DEVICE_NAME " unexpected call to read()\n");
		return simple_read_from_buffer(buffer, len, offset,
			&message_err, sizeof(message_err));
	}

	this = (struct t_data*)file->private_data;
	DBG_PRINT(DEVICE_NAME " read(%d)\n", this->message);
	return simple_read_from_buffer(buffer, len, offset,
		&this->message, sizeof(this->message));
}

static ssize_t message_set_key(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SET_KEY set_key;

	if (len < sizeof(set_key)) {
		DBG_PRINT(DEVICE_NAME " write(): message too short (1)\n");
		return -1;
	}

	if (len > 4096 + sizeof(set_key)) {
		DBG_PRINT(DEVICE_NAME " write(): message too long\n");
		return -1;
	}

	this->key = kmalloc(len, GFP_KERNEL);
	copy_from_user(this->key, buff, len);

	if (len > this->key->key_length + 31) {
		DBG_PRINT(DEVICE_NAME " write(): key_length != len; %d != %ld\n",
			this->key->key_length,
			len);
		return -1;
	}

	DBG_PRINT_HEX(KERN_ERR, " key: ", DUMP_PREFIX_NONE, 16, 1,
				  this->key->key_data, this->key->key_length, 1);
	DBG_PRINT_HEX(KERN_ERR, " iv : ", DUMP_PREFIX_NONE, 16, 1,
				  this->key->iv_data, this->key->iv_length, 1);

	if (this->key->encrypt) {
		AES_SET_ENCRYPT_KEY(this->key->key_data, this->key->key_length * 8, &this->aes_key);
	} else {
		AES_SET_DECRYPT_KEY(this->key->key_data, this->key->key_length * 8, &this->aes_key);
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

	DBG_PRINT(DEVICE_NAME " do_sendfile_aes_encrypt:\n\t"
		"out_fd: %d\n\t"
		"in_fd: %d\n\t"
		"count: %ld\n\t"
		"encrypt: %d\n",
		message->out_fd, message->in_fd, message->count, this->key->encrypt);

	file_in = fget(message->in_fd);
	file_out = fget(message->out_fd);

	//TODO: handle error on file_in and file_out

	while ((n = file_read(file_in, &in_off, this->tmp_buf, sizeof(this->tmp_buf)))) {
		// Encrypt!
		int n2 = n & (~0xf);
		int n_trailing = n & 0xf;

		if (likely(n2)) {
			AES_CBC_ENCRYPT(this->tmp_buf, this->dst_buf, n2, &this->aes_key, this->key->iv_data, this->key->encrypt);
		}

		if (unlikely(n_trailing)) {
			size_t zero_padding = 0x10 - (n_trailing);
			char pad[16];
			memcpy(pad, this->tmp_buf + n2, n_trailing);
			memset(pad + n_trailing, zero_padding, zero_padding);
			AES_CBC_ENCRYPT(pad, this->dst_buf + n2, sizeof(pad), &this->aes_key, this->key->iv_data, this->key->encrypt);
			DBG_PRINT(DEVICE_NAME " PAD! Wrote %d extra bytes\n", n_trailing);
			n = n2 + sizeof(pad);
		}

		*dst_len = n;
		DBG_PRINT(DEVICE_NAME " n= %ld, n2=%d, n_trailing=%d\n", n, n2, n_trailing);
		// write to out_fd
		file_write(file_out, this->dst_buf, n, &out_off);
	}
	DBG_PRINT(DEVICE_NAME " (after loop) n= %ld\n", n);
	this->message = message->count;
	DBG_PRINT(DEVICE_NAME " message: %d\n", this->message);

	// clean up temp buffers so we don't leave plaintext in RAM
	memset(this->tmp_buf, 0, sizeof(this->tmp_buf));
	memset(this->dst_buf, 0, sizeof(this->dst_buf));
	return this->message;
}

static ssize_t message_sendfile(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SENDFILE message;

	if (len < sizeof(message)) {
		DBG_PRINT(DEVICE_NAME " size mismatch %ld should be %ld\n",
			   len, sizeof(message));
		this->message = -1;
		return -1;
	}

	copy_from_user(&message, buff, sizeof(message));
	DBG_PRINT(DEVICE_NAME " message received (%d, %d, %p, %ld)\n",
		   message.out_fd,
		   message.in_fd,
		   message.offset,
		   message.count);

	if (!message.offset) {
		this->message = -1;
		return -1;
	}

	DBG_PRINT(DEVICE_NAME " message received (*offset=%ld)\n",
		   *message.offset);
	return do_sendfile_aes_encrypt(this, &message);
}

static ssize_t device_write(struct file *file, const char __user *buff, size_t len, loff_t *off)
{
	struct t_data* this;
	enum e_message_type message_type;

	if (!(file && file->private_data)) {
		DBG_PRINT(DEVICE_NAME " write(): invalid stuff\n");
		return -1;
	}
	this = (struct t_data*)file->private_data;

	if (!off) {
		DBG_PRINT(DEVICE_NAME " write() warning: off is null\n");
	} else {
		DBG_PRINT(DEVICE_NAME " write() *off: %lld\n", *off);
	}

	if (len < sizeof(enum e_message_type)) {
		DBG_PRINT(DEVICE_NAME " write(): message too short\n");
		return -1;
	}

	if (!buff) {
		DBG_PRINT(DEVICE_NAME " write(): buff is NULL\n");
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

	DBG_PRINT(DEVICE_NAME " write(): message_type: %d\n", message_type);
	switch (message_type) {
		case MESSAGE_TYPE_SET_KEY:
			return message_set_key(this, buff, len);
		case MESSAGE_TYPE_GET_KEY:
			return 0;
		case MESSAGE_TYPE_SENDFILE:
			return message_sendfile(this, buff, len);
		default:
			DBG_PRINT(DEVICE_NAME " write() invalid message_type\n");
	}

	return -1;
}

static int device_open(struct inode *inode, struct file *file)
{
	DBG_PRINT(DEVICE_NAME " open\n");
	if (likely(file)) {
		struct t_data* data = (struct t_data*) kmalloc(sizeof(struct t_data), GFP_KERNEL);

		DBG_PRINT(DEVICE_NAME " private_data: %p\n", file->private_data);
		data->key = 0;
		data->message = 0;
		file->private_data = data;

		num_open_files++;
		DBG_PRINT(DEVICE_NAME " open files: %d\n", num_open_files);
	}
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	if (likely(file)) {
		DBG_PRINT(DEVICE_NAME " private_data: %p\n", file->private_data);
		if (file->private_data) {
			struct t_data* this = (struct t_data*)file->private_data;
			if (this->key) {
				DBG_PRINT(DEVICE_NAME " freeing this->key: %p\n", this->key);
				kfree(this->key);
				this->key = 0;
			}
			DBG_PRINT(DEVICE_NAME " freeing this\n");
			kfree(file->private_data);
			file->private_data = 0;
		}
	}
	num_open_files--;
	DBG_PRINT(DEVICE_NAME " release\n");
	DBG_PRINT(DEVICE_NAME " open files: %d\n", num_open_files);
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
	DBG_PRINT(DEVICE_NAME " init\n");
	major = register_chrdev(0, DEVICE_NAME, &fops);
	if (major < 0) {
		DBG_PRINT ("Registering the character device failed with %d\n", major);
		return major;
	}
	DBG_PRINT("sendfile_aes: assigned major: %d\n", major);
	DBG_PRINT("create node with mknod /dev/sendfile_aes c %d 0\n", major);
	return 0;
}

static void __exit sendfile_aes_exit(void)
{
	DBG_PRINT(DEVICE_NAME " exit\n");
	unregister_chrdev(major, DEVICE_NAME);
}

module_init(sendfile_aes_init);
module_exit(sendfile_aes_exit);

MODULE_AUTHOR("Konrad Beckmann <konrad.beckmann@gmail.com>");
MODULE_DESCRIPTION("Sendfile with on-the-fly encryption");
MODULE_LICENSE("GPL");
