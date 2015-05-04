#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/aes.h>

#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

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

#define CHUNK_SIZE 1024
#define MAX_PADDING 32


static int major;
static int message_err = -1;
static int num_open_files = 0;

struct t_data {
	struct T_SENDFILE_AES_SET_KEY *key;
	int message;
	struct crypto_blkcipher *crypto_session;
	char tmp_buf[CHUNK_SIZE];
	char dst_buf[CHUNK_SIZE + MAX_PADDING];
};


//TODO: understand the code below :)

/*
 * Should be used for buffers allocated with ceph_kvmalloc().
 * Currently these are encrypt out-buffer (ceph_buffer) and decrypt
 * in-buffer (msg front).
 *
 * Dispose of @sgt with teardown_sgtable().
 *
 * @prealloc_sg is to avoid memory allocation inside sg_alloc_table()
 * in cases where a single sg is sufficient.  No attempt to reduce the
 * number of sgs by squeezing physically contiguous pages together is
 * made though, for simplicity.
 */
static int setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
			 const void *buf, unsigned int buf_len)
{
	struct scatterlist *sg;
	const bool is_vmalloc = is_vmalloc_addr(buf);
	unsigned int off = offset_in_page(buf);
	unsigned int chunk_cnt = 1;
	unsigned int chunk_len = PAGE_ALIGN(off + buf_len);
	int i;
	int ret;

	if (buf_len == 0) {
		memset(sgt, 0, sizeof(*sgt));
		return -EINVAL;
	}

	if (is_vmalloc) {
		chunk_cnt = chunk_len >> PAGE_SHIFT;
		chunk_len = PAGE_SIZE;
	}

	if (chunk_cnt > 1) {
		ret = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
		if (ret)
			return ret;
	} else {
		WARN_ON(chunk_cnt != 1);
		sg_init_table(prealloc_sg, 1);
		sgt->sgl = prealloc_sg;
		sgt->nents = sgt->orig_nents = 1;
	}

	for_each_sg(sgt->sgl, sg, sgt->orig_nents, i) {
		struct page *page;
		unsigned int len = min(chunk_len - off, buf_len);

		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		sg_set_page(sg, page, len, off);

		off = 0;
		buf += len;
		buf_len -= len;
	}
	WARN_ON(buf_len != 0);

	return 0;
}

static void teardown_sgtable(struct sg_table *sgt)
{
	if (sgt->orig_nents > 1)
		sg_free_table(sgt);
}

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

	// Initiate crypto sesion
	this->crypto_session = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(this->crypto_session)) {
		DBG_PRINT(DEVICE_NAME " error calling crypto_alloc_aead() = 0x%p\n", this->crypto_session);
		this->message = -1;
		return -1;
	}

	DBG_PRINT(DEVICE_NAME " crypto_blkcipher = 0x%p\n", this->crypto_session);

	this->message = 0;
	return 0;
}


static ssize_t do_sendfile_aes_encrypt(struct t_data *this,
				   struct T_SENDFILE_AES_SENDFILE *message)
{
	ssize_t n;
	struct file *file_in;
	struct file *file_out;
	const void *key = this->key->key_data;
	int key_len = this->key->key_length;
	void *dst = this->dst_buf;
	size_t dst_len_value = 0;
	size_t *dst_len = &dst_len_value;
	const void *src = this->tmp_buf;
	void *iv;
	int ivsize;
	int ret;
	loff_t in_off = 0;
	loff_t out_off = 0;

	file_in = fget(message->in_fd);
	file_out = fget(message->out_fd);

	//TODO: handle error on file_in and file_out

	crypto_blkcipher_setkey((void *)this->crypto_session, key, key_len);
	iv = crypto_blkcipher_crt(this->crypto_session)->iv;
	ivsize = crypto_blkcipher_ivsize(this->crypto_session);
	DBG_PRINT(DEVICE_NAME " ivsize: %d, key->iv_length: %d\n", ivsize, this->key->iv_length);
	memcpy(iv, this->key->iv_data, this->key->iv_length);

	while ((n = file_read(file_in, &in_off, this->tmp_buf, sizeof(this->tmp_buf)))) {
		// Encrypt!
		size_t src_len = n;
		struct scatterlist sg_in[2], prealloc_sg;
		struct sg_table sg_out;
		struct blkcipher_desc desc = { .tfm = this->crypto_session, .flags = 0 };
		size_t zero_padding = (0x10 - (src_len & 0x0f)) % 0x10;
		char pad[16];

		memset(pad, zero_padding, zero_padding);

		*dst_len = src_len + zero_padding;
		DBG_PRINT(DEVICE_NAME " dst_len: %ld", *dst_len);

		sg_init_table(sg_in, 2);
		sg_set_buf(&sg_in[0], src, src_len);
		sg_set_buf(&sg_in[1], pad, zero_padding);
		ret = setup_sgtable(&sg_out, &prealloc_sg, dst, *dst_len);
		if (ret) {
			DBG_PRINT(DEVICE_NAME " setup_sgtable() failed");
			break;
		}

		DBG_PRINT_HEX(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
					  key, key_len, 1);
		DBG_PRINT_HEX(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
					  src, src_len, 1);
		DBG_PRINT_HEX(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
					  pad, zero_padding, 1);
		DBG_PRINT_HEX(KERN_ERR, "iv:      ", DUMP_PREFIX_NONE, 16, 1,
					  iv, ivsize, 1);
		ret = crypto_blkcipher_encrypt(&desc, sg_out.sgl, sg_in,
									   src_len + zero_padding);
		if (ret < 0) {
			pr_err("sendfile_aes failed %d\n", ret);
			goto out_sg;
		}
		DBG_PRINT_HEX(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
					  dst, *dst_len, 1);

		out_sg:
		teardown_sgtable(&sg_out);

		// n is used outside the loop to return the actual written bytes
		n = *dst_len;
		DBG_PRINT(DEVICE_NAME " n= %ld\n", n);

		// write to out_fd
		file_write(file_out, this->dst_buf, n, &out_off);
	}
	DBG_PRINT(DEVICE_NAME " (after loop) n= %ld\n", n);
	this->message = message->count;
	DBG_PRINT(DEVICE_NAME " message: %d\n", this->message);

	// clean up temp buffers so we don't leave plaintext in RAM?
	//	memset(this->tmp_buf, 0, sizeof(this->tmp_buf));
	//	memset(this->dst_buf, 0, sizeof(this->dst_buf));
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
	if (file) {
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
	if (file) {
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
