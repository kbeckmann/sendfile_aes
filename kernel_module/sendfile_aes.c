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

#include "sendfile_aes.h"

#define DEVICE_NAME "sendfile_aes"

static int major;
static int message_err = -1;
static int num_open_files = 0;

struct t_data {
	struct T_SENDFILE_AES_SET_KEY *key;
	int message;
/*
	struct {
		// TODO: Read Key and IV from userspace
		char key[32];
		char iv[16];
	} aes_key_data;
*/
	struct crypto_blkcipher *crypto_session;
};

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

	{
		int i;
		printk(DEVICE_NAME " write(): iv: [");
		for (i = 0; i < this->key->iv_length; i++)
			printk("%02x", this->key->iv_data[i]);
		printk("]\n");
	}

	// TODO: Implement key expension from userspace key
//	memcpy(&this->aes_key_data.key, "\x42\x93\x20\x9e\x7a\x46\x38\xbe\x35\xc2\xc2\x91\x53\x3a\x3c\x0b\xe4\x86\x7b\x6b\xd7\x66\x98\x04\x58\xc0\x2b\x3b\x02\x9e\x7d\xf6", 32);
//	memcpy(&this->aes_key_data.iv, "\x09\xca\xa1\x9c\x39\x40\x62\x0b\x6b\x97\xa5\x0a\x7e\x2a\x97\x1d", 16);



	// Initiate crypto sesion
	this->crypto_session = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(this->crypto_session)) {
		printk(DEVICE_NAME " error calling crypto_alloc_aead() = 0x%p\n", this->crypto_session);
		this->message = -1;
		return -1;
	}

	printk(DEVICE_NAME " crypto_aead = 0x%p\n", this->crypto_session);

	this->message = 0;
	return 0;
}

static ssize_t message_sendfile(struct t_data* this, const char __user *buff, size_t len)
{
	struct T_SENDFILE_AES_SENDFILE message;
	char tmp_buf[32];
	char dst_buf[64];
	ssize_t n;
	struct file *file_in;
	struct file *file_out;
	loff_t offset = 0;

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
	memset(tmp_buf, 0, sizeof(tmp_buf));




	const void *key = this->key->key_data;
	int key_len = this->key->key_length;
	void *dst = dst_buf;
	size_t dst_len_value = 0;
	size_t *dst_len = &dst_len_value;
	const void *src = tmp_buf;
	void *iv;
	int ivsize;

	printk(DEVICE_NAME " key: %p, key_len: %d\n", key, key_len);
	crypto_blkcipher_setkey((void *)this->crypto_session, key, key_len);

	iv = crypto_blkcipher_crt(this->crypto_session)->iv;
	ivsize = crypto_blkcipher_ivsize(this->crypto_session);
	memcpy(iv, this->key->iv_data, this->key->iv_length);

	printk(DEVICE_NAME " ivsize: %d\n", ivsize);


	while ((n = file_in->f_op->read(file_in, tmp_buf,
		sizeof(tmp_buf), &file_in->f_pos)) > 0) {

		// Encrypt!
		if (1 == 1) {
			size_t src_len = n;

			struct scatterlist sg_in[2], prealloc_sg;
			struct sg_table sg_out;
			struct blkcipher_desc desc = { .tfm = this->crypto_session, .flags = 0 };
			int ret;
			size_t zero_padding = (0x10 - (src_len & 0x0f)) % 0x10;
			char pad[16];

			memset(pad, zero_padding, zero_padding);

			*dst_len = src_len + zero_padding;
			printk(DEVICE_NAME " dst_len: %ld", *dst_len);

			sg_init_table(sg_in, 2);
			sg_set_buf(&sg_in[0], src, src_len);
			sg_set_buf(&sg_in[1], pad, zero_padding);
			ret = setup_sgtable(&sg_out, &prealloc_sg, dst, *dst_len);
			if (ret)
				goto out_tfm;


			print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
						   key, key_len, 1);
			print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
						   src, src_len, 1);
			print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
						   pad, zero_padding, 1);
			print_hex_dump(KERN_ERR, "iv:      ", DUMP_PREFIX_NONE, 16, 1,
						   iv, ivsize, 1);
			ret = crypto_blkcipher_encrypt(&desc, sg_out.sgl, sg_in,
										   src_len + zero_padding);
			if (ret < 0) {
				pr_err("ceph_aes_crypt failed %d\n", ret);
				goto out_sg;
			}
			print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
						   dst, *dst_len, 1);

			out_sg:
			teardown_sgtable(&sg_out);
			out_tfm:
			//crypto_free_blkcipher(tfm);

			printk(DEVICE_NAME " ok\n");

			n = *dst_len;

		} else {
			ssize_t i;

			printk(DEVICE_NAME " message_sendfile(): f_op->read()\n");
			for (i = 0; i < n; i++) {
				// mostly harmless scrambling
				if (tmp_buf[i] == 'A')
					dst_buf[i] = 'B';
				else
					dst_buf[i] = tmp_buf[i];
			}
		}


		// write to out_fd
		file_write(file_out, dst_buf, n, &offset);
		{
			char c;
			int i = 0;
			printk(DEVICE_NAME " message_sendfile(): [");
			while ((c = dst_buf[i])) {
				if (++i == sizeof(dst_buf))
					break;
				printk("%02x", (unsigned char) c);
			}
			printk("]\n");
		}
		printk(DEVICE_NAME " n= %ld\n", n);
	}
	printk(DEVICE_NAME " (after loop) n= %ld\n", n);
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
