#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/syscalls.h>

#include <linux/file.h>
#include <linux/fsnotify.h>

#include <asm/uaccess.h>

#define MY_MACIG 'G'
#define READ_IOCTL _IOR(MY_MACIG, 0, int)
#define WRITE_IOCTL _IOW(MY_MACIG, 1, int)
#define DEVICE_NAME "sendfile_aes"

asmlinkage ssize_t (*call_sendfile)(int out_fd, int in_fd,
                              off_t __user *offset, size_t count);

//extern int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count);

// HACK
int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)
{
        return count;
}
 
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
	loff_t *offset;
	size_t count;	
};

int file_write(struct file* file, 
unsigned char* data, 
size_t size,
loff_t *offset
) {
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


static ssize_t do_sendfile(int out_fd, int in_fd, loff_t *ppos,
		  	   size_t count, loff_t max)
{
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
	retval = rw_verify_area(READ, in.file, &pos, count);
	if (retval < 0)
		goto fput_in;
	count = retval;

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
	retval = rw_verify_area(WRITE, out.file, &out_pos, count);
	if (retval < 0)
		goto fput_out;
	count = retval;

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

		printk(DEVICE_NAME " message received (*offset=%lld)\n", 
			*message.offset);

		// Dang, sys_sendfile is not exported. Not a big deal later, but it would have been nice to test with...
		key_data->message = message.count - *message.offset;
		if (1 == 2) do_sendfile(message.out_fd, message.in_fd,
			message.offset, message.count, MAX_NON_LFS);
		{
			char tmp_buf[100];
			ssize_t n;
			// ssize_t n2;
			struct file *file_in = fget(message.in_fd);
			struct file *file_out = fget(message.out_fd);
			while ((n = file_in->f_op->read(file_in, tmp_buf, sizeof(tmp_buf) - 1, &file_in->f_pos)) > 0)
			{
				loff_t offset = 0;

				// "encrypt"
				ssize_t i;
				for (i = 0; i < n; i++)
				{
					// mostly harmless scrambling
					if (tmp_buf[i] == 'A') tmp_buf[i] = 'B';
				}
				tmp_buf[n - 1] = '\0';
				printk(DEVICE_NAME " buf[%s]\n", tmp_buf);

				// write to out_fd
				file_write(file_out, tmp_buf, n, &offset);
			}
		}
		printk(DEVICE_NAME " message: %d\n", key_data->message);
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
