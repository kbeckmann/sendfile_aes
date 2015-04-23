#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

struct t_data {
	size_t aes_key_length;
	char aes_key_data[0]; // must be the last element, 0-length array
};

struct t_message {
	int out_fd;
	int in_fd;
	off_t *offset;
	size_t count;
};

static char buf[200];

int sendfile_aes_open(size_t key_length, char* key_data)
{
	int fd = -1;
	if ((fd = open("/dev/sendfile_aes", O_RDWR)) < 0) {
		perror("open");
		return -1;
	}

	size_t data_size = key_length + sizeof(struct t_data);
	char prepare_data[data_size + 1];
	struct t_data *data = (struct t_data*) &prepare_data;
	data->aes_key_length = strlen(key_data);
	memcpy(&data->aes_key_data, key_data, data->aes_key_length);
	data->aes_key_data[data->aes_key_length] = '\0';

	printf(" size: %lx - %lx\n", sizeof(struct t_data), sizeof(data)); 
	printf(" p: %p, len: %ld, contents: %p\n", data, data->aes_key_length, data->aes_key_data); 
	printf(" len: %ld, contents: %s\n", data->aes_key_length, data->aes_key_data); 

	if (write(fd, data, data_size) < 0) {
		perror ("write error");
		return -1;
	}

	if (read(fd, buf, sizeof(buf)) < 0) {
		perror ("read error");
	}
	printf("BUF: %d\n", *((int*)buf));

	return fd;
}

int sendfile_aes_send(int fd, int out_fd, int in_fd, off_t *offset, size_t count)
{
	int ret = -1;
	struct t_message message = {
		.out_fd = out_fd,
		.in_fd = in_fd,
		.offset = offset,
		.count = count,
	};

	ret = write(fd, &message, sizeof(struct t_message));
	if (ret < 0) {
		perror ("write error");
		return -1;
	}

	return ret;
}

int sendfile_aes_close(int fd)
{
	return close(fd);
}

