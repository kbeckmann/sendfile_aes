#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "sendfile_aes.h"
#include "sendfile_aes_client.h"

//#define DEBUG
#ifdef DEBUG
#define DBG_PRINT(...) printf(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

static char buf[200];

int sendfile_aes_open(char* key_data, size_t key_length, char* iv_data, size_t iv_length, int encrypt)
{
	int fd = -1;
	SENDFILE_AES_BUILD_MESSAGE(SET_KEY, message, set_key);

	assert(key_length == 32);
	assert(iv_length == 16);

	DBG_PRINT("sendfile_aes_open(%p, %ld, %p, %ld, %d)\n", key_data, key_length, iv_data, iv_length, encrypt);

	DBG_PRINT("enum: %ld, int: %ld, off_t*: %ld, size_t: %ld, SENDFILE_AES_SET_KEY:%ld\n",
		   sizeof(enum e_message_type),
		   sizeof(int),
		   sizeof(off_t*),
		   sizeof(size_t),
		   sizeof(message)
		  );

	memcpy(set_key->key_data, key_data, key_length);
	set_key->key_length = key_length;
	memcpy(set_key->iv_data, iv_data, iv_length);
	set_key->iv_length = iv_length;
	set_key->encrypt = encrypt;

	DBG_PRINT("Dumping message struct \n\t"
		   "sizeof(message): %ld\n\t"
		   "message_type: %d\n\t"
		   "key_length: %d\n\t"
		   "key_data: [",
		   sizeof(message), message.message_type, set_key->key_length);

	{
		int i;
		for (i = 0; i < set_key->key_length; i++)
			DBG_PRINT("%02x", (unsigned char) set_key->key_data[i]);
		DBG_PRINT("]\n\t");
	}
	DBG_PRINT("iv_data: [");
	{
		int i;
		for (i = 0; i < set_key->iv_length; i++)
			DBG_PRINT("%02x", (unsigned char) set_key->iv_data[i]);
		DBG_PRINT("]\n\t");
	}
	DBG_PRINT("encrypt: %d\n", set_key->encrypt);

	if ((fd = open("/dev/sendfile_aes", O_RDWR)) < 0) {
		perror("open");
		return -1;
	}

	if (write(fd, &message, sizeof(message)) < 0) {
		perror ("write error");
		return -1;
	}

	if (read(fd, buf, sizeof(buf)) < 0) {
		perror ("read error");
	}
	DBG_PRINT("sendfile_aes read: %d\n", *((int*)buf));

	return fd;
}

int sendfile_aes_send(int fd, int out_fd, int in_fd, off_t *offset, size_t count)
{
	int ret = -1;
	SENDFILE_AES_BUILD_MESSAGE(SENDFILE, message, payload);
	payload->out_fd = out_fd;
	payload->in_fd = in_fd;
	payload->offset = offset;
	payload->count = count;

	ret = write(fd, &message, sizeof(message));
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
