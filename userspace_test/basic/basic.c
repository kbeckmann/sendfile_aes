#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>

#include "sendfile_aes_client.h"

static int delay_seconds = 0; // TODO: add argument

static void do_delay(void)
{
	if (delay_seconds > 0)
		sleep(delay_seconds);
}

static void die (const char * format, ...)
{
    va_list vargs;
    va_start (vargs, format);
    vfprintf (stderr, format, vargs);
    fprintf (stderr, "\n");
    exit (1);
}

static int print_help(int argc, char **argv)
{
	(void) argc;
	printf("Usage: %s <in_file> <out_file> [key iv [encrypt]]\n"
		"\tkey and iv should be a hex string, 128 or 256 bit long\n"
		"\tencrypt: 1=encrypt, 0=decrypt\n"
		"Note: out_file will not be deleted before it gets over-written.\n",
		argv[0]);
	return -1;
}

static int do_sendfile(char *filename_out, char *filename_in)
{
	struct stat stat_buf;
	off_t offset = 0;
	int in_fd;
	int out_fd;

	in_fd = open(filename_in, O_RDONLY);
	if (in_fd < 0) die("Can't open file: %s", filename_in);

	out_fd = open(filename_out, O_WRONLY | O_CREAT, 0644);
	if (out_fd < 0) die("Can't open file: %s", filename_in);

	fstat(in_fd, &stat_buf);
	sendfile(out_fd, in_fd, &offset, stat_buf.st_size);
	do_delay();

	close(out_fd);
	close(in_fd);

	return 0;
}

static int do_sendfile_aes(char *filename_out, char *filename_in,
                           char *key, int key_length, char *iv, int iv_length, int encrypt)
{
	struct stat stat_buf;
	off_t offset = 0;
	int in_fd;
	int out_fd;
	int handle;

	handle = sendfile_aes_open(key, key_length, iv, iv_length, encrypt);
	do_delay();

	in_fd = open(filename_in, O_RDONLY);
	if (in_fd < 0) die("Can't open file: %s", filename_in);

	out_fd = open(filename_out, O_WRONLY | O_CREAT, 0644);
	if (out_fd < 0) die("Can't open file: %s", filename_in);

	fstat(in_fd, &stat_buf);
	sendfile_aes_send(handle, out_fd, in_fd, &offset, stat_buf.st_size);
	do_delay();

	sendfile_aes_close(handle);
	close(out_fd);
	close(in_fd);

	return 0;
}

static int hex_to_char(char c)
{
	if (c >= '0' && c <= '9') return      c - '0';
	if (c >= 'A' && c <= 'F') return 10 + c - 'A';
	if (c >= 'a' && c <= 'f') return 10 + c - 'a';
	return -1;
}

static void parse_hex(char *buf, int *size, char *hex)
{
	int len = strlen(hex);
	int i;

	if (len % 2 == 1) {
		printf("Invalid hex length\n");
		*size = 0;
		return;
	}

	if (len / 2 > *size) {
		printf("Hex too long\n");
		*size = 0;
		return;
	}

	for (i = 0; i < len / 2; i++, hex += 2) {
		int c1 = hex_to_char(hex[0]);
		int c2 = hex_to_char(hex[1]);
		if (c1 == -1 || c2 == -1) {
			printf("Invalid character in hex: @%d: %c%c\n", i, hex[0], hex[1]);
			*size = 0;
			return;
		}
		buf[i] = (c1 << 4) | c2;
	}

	*size = len / 2;
}

int main(int argc, char **argv)
{
	char *filename_in = argv[1];
	char *filename_out = argv[2];
	char key[128];
	int key_length = sizeof(key);
	char iv[128];
	int iv_length = sizeof(iv);
	int encrypt = 1;

	switch (argc) {
	case 3:
		return do_sendfile(filename_out, filename_in);
	case 6:
		encrypt = argv[5][0] == '1' ? 1 : 0;
	case 5:
		parse_hex(key, &key_length, argv[3]);
		parse_hex(iv, &iv_length, argv[4]);
		if (key_length == 0 || iv_length == 0)
			return -1;
		return do_sendfile_aes(filename_out, filename_in, key, key_length, iv, iv_length, encrypt);
	default:
		return print_help(argc, argv);
	}
}
