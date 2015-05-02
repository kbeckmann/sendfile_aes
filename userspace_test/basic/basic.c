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

void do_delay()
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

int print_help(int argc, char **argv)
{
	(void) argc;
	printf("Usage: %s <in_file> <out_file> [key]\n"
		   "Note: out_file will be over-written.\n",
		   argv[0]);
	return -1;
}

int do_sendfile(char *filename_out, char *filename_in)
{
	int in_fd = open(filename_in, O_RDONLY);
	if (in_fd < 0) die("Can't open file: %s", filename_in);

	int out_fd = open(filename_out, O_WRONLY | O_CREAT, 0644);
	if (out_fd < 0) die("Can't open file: %s", filename_in);

	struct stat stat_buf;
	fstat(in_fd, &stat_buf);
	off_t offset = 0;
	sendfile(out_fd, in_fd, &offset, stat_buf.st_size);
	do_delay();

	close(out_fd);
	close(in_fd);

	return 0;
}

int do_sendfile_aes(char *key, char *filename_out, char *filename_in)
{
	char override_key[32] = "\x42\x93\x20\x9e\x7a\x46\x38\xbe\x35\xc2\xc2\x91\x53\x3a\x3c\x0b\xe4\x86\x7b\x6b\xd7\x66\x98\x04\x58\xc0\x2b\x3b\x02\x9e\x7d\xf6";
	key = override_key;
	char iv[16] = "\x09\xca\xa1\x9c\x39\x40\x62\x0b\x6b\x97\xa5\x0a\x7e\x2a\x97\x1d";

	int handle = sendfile_aes_open(key, 32, iv, sizeof(iv));
	do_delay();

	int in_fd = open(filename_in, O_RDONLY);
	if (in_fd < 0) die("Can't open file: %s", filename_in);

	int out_fd = open(filename_out, O_WRONLY | O_CREAT, 0644);
	if (out_fd < 0) die("Can't open file: %s", filename_in);

	struct stat stat_buf;
	fstat(in_fd, &stat_buf);
	off_t offset = 0;
	sendfile_aes_send(handle, out_fd, in_fd, &offset, stat_buf.st_size);
	do_delay();

	sendfile_aes_close(handle);
	close(out_fd);
	close(in_fd);

	return 0;
}

int main(int argc, char **argv)
{
	char *filename_in = argv[1];
	char *filename_out = argv[2];
	char *key = argv[3];

	switch (argc) {
	case 3:
		return do_sendfile(filename_out, filename_in);
	case 4:
		return do_sendfile_aes(key, filename_out, filename_in);
	default:
		return print_help(argc, argv);
	}
}
