#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sendfile_aes_client.h"

int main()
{
	char key[] = "1234abcd567";

	int handle = sendfile_aes_open(strlen(key), key);
	sleep(5);

	off_t offset = 0;
	sendfile_aes_send(handle, 23, 42, &offset, 256);
	sleep(5);

	sendfile_aes_close(handle);

	return 0;
}
