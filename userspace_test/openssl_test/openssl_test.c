#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

static void dump(char *prefix, unsigned char *buf, int size)
{
	int i = 0;
	printf("%s: [", prefix);
	while (size--) {
		if (i++ % 16 == 0) printf("\n ");
		printf("%02x", *buf++);
	}
	printf("]\n");
}

int main(int argc, char **argv)
{
	char *input[] = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			 "AAAAAAAAAAAAAAAA",
       			 "AAAAAAAAAAAAAAA",
			 "A",
			 "",
			};
	unsigned char key[] = "\x42\x93\x20\x9e\x7a\x46\x38\xbe\x35\xc2\xc2\x91\x53\x3a\x3c\x0b\xe4\x86\x7b\x6b\xd7\x66\x98\x04\x58\xc0\x2b\x3b\x02\x9e\x7d\xf6";
	unsigned char iv_start[] = "\x09\xca\xa1\x9c\x39\x40\x62\x0b\x6b\x97\xa5\x0a\x7e\x2a\x97\x1d";
	unsigned char iv[sizeof(iv_start)];
	unsigned char tmp_buf[1024];
	AES_KEY aes_key;
	int encrypt = 1;
	size_t i;

	(void) argc;
	(void) argv;

	if (encrypt) {
		aes_auto_set_encrypt_key(key, (sizeof(key) - 1) * 8, &aes_key);
	} else {
		aes_auto_set_decrypt_key(key, (sizeof(key) - 1) * 8, &aes_key);
	}

	for (i = 0; i < sizeof(input) / sizeof(char*); i++) {
		size_t n = strlen(input[i]);
		int n2 = n & (~0xf);
		int n_trailing;
		int dst_len = 0;
		unsigned char pad[16];
		size_t padding = (0x10 - (n & 0x0f));

		// Reset the IV for each string we process
		memcpy(iv, iv_start, sizeof(iv));

		printf("\n");
		dump("plaintext", (unsigned char*)input[i], n);


		n2 = n & (~0xf);
		if ((n2)) {
			aes_auto_cbc_encrypt((unsigned char*)input[i], tmp_buf, n2, &aes_key, iv, encrypt);
			dst_len += n2;
		}

		// Always write padding in the end
		n_trailing = n & 0xf;
		printf("Padding bytes: %zd, n: %zd\n", padding, n);
		memcpy(pad, input[i] + n2, n_trailing);
		memset(pad + n_trailing, padding, padding);

		aes_auto_cbc_encrypt(pad, tmp_buf + n2, sizeof(pad), &aes_key, iv, encrypt);
		dst_len += sizeof(pad);

		dump("ciphertext", tmp_buf, dst_len);
	}

	return 0;
}
