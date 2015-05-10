/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  Ripped from: https://raw.githubusercontent.com/saju/misc/master/misc/openssl_aes.c

  this is public domain code.

  Saju Pillai (saju.pillai@gmail.com)
**/

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
					 /*"ABCD",
					 "abcd", "this is a test", "this is a bigger test",
					 "\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",*/
					 NULL};
	char key[] = "\x42\x93\x20\x9e\x7a\x46\x38\xbe\x35\xc2\xc2\x91\x53\x3a\x3c\x0b\xe4\x86\x7b\x6b\xd7\x66\x98\x04\x58\xc0\x2b\x3b\x02\x9e\x7d\xf6";
	char iv[] = "\x09\xca\xa1\x9c\x39\x40\x62\x0b\x6b\x97\xa5\x0a\x7e\x2a\x97\x1d";
	char tmp_buf[1024];
	AES_KEY aes_key;
	int encrypt = 1;
	int i;

	(void) argc;


	if (encrypt) {
		aes_auto_set_encrypt_key(key, (sizeof(key) - 1) * 8, &aes_key);
	} else {
		aes_auto_set_decrypt_key(key, (sizeof(key) - 1) * 8, &aes_key);
	}

	/* encrypt and decrypt each input string and compare with the original */
	for (i = 0; input[i]; i++) {
		int n = strlen(input[i]);
		int n2 = n & (~0xf);
		int n_trailing = n & 0xf;

		if ((n2)) {
			aes_auto_cbc_encrypt(input[i], tmp_buf, n2, &aes_key, iv, encrypt);
		}

		if ((n_trailing)) {
			size_t zero_padding = 0x10 - (n_trailing);
			char pad[16];
			memcpy(pad, input[i] + n2, n_trailing);
			memset(pad + n_trailing, zero_padding, zero_padding);
			aes_auto_cbc_encrypt(pad, tmp_buf + n2, sizeof(pad), &aes_key, iv, encrypt);
			printf(" PAD! Wrote %d extra bytes\n", n_trailing);
			n = n2 + sizeof(pad);
		}

		dump("ciphertext", tmp_buf, n);
	}

	return 0;
}

