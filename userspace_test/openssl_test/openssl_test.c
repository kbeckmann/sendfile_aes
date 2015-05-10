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



#define CHUNK_SIZE 1024 * 10
#define MAX_PADDING 32

# define AES_MAXNR 14
# define AES_BLOCK_SIZE 16

struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;



// TODO use cpuid
//#define HAS_AESNI

#ifdef HAS_AESNI
#define AES_SET_ENCRYPT_KEY(...) aesni_set_encrypt_key(__VA_ARGS__)
#define AES_SET_DECRYPT_KEY(...) aesni_set_decrypt_key(__VA_ARGS__)
#define AES_CBC_ENCRYPT(...) aesni_cbc_encrypt(__VA_ARGS__)
#else
#define AES_SET_ENCRYPT_KEY(...) vpaes_set_encrypt_key(__VA_ARGS__)
#define AES_SET_DECRYPT_KEY(...) vpaes_set_decrypt_key(__VA_ARGS__)
#define AES_CBC_ENCRYPT(...) vpaes_cbc_encrypt(__VA_ARGS__)
#endif


// VP-AES
int vpaes_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

// AES-NI
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
                   const AES_KEY *key);

void aesni_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);

/* Used from assembly aesni_* */
extern unsigned int OPENSSL_ia32cap_P[4];
unsigned int OPENSSL_ia32cap_P[4] = {0};

#define VPAES_ASM
#define BSAES_ASM
#define AESNI_ASM


#  ifdef VPAES_ASM
#   define VPAES_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(41-32)))
#  endif
#  ifdef BSAES_ASM
#   define BSAES_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(41-32)))
#  endif
/*
 * AES-NI section
 */
#  define AESNI_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(57-32)))




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

void OPENSSL_cpuid_setup(void)
{
	unsigned long long vec;
	unsigned long long OPENSSL_ia32_cpuid(unsigned int *);

	vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);

    /*
     * |(1<<10) sets a reserved bit to signal that variable
     * was initialized already... This is to avoid interference
     * with cpuid snippets in ELF .init segment.
     */
    OPENSSL_ia32cap_P[0] = (unsigned int)vec | (1 << 10);
    OPENSSL_ia32cap_P[1] = (unsigned int)(vec >> 32);
}

int main(int argc, char **argv)
{
	char *input[] = {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
					 /*"A\n",
					 "ABCD",
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

	dump("cpuid", OPENSSL_ia32cap_P, sizeof(OPENSSL_ia32cap_P));
	OPENSSL_cpuid_setup();
	dump("cpuid", OPENSSL_ia32cap_P, sizeof(OPENSSL_ia32cap_P));

	printf("VPAES_CAPABLE: %d\n", VPAES_CAPABLE);
	printf("BSAES_CAPABLE: %d\n", BSAES_CAPABLE);
	printf("AESNI_CAPABLE: %d\n", AESNI_CAPABLE);

	if (encrypt) {
		AES_SET_ENCRYPT_KEY(key, (sizeof(key) - 1) * 8, &aes_key);
	} else {
		AES_SET_DECRYPT_KEY(key, (sizeof(key) - 1) * 8, &aes_key);
	}

	/* encrypt and decrypt each input string and compare with the original */
	for (i = 0; input[i]; i++) {
		int n = strlen(input[i]);
		int n2 = n & (~0xf);
		int n_trailing = n & 0xf;

		if ((n2)) {
			AES_CBC_ENCRYPT(input[i], tmp_buf, n2, &aes_key, iv, encrypt);
		}

		if ((n_trailing)) {
			size_t zero_padding = 0x10 - (n_trailing);
			char pad[16];
			memcpy(pad, input[i] + n2, n_trailing);
			memset(pad + n_trailing, zero_padding, zero_padding);
			AES_CBC_ENCRYPT(pad, tmp_buf + n2, sizeof(pad), &aes_key, iv, encrypt);
			printf(" PAD! Wrote %d extra bytes\n", n_trailing);
			n = n2 + sizeof(pad);
		}

		dump("ciphertext", tmp_buf, n);
	}

	return 0;
}

