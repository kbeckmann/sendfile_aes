#include <stdlib.h>
#include <stdio.h>

#include "aes.h"

#define CHUNK_SIZE 1024 * 10
#define MAX_PADDING 32





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

// vanilla implementation

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t len, const AES_KEY *key,
                     unsigned char *ivec, const int enc);


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
#  define AESNI_CAPABLE   (OPENSSL_ia32cap_P[1]&(1<<(57-32)))

typedef int (*_aes_set_encrypt_key) (const unsigned char *userKey,
                                    int bits, AES_KEY *key);
typedef int (*_aes_set_decrypt_key) (const unsigned char *userKey,
                                    int bits, AES_KEY *key);
typedef void (*_aes_cbc_encrypt) (const unsigned char *in,
                                unsigned char *out,
                                size_t length,
                                const AES_KEY *key, unsigned char *ivec, int enc);


static _aes_set_encrypt_key s_aes_set_encrypt_key;
static _aes_set_decrypt_key s_aes_set_decrypt_key;
static _aes_cbc_encrypt s_aes_cbc_encrypt;











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

static void print_capabilities(void)
{
	dump("cpuid", (unsigned char*)OPENSSL_ia32cap_P, sizeof(OPENSSL_ia32cap_P));

	printf("VPAES_CAPABLE: %d\n", VPAES_CAPABLE);
	printf("BSAES_CAPABLE: %d\n", BSAES_CAPABLE);
	printf("AESNI_CAPABLE: %d\n", AESNI_CAPABLE);
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

	print_capabilities();

	if (AESNI_CAPABLE) {
		s_aes_set_encrypt_key = &aesni_set_encrypt_key;
		s_aes_set_decrypt_key = &aesni_set_decrypt_key;
		s_aes_cbc_encrypt = &aesni_cbc_encrypt;
	} else if (VPAES_CAPABLE) {
		s_aes_set_encrypt_key = vpaes_set_encrypt_key;
		s_aes_set_decrypt_key = vpaes_set_decrypt_key;
		s_aes_cbc_encrypt = vpaes_cbc_encrypt;
	} else {
		// standard implementation from aes_core.c
		s_aes_set_encrypt_key = AES_set_encrypt_key;
		s_aes_set_decrypt_key = AES_set_decrypt_key;
		s_aes_cbc_encrypt = AES_cbc_encrypt;
	}
}

int aes_auto_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key)
{
	return (*s_aes_set_encrypt_key)(userKey, bits, key);
}

int aes_auto_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key)
{
	return s_aes_set_decrypt_key(userKey, bits, key);
}

void aes_auto_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc)
{
	s_aes_cbc_encrypt(in, out, length, key, ivec, enc);
}


