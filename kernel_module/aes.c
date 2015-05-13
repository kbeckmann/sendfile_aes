#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/aes.h>


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
                          struct aes_key_st *key);
int vpaes_set_decrypt_key(const unsigned char *userKey, int bits,
                          struct aes_key_st *key);

void vpaes_encrypt(const unsigned char *in, unsigned char *out,
                   const struct aes_key_st *key);
void vpaes_decrypt(const unsigned char *in, unsigned char *out,
                   const struct aes_key_st *key);

void vpaes_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const struct aes_key_st *key, unsigned char *ivec, int enc);

// AES-NI
int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                          struct aes_key_st *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
                          struct aes_key_st *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
                   const struct aes_key_st *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
                   const struct aes_key_st *key);

void aesni_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const struct aes_key_st *key, unsigned char *ivec, int enc);

// vanilla implementation

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        struct aes_key_st *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        struct aes_key_st *key);

void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t len, const struct aes_key_st *key,
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
                                    int bits, struct aes_key_st *key);
typedef int (*_aes_set_decrypt_key) (const unsigned char *userKey,
                                    int bits, struct aes_key_st *key);
typedef void (*_aes_cbc_encrypt) (const unsigned char *in,
                                unsigned char *out,
                                size_t length,
                                const struct aes_key_st *key, unsigned char *ivec, int enc);
typedef void (*_aes_teardown) (struct aes_key_st *key);


static _aes_set_encrypt_key s_aes_set_encrypt_key;
static _aes_set_decrypt_key s_aes_set_decrypt_key;
static _aes_cbc_encrypt s_aes_cbc_encrypt;
static _aes_teardown s_aes_teardown;









static int aes_linux_set_encrypt_key(const unsigned char *userKey, const int bits,
                        struct aes_key_st *key)
{
	struct crypto_blkcipher **c = (struct crypto_blkcipher **)key;
	int *has_set_iv = ((int*)(&c[1]));

	*has_set_iv = 0;
	*c = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	crypto_blkcipher_setkey(*c, userKey, bits/8);
	
	return 0;
}

static int aes_linux_set_decrypt_key(const unsigned char *userKey, const int bits,
                        struct aes_key_st *key)
{
	return 0;
}

static void aes_linux_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t len, const struct aes_key_st *key,
                     unsigned char *ivec, const int enc)
{
	struct crypto_blkcipher **c = (struct crypto_blkcipher **)key; // yes very ugly
	struct blkcipher_desc desc = { .tfm = *c, .flags = 0 };
	struct scatterlist sg_in[1], sg_out[1];
	int ret;
	int *has_set_iv = ((int*)(&c[1]));
	
	if (!*has_set_iv) {
		void *iv;
		int ivsize;
		iv = crypto_blkcipher_crt(*c)->iv;
		ivsize = crypto_blkcipher_ivsize(*c);
		memcpy(iv, ivec, ivsize);
		*has_set_iv = 1;
	}

	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 1);

	sg_set_buf(&sg_in[0], in, len);
	sg_set_buf(&sg_out[0], out, len);

	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, len);
}

static void aes_linux_teardown(struct aes_key_st *key)
{
	struct crypto_blkcipher **c = (struct crypto_blkcipher **)key;
	crypto_free_blkcipher(*c);
}



static void aes_null_teardown(struct aes_key_st *key)
{
	(void)key;
}

static void print_capabilities(void)
{
	printk("VPAES_CAPABLE: %d\n", VPAES_CAPABLE);
	printk("BSAES_CAPABLE: %d\n", BSAES_CAPABLE);
	printk("AESNI_CAPABLE: %d\n", AESNI_CAPABLE);
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

	s_aes_teardown = aes_null_teardown;

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

	if (1) {
		s_aes_set_encrypt_key = aes_linux_set_encrypt_key;
		s_aes_set_decrypt_key = aes_linux_set_decrypt_key;
		s_aes_cbc_encrypt = aes_linux_cbc_encrypt;
		s_aes_teardown = aes_linux_teardown;
	}
}

int aes_auto_set_encrypt_key(const unsigned char *userKey, int bits,
                          struct aes_key_st *key)
{
	return (*s_aes_set_encrypt_key)(userKey, bits, key);
}

int aes_auto_set_decrypt_key(const unsigned char *userKey, int bits,
                          struct aes_key_st *key)
{
	return s_aes_set_decrypt_key(userKey, bits, key);
}

void aes_auto_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const struct aes_key_st *key, unsigned char *ivec, int enc)
{
	s_aes_cbc_encrypt(in, out, length, key, ivec, enc);
}

void aes_auto_teardown(struct aes_key_st *key)
{
	s_aes_teardown(key);
}
