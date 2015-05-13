#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

struct aes_key_st {
# ifdef AES_LONG
    unsigned long rd_key[4 * (AES_MAXNR + 1)];
# else
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
# endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;


int aes_auto_set_encrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
int aes_auto_set_decrypt_key(const unsigned char *userKey, int bits,
                          AES_KEY *key);
void aes_auto_cbc_encrypt(const unsigned char *in,
                       unsigned char *out,
                       size_t length,
                       const AES_KEY *key, unsigned char *ivec, int enc);
void aes_auto_teardown(AES_KEY *key);

void OPENSSL_cpuid_setup(void);
