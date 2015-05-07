#include <sys/types.h>

int sendfile_aes_open(char* key_data, size_t key_length, char* iv_data, size_t iv_length, int encrypt);
int sendfile_aes_send(int fd, int out_fd, int in_fd, off_t *offset, size_t count);
int sendfile_aes_close(int fd);

