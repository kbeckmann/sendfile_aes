#include <sys/types.h>

int sendfile_aes_open(size_t key_length, char* key_data);
int sendfile_aes_send(int fd, int out_fd, int in_fd, off_t *offset, size_t count);
int sendfile_aes_close(int fd);

