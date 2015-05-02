#include <stddef.h>

#pragma pack(4)

enum e_message_type {
	MESSAGE_TYPE_SET_KEY = 1,
	MESSAGE_TYPE_GET_KEY,
	MESSAGE_TYPE_SENDFILE
};

struct T_SENDFILE_AES_SET_KEY {
	int key_length;
	int iv_length;
	char key_data[32];
	char iv_data[16];
};

struct T_SENDFILE_AES_GET_KEY {
};

struct T_SENDFILE_AES_SENDFILE {
	int out_fd;
	int in_fd;
	off_t *offset;
	size_t count;
};


#define SENDFILE_AES_SET_KEY(_key_length_, _instance_) \
struct { \
  enum e_message_type message_type; \
  int key_length; \
  char key_data[(_key_length_)]; \
} (_instance_); \
(_instance_).message_type = MESSAGE_TYPE_SET_KEY; \
(_instance_).key_length = (_key_length_);


#define SENDFILE_AES_BUILD_MESSAGE(_message_payload_, _instance_, _payload_) \
struct { \
  enum e_message_type message_type; \
  struct T_SENDFILE_AES_##_message_payload_ payload; \
} _instance_ = { \
  .message_type = MESSAGE_TYPE_##_message_payload_, \
}; \
struct T_SENDFILE_AES_##_message_payload_ *_payload_ = &_instance_.payload;
