#ifndef _H_SHA
#define _H_SHA

#include <stdint.h>

#define MIN(x, y)  (((x) < (y)) ? (x) : (y))

#define SHA1_BLOCK_LEN  64  /* 512 bits. */

typedef struct sha_st {
	uint8_t buf[SHA1_BLOCK_LEN * 5];
	size_t r_len, d_len;
	uint32_t digest[5];
	uint32_t saved_digest[5];
} SHA_CTX;

#endif

