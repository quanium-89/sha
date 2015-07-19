#include <string.h>
#include <endian.h>
#include "sha.h"

void SHA_init(SHA_CTX *ctx)
{
	ctx->r_len = ctx->d_len = 0;

	ctx->digest[0] = 0x67452301;
	ctx->digest[1] = 0xefcdab89;
	ctx->digest[2] = 0x98badcfe;
	ctx->digest[3] = 0x10325476;
	ctx->digest[4] = 0xc3d2e1f0;
}

inline uint32_t rotl32(uint32_t n, int m)
{
	uint32_t mask = ((1 << m) - 1) << (32 - m);
	uint32_t tmp;

	tmp = (n & mask) >> (32 - m);
	n <<= m;
	n |= tmp;
	return n;
}

inline void fill_chunks(uint32_t chunks[])
{
	uint32_t tmp;
	int i;

	for (i = 0; i < 16; i++)
		chunks[i] = htobe32(chunks[i]);

	for (i = 16; i < 80; i++) {
		tmp = chunks[i - 3] ^ chunks[i - 8] ^ chunks[i - 14] ^ chunks[i - 16];
		chunks[i] = rotl32(tmp, 1);
	}
}

inline uint32_t f(int i, uint32_t B, uint32_t C, uint32_t D)
{
	uint32_t ret;

	if (i < 20)
		ret = (B & C) | (~B & D);
	else if (i < 40)
		ret = B ^ C ^ D;
	else if (i < 60)
		ret = (B & C) | (B & D) | (C & D);
	else
		ret = B ^ C ^ D;

	return ret;
}

inline void _SHA_update(SHA_CTX *ctx, uint32_t w, int i)
{
	static uint32_t K[] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
	uint32_t old_A = ctx->digest[0];
	uint32_t k;

	k = (i < 20) ? K[0] : (
			(i < 40) ? K[1] : (
			(i < 60) ? K[2] : K[3]));

	ctx->digest[0] = ctx->digest[4] + rotl32(old_A, 5) + w + k +
			f(i, ctx->digest[1], ctx->digest[2], ctx->digest[3]);
	ctx->digest[4] = ctx->digest[3];
	ctx->digest[3] = ctx->digest[2];
	ctx->digest[2] = rotl32(ctx->digest[1], 30);
	ctx->digest[1] = old_A;
}

void SHA_update(SHA_CTX *ctx, void *data, size_t size)
{
	uint32_t *buf = (uint32_t *)(ctx->buf);
	size_t len, idx;
	int i;

	for (idx = 0; idx != size; ) {
		len = MIN(size - idx, SHA1_BLOCK_LEN - ctx->r_len);
		memcpy(ctx->buf + ctx->r_len, data + idx, len);
		ctx->r_len += len;
		idx += len;
		if (ctx->r_len == SHA1_BLOCK_LEN) {
			ctx->r_len = 0;
			fill_chunks(buf);

			memcpy(ctx->saved_digest, ctx->digest, 20);
			for (i = 0; i < 80; i++)
				_SHA_update(ctx, buf[i], i);
			for (i = 0; i < 5; i++)
				ctx->digest[i] += ctx->saved_digest[i];
		}
	}
	ctx->d_len += size;
}

void SHA_final(uint8_t md[], SHA_CTX *ctx)
{
	uint64_t length = htobe64(((uint64_t)(ctx->d_len)) << 3);
	uint8_t padding;
	size_t fill;
	int i;

	padding = 0x80;
	SHA_update(ctx, &padding, 1);

	padding = 0x0;

	fill = SHA1_BLOCK_LEN - ctx->r_len;
	if (fill < 8) {
		for (i = 0; i < fill; i++)
			SHA_update(ctx, &padding, 1);
	}

	fill = SHA1_BLOCK_LEN - ctx->r_len - 8;
	for (i = 0; i < fill; i++)
		SHA_update(ctx, &padding, 1);
	SHA_update(ctx, &length, 8);

	for (i = 0; i < 5; i++)
		ctx->digest[i] = be32toh(ctx->digest[i]);
	memcpy(md, ctx->digest, 20);
}

