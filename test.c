#include <stdio.h>
#include <stdlib.h>
#include "sha.h"

int main(int argc, char *argv[])
{
	SHA_CTX ctx;
	unsigned char buf[1024];
	unsigned char md[20];
	FILE *fp;
	int i, nread;

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Open failed\n");
		exit(-1);
	}

	SHA_init(&ctx);
	while (!feof(fp)) {
		nread = fread(buf, 1, sizeof(buf), fp);
		SHA_update(&ctx, buf, nread);
	}
	SHA_final(md, &ctx);

	for (i = 0; i < 20; i++)
		printf("%02x", md[i]);
	printf("\n");

	return 0;
}

