#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "hotp.h"

void usage()
{
	/* TODO */

	exit(1);
}

int main(int argc, char **argv)
{
	unsigned char *secret = NULL;
	int offset = 3;
	int response;
	int digits = 6;
	int challenge = 0;
	int opt;
	int timestamp;
	unsigned char timestamp_str[8];
	int i;

	while ((opt = getopt(argc, argv, "s:d:c:o:")) != -1) {
		switch (opt) {
		case 's':
			secret = (unsigned char *)optarg;
			break;
		case 'd':
			digits = atoi(optarg);
			break;
		case 'c':
			challenge = atoi(optarg);
			break;
		case 'o':
			offset = atoi(optarg);
			break;
		default:
			fprintf(stderr, "unknown option\n");
		}
	}

	if (!secret || !challenge) {
		usage();
	}

	timestamp = time(NULL) / 60;
	digits = power(10, digits);
	for (i = -offset; i <= offset; i++) {
		c2c(timestamp + i, timestamp_str);
		response = hotp(timestamp_str, secret);
		response = response % digits;

		if (response == challenge) {
			fprintf(stdout, "offset: %d\n", i);
			return 0;
		}
	}

	fprintf(stdout, "token was not found, consider increase the offset\n");

	return 1;
}
