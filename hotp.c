#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <time.h>

#include "hotp.h"

/*
 * c2c and hotp were taken from resynctool, from otpd
 * http://sourceforge.net/projects/otpd/
 */
void c2c(uint64_t counter, unsigned char challenge[])
{
	challenge[0] = counter >> 56;
	challenge[1] = counter >> 48;
	challenge[2] = counter >> 40;
	challenge[3] = counter >> 32;
	challenge[4] = counter >> 24;
	challenge[5] = counter >> 16;
	challenge[6] = counter >> 8;
	challenge[7] = counter;
}

long hotp(unsigned char challenge[], unsigned char keyblock[])
{
	uint32_t dbc;		/* "dynamic binary code" from HOTP draft */
	unsigned char md[20];
	unsigned md_len;

	/* 1. hmac */
	(void)HMAC(EVP_sha1(), keyblock, 20, challenge, 8, md, &md_len);

	/* 2. the truncate step is unnecessarily complex */
	{
		int offset;

		offset = md[19] & 0x0F;
		/* we can't just cast md[offset] because of alignment and endianness */
		dbc = (md[offset] & 0x7F) << 24 |
		    md[offset + 1] << 16 | md[offset + 2] << 8 | md[offset + 3];
	}

	return dbc;
}

int find_otpuser(char *otpfile, char *delim, char *username, struct otpuser *ou)
{
	FILE *fd;
	char buffer[255];
	char *aux;

	/* find a better way? */
	fd = fopen(otpfile, "r");
	if (!fd)
		return -1;

	while (fscanf(fd, "%s\n", buffer) != EOF) {
		aux = strtok(buffer, delim);
		if (strcmp(username, aux) != 0)
			continue;

		strcpy(ou->username, aux);
		aux = strtok(NULL, delim);
		ou->offset = atoi(aux);
		aux = strtok(NULL, delim);
		memcpy(ou->secret, aux, strlen(aux));

		fclose(fd);

		return 1;
	}

	fclose(fd);

	/* no user found */
	return -2;
}

int power(int x, int y)
{
	int z = x;

	while (y > 1) {
		z *= x;
		y--;
	}
	return z;
}

int check_hotp(char *otpfile, int offset, int challenge_length, char *username,
	       int challenge)
{
	int i;
	struct otpuser ou;
	int timestamp;
	unsigned char timestamp_str[8];
	long result;
	long base;
	int retval;

	base = power(10, challenge_length);

	retval = find_otpuser(otpfile, ":", username, &ou);
	if (retval != 1)
		return retval;

	timestamp = time(NULL) / 60;
	for (i = ou.offset - offset; i <= ou.offset + offset; i++) {
		c2c(timestamp + i, timestamp_str);
		result = hotp(timestamp_str, ou.secret);
		result = result % base;

		if (result == challenge)
			return 1;
	}

	return 0;
}
