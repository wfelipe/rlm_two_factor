#ifndef __HOTP_H__
#define __HOTP_H__

#include <inttypes.h>

typedef struct otpuser {
	char username[255];
	unsigned char secret[255];
	int offset;
} otpuser;

int power(int x, int y);
void c2c(uint64_t counter, unsigned char challenge[]);
long hotp(unsigned char challenge[], unsigned char keyblock[]);
int find_otpuser(char *otpfile, char *delim, char *username,
		 struct otpuser *ou);
int check_hotp(char *otpfile, int offset, int challenge_length, char *username,
	       int challenge);

#endif
