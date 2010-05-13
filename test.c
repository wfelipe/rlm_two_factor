#include <stdio.h>
#include <stdlib.h>

#include "hotp.h"

int main(int argc, char **argv)
{
	int retval;

	retval =
	    check_hotp("/etc/otpfile", 1, 6, "testuser",
		       atoi(argv[1]));

	printf("retval: %d\n", retval);

	return 0;
}
