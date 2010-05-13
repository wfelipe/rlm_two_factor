/*
 * rlm_two_factor.c
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2010  Wilson Felipe <wfelipe@gmail.com>
 */

#include <freeradius/ident.h>

#include <freeradius/radiusd.h>
#include <freeradius/modules.h>

#include "hotp.h"

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_two_factor_t {
	char *otpfile;
	char *delim;
	int challenge_length;
	int offset;
} rlm_two_factor_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{"otpfile", PW_TYPE_STRING_PTR, offsetof(rlm_two_factor_t, otpfile),
	 NULL, "/etc/otpfile"},
	{"delim", PW_TYPE_STRING_PTR, offsetof(rlm_two_factor_t, delim),
	 NULL, ":"},
	{"challenge_length", PW_TYPE_INTEGER,
	 offsetof(rlm_two_factor_t, challenge_length), NULL, "6"},
	{"offset", PW_TYPE_INTEGER, offsetof(rlm_two_factor_t, offset), NULL,
	 "3"},

	{NULL, -1, 0, NULL, NULL}	/* end the list */
};

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int two_factor_instantiate(CONF_SECTION * conf, void **instance)
{
	rlm_two_factor_t *inst;

	/*
	 *      Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *      If the configuration parameters can't be parsed, then
	 *      fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	Authenticate the user with the given password.
 */
static int two_factor_authenticate(void *instance, REQUEST * request)
{
	rlm_two_factor_t *inst = instance;
	char passwd[MAX_STRING_LEN];
	char challenge[MAX_STRING_LEN];
	int clength = inst->challenge_length;
	int retval;

	if (!request->username || !request->password) {
		radlog(L_AUTH,
		       "rlm_two_factor: Attribute User-Name or User-Password is missing and it's required for authentication.");
		return RLM_MODULE_INVALID;
	}

	if (strlen(request->password->vp_strvalue) < clength) {
		radlog(L_AUTH,
		       "rlm_two_factor: Attribute User-Password is lower than challenge length: %d.",
		       clength);
		return RLM_MODULE_INVALID;
	}

	memcpy(challenge, request->password->vp_strvalue, clength);
	memset(challenge + clength + 1, '\0', 1);
	memcpy(passwd,
	       request->password->vp_strvalue + (sizeof(char) * clength),
	       strlen(request->password->vp_strvalue) - clength + 1);
	strcpy(request->password->vp_strvalue, passwd);

	/* check OTP */
	retval = check_hotp
	    (inst->otpfile, inst->offset, clength,
	     request->username->vp_strvalue, atoi(challenge));
	/*
	 * 0: wrong validation
	 * 1: validation was correct and return ok
	 * -1: could not read otpfile
	 * -2: user not found in otpfile
	 */
	switch (retval) {
	case 1:
		return RLM_MODULE_OK;
	case 0:
		radlog(L_AUTH,
		       "rlm_two_factor: validation of token for user %s was not correct.",
		       request->username->vp_strvalue);
		return RLM_MODULE_REJECT;
	case -1:
		radlog(L_AUTH,
		       "rlm_two_factor: could not read otpfile %s.",
		       inst->otpfile);
		return RLM_MODULE_REJECT;
	case -2:
		radlog(L_AUTH, "rlm_two_factor: user %s not found.",
		       request->username->vp_strvalue);
		return RLM_MODULE_REJECT;
	default:
		radlog(L_AUTH, "rlm_two_factor: unknown error %d.", retval);
		return RLM_MODULE_REJECT;
	}
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int two_factor_detach(void *instance)
{
	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_two_factor = {
	RLM_MODULE_INIT,
	"two_factor",
	RLM_TYPE_THREAD_SAFE,	/* type */
	two_factor_instantiate,	/* instantiation */
	two_factor_detach,	/* detach */
	{
	 two_factor_authenticate,	/* authentication */
	 NULL,			/* authorization */
	 NULL,			/* preaccounting */
	 NULL,			/* accounting */
	 NULL,			/* checksimul */
	 NULL,			/* pre-proxy */
	 NULL,			/* post-proxy */
	 NULL			/* post-auth */
	 }
	,
};
