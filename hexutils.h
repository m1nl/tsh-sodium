#ifndef _HEXUTILS_H
#define _HEXUTILS_H

#include <string.h>

unsigned char hex2bin(const char *str, unsigned char *bytes, size_t blen);
unsigned char bin2hex(const unsigned char *bytes, size_t blen, char *str, size_t slen);

#endif /* hexutils.h */
