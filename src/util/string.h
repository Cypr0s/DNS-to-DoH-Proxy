#ifndef UTIL_STRING_H
#define UTIL_STRING_H

#include "common.h"
#include "error.h"
#include <stdint.h>

long convertStrToNum(char* input, size_t min_boundary, size_t max_boundary);

uint16_t bytesToUShort(char* input);

uint32_t bytesToUint(char* input);

uint8_t isValidDomainName(char* name);

static void uShortToBytes(uint16_t value, char *output);

#endif // UTIL_STRING_H