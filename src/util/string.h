#ifndef UTIL_STRING_H
#define UTIL_STRING_H

#include "common.h"
#include "error.h"
#include <stdint.h>
#include <string.h>
#include "file.h"

ssize_t convertStrToNum(char* input, ssize_t min_boundary, ssize_t max_boundary);

uint16_t bytesToUShort(char* input);

uint32_t bytesToUint(char* input);

uint8_t isValidDomainName(char* name);

uint32_t bytesToUint(char* input);

uint16_t bytesToUShort(char* input);

void uShortToBytes(uint16_t value, char *output);

void uIntToBytes(uint32_t value, char *output);

#endif // UTIL_STRING_H