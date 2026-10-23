#ifndef UTIL_FILE_H
#define UTIL_FILE_H

#include <stdio.h>
#include "error.h"
#include <stdint.h>
#include "common.h"
#include <ctype.h>

ExitStatus openFile(FILE** fp, const char* filename);

void removeComment(char* line, const char comment_delimeter);

char* getToken(char** line);

typedef struct {
    char* filename;
    size_t line;
} DNSFileContext, *DNSFileContextPtr;


static inline int8_t allowedCharacterCheck(const char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-';
}

#endif // UTIL_FILE_H