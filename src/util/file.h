#ifndef UTIL_FILE_H
#define UTIL_FILE_H

#include <stdio.h>
#include "error.h"
#include <stdint.h>
#include "common.h"

ExitStatus openFile(FILE** fp, const char* filename);

void removeComment(char* line, const char comment_delimeter);

char* getToken(char** line);

typedef struct {
    char* filename;
    size_t line;
    uint8_t label_count;
    uint8_t label_length;
    uint8_t token_length;
} DNSFileContext, *DNSFileContextPtr;

inline ExitStatus checkTokenOverFlow(DNSFileContextPtr ctx) {
    return (ctx->token_length >DNS_MAX_TOKEN_LENGTH ||
        ctx->label_count > DNS_MAX_LABEL_COUNT ||
        ctx->label_length > DNS_MAX_LABEL_LENGTH) ? 
        STATUS_EX_CONFIG : STATUS_SUCCESS;
}

inline int8_t allowedCharacterCheck(const char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-';
}

#endif // UTIL_FILE_H