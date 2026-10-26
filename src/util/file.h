/**
 * @file    file.h
 * @author  Kristian Luptak
 * @brief   contains declarations of util funcions for working with files and getting tokens from them
 *          
 * @date    2026-10-23
 */


#ifndef UTIL_FILE_H
#define UTIL_FILE_H

#include <stdio.h>
#include "error.h"
#include <stdint.h>
#include "common.h"
#include <ctype.h>


/**
 * @brief           Opens filename and returns file descriptor
 * 
 * @param fp        Output file descriptor
 * @param filename  Input file name
 * @return ExitStatus 
 */
ExitStatus openFile(FILE** fp, const char* filename);


/**
 * @brief       Sets line index to '\0' when it finds comment delimeter
 * 
 * @param line  Input line
 * @param comment_delimeter
 */
void removeComment(char* line, const char comment_delimeter);


/**
 * @brief       Creates a single token until a ' ' is found
 * 
 * @param line  Input line
 * @return char* token
 */
char* getToken(char** line);

typedef struct {
    char* filename;
    size_t line;
} DNSFileContext, *DNSFileContextPtr;


static inline int8_t allowedCharacterCheck(const char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-';
}

#endif // UTIL_FILE_H