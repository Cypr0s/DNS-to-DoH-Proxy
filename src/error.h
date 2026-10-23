/**
 * @file    error.h
 * @author  Kristian Luptak
 * @brief   Printing errors onto stderr, checking errors
 *          copied from: https://github.com/Cypr0s/CyprSH/blob/main/src/error.c
 *          
 * @date    2026-10-23
 */

#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>


#define CHECK_ERR(status) do {      \
    if(status != STATUS_SUCCESS) {  \
        return status;              \
    }                               \
} while(0);

#define CHECK_ERR_AND_FREE(status, ...) do {    \
    if(status != STATUS_SUCCESS) {              \
        __VA_ARGS__;                            \
        return status;                          \
    }                                           \
} while(0);

#define CHECK_CURL(status) do {     \
    if(status != CURLE_OK) {        \
        return status;              \
    }                               \
} while(0);

typedef enum {
    STATUS_SUCCESS = EXIT_SUCCESS,
    STATUS_FAILURE = EXIT_FAILURE,
    STATUS_EX_USAGE = 64,
    STATUS_EX_UNAVAIABLE = 69,
    STATUS_EX_CONFIG = 78,
    STATUS_MALLOC_FAILURE = 99,
    STATUS_CONNECTION_CLOSED = -1,
    STATUS_FORWARDED_QUERY_SENT = -2
} ExitStatus;


/**
 * @brief           Prints message into stderr
 * 
 * @param format    Format of the message eg "aaaa:%s %d"
 * @param ...       Format parameters
 */
void printErrorMsg(char* format, ...);

// 
#define PRINT_FILELIST_PARSE_ERROR(file, line, msg) (printErrorMsg("%s:%zu: %s", file, line, msg))
#define PRINT_ARGUMENT_PARSE_ERROR(format, ...) (printErrorMsg(format, __VA_ARGS__))
#define PRINT_LISTENING_SOCKET(address, port) (printErrorMsg("listening on %s:%u", address, port))
#define PRINT_LISTENING_SOCKET_V6(address, port) (printErrorMsg("listening on [%s]:%u", address, port))
#define PRINT_ERROR(...) (printErrorMsg(__VA_ARGS__))

#endif // ERROR_H