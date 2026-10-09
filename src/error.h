#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <errno.h>
#include <stdarg.h> // va_list, va_start, va_end
#include <stdio.h> // vprintf, fprintf, stderr


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

typedef enum {
    STATUS_SUCCESS = EXIT_SUCCESS,
    STATUS_FAILURE = EXIT_FAILURE,
    STATUS_EX_USAGE = 64,
    STATUS_EX_UNAVAIABLE = 69,
    STATUS_EX_CONFIG = 78,
    STATUS_MALLOC_FAILURE = 99,
    STATUS_CONNECTION_CLOSED = -1
} ExitStatus;


void printErrorMsg(char* format, ...);

#define PRINT_FILELIST_PARSE_ERROR(file, line, msg) (printErrorMsg("%s:%zu: %s", file, line, msg))
#define PRINT_ARGUMENT_PARSE_ERROR(format, ...) (printErrorMsg(format, __VA_ARGS__))
#define PRINT_LISTENING_SOCKET(address, port) (printErrorMsg("listening on %s:%u", address, port))
#define PRINT_LISTENING_SOCKET_V6(address, port) (printErrorMsg("listening on [%s]:%u", address, port))
#define PRINT_ERROR(...) (printErrorMsg(__VA_ARGS__))

#endif // ERROR_H