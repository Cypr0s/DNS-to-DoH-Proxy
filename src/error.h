

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
    }                                           \
} while(0);

typedef enum {
    STATUS_SUCCESS = EXIT_SUCCESS,
    STATUS_FAILURE = EXIT_FAILURE,
    STATUS_EX_USAGE = 64,
    STATUS_EX_CONFIG = 78,
    STATUS_MALLOC_FAILURE = 99,
} ExitStatus;


void printErrorMsg(char* format, ...);

#define PRINT_BLOCKLIST_PARSE_ERROR(file, line, msg) (printErrorMsg("%s:%s:%s", file, line, msg))
#define PRINT_ARGUMENT_PARSE_ERROR(format, ...) (printErrorMsg(format, __VA_ARGS__))