#include "error.h"


/**
 *  https://github.com/Cypr0s/CyprSH/blob/main/src/error.c
 */
void printErrorMsg(char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}