/**
 * @file    error.c
 * @author  Kristian Luptak
 * @brief   Printing errors onto stderr
 *          copied from: https://github.com/Cypr0s/CyprSH/blob/main/src/error.c
 *          
 * @date    2026-10-23
 */

#include "error.h"


void printErrorMsg(char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}