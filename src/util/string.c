#include "util/string.h"

long convertStrToNum(char* input, size_t min_boundary, size_t max_boundary) {
    char* end;
    errno = 0;
    long output = strtol(input, &end, 10);
    if(end == input) {
        return -1;
    }

    if(errno == ERANGE || output < min_boundary || output > max_boundary) {
        return -1;
    }
    return output;
}

uint16_t bytesToUShort(char* input) {
    return (uint16_t)((input[0] << 8) | input[1]); 
}

uint32_t bytesToUint(char* input) {
    return (uint32_t)((input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3]); 
}