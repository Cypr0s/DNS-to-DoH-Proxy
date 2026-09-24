#include "util/strings.h"

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