#include "util/file.h"

ExitStatus openFile(FILE** fp, const char* filename) {
    *fp = fopen(filename, "r");
    if(*fp == NULL) {
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}
