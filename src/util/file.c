#include "util/file.h"

ExitStatus openFile(FILE** fp, const char* filename) {
    *fp = fopen(filename, "r");
    if(*fp == NULL) {
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}


void removeComment(char* line, char comment_delimeter) {
    while(*line != '\0') {
        if(*line == comment_delimeter) {
            *line = '\0';
            return;
        }
    }
}
