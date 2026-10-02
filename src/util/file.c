#include "util/file.h"

ExitStatus openFile(FILE** fp, const char* filename) {
    *fp = fopen(filename, "r");
    if(*fp == NULL) {
        return STATUS_FAILURE;
    }
    return STATUS_SUCCESS;
}


void removeComment(char* line, const char comment_delimeter) {
    while(*line != '\0') {
        if(*line == comment_delimeter) {
            *line = '\0';
            return;
        }
    }
}


char* getToken(char** line) {
    while(**line != '\0' && isspace((unsigned char)** line)) {
        (*line)++;
    }
    if(**line == '\0') {
        return NULL;
    }

    char* token = *line;
    while(**line != '\0' && !isspace((unsigned char)** line)) {
        (*line)++;
    }

    if(**line != '\0') {
        **line = '\0';
        (*line)++;
    }
    
    return token;
}

