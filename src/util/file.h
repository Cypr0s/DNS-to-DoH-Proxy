#include <stdio.h>
#include "error.h"

ExitStatus openFile(FILE** fp, const char* filename);

void removeComment(char* line, const char comment_delimeter);

char* getToken(char** line);
typedef struct {
    char* filename;
    size_t line;
} FilePrintContext, *FilePrintContextPtr;