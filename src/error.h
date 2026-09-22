

#include <stdlib.h>
#include <errno.h>

typedef enum {
    STATUS_SUCCESS = EXIT_SUCCESS,
    STATUS_FAILURE = EXIT_FAILURE,
    STATUS_EX_USAGE = 64,
    STATUS_EX_CONFIG = 78,
    STATUS_MALLOC_FAILURE = 99,
} ExitStatus;

#define CHECK_ERR(status) do {      \
    if(status != STATUS_SUCCESS) {  \
        return status;              \
    }                               \
} while(0);