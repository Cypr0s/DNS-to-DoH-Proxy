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


uint8_t isValidDomainName(char* name) {
    if(name == NULL || *name == '\0') {
        return 0;
    }

    if(!strcmp(name, ".")) {
        return 1;
    }

    size_t label_length = 0;
    size_t name_length = 0;
    size_t label_count = 0;

   while(*name != '\0') {
        if(*name == '.') {
            if(*(name + 1) == '\0') {
                if(label_length == 0) {
                    return 0;
                }
                break;
            }

            if(label_length == 0 || label_length > DNS_MAX_LABEL_LENGTH) {
                return 0;
            }

            name_length++;
            label_count++;
            label_length = 0;
            name++;
            continue;
        }

        if (label_length > DNS_MAX_LABEL_LENGTH || 
            name_length > DNS_MAX_TOKEN_LENGTH || 
            label_count > DNS_MAX_LABEL_COUNT || 
            !allowedCharacterCheck(*name)) 
        {
            return 0;
        }
        label_length++;
        name_length++;
        name++;
    }

    label_count++;

    if(label_length > DNS_MAX_LABEL_LENGTH || 
        name_length > DNS_MAX_TOKEN_LENGTH || 
        label_count > DNS_MAX_LABEL_COUNT) 
    {
        return 0;
    }

    return 1;
}