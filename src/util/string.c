#include "util/string.h"

ssize_t convertStrToNum(char* input, ssize_t min_boundary, ssize_t max_boundary) {
    char* end;
    errno = 0;
    ssize_t output = strtol(input, &end, 10);
    if(end == input) {
        return -1;
    }

    if(errno == ERANGE || output < min_boundary || output > max_boundary) {
        return -1;
    }
    return output;
}

uint16_t bytesToUShort(char* input) {
    return (uint16_t)(((unsigned char)input[0] << 8) | (unsigned char)input[1]); 
}

uint32_t bytesToUint(char* input) {
    return (uint32_t)(((unsigned char)input[0] << 24) | ((unsigned char)input[1] << 16) | ((unsigned char)input[2] << 8) | (unsigned char)input[3]);
}

void uShortToBytes(uint16_t value, char *output) {
    output[0] = (char)(value >> 8);
    output[1] = (char)(value & 0xFF);
}

void uIntToBytes(uint32_t value, char *output) {
    output[0] = (char)(value >> 24);
    output[1] = (char)(value >> 16);
    output[2] = (char)(value >> 8);
    output[3] = (char)(value & 0xFF);
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