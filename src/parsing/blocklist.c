#include "parsing/blocklist.h"

static const char* ignored_blocks[] = {
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts"
};


static inline int8_t allowedCharacterCheck(const char c);
static ExitStatus processEntry(const char* entry, size_t full_entry_length, BlockListTreePtr root);


static inline int8_t allowedCharacterCheck(const char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-';
}


static ExitStatus processEntry(const char* entry, size_t full_entry_length, BlockListTreePtr root) {
    size_t label_start = 0;

    for(size_t i = 0; i < ARRAY_SIZE(ignored_blocks); i++) {
        if(!strcmp(ignored_blocks[i], entry)) {
            return STATUS_SUCCESS;
        }
    }
    StringList s;
    stringListInit(&s);
    for (size_t i = 0; i <= full_entry_length; i++) {
        if (i == full_entry_length || entry[i] == '.') {
            size_t label_length = i - label_start;
            char* label = malloc(sizeof(char) * (label_length + 1));
            if(label == NULL) {
                stringListDestroyFree(&s);
                return STATUS_MALLOC_FAILURE;
            }
            memcpy(label, entry + label_start, label_length);
            label[label_length] = '\0';
            if(stringListInsert(&s, label)) {
                free(label);
                stringListDestroyFree(&s);
                return STATUS_MALLOC_FAILURE;
            }
            label_start = i + 1;
        }
    }
    StringListIterator it;
    stringListIterInit(&it, &s);
    char* val;
    BlockListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        BlockListTreePtr child = blockListFindNode(tmp, val);

        if(child == NULL) {
            child = blockListCreateNode(val);

            if(child == NULL) {
                free(val);
                stringListDestroyFree(&s);
                return STATUS_MALLOC_FAILURE;
            }

            if(blockListAddChild(tmp, child) != STATUS_SUCCESS) {
                free(child);
                free(val);
                stringListDestroyFree(&s);
                return STATUS_MALLOC_FAILURE;
            }
        } else {
            free(val);
        }

        tmp = child;
    }
    stringListDestroy(&s);
    return STATUS_SUCCESS;
}


ExitStatus parseBlockList(StringListPtr block_list, BlockListTreePtr root) {
    StringListIterator it;
    stringListIterInit(&it, block_list);
    char* filename = stringListIterNext(&it);
    FILE* fp;
    while(filename != NULL) {
        if(openFile(&fp, filename) != STATUS_SUCCESS) {
            // TODO
            return STATUS_EX_CONFIG;
        }
        size_t line_cnt = 1;
        char* line_str = 0;
        size_t line_str_capacity = 0;
        ssize_t line_char_count;
        while((line_char_count = getdelim(&line_str, &line_str_capacity, '\n', fp)) != -1) {
            if(line_str[0] == '\n') {
                continue;
            }
            char entry[MAX_BLOCKLIST_ENTRY_LENGTH + 1];
            size_t full_entry_length = 0;
            int8_t only_digits = 1;
            uint8_t label_count = 1;
            int8_t label_length = 0;
            int8_t is_first_entry = 1;
            int8_t entry_has_colon = 0;
            for(size_t i = 0; i < (size_t)line_char_count; i++) {
                char c = line_str[i];

                // character
                if(full_entry_length >= MAX_BLOCKLIST_ENTRY_LENGTH) {
                    // todo
                    free(line_str);
                    fclose(fp);
                    return STATUS_EX_CONFIG;
                }
                // comment (breaks label approved characters so no check here)
                if(c == '#') {
                    break;
                }

                // whitespace token end
                if(isspace((unsigned char)c)) {
                    if(full_entry_length == 0) {
                        continue;
                    }
                    if(only_digits || (is_first_entry && entry_has_colon) ) {
                        full_entry_length = 0;
                        only_digits = 1;
                        label_count = 1;
                        label_length = 0;
                        is_first_entry = 0;
                        entry_has_colon = 0;
                        continue;
                    }

                    entry[full_entry_length] = '\0';
                    if(processEntry(entry, full_entry_length, root) != STATUS_SUCCESS) {
                        // TODO
                        free(line_str);
                        fclose(fp);
                        return STATUS_MALLOC_FAILURE;
                    }

                    full_entry_length = 0;
                    label_count = 1;
                    label_length = 0;
                    only_digits = 1;
                    is_first_entry = 0;
                    continue;
                }

                // check for allowed characters nums, letters, `-`, `.`, `_`
        
                if(is_first_entry) {
                    if(!allowedCharacterCheck(c) && c != ':') {
                        // TODO
                        free(line_str);
                        fclose(fp);
                        return STATUS_EX_CONFIG;
                    }
                    if(c == ':') {
                        entry_has_colon = 1;
                    }
                }  else {
                    if(!allowedCharacterCheck(c)) {
                        // TODO
                        free(line_str);
                        fclose(fp);
                        return STATUS_EX_CONFIG;
                    }
                }

                if(label_count > MAX_BLOCK_LIST_LABEL_COUNT) {
                    // TODO
                    free(line_str);
                    fclose(fp);
                    return STATUS_EX_CONFIG;
                }

                if(c == '.') {
                    if(label_length == 0) {
                        // TODO
                        free(line_str);
                        fclose(fp);
                        return STATUS_EX_CONFIG;
                    }
                    label_count++;
                    label_length = 0;
                } else {
                    label_length++;
                    if(label_length > MAX_LABEL_LETTER_COUNT) {
                        // TODO
                        free(line_str);
                        fclose(fp);
                        return STATUS_EX_CONFIG;
                    }
                }
                if(only_digits && c != '.' && (c <'0'|| c >'9')) {
                    only_digits = 0;
                }
                

                entry[full_entry_length++] = c;
            
            }
            if(full_entry_length > 0 && !only_digits && !(is_first_entry && entry_has_colon)) {
                entry[full_entry_length] = '\0';
                if(processEntry(entry, full_entry_length, root)!= STATUS_SUCCESS) {
                    free(line_str);
                    fclose(fp);
                    return STATUS_MALLOC_FAILURE;
                }
            }
            line_cnt++;
        }
        free(line_str);
        fclose(fp);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}