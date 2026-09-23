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


static inline int8_t allowedCharacterCheck(const char c) {
    return isalnum((unsigned char)c) || c == '.' || c == '_' || c == '-';
}


static ExitStatus addListToTree(StringListPtr list, BlockListTreePtr root) {
    StringListIterator it;
    stringListIterInit(&it, list);
    char* val;
    BlockListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        BlockListTreePtr child = blockListFindNode(tmp, val);

        if(child == NULL) {
            child = blockListCreateNode(val);

            if(child == NULL) {
                return STATUS_MALLOC_FAILURE;
            }

            if(blockListAddChild(tmp, child) != STATUS_SUCCESS) {
                free(child);
                return STATUS_MALLOC_FAILURE;
            }
        } else {
            free(val);
        }

        tmp = child;
    }
    return STATUS_SUCCESS;
}


ExitStatus getBlockListToken(char** line, char** token) {
    while(**line != '\0' && isspace((unsigned char)** line)) {
        (*line)++;
    }
    if(**line == '\0') {
        return STATUS_SUCCESS;
    }

    *token = *line;
    uint8_t cnt = 0;
    while(**line != '\0' && !isspace((unsigned char)** line)) {
        (*line)++; cnt++;
        if(cnt >= BLOCKLIST_MAX_TOKEN_LENGTH) {
            return STATUS_EX_CONFIG;
        }

    }

    if(**line != '\0') {
        **line = '\0';
        (*line)++;
    }
    
    return STATUS_SUCCESS;
}

ExitStatus processToken(char* token, BlockListTreePtr root, BlockListCtxPtr ctx) {
    for(size_t i = 0; i < ARRAY_SIZE(ignored_blocks); i++) {
        if(!strcmp(ignored_blocks[i], token)) {
        return STATUS_SUCCESS;
        }
    }
    // check sizes, validate characters
    StringList list;
    stringListInit(&list);
    ExitStatus e = checkAndLabelizeToken(token,  ctx, &list);

    if(e) {
        stringListDestroyFree(&list);
        return e;
    }

    e = addListToTree(&list, root);
    if(e) {
        stringListDestroyFree(&list);
        return e;
    }
    stringListDestroyFree(&list);
    ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
    ctx->flags |= BLOCKLIST_IS_FIRST_TOKEN;
    return STATUS_SUCCESS;
}





ExitStatus checkAndLabelizeToken(char* token, BlockListCtxPtr ctx, StringListPtr list) {
    char* label_start = token;
    while(*token != '\0') {
        if(ctx->label_count > BLOCKLIST_MAX_LABEL_COUNT) {
            stringListDestroyFree(list);
            return STATUS_EX_CONFIG;
        }

        if(ctx->label_length > BLOCKLIST_MAX_LABEL_LENGTH) {
            stringListDestroyFree(list);
            return STATUS_EX_CONFIG;
        }

        if(*token == '.') {
            if(ctx->flags & BLOCKLIST_IS_ONLY_NUMBERS) {
                ctx->label_count++;
                ctx->label_length = 0;
                (*token)++;
                label_start = token;
                continue;
            }

            if(ctx->label_length == 0) {
                stringListDestroyFree(list);
                return STATUS_EX_CONFIG;
            }

            char* list_entry = malloc(sizeof(char) * (ctx->label_length + 1));
            if(list_entry == NULL) {
                stringListDestroyFree(list);
                return STATUS_MALLOC_FAILURE;
            }

            *token = '\0';
            strcpy(list_entry, label_start);

            if(stringListInsert(list, list_entry)) {
                free(list_entry);
                stringListDestroyFree(list);
                return STATUS_MALLOC_FAILURE;
            }
            ctx->label_count++;
            ctx->label_length = 0;
            token++;
            label_start = token;
            continue;
        }

        if((ctx->flags & BLOCKLIST_IS_FIRST_TOKEN) && *token == ':') {
            stringListDestroyFree(list);
            return STATUS_EX_CONFIG;
        }

        if((ctx->flags & BLOCKLIST_IS_ONLY_NUMBERS) && (*token < '0' || *token > '9')) {
            ctx->flags &= ~BLOCKLIST_IS_ONLY_NUMBERS;
        }

        if(!allowedCharacterCheck(*token)) {
            stringListDestroyFree(list);
            return STATUS_EX_CONFIG;
        }

        ctx->label_length++;
        token++;
    }

    return STATUS_SUCCESS;
}


static ExitStatus parseFile(FILE* fp, BlockListTreePtr root, BlockListCtxPtr ctx) {
    char* line_str = NULL;
    size_t line_str_capacity = 0;
    while(getdelim(&line_str, &line_str_capacity, '\n', fp) != -1) {
        removeComment(line_str, '#');
        char* token = NULL;
        char* tmp = line_str;
        ExitStatus e = getBlockListToken(&tmp, &token);
        if(e) {
            free(line_str);
            return e;
        }
        while(token != NULL) {
            e = processToken(token, root, ctx);
            if(e) {
                free(line_str);
                return e;
            }
            e = getBlockListToken(&tmp, &token);
            if(e) {
                free(line_str);
                return e;
            }
            ctx->flags |= BLOCKLIST_IS_ONLY_NUMBERS;
            ctx->label_count = 0;
        }
        ctx->file_print.line++;
    }
    free(line_str);
    return STATUS_SUCCESS;
}


ExitStatus parseBlockList(StringListPtr block_list, BlockListTreePtr root) {
    StringListIterator it;
    stringListIterInit(&it, block_list);
    char* filename = stringListIterNext(&it);
    FILE* fp;
    while(filename != NULL) {
        BlockListCtx ctx = {
            .file_print = {.filename = filename, .line = 1},
            .flags = BLOCKLIST_IS_FIRST_TOKEN | BLOCKLIST_IS_ONLY_NUMBERS,
            .label_count = 0,
            .label_length = 0
        };
        if(openFile(&fp, filename) != STATUS_SUCCESS) {
            // TODO
            return STATUS_EX_CONFIG;
        }
        parseFile(fp, root, &ctx);

        fclose(fp);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}