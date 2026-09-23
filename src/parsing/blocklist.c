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

static inline ExitStatus checkTokenOverFlow(BlockListCtxPtr ctx) {
    return (ctx->token_length >BLOCKLIST_MAX_TOKEN_LENGTH ||
        ctx->label_count > BLOCKLIST_MAX_LABEL_COUNT ||
        ctx->label_length > BLOCKLIST_MAX_LABEL_LENGTH) ? 
        STATUS_EX_CONFIG : STATUS_SUCCESS;
}

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


static ExitStatus processToken(char* token, BlockListTreePtr root, BlockListCtxPtr ctx) {
    for(size_t i = 0; i < ARRAY_SIZE(ignored_blocks); i++) {
        if(!strcmp(ignored_blocks[i], token)) {
            return STATUS_SUCCESS;
        }
    }
    // check sizes, validate characters
    StringList list;
    stringListInit(&list);
    ExitStatus e = checkAndLabelizeToken(token,  ctx, &list);
    CHECK_ERR_AND_FREE(e, stringListDestroyFree(&list););
    
    // add to tree
    e = addListToTree(&list, root);
    stringListDestroyFree(&list);
    CHECK_ERR(e);
    ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
    return STATUS_SUCCESS;
}



static ExitStatus checkAndLabelizeToken(char* token, BlockListCtxPtr ctx, StringListPtr list) {
    char* label_start = token;
    while(*token != '\0') {
        ctx->token_length++;
        ExitStatus e = checkTokenOverFlow(ctx);
        CHECK_ERR_AND_FREE(e, stringListDestroyFree(list););

        if(*token == '.') {
            // function insert into list, TODO
            if(ctx->flags & BLOCKLIST_IS_ONLY_NUMBERS) {
                ctx->label_count++;
                ctx->label_length = 0;
                (*token)++;
                label_start = token;
                continue;
            }

            if(ctx->label_length == 0) {
                return STATUS_EX_CONFIG;
            }

            char* list_entry = malloc(sizeof(char) * (ctx->label_length + 1));
            if(list_entry == NULL) {
                return STATUS_MALLOC_FAILURE;
            }

            *token = '\0';
            strcpy(list_entry, label_start);

            if(stringListInsert(list, list_entry)) {
                free(list_entry);
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
    if()

    return STATUS_SUCCESS;
}


static ExitStatus parseFile(FILE* fp, BlockListTreePtr root, BlockListCtxPtr ctx) {
    char* line_str = NULL;
    size_t line_str_capacity = 0;
    while(getdelim(&line_str, &line_str_capacity, '\n', fp) != -1) {
        removeComment(line_str, '#');
        char* token = NULL;
        char* tmp = line_str;
        do {
            token = getToken(&tmp);
            if(token != NULL) {
                ExitStatus e = processToken(token, root, ctx);
                CHECK_ERR_AND_FREE(e, free(line_str););
            }
            ctx->flags |= BLOCKLIST_IS_ONLY_NUMBERS;
            ctx->label_count = 0;
            ctx->label_length = 0;
            ctx->token_length = 0;
    
        } while(token != NULL);
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