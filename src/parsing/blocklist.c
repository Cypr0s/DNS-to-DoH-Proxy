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

inline int8_t allowedCharacterCheck(const char c);
static ExitStatus addListToTree(StringListPtr list, BlockListTreePtr root);
static ExitStatus processToken(char* token, BlockListTreePtr root, BlockListCtxPtr ctx);
static ExitStatus AddLabelToList(char* label, BlockListCtxPtr ctx, StringListPtr list);
static ExitStatus LabelizeToken(char* token, BlockListCtxPtr ctx, StringListPtr list);
static ExitStatus parseFile(FILE* fp, BlockListTreePtr root, BlockListCtxPtr ctx);


static ExitStatus addListToTree(StringListPtr list, BlockListTreePtr root) {
    if(list->head == NULL) {
        return STATUS_SUCCESS;
    }

    StringListIterator it;
    stringListIterInit(&it, list);
    char* val;
    BlockListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        BlockListTreePtr child = blockListTreeFindNode(tmp, val);

        if(child == NULL) {
            child = blockListTreeCreateNode(val, 0);

            if(child == NULL) {
                PRINT_ERROR("Memory allocation failure");
                return STATUS_MALLOC_FAILURE;
            }

            if(blockListTreeAddChild(tmp, child) != STATUS_SUCCESS) {
                free(child);
                PRINT_ERROR("Memory allocation failure");
                return STATUS_MALLOC_FAILURE;
            }
        } else {
            free(val);
        }

        tmp = child;
    }
    tmp->is_blocked = 1;
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
    ExitStatus e = LabelizeToken(token,  ctx, &list);
    CHECK_ERR_AND_FREE(e, stringListDestroyFree(&list););
    
    // add to tree
    e = addListToTree(&list, root);
    stringListDestroyFree(&list);
    CHECK_ERR(e);
    ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
    return STATUS_SUCCESS;
}


static ExitStatus AddLabelToList(char* label, BlockListCtxPtr ctx, StringListPtr list) {
    char* list_entry = malloc(sizeof(char) * (ctx->dns_context.label_length + 1));
    if(list_entry == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    strcpy(list_entry, label);

    if(stringListInsert(list, list_entry)) {
        free(list_entry);
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }
    return STATUS_SUCCESS;
}


static ExitStatus LabelizeToken(char* token, BlockListCtxPtr ctx, StringListPtr list) {
    char* label_start = token;
    while(*token != '\0') {
        ctx->dns_context.token_length++;
        ExitStatus e = checkTokenOverFlow(ctx);
        CHECK_ERR_AND_FREE(e, PRINT_BLOCKLIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Token overflow"););

        if(*token == '.') {
            if(ctx->dns_context.label_length == 0) {
                if(*(token + 1) == '\0') {
                    break;
                } else {
                    PRINT_BLOCKLIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Empty label");
                    return STATUS_EX_CONFIG;
                }
            }

            *token = '\0';
            e = AddLabelToList(label_start, ctx, list);
            CHECK_ERR(e);
            ctx->dns_context.label_count++;
            ctx->dns_context.label_length = 0;
            token++;
            label_start = token;
            continue;
        }

        if((ctx->flags & BLOCKLIST_IS_FIRST_TOKEN) && *token == ':') {
            stringListDestroyFree(list);// makes so nothing will be inserted into tree, without error (essentially skip)
            return STATUS_SUCCESS;
        }

        if((ctx->flags & BLOCKLIST_IS_ONLY_NUMBERS) && (*token < '0' || *token > '9')) {
            ctx->flags &= ~BLOCKLIST_IS_ONLY_NUMBERS;
        }

        if(!allowedCharacterCheck(*token)) {
            PRINT_BLOCKLIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Label with invalid character");
            return STATUS_EX_CONFIG;
        }

        ctx->dns_context.label_length++;
        token++;
    }

    if(ctx->dns_context.label_length > 0) {
        ExitStatus e = AddLabelToList(label_start, ctx, list);
        CHECK_ERR(e);
    }

    if(ctx->flags & BLOCKLIST_IS_ONLY_NUMBERS) {
        stringListDestroyFree(list); // makes so nothing will be inserted into tree, without error (essentially skip)
    }

    return STATUS_SUCCESS;
}


static ExitStatus parseFile(FILE* fp, BlockListTreePtr root, BlockListCtxPtr ctx) {
    char* line_str = NULL;
    size_t line_str_capacity = 0;
    while(getdelim(&line_str, &line_str_capacity, '\n', fp) != -1) {
        ctx->dns_context.line++;
        ctx->flags |= BLOCKLIST_IS_FIRST_TOKEN;
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
            ctx->dns_context.label_count = 0;
            ctx->dns_context.label_length = 0;
            ctx->dns_context.token_length = 0;
    
        } while(token != NULL);
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
            .dns_context = {.filename = filename, .line = 0, .label_count = 0, .label_length = 0, .token_length = 0},
            .flags = BLOCKLIST_IS_FIRST_TOKEN | BLOCKLIST_IS_ONLY_NUMBERS,
        };
        if(openFile(&fp, filename) != STATUS_SUCCESS) {
            PRINT_BLOCKLIST_PARSE_ERROR(filename, 0, "read err");
            return STATUS_EX_CONFIG;
        }
        ExitStatus e = parseFile(fp, root, &ctx);
        fclose(fp);
        CHECK_ERR(e);
        if(ctx.dns_context.line == 0) {
            PRINT_BLOCKLIST_PARSE_ERROR(filename, 0, "read err");
            return STATUS_EX_CONFIG;
        }
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}