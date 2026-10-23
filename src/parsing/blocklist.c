// todo complete this file
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
static ExitStatus processToken(char* token, HashTablePtr table, BlockListCtxPtr ctx);
static ExitStatus parseFile(FILE* fp, HashTablePtr table, BlockListCtxPtr ctx);



static ExitStatus processToken(char* token, HashTablePtr table, BlockListCtxPtr ctx) {
    for(size_t i = 0; i < ARRAY_SIZE(ignored_blocks); i++) {
        if(!strcmp(ignored_blocks[i], token)) {
            ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
            return STATUS_SUCCESS;
        }
    }
    // check sizes, validate characters
    if(!isValidDomainName(token)) {
        PRINT_FILELIST_PARSE_ERROR(filename, 0, "read err");
        return STATUS_EX_CONFIG;
    } 

    stringListDestroyFree(&list);
    CHECK_ERR(e);
    ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
    return STATUS_SUCCESS;
}



static ExitStatus parseFile(FILE* fp, HashTablePtr table, BlockListCtxPtr ctx) {
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
                ExitStatus e = processToken(token, table, ctx);
                CHECK_ERR_AND_FREE(e, free(line_str););
            }
    
        } while(token != NULL);
    }
    free(line_str);
    return STATUS_SUCCESS;
}


ExitStatus parseBlockList(StringListPtr block_list, HashTablePtr table) {
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
            PRINT_FILELIST_PARSE_ERROR(filename, 0, "read err");
            return STATUS_EX_CONFIG;
        }
        ExitStatus e = parseFile(fp, table, &ctx);
        fclose(fp);
        CHECK_ERR(e);
        if(ctx.dns_context.line == 0) {
            PRINT_FILELIST_PARSE_ERROR(filename, 0, "read err");
            return STATUS_EX_CONFIG;
        }
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}