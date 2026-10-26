/**
 * @file    blocklist.c
 * @author  Kristian Luptak
 * @brief   Contains parsing of blocklists
 *          
 * @date    2026-10-23
 */


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


/**
 * @brief       Processes one blocklist token
 * 
 * @param token Input token
 * @param table Hash table of blocked domains
 * @param ctx   Blocklist context
 * @return      ExitStatus 
 */
static ExitStatus processToken(char* token, HashTablePtr table, BlockListCtxPtr ctx);

/**
 * @brief       Parses blocklist file
 * 
 * @param fp    Opened file
 * @param table Hash table of blocked domains
 * @param ctx   Blocklist context
 * @return      ExitStatus 
 */
static ExitStatus parseFile(FILE* fp, HashTablePtr table, BlockListCtxPtr ctx);



static ExitStatus processToken(char* token, HashTablePtr table, BlockListCtxPtr ctx) {
    for(size_t i = 0; i < ARRAY_SIZE(ignored_blocks); i++) {
        if(!strcasecmp(ignored_blocks[i], token)) {
            ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
            return STATUS_SUCCESS;
        }
    }
    if(strchr(token, ':') && ctx->flags & BLOCKLIST_IS_FIRST_TOKEN) {
        ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
        return STATUS_SUCCESS;
    }

    if(!strcmp(token, ".")) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Root as blocked domain");
        return STATUS_EX_CONFIG;
    }

    // check sizes, validate characters
    if(!isValidDomainName(token)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid domain name");
        return STATUS_EX_CONFIG;
    }

    uint8_t is_only_digit = 1;
    size_t token_length = strlen(token);
    for(size_t i = 0; i < token_length; i++) {
        if(!isdigit(token[i]) && token[i] != '.') {
            is_only_digit = 0;
            break;
        }
    }

    if(is_only_digit) {
        ctx->flags &= ~BLOCKLIST_IS_FIRST_TOKEN;
        return STATUS_SUCCESS;
    }

    for(size_t i = 0; i < token_length; i++) {
        token[i] = tolower(token[i]);
    }

    if(token[token_length - 1] == '.') {
        token[token_length - 1] = '\0';
    }

    ExitStatus e = hashTableInsert(table, token);
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
    stringListIterCtor(&it, block_list);
    char* filename = stringListIterNext(&it);
    FILE* fp;
    while(filename != NULL) {
        BlockListCtx ctx = {
            .dns_context = {.filename = filename, .line = 0},
            .flags = BLOCKLIST_IS_FIRST_TOKEN,
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