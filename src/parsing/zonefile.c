#include "parsing/zonefile.h"

// TODO FINISH THIS PARSING

static ExitStatus createEntry(StringListPtr list, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry) {
    // process items in list one by one
    StringListIterator it; 
    stringListIterInit(&it, list);
    char* first_tok = stringListIterNext(&it);
    if(first_tok != NULL) {
        if(!strcmp(first_tok, "$ORIGIN")) {
            if(ctx->origin != NULL || !(ctx->flags & ZONEFILE_IS_FIRST_ENTRY)) {
                return STATUS_EX_CONFIG;
            }
            
            char* second_tok = stringListIterNext(&it);
            if(second_tok == NULL) {
                return STATUS_EX_CONFIG;
            }

        } else if(!strcmp(first_tok, "$TTL")) {
            if(ctx->ttl != -1) {
                return STATUS_EX_CONFIG;
            }
            char* second_tok = stringListIterNext(&it);
            if(second_tok == NULL) {
                return STATUS_EX_CONFIG;
            }
            long ttl = convertStrToNum(second_tok, ZONEFILE_MIN, ZONEFILE_MINIMUM_MAX);
            if(ttl == -1) {
                return STATUS_EX_CONFIG;
            }
            
        }
    }
}


ExitStatus tokenizeLine(char* line_str, StringListPtr list) {
    char* token = NULL;
    do {
        token = getToken(&line_str);
        if(token != NULL) {
            size_t token_size = strlen(token);
            char* list_entry = malloc(sizeof(char) * (token_size + 1));
            if(list_entry == NULL) {
                    return STATUS_MALLOC_FAILURE;
            }

            strcpy(list_entry, token);

            ExitStatus e = stringListInsert(list, list_entry);
            CHECK_ERR_AND_FREE(e, free(list_entry);); 
        }
    } while(token != NULL);

    return STATUS_SUCCESS;
}


static ExitStatus parseFile(FILE* fp, ZoneFileListTreePtr root, ZoneFileListCtxPtr ctx) {
    char* line_str = NULL;
    size_t line_str_capacity = 0;
    while(getdelim(&line_str, &line_str_capacity, '\n', fp) != -1) {
        if(isspace((unsigned char)*line_str)) {
            ctx->flags |= ZONEFILE_LEADING_WHITESPACE;
        }

        removeComment(line_str, ';');
        StringList list;
        stringListInit(&list);

        ExitStatus e = tokenizeLine(line_str, &list);
        CHECK_ERR_AND_FREE(e, stringListDestroyFree(&list););
        ZoneEntry entry = {0};
        e = createEntry(&list, ctx, &entry);
        CHECK_ERR_AND_FREE(e, stringListDestroyFree(&list););

        ctx->dns_context.line;
        ctx->flags &= ~ZONEFILE_LEADING_WHITESPACE;
    }
    free(line_str);
    return STATUS_SUCCESS;
}


ExitStatus parseZoneList(StringListPtr zone_list, ZoneFileListTreePtr root) {
    StringListIterator it;
    stringListIterInit(&it, zone_list);
    char* filename = stringListIterNext(&it);
    FILE* fp;
    while(filename != NULL) {
        ZoneFileListCtx ctx = {
            .dns_context = {.filename = filename, .line = 1},
            .origin = NULL,
            .ttl = -1,
        };
        if(openFile(&fp, filename) != STATUS_SUCCESS) {
            // TODO
            return STATUS_EX_CONFIG;
        }

        ExitStatus e = parseFile(fp, root, &ctx);
        fclose(fp);
        CHECK_ERR(e);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}