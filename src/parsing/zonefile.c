#include "parsing/zonefile.h"

// TODO FINISH THIS PARSING
static ZoneTypeString zone_types[] = {
    {"A", ENTRY_A},
    {"AAAA", ENTRY_AAAA},
    {"NS", ENTRY_NS},
    {"SOA", ENTRY_SOA},
    {"CNAME", ENTRY_CNAME},
    {"MX", ENTRY_MX},
};

static ExitStatus parseOrigin(StringListIteratorPtr it, ZoneFileListCtxPtr ctx) {
    if(ctx->origin != NULL || !(ctx->flags & ZONEFILE_IS_FIRST_ENTRY)) {
            return STATUS_EX_CONFIG;
        }
            
        char* token = stringListIterNext(it);
        if(token == NULL || stringListIterNext(it) != NULL) {
            return STATUS_EX_CONFIG;
        }

        if(!isValidDomainName(token)) {
            return STATUS_EX_CONFIG;
        }
        
        size_t size = strlen(token);
        if(token[size - 1] != '.') {
            return STATUS_EX_CONFIG;
        }
        ctx->origin = strdup(token);
        if(ctx->origin == NULL) {
            return STATUS_MALLOC_FAILURE;
        }
        return STATUS_SUCCESS;
}


static ExitStatus parseTTL(StringListIteratorPtr it, ZoneFileListCtxPtr ctx) {
    char* token = stringListIterNext(it);
    if(token == NULL || stringListIterNext(it) != NULL) {
        return STATUS_EX_CONFIG;
    }
    long ttl = convertStrToNum(token, ZONEFILE_MIN, ZONEFILE_MINIMUM_MAX);
    if(ttl == -1) {
        return STATUS_EX_CONFIG;
    }
    ctx->ttl = ttl;
    return STATUS_SUCCESS;
}

static ExitStatus parseRecord(StringListIteratorPtr it, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry) {
    char* token;
    token = stringListIterNext(it);
    if(token == NULL) {
        return STATUS_EX_CONFIG;
    }

    // owner
    char* owner;
    if(ctx->flags & ZONEFILE_LEADING_WHITESPACE) {
        if(ctx->current_owner == NULL) {
            return STATUS_EX_CONFIG;
        }
        owner = ctx->current_owner;
    } else {
        if(!strcmp(token, "@")) {
            if(ctx->origin == NULL) {
                return STATUS_EX_CONFIG;
            }
            owner = ctx->origin;
        } else {
            owner = token;
        }
        token = stringListIterNext(it); // ttl
        if(token == NULL) {
            return STATUS_EX_CONFIG;
        }
    }

    // ttl
    long ttl = convertStrToNum(token, 0, ZONEFILE_MINIMUM_MAX);
    if(ttl != -1) {
        zone_entry->ttl = ttl;
        token = stringListIterNext(it); // IN
        if(token == NULL) {
            return STATUS_EX_CONFIG;
        }
    } else {
        if(ctx->ttl == -1) {
            return STATUS_EX_CONFIG;
        }
        zone_entry->ttl = ctx->ttl;
    }

    // IN
    if(!strcasecmp(token, "IN")) {
        token = stringListIterNext(it); // type
        if(token == NULL) {
            return STATUS_EX_CONFIG;
        }
    }
    zone_entry->entry_type = ENTRY_INVALID;
    for(size_t i = 0; i < ARRAY_SIZE(zone_types); i++) {
        if(!strcasecmp(token, zone_types[i].name)) {
            zone_entry->entry_type = zone_types[i].value;
            break;
        }
    }
    token = stringListIterNext(it);
    if(token == NULL) {
        return STATUS_EX_CONFIG;
    }

    switch(zone_entry->entry_type) {
        case ENTRY_INVALID:
            return STATUS_EX_CONFIG;
        case ENTRY_VALID:
            return; //valid??;
        case ENTRY_A: {
            if(stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }
            struct in_addr addr;
            if(inet_pton(AF_INET, token, &addr) != 1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.a_entry.address = strdup(token);
            if(zone_entry->entry.a_entry.address == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_AAAA: {
            if(stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }

            struct in6_addr addr;

            if(inet_pton(AF_INET6, token, &addr) != 1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.aaaa_entry.address = strdup(token);
            if(zone_entry->entry.aaaa_entry.address == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_CNAME: {
            if(stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }

            if(!isValidDomainName(token)) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.cname_entry.cname = strdup(token);
            if(zone_entry->entry.cname_entry.cname == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_MX: {
            long preference = convertStrToNum(token, 0, ZONEFILE_MX_PREFERENCE_MAX);
            if(preference == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.mx_entry.preference = (uint16_t) preference;
            token = stringListIterNext(it);
            if(token == NULL || stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }
            if(!isValidDomainName(token)) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.mx_entry.exchange = strdup(token);
            if(zone_entry->entry.mx_entry.exchange == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_NS: {
            if(stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }

            if(!isValidDomainName(token)) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.ns_entry.nsdname = strdup(token);
            if(zone_entry->entry.ns_entry.nsdname == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_SOA: {
            if(!isValidDomainName(token)) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.mname = strdup(token);
            if(zone_entry->entry.soa_entry.mname == NULL) {
                return STATUS_MALLOC_FAILURE;
            }

            token = stringListIterNext(it);
            if(token == NULL || !isValidDomainName(token)) {
                return STATUS_EX_CONFIG;
            }

            zone_entry->entry.soa_entry.rname = strdup(token);
            if(zone_entry->entry.soa_entry.rname == NULL) {
                return STATUS_MALLOC_FAILURE;
            }
            // serial
            token = stringListIterNext(it);
            if(token == NULL) {
                return STATUS_EX_CONFIG;
            }
            long serial = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(serial == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.serial = (uint32_t) serial;
            // refresh
            token = stringListIterNext(it);
            if(token == NULL) {
                return STATUS_EX_CONFIG;
            }
            long refresh = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(refresh == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.refresh = (uint32_t) refresh;
            // retry
            token = stringListIterNext(it);
            if(token == NULL) {
                return STATUS_EX_CONFIG;
            }
            long retry = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(retry == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.retry = (uint32_t) retry;

            // expier
            token = stringListIterNext(it);
            if(token == NULL) {
                return STATUS_EX_CONFIG;
            }
            long expire = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(expire == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.expire = (uint32_t) expire;
            // minimum
            token = stringListIterNext(it);
            if(token == NULL || stringListIterNext(it) != NULL) {
                return STATUS_EX_CONFIG;
            }
            long minimum = convertStrToNum(token, 0, ZONEFILE_MINIMUM_MAX);
            if(minimum == -1) {
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.minimum = (uint32_t) minimum;
        }
    }

    if(!(ctx->flags & ZONEFILE_LEADING_WHITESPACE)) {
        char* new_owner = strdup(owner);
        if(new_owner == NULL) {
            return STATUS_MALLOC_FAILURE;
        }

        free(ctx->current_owner);
        ctx->current_owner = new_owner;
    }
    return STATUS_SUCCESS;
}


static ExitStatus createEntry(StringListPtr list, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry) {
    // process items in list one by one
    StringListIterator it; 
    stringListIterInit(&it, list);
    char* token = stringListIterNext(&it);
    if (token == NULL) {
        return STATUS_SUCCESS;
    }

    if(!strcasecmp(token, "$ORIGIN")) {
        return parseOrigin(&it, ctx);
    } else if(!strcasecmp(token, "$TTL")) {
        return parseTTL(&it, ctx);
        
    }
    stringListIterInit(&it, list);
    return parseRecord(&it, ctx, zone_entry);
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
        ctx->dns_context.line++;
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
            .dns_context = {.filename = filename, .line = 0},
            .origin = NULL,
            .ttl = -1,
            .flags = ZONEFILE_IS_FIRST_ENTRY
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