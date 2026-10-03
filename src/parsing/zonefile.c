#include "parsing/zonefile.h"

// TODO FINISH THIS PARSING
static ZoneTypeString zone_types[] = {
    {"A", ENTRY_A},
    {"AAAA", ENTRY_AAAA},
    {"NS", ENTRY_NS},
    {"SOA", ENTRY_SOA},
    {"CNAME", ENTRY_CNAME},
    {"MX", ENTRY_MX},
    {"ANY", ENTRY_ANY}
};


static ExitStatus checkAndCreateDomainStr(char* token, char* origin, char** out, DNSFileContextPtr ctx);
static ExitStatus resolveDomainName(char* name, char* origin, char** resolved);
static ExitStatus isInOrigin(char* name, char* origin, DNSFileContextPtr ctx);
static ExitStatus parseOrigin(StringListIteratorPtr it, ZoneFileListCtxPtr ctx);
static ExitStatus parseTTL(StringListIteratorPtr it, ZoneFileListCtxPtr ctx);
static ExitStatus parseRecord(StringListIteratorPtr it, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry);
static ExitStatus createEntry(StringListPtr list, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry);
static ExitStatus insertEntry(char* owner, ZoneEntryPtr entry, ZoneFileListTreePtr root, DNSFileContextPtr ctx);
static ExitStatus tokenizeLine(char* line_str, StringListPtr list);
static ExitStatus parseFile(FILE* fp, ZoneFileListTreePtr root, ZoneFileListCtxPtr ctx);
static void destroyZoneFIleCtx(ZoneFileListCtxPtr ctx);


static ExitStatus checkAndCreateDomainStr(char* token, char* origin, char** out, DNSFileContextPtr ctx) {
    if(!isValidDomainName(token)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Invalid character in domain name");
        return STATUS_EX_CONFIG;
    }
    ExitStatus e;
    size_t token_size =strlen(token);
    if(token[token_size - 1] == '.') {
        *out = strdup(token);
        if(*out == NULL) {
            PRINT_ERROR("Memory Allocation failure");
            return STATUS_MALLOC_FAILURE;
        }
        return STATUS_SUCCESS;
    }

    return resolveDomainName(token, origin, out);
}


static ExitStatus resolveDomainName(char* name, char* origin, char** resolved) {
    size_t name_len = strlen(name);
    size_t origin_len = strlen(origin);

    if(!strcmp(origin, ".")) {
        *resolved =(char*) malloc(name_len + 2);

        if(*resolved == NULL) {
            PRINT_ERROR("Memory Allocation failure");
            return STATUS_MALLOC_FAILURE;
        }

        memcpy(*resolved, name, name_len);
        (*resolved)[name_len] = '.';
        (*resolved)[name_len + 1] = '\0';
    } else {
        *resolved =(char*) malloc(name_len + 1 + origin_len + 1);

        if(*resolved == NULL) {
            PRINT_ERROR("Memory Allocation failure");
            return STATUS_MALLOC_FAILURE;
        }

        memcpy(*resolved, name, name_len);
        (*resolved)[name_len] = '.';
        memcpy(*resolved + name_len + 1, origin, origin_len + 1);
    }

    return STATUS_SUCCESS;
}


static ExitStatus isInOrigin(char* name, char* origin, DNSFileContextPtr ctx) {
    if(!strcmp(origin, ".")) {
        return STATUS_SUCCESS;
    }

    size_t name_size = strlen(name);
    size_t origin_size = strlen(origin);

    if(name_size < origin_size) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Name outside origin zone");
        return STATUS_EX_CONFIG;
    }

    if(strcmp(name + name_size - origin_size, origin)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Name outside origin zone");
        return STATUS_EX_CONFIG;
    }

    if(name_size == origin_size) {
        return STATUS_SUCCESS;
    }
    if(name[name_size - origin_size - 1] == '.') {
        return STATUS_SUCCESS;
    }
    PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Name outside origin zone");
    return STATUS_EX_CONFIG;
}


static ExitStatus parseOrigin(StringListIteratorPtr it, ZoneFileListCtxPtr ctx) {
    if(ctx->origin != NULL || !(ctx->flags & ZONEFILE_IS_FIRST_ENTRY)) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Origin is not before entries");
            return STATUS_EX_CONFIG;
        }
            
        char* token = stringListIterNext(it);
        if(token == NULL || stringListIterNext(it) != NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
            return STATUS_EX_CONFIG;
        }

        if(!isValidDomainName(token)) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid domain name");
            return STATUS_EX_CONFIG;
        }
        
        size_t size = strlen(token);
        if(token[size - 1] != '.') {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Origin doesnt have absolute name");
            return STATUS_EX_CONFIG;
        }
        ctx->origin = strdup(token);
        if(ctx->origin == NULL) {
            PRINT_ERROR("Memory allocation failure");
            return STATUS_MALLOC_FAILURE;
        }
        return STATUS_SUCCESS;
}


static ExitStatus parseTTL(StringListIteratorPtr it, ZoneFileListCtxPtr ctx) {
    char* token = stringListIterNext(it);
    if(token == NULL || stringListIterNext(it) != NULL) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
        return STATUS_EX_CONFIG;
    }
    long ttl = convertStrToNum(token, ZONEFILE_MIN, ZONEFILE_MINIMUM_MAX);
    if(ttl == -1) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid tll value");
        return STATUS_EX_CONFIG;
    }
    ctx->ttl = ttl;
    return STATUS_SUCCESS;
}

static ExitStatus parseRecord(StringListIteratorPtr it, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry) {
    char* token;
    token = stringListIterNext(it);
    if(token == NULL) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
        return STATUS_EX_CONFIG;
    }

    // owner
    char* owner;
    if(ctx->flags & ZONEFILE_LEADING_WHITESPACE) {
        if(ctx->current_owner == NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing previous owner");
            return STATUS_EX_CONFIG;
        }
        // no need to set owner it will not be replaced
    } else {
        if(!strcmp(token, "@")) {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }
            owner = ctx->origin;
        } else {
            owner = token;
        }
        token = stringListIterNext(it); // ttl
        if(token == NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
            return STATUS_EX_CONFIG;
        }
    }

    // ttl
    long ttl = convertStrToNum(token, 0, ZONEFILE_MINIMUM_MAX);
    if(ttl != -1) {
        zone_entry->ttl = ttl;
        token = stringListIterNext(it); // IN
        if(token == NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
            return STATUS_EX_CONFIG;
        }
    } else {
        if(ctx->ttl == -1) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "TTL is missing");
            return STATUS_EX_CONFIG;
        }
        zone_entry->ttl = ctx->ttl;
    }

    // IN
    if(!strcasecmp(token, "IN")) {
        token = stringListIterNext(it); // type
        if(token == NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid fomrat");
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
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
        return STATUS_EX_CONFIG;
    }

    switch(zone_entry->entry_type) {
        case ENTRY_INVALID:
            return STATUS_EX_CONFIG;
        case ENTRY_VALID:
        case ENTRY_ANY:
            // TODO INSERT EVEN IF ITS VALID
            break;
        case ENTRY_A: {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }
            if(stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            struct in_addr addr;
            if(inet_pton(AF_INET, token, &addr) != 1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid ipv4 address");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.a_entry.address = strdup(token);
            if(zone_entry->entry.a_entry.address == NULL) {
                PRINT_ERROR("Memory allocation failure");
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_AAAA: {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }
            if(stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }

            struct in6_addr addr;

            if(inet_pton(AF_INET6, token, &addr) != 1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid ipv6 address");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.aaaa_entry.address = strdup(token);
            if(zone_entry->entry.aaaa_entry.address == NULL) {
                PRINT_ERROR("Memory allocation failure");
                return STATUS_MALLOC_FAILURE;
            }
            break;
        }
        case ENTRY_CNAME: {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }

            if(stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }

            char* resolved;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &resolved, &ctx->dns_context);
            CHECK_ERR(e);
            zone_entry->entry.cname_entry.cname = resolved;
            break;
        }
        case ENTRY_MX: {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }
            long preference = convertStrToNum(token, 0, ZONEFILE_MX_PREFERENCE_MAX);
            if(preference == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid preference value");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.mx_entry.preference = (uint16_t) preference;
            token = stringListIterNext(it);
            if(token == NULL || stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }

            char* resolved;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &resolved, &ctx->dns_context);
            CHECK_ERR(e);
            zone_entry->entry.mx_entry.exchange = resolved;
            break;
        }
        case ENTRY_NS: {
            if(ctx->origin == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin");
                return STATUS_EX_CONFIG;
            }
            if(stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }

            char* resolved;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &resolved, &ctx->dns_context);
            CHECK_ERR(e);
            zone_entry->entry.ns_entry.nsdname = resolved;
            break;
        }
        case ENTRY_SOA: {
            // firstly check multiple things per spec
            if(ctx->flags & ZONEFILE_HAS_SOA) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "File already has SOA entry");
                return STATUS_EX_CONFIG;
            }
            if(ctx->origin == NULL) {
                if(!(ctx->flags & ZONEFILE_IS_FIRST_ENTRY)) {
                    PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing origin and SOA entry is not first");
                    return STATUS_EX_CONFIG;
                }
                size_t owner_size = strlen(owner);
                if(owner[owner_size - 1] != '.') {
                     PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA owner is not absolute domain");
                    return STATUS_EX_CONFIG;
                }
                ctx->origin = strdup(owner);
                if(ctx->origin == NULL) {
                    PRINT_ERROR("Memory allocation failure");
                    return STATUS_MALLOC_FAILURE;
                }
            } else {
                if(strcmp(owner, ctx->origin)) {
                     PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA owner is not origin");
                    return STATUS_EX_CONFIG;
                }
            }
            ctx->flags |= ZONEFILE_HAS_SOA;

            //actual parsing
            // mname
            char* resolved;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &resolved, &ctx->dns_context);
            CHECK_ERR(e);
            zone_entry->entry.soa_entry.mname = resolved;

            // rname
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            e = checkAndCreateDomainStr(token, ctx->origin, &resolved, &ctx->dns_context);
            CHECK_ERR(e);
            zone_entry->entry.soa_entry.rname = resolved;
            
            // serial
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            long serial = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(serial == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA invalid serial");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.serial = (uint32_t) serial;
            // refresh
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            long refresh = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(refresh == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA invalid refresh");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.refresh = (uint32_t) refresh;
            // retry
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            long retry = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(retry == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA invalid retry");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.retry = (uint32_t) retry;

            // expier
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            long expire = convertStrToNum(token, 0, ZONEFILE_COUNTER_MAX);
            if(expire == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA invalid expire");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.expire = (uint32_t) expire;
            // minimum
            token = stringListIterNext(it);
            if(token == NULL || stringListIterNext(it) != NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            long minimum = convertStrToNum(token, 0, ZONEFILE_MINIMUM_MAX);
            if(minimum == -1) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "SOA invalid minimum");
                return STATUS_EX_CONFIG;
            }
            zone_entry->entry.soa_entry.minimum = (uint32_t) minimum;
        }
    }


    if(!(ctx->flags & ZONEFILE_LEADING_WHITESPACE)) {
        size_t owner_size = strlen(owner);
        ExitStatus e;
        if(owner[owner_size - 1] == '.') {
            e = isInOrigin(owner, ctx->origin, &ctx->dns_context);
            CHECK_ERR(e);
        }
        char* new_owner = NULL;
        e = checkAndCreateDomainStr(owner, ctx->origin, &new_owner, &ctx->dns_context);
        CHECK_ERR(e);
        free(ctx->current_owner);
        ctx->current_owner = new_owner;
    }
    ctx->flags &= ~ZONEFILE_IS_FIRST_ENTRY;
    ctx->flags |= ZONEFILE_IS_RECORD;
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

static ExitStatus insertEntry(char* owner, ZoneEntryPtr entry, ZoneFileListTreePtr root, DNSFileContextPtr ctx) {
    StringList list;
    stringListInit(&list);
    // create token labels(owner is already checked)
    char* label_start = owner;
    char* label_end = owner;
    while(*label_end != '\0') {
        if(*label_end == '.') {
            *label_end = '\0';
            char* label = strdup(label_start);
            if(label == NULL) {
                PRINT_ERROR("Memory allocation failure");
                stringListDestroyFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            ExitStatus e = stringListInsert(&list, label);
            CHECK_ERR_AND_FREE(e, PRINT_ERROR("Memory allocation failure"); stringListDestroyFree(&list););
            *label_end = '.';
            label_start = label_end + 1;
        }
        label_end++;
    }

    StringListIterator it;
    stringListIterInit(&it, &list);
    char* val;
    ZoneFileListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        ZoneFileListTreePtr child = zoneFileTreeFindNode(tmp, val);

        if(child == NULL) {
            child = zoneFileTreeCreateNode(val);
            if(child == NULL) {
                PRINT_ERROR("Memory allocation failure");
                stringListDestroyFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            ExitStatus e = zoneFileTreeAddChild(tmp, child);
            CHECK_ERR_AND_FREE(e, free(child);PRINT_ERROR("Memory allocation failure");stringListDestroyFree(&list););
        } else {
            free(val);
        }

        tmp = child;
    }
    stringListDestroy(&list);
    tmp->is_apex = 1;
    ZoneListPtr zone_entry_list = &(tmp->list);
    // cname check
    if(entry->entry_type == ENTRY_CNAME && zone_entry_list->head != NULL) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Only one entry per domain is if the entry IS CNAME");
        return STATUS_EX_CONFIG;
    }
    
    // ttl check and cname check
    ZoneListIterator zone_entry_it;
    zoneListIterInit(&zone_entry_it, zone_entry_list);
    ZoneEntryPtr list_entry;
    while((list_entry = (zoneListIterNext(&zone_entry_it))) != NULL) {
        if(list_entry->entry_type == entry->entry_type && list_entry->ttl != entry->ttl) {
            PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "invalid TTL");
            return STATUS_EX_CONFIG;
        } 
        if(list_entry->entry_type == ENTRY_CNAME) {
            PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Only one entry per domain is if the entry IS CNAME");
            return STATUS_EX_CONFIG;
        }
    }

    // actual insertion
    ExitStatus e = zoneListInsert(zone_entry_list, entry);
    CHECK_ERR(e);

    return STATUS_SUCCESS;
}


static ExitStatus tokenizeLine(char* line_str, StringListPtr list) {
    char* token = NULL;
    do {
        token = getToken(&line_str);
        if(token != NULL) {
            size_t token_size = strlen(token);
            char* list_entry = malloc(sizeof(char) * (token_size + 1));
            if(list_entry == NULL) {
                PRINT_ERROR("Memory Allocation failure");
                return STATUS_MALLOC_FAILURE;
            }

            strcpy(list_entry, token);

            ExitStatus e = stringListInsert(list, list_entry);
            CHECK_ERR_AND_FREE(e, PRINT_ERROR("Memory Allocation failure"); free(list_entry);); 
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
        if(ctx->flags & ZONEFILE_IS_RECORD) {
            e = insertEntry(ctx->current_owner, &entry, root, &ctx->dns_context);
        }
        stringListDestroyFree(&list);
        CHECK_ERR(e);
        ctx->flags &= ~ZONEFILE_LEADING_WHITESPACE;
        ctx->flags &= ~ZONEFILE_IS_RECORD;
    }
    free(line_str);
    if(!(ctx->flags & ZONEFILE_HAS_SOA)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "File doesnt have SOA entry");
        return STATUS_EX_CONFIG;
    }
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
            PRINT_FILELIST_PARSE_ERROR(ctx.dns_context.filename, ctx.dns_context.line, "Cant read file");
            return STATUS_EX_CONFIG;
        }

        ExitStatus e = parseFile(fp, root, &ctx);
        fclose(fp);
        destroyZoneFileCtx(&ctx);
        CHECK_ERR(e);
        filename = stringListIterNext(&it);
    }
    return STATUS_SUCCESS;
}

static void destroyZoneFIleCtx(ZoneFileListCtxPtr ctx) {
    if(ctx == NULL) {
        return;
    }
    if(ctx->current_owner != NULL) {
        free(ctx->current_owner);
    }
    if(ctx->origin != NULL) {
        free(ctx->origin);
    }
}