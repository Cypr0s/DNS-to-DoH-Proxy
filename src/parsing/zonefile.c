#include "parsing/zonefile.h"


// https://www.iana.org/assignments/dns-parameters (Resource Record (RR) TYPEs), updated 2026-08-28, filled with AI (claude)
static ZoneTypeString zone_types[] = {
    // supported
    {"A", ENTRY_A},
    {"AAAA", ENTRY_AAAA},
    {"NS", ENTRY_NS},
    {"SOA", ENTRY_SOA},
    {"CNAME", ENTRY_CNAME},
    {"MX", ENTRY_MX},
    {"ANY", ENTRY_ANY},
    // registered by IANA but not supported: valid, parse and skip with a warning
    {"MD", ENTRY_VALID},
    {"MF", ENTRY_VALID},
    {"MB", ENTRY_VALID},
    {"MG", ENTRY_VALID},
    {"MR", ENTRY_VALID},
    {"NULL", ENTRY_VALID},
    {"WKS", ENTRY_VALID},
    {"PTR", ENTRY_VALID},
    {"HINFO", ENTRY_VALID},
    {"MINFO", ENTRY_VALID},
    {"TXT", ENTRY_VALID},
    {"RP", ENTRY_VALID},
    {"AFSDB", ENTRY_VALID},
    {"X25", ENTRY_VALID},
    {"ISDN", ENTRY_VALID},
    {"RT", ENTRY_VALID},
    {"NSAP", ENTRY_VALID},
    {"NSAP-PTR", ENTRY_VALID},
    {"SIG", ENTRY_VALID},
    {"KEY", ENTRY_VALID},
    {"PX", ENTRY_VALID},
    {"GPOS", ENTRY_VALID},
    {"LOC", ENTRY_VALID},
    {"NXT", ENTRY_VALID},
    {"EID", ENTRY_VALID},
    {"NIMLOC", ENTRY_VALID},
    {"SRV", ENTRY_VALID},
    {"ATMA", ENTRY_VALID},
    {"NAPTR", ENTRY_VALID},
    {"KX", ENTRY_VALID},
    {"CERT", ENTRY_VALID},
    {"A6", ENTRY_VALID},
    {"DNAME", ENTRY_VALID},
    {"SINK", ENTRY_VALID},
    {"OPT", ENTRY_VALID},
    {"APL", ENTRY_VALID},
    {"DS", ENTRY_VALID},
    {"SSHFP", ENTRY_VALID},
    {"IPSECKEY", ENTRY_VALID},
    {"RRSIG", ENTRY_VALID},
    {"NSEC", ENTRY_VALID},
    {"DNSKEY", ENTRY_VALID},
    {"DHCID", ENTRY_VALID},
    {"NSEC3", ENTRY_VALID},
    {"NSEC3PARAM", ENTRY_VALID},
    {"TLSA", ENTRY_VALID},
    {"SMIMEA", ENTRY_VALID},
    {"HIP", ENTRY_VALID},
    {"NINFO", ENTRY_VALID},
    {"RKEY", ENTRY_VALID}, 
    {"TALINK", ENTRY_VALID},
    {"CDS", ENTRY_VALID},
    {"CDNSKEY", ENTRY_VALID},
    {"OPENPGPKEY", ENTRY_VALID},
    {"CSYNC", ENTRY_VALID},
    {"ZONEMD", ENTRY_VALID},
    {"SVCB", ENTRY_VALID},
    {"HTTPS", ENTRY_VALID},
    {"DSYNC", ENTRY_VALID},
    {"HHIT", ENTRY_VALID},
    {"BRID", ENTRY_VALID},
    {"UNECE", ENTRY_VALID},
    {"ISO", ENTRY_VALID},
    {"SPF", ENTRY_VALID},
    {"UINFO", ENTRY_VALID},
    {"UID", ENTRY_VALID},
    {"GID", ENTRY_VALID},
    {"UNSPEC", ENTRY_VALID},
    {"NID", ENTRY_VALID},
    {"L32", ENTRY_VALID},
    {"L64", ENTRY_VALID},
    {"LP", ENTRY_VALID},
    {"EUI48", ENTRY_VALID},
    {"EUI64", ENTRY_VALID},
    {"NXNAME", ENTRY_VALID},
    {"TKEY", ENTRY_VALID},
    {"TSIG", ENTRY_VALID},
    {"IXFR", ENTRY_VALID},
    {"AXFR", ENTRY_VALID},
    {"MAILB", ENTRY_VALID},
    {"MAILA", ENTRY_VALID},
    {"URI", ENTRY_VALID},
    {"CAA", ENTRY_VALID},
    {"AVC", ENTRY_VALID},
    {"DOA", ENTRY_VALID},
    {"AMTRELAY", ENTRY_VALID},
    {"RESINFO", ENTRY_VALID},
    {"WALLET", ENTRY_VALID},
    {"CLA", ENTRY_VALID},
    {"IPN", ENTRY_VALID},
    {"TA", ENTRY_VALID},
    {"DLV", ENTRY_VALID},
};

static ExitStatus domainToBytes(char* owner, char** out, size_t* out_size);
static ExitStatus domainToStringList(char* owner, StringListPtr list);
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
static void destroyZoneFileCtx(ZoneFileListCtxPtr ctx);


static ExitStatus domainToBytes(char* owner, char** out, size_t* out_size) {
    size_t owner_size = strlen(owner);

    char* bytes = malloc(owner_size + 1);
    if(bytes == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    size_t domain_pos = 0;
    size_t label_start = 0;

    for(size_t i = 0; i < owner_size; i++) {
        if(owner[i] != '.') {
            continue;
        }
        size_t label_len = i - label_start;

        bytes[domain_pos++] = (char)label_len;

        memcpy(bytes + domain_pos,owner + label_start, label_len);

        domain_pos += label_len;
        label_start = i + 1;
    }

    bytes[domain_pos++] = 0;

    *out = bytes;
    *out_size = domain_pos;
    return STATUS_SUCCESS;
}


static ExitStatus domainToStringList(char* owner, StringListPtr list) {
    char* label_start = owner;
    char* label_end = owner;

    while(*label_end != '\0') {
        if(*label_end == '.') {
            *label_end = '\0';

            char* label = strdup(label_start);
            if(label == NULL) {
                PRINT_ERROR("Memory allocation failure");
                stringListDestroyFree(list);
                return STATUS_MALLOC_FAILURE;
            }

            ExitStatus e = stringListInsert(list, label);
            if(e != STATUS_SUCCESS) {
                free(label);
                stringListDestroyFree(list);
                return e;
            }

            *label_end = '.';
            label_start = label_end + 1;
        }

        label_end++;
    }

    return STATUS_SUCCESS;
}


static ExitStatus checkAndCreateDomainStr(char* token, char* origin, char** out, DNSFileContextPtr ctx) {
    if(!isValidDomainName(token)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Invalid character in domain name");
        return STATUS_EX_CONFIG;
    }

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
    char* owner = NULL;
    if(ctx->flags & ZONEFILE_LEADING_WHITESPACE) {
        if(ctx->current_owner == NULL) {
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Missing previous owner");
            return STATUS_EX_CONFIG;
        }
        owner = ctx->current_owner;
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
        case ENTRY_ANY:
            return STATUS_EX_CONFIG;
        case ENTRY_VALID:
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
            memcpy(zone_entry->entry.a_entry.address,&addr, IP_ADDRESS_BYTES);
            zone_entry->rdata_size = IP_ADDRESS_BYTES;
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
            memcpy(zone_entry->entry.aaaa_entry.address,&addr, IPV6_ADDRESS_BYTES);
            zone_entry->rdata_size = IPV6_ADDRESS_BYTES;
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

            char* cname;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &cname, &ctx->dns_context);
            CHECK_ERR(e);
            e = domainToStringList(cname, &zone_entry->entry.cname_entry.list);
            CHECK_ERR(e);
            e = domainToBytes(cname, &zone_entry->entry.cname_entry.cname, &zone_entry->entry.cname_entry.cname_size);
            zone_entry->rdata_size = zone_entry->entry.cname_entry.cname_size;
            CHECK_ERR(e);
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

            char* exchange;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &exchange, &ctx->dns_context);
            CHECK_ERR(e);
            e = domainToBytes(exchange, &zone_entry->entry.mx_entry.exchange, &zone_entry->entry.mx_entry.exchange_size);
            CHECK_ERR(e);
            zone_entry->rdata_size = zone_entry->entry.mx_entry.exchange_size + 2;
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

            char* nsdname;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &nsdname, &ctx->dns_context);
            CHECK_ERR(e);
            e = domainToBytes(nsdname, &zone_entry->entry.ns_entry.nsdname, &zone_entry->entry.ns_entry.nsdname_size);
            CHECK_ERR(e);
            zone_entry->rdata_size = zone_entry->entry.ns_entry.nsdname_size;
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
            char* mname;
            ExitStatus e = checkAndCreateDomainStr(token, ctx->origin, &mname, &ctx->dns_context);
            CHECK_ERR(e);
            e = domainToBytes(mname, &zone_entry->entry.soa_entry.mname, &zone_entry->entry.soa_entry.mname_size);
            CHECK_ERR(e);

            // rname
            char* rname;
            token = stringListIterNext(it);
            if(token == NULL) {
                PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Invalid format");
                return STATUS_EX_CONFIG;
            }
            e = checkAndCreateDomainStr(token, ctx->origin, &rname, &ctx->dns_context);
            CHECK_ERR(e);
            e = domainToBytes(rname, &zone_entry->entry.soa_entry.rname, &zone_entry->entry.soa_entry.rname_size);
            CHECK_ERR(e);
            
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
            zone_entry->rdata_size = zone_entry->entry.soa_entry.mname_size + zone_entry->entry.soa_entry.rname_size + 20;
            break;
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
    stringListReverse(list);

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
    ExitStatus e = domainToStringList(owner, &list);
    CHECK_ERR_AND_FREE(e, stringListDestroyFree(&list););

    StringListIterator it;
    stringListIterInit(&it, &list);
    char* val;
    ZoneFileListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        ZoneFileListTreePtr child = zoneFileTreeFindNode(tmp, val);

        if(child == NULL) {
            char* label = strdup(val);
            if(label == NULL) {
                PRINT_ERROR("Memory allocation failure");
                stringListDestroyFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            child = zoneFileTreeCreateNode(label);
            if(child == NULL) {
                free(label);
                PRINT_ERROR("Memory allocation failure");
                stringListDestroyFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            e = zoneFileTreeAddChild(tmp, child);
            CHECK_ERR_AND_FREE(e, zoneFileTreeDelete(child);PRINT_ERROR("Memory allocation failure");stringListDestroyFree(&list););
        }

        tmp = child;
    }
    stringListDestroyFree(&list);

    if(entry->entry_type == ENTRY_SOA) {
        tmp->is_apex = 1;
    }

    if(tmp->full_domain_name == NULL) {
        e = domainToBytes(owner, &tmp->full_domain_name, &tmp->full_domain_name_size);
        CHECK_ERR(e);
    } 

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
    e = zoneListInsert(zone_entry_list, entry);
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

static void destroyZoneFileCtx(ZoneFileListCtxPtr ctx) {
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