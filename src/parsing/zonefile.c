/**
 * @file    zonefile.c
 * @author  Kristian Luptak
 * @brief   Contains parsing of zone files
 *          
 * @date    2026-10-23
 */

#include "parsing/zonefile.h"


// https://www.iana.org/assignments/dns-parameters (Resource Record (RR) TYPEs), updated 2026-08-28, filled with AI (claude)
static ZoneTypeString zone_types[] = {
    {"A", ENTRY_A},
    {"NS", ENTRY_NS},
    {"MD", ENTRY_MD},
    {"MF", ENTRY_MF},
    {"CNAME", ENTRY_CNAME},
    {"SOA", ENTRY_SOA},
    {"MB", ENTRY_MB},
    {"MG", ENTRY_MG},
    {"MR", ENTRY_MR},
    {"NULL", ENTRY_NULL},
    {"WKS", ENTRY_WKS},
    {"PTR", ENTRY_PTR},
    {"HINFO", ENTRY_HINFO},
    {"MINFO", ENTRY_MINFO},
    {"MX", ENTRY_MX},
    {"TXT", ENTRY_TXT},
    {"RP", ENTRY_RP},
    {"AFSDB", ENTRY_AFSDB},
    {"X25", ENTRY_X25},
    {"ISDN", ENTRY_ISDN},
    {"RT", ENTRY_RT},
    {"NSAP", ENTRY_NSAP},
    {"NSAP-PTR", ENTRY_NSAP_PTR},
    {"SIG", ENTRY_SIG},
    {"KEY", ENTRY_KEY},
    {"PX", ENTRY_PX},
    {"GPOS", ENTRY_GPOS},
    {"AAAA", ENTRY_AAAA},
    {"LOC", ENTRY_LOC},
    {"NXT", ENTRY_NXT},
    {"EID", ENTRY_EID},
    {"NIMLOC", ENTRY_NIMLOC},
    {"SRV", ENTRY_SRV},
    {"ATMA", ENTRY_ATMA},
    {"NAPTR", ENTRY_NAPTR},
    {"KX", ENTRY_KX},
    {"CERT", ENTRY_CERT},
    {"A6", ENTRY_A6},
    {"DNAME", ENTRY_DNAME},
    {"SINK", ENTRY_SINK},
    {"OPT", ENTRY_OPT},
    {"APL", ENTRY_APL},
    {"DS", ENTRY_DS},
    {"SSHFP", ENTRY_SSHFP},
    {"IPSECKEY", ENTRY_IPSECKEY},
    {"RRSIG", ENTRY_RRSIG},
    {"NSEC", ENTRY_NSEC},
    {"DNSKEY", ENTRY_DNSKEY},
    {"DHCID", ENTRY_DHCID},
    {"NSEC3", ENTRY_NSEC3},
    {"NSEC3PARAM", ENTRY_NSEC3PARAM},
    {"TLSA", ENTRY_TLSA},
    {"SMIMEA", ENTRY_SMIMEA},
    {"DELEGPARAM", ENTRY_DELEGPARAM},
    {"HIP", ENTRY_HIP},
    {"NINFO", ENTRY_NINFO},
    {"RKEY", ENTRY_RKEY},
    {"TALINK", ENTRY_TALINK},
    {"CDS", ENTRY_CDS},
    {"CDNSKEY", ENTRY_CDNSKEY},
    {"OPENPGPKEY", ENTRY_OPENPGPKEY},
    {"CSYNC", ENTRY_CSYNC},
    {"ZONEMD", ENTRY_ZONEMD},
    {"SVCB", ENTRY_SVCB},
    {"HTTPS", ENTRY_HTTPS},
    {"DSYNC", ENTRY_DSYNC},
    {"HHIT", ENTRY_HHIT},
    {"BRID", ENTRY_BRID},
    {"UNECE", ENTRY_UNECE},
    {"ISO", ENTRY_ISO},
    {"SPF", ENTRY_SPF},
    {"UINFO", ENTRY_UINFO},
    {"UID", ENTRY_UID},
    {"GID", ENTRY_GID},
    {"UNSPEC", ENTRY_UNSPEC},
    {"NID", ENTRY_NID},
    {"L32", ENTRY_L32},
    {"L64", ENTRY_L64},
    {"LP", ENTRY_LP},
    {"EUI48", ENTRY_EUI48},
    {"EUI64", ENTRY_EUI64},
    {"NXNAME", ENTRY_NXNAME},
    {"TKEY", ENTRY_TKEY},
    {"TSIG", ENTRY_TSIG},
    {"IXFR", ENTRY_IXFR},
    {"AXFR", ENTRY_AXFR},
    {"MAILB", ENTRY_MAILB},
    {"MAILA", ENTRY_MAILA},
    {"ANY", ENTRY_ANY},
    {"URI", ENTRY_URI},
    {"CAA", ENTRY_CAA},
    {"AVC", ENTRY_AVC},
    {"DOA", ENTRY_DOA},
    {"AMTRELAY", ENTRY_AMTRELAY},
    {"RESINFO", ENTRY_RESINFO},
    {"WALLET", ENTRY_WALLET},
    {"CLA", ENTRY_CLA},
    {"IPN", ENTRY_IPN},
    {"TA", ENTRY_TA},
    {"DLV", ENTRY_DLV},
    {"DELEG", ENTRY_DELEG},
};
/**
 * @brief           Converts domain name to wire format
 * 
 * @param owner     Absolute domain name
 * @param out       Output bytes
 * @param out_size  Output size
 * @return          ExitStatus 
 */
static ExitStatus domainToBytes(char* owner, char** out, size_t* out_size);

/**
 * @brief           Splits domain name into labels
 * 
 * @param owner     Domain name
 * @param list      Output label list
 * @return          ExitStatus 
 */
static ExitStatus domainToStringList(char* owner, StringListPtr list);

/**
 * @brief           Validates domain name and makes it absolute
 * 
 * @param token     Domain name
 * @param origin    Zone origin
 * @param out       Output absolute name
 * @param ctx       File context for errors
 * @return          ExitStatus 
 */
static ExitStatus checkAndCreateDomainStr(char* token, char* origin, char** out, DNSFileContextPtr ctx);

/**
 * @brief           Appends origin to relative domain name
 * 
 * @param name      Relative domain name
 * @param origin    Zone origin
 * @param resolved  Output absolute name
 * @return          ExitStatus 
 */
static ExitStatus resolveDomainName(char* name, char* origin, char** resolved);

/**
 * @brief           Checks if name belongs to origin zone
 * 
 * @param name      Absolute domain name
 * @param origin    Zone origin
 * @param ctx       File context for errors
 * @return          ExitStatus 
 */
static ExitStatus isInOrigin(char* name, char* origin, DNSFileContextPtr ctx);
/**
 * @brief       Parses $ORIGIN
 * 
 * @param it    Token iterator
 * @param ctx   Zone file context
 * @return      ExitStatus 
 */
static ExitStatus parseOrigin(StringListIteratorPtr it, ZoneFileListCtxPtr ctx);

/**
 * @brief       Parses $TTL
 * 
 * @param it    Token iterator
 * @param ctx   Zone file context
 * @return      ExitStatus 
 */
static ExitStatus parseTTL(StringListIteratorPtr it, ZoneFileListCtxPtr ctx);

/**
 * @brief               Parses resource record line
 * 
 * @param it            Token iterator
 * @param ctx           Zone file context
 * @param zone_entry    Output zone entry
 * @return              ExitStatus 
 */
static ExitStatus parseRecord(StringListIteratorPtr it, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry);

/**
 * @brief               Parses one zone file line
 * 
 * @param list          Line tokens
 * @param ctx           Zone file context
 * @param zone_entry    Output zone entry
 * @return              ExitStatus 
 */


static ExitStatus createEntry(StringListPtr list, ZoneFileListCtxPtr ctx, ZoneEntryPtr zone_entry);

/**
 * @brief       Inserts entry into zone tree
 * 
 * @param owner Absolute owner name
 * @param entry Zone entry
 * @param root  Zone tree root
 * @param ctx   File context for errors
 * @return      ExitStatus 
 */
static ExitStatus insertEntry(char* owner, ZoneEntryPtr entry, ZoneFileListTreePtr root, DNSFileContextPtr ctx);

/**
 * @brief           Splits line into tokens
 * 
 * @param line_str  Input line
 * @param list      Output token list
 * @return          ExitStatus 
 */

static ExitStatus tokenizeLine(char* line_str, StringListPtr list);

/**
 * @brief       Parses zone file
 * 
 * @param fp    Opened file
 * @param root  Zone tree root
 * @param ctx   Zone file context
 * @return      ExitStatus 
 */
static ExitStatus parseFile(FILE* fp, ZoneFileListTreePtr root, ZoneFileListCtxPtr ctx);

/**
 * @brief       Frees zone file context
 * 
 * @param ctx   Zone file context
 */
static void destroyZoneFileCtx(ZoneFileListCtxPtr ctx);


static ExitStatus domainToBytes(char* owner, char** out, size_t* out_size) {
    size_t owner_size = strlen(owner);

    char* bytes = malloc(owner_size + 1);
    if(bytes == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    size_t domain_pos = 0;
    size_t label_start = 0;

    for(size_t i = 0; i < owner_size; i++) {
        if(owner[i] != '.') { // skip dots 
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
                stringListDtorFree(list);
                return STATUS_MALLOC_FAILURE;
            }

            ExitStatus e = stringListInsert(list, label);
            if(e != STATUS_SUCCESS) {
                free(label);
                stringListDtorFree(list);
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
    if(!strcmp(token, "@")) {
        *out = strdup(origin);
        if(*out == NULL) {
            PRINT_ERROR("Memory Allocation failure");
            return STATUS_MALLOC_FAILURE;
        }
        return STATUS_SUCCESS;
    }

    if(!isValidDomainName(token)) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Invalid character in domain name");
        return STATUS_EX_CONFIG;
    }

    size_t token_size = strlen(token);
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

    if(!strcasecmp(origin, ".")) {
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
    if(!strcasecmp(origin, ".")) {
        return STATUS_SUCCESS;
    }

    size_t name_size = strlen(name);
    size_t origin_size = strlen(origin);

    if(name_size < origin_size) {
        PRINT_FILELIST_PARSE_ERROR(ctx->filename, ctx->line, "Name outside origin zone");
        return STATUS_EX_CONFIG;
    }

    if(strcasecmp(name + name_size - origin_size, origin)) {
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
        if(!strcasecmp(token, "@")) {
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
            PRINT_FILELIST_PARSE_ERROR(ctx->dns_context.filename, ctx->dns_context.line, "Unsupported entry type");
            return STATUS_EX_CONFIG;
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
            CHECK_ERR_AND_FREE(e, free(cname););
            e = domainToBytes(cname, &zone_entry->entry.cname_entry.cname, &zone_entry->entry.cname_entry.cname_size);
            zone_entry->rdata_size = zone_entry->entry.cname_entry.cname_size;
            CHECK_ERR_AND_FREE(e, free(cname););
            free(cname);
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
            CHECK_ERR_AND_FREE(e, free(exchange););
            zone_entry->rdata_size = zone_entry->entry.mx_entry.exchange_size + 2;
            free(exchange);
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
            CHECK_ERR_AND_FREE(e, free(nsdname););
            zone_entry->rdata_size = zone_entry->entry.ns_entry.nsdname_size;
            free(nsdname);
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
                if(strcasecmp(owner, ctx->origin)) {
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
            CHECK_ERR_AND_FREE(e, free(mname););
            free(mname);
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
            CHECK_ERR_AND_FREE(e, free(rname););
            free(rname);
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
        default:
            break;
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
    stringListIterCtor(&it, list);
    char* token = stringListIterNext(&it);
    if(token == NULL) {
        return STATUS_SUCCESS;
    }
    if(!strcasecmp(token, "$ORIGIN")) {
        return parseOrigin(&it, ctx);
    } else if(!strcasecmp(token, "$TTL")) {
        return parseTTL(&it, ctx);
        
    }
    stringListIterCtor(&it, list);
    return parseRecord(&it, ctx, zone_entry);
}

static ExitStatus insertEntry(char* owner, ZoneEntryPtr entry, ZoneFileListTreePtr root, DNSFileContextPtr ctx) {
    StringList list;
    stringListCtor(&list);
    // create token labels(owner is already checked)
    ExitStatus e = domainToStringList(owner, &list);
    CHECK_ERR_AND_FREE(e, stringListDtorFree(&list););

    StringListIterator it;
    stringListIterCtor(&it, &list);
    char* val;
    ZoneFileListTreePtr tmp = root;
    while((val = stringListIterNext(&it)) != NULL) {
        ZoneFileListTreePtr child = zoneFileTreeFindNode(tmp, val);

        if(child == NULL) {
            char* label = strdup(val);
            if(label == NULL) {
                PRINT_ERROR("Memory allocation failure");
                stringListDtorFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            child = zoneFileTreeCreateNode(label);
            if(child == NULL) {
                free(label);
                PRINT_ERROR("Memory allocation failure");
                stringListDtorFree(&list);
                return STATUS_MALLOC_FAILURE;
            }
            e = zoneFileTreeAddChild(tmp, child);
            CHECK_ERR_AND_FREE(e, zoneFileTreeDelete(child);PRINT_ERROR("Memory allocation failure");stringListDtorFree(&list););
        }

        tmp = child;
    }
    stringListDtorFree(&list);

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
    zoneListIterCtor(&zone_entry_it, zone_entry_list);
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
        stringListCtor(&list);

        ExitStatus e = tokenizeLine(line_str, &list);
        CHECK_ERR_AND_FREE(e, stringListDtorFree(&list); free(line_str););

        ZoneEntry entry = {0};
        e = createEntry(&list, ctx, &entry);
        CHECK_ERR_AND_FREE(e, stringListDtorFree(&list); free(line_str); zoneEntryFree(&entry));
        if(ctx->flags & ZONEFILE_IS_RECORD) {
            e = insertEntry(ctx->current_owner, &entry, root, &ctx->dns_context);
        }
        stringListDtorFree(&list);
        CHECK_ERR_AND_FREE(e, free(line_str); zoneEntryFree(&entry));
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
    stringListIterCtor(&it, zone_list);
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

char* getZoneTypeName(uint16_t qtype) {
    for(size_t i = 0; i < ARRAY_SIZE(zone_types); i++) {
        if(zone_types[i].value == qtype) {
            return (char*)zone_types[i].name;
        }
    }
    return NULL;
}

uint8_t isSupportedQType(uint16_t qtype) {
    return qtype == ENTRY_A || qtype == ENTRY_AAAA || qtype == ENTRY_MX || qtype == ENTRY_NS || qtype == ENTRY_SOA || qtype == ENTRY_CNAME || qtype == ENTRY_ANY;
}