/**
 * @file    zonefile.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of parsing of zone files
 *          
 * @date    2026-10-23
 */

#ifndef PARSING_ZONEFILE_H
#define PARSING_ZONEFILE_H

#include "data-structures/zone-file-tree.h"
#include "error.h"
#include "data-structures/string-linked-list.h"
#include "util/file.h"
#include "util/string.h"
#include <ctype.h>
#include <arpa/inet.h>
#include <strings.h>

#define ZONEFILE_COUNTER_MAX UINT32_MAX
#define ZONEFILE_MIN 0U
#define ZONEFILE_MINIMUM_MAX ZONEFILE_COUNTER_MAX / 2
#define ZONEFILE_MX_PREFERENCE_MAX UINT16_MAX

typedef enum {
    ZONEFILE_LEADING_WHITESPACE = 0x01,
    ZONEFILE_IS_FIRST_ENTRY = 0x02,
    ZONEFILE_HAS_SOA = 0x04,
    ZONEFILE_IS_RECORD = 0x08
} ZoneFileFlags;


typedef struct {
    DNSFileContext dns_context;
    ZoneFileFlags flags;
    char* origin;
    int32_t ttl;
    char* current_owner;
} ZoneFileListCtx, *ZoneFileListCtxPtr;

typedef struct {
    const char* name;
    ZoneEntryEnum value;
} ZoneTypeString;


/**
 * @brief           Parses all zone files into tree
 * 
 * @param zone_list List of zone file names
 * @param root      Zone tree root
 * @return          ExitStatus 
 */
ExitStatus parseZoneList(StringListPtr zone_list, ZoneFileListTreePtr root);

char* getZoneTypeName(uint16_t qtype);

uint8_t isSupportedQType(uint16_t qtype);

#endif // PARSING_ZONEFILE_H