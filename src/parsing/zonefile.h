#ifndef PARSING_ZONEFILE_H
#define PARSING_ZONEFILE_H

#include "data-structures/zone-file-tree.h"
#include "error.h"
#include "data-structures/string-linked-list.h"
#include "util/file.h"
#include "util/string.h"
#include <ctype.h>
#include <arpa/inet.h>

#define ZONEFILE_COUNTER_MAX UINT32_MAX
#define ZONEFILE_MIN 0U
#define ZONEFILE_MINIMUM_MAX ZONEFILE_COUNTER_MAX / 2
#define ZONEFILE_MX_PREFERENCE_MAX UINT16_MAX

typedef enum {
    ZONEFILE_LEADING_WHITESPACE = 0x01,
    ZONEFILE_IS_FIRST_ENTRY = 0x02,
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

ExitStatus parseZoneList(StringListPtr zone_list, ZoneFileListTreePtr root);

#endif // PARSING_ZONEFILE_H