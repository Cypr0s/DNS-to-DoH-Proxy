#ifndef ZONE_FILE_TREE_H
#define ZONE_FILE_TREE_H

#include "data-structures/zone-entry-list.h"
#include "data-structures/string-linked-list.h"
#include "server/dns.h"
#include <strings.h>
typedef struct zonefile_tree_node {
    char* value;
    char* full_domain_name;
    int8_t is_apex;
    size_t full_domain_name_size;
    ZoneList list;
    size_t child_count;
    struct zonefile_tree_node** children;
} ZoneFileListTree, *ZoneFileListTreePtr;

ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val);

ZoneFileListTreePtr zoneFileTreeCreateNode(char* val);

ExitStatus zoneFileTreeAddChild(ZoneFileListTreePtr parent, ZoneFileListTreePtr child);

void zoneFileTreeDelete(ZoneFileListTreePtr node);

uint8_t isInZone(ZoneFileListTreePtr root, StringListPtr labels, ZoneFileListTreePtr* zone, ZoneFileListTreePtr* name);

#endif // ZONE_FILE_TREE_H