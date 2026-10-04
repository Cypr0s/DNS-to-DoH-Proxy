#ifndef ZONE_FILE_TREE_H
#define ZONE_FILE_TREE_H

#include "data-structures/zone-entry-list.h"
#include "data-structures/string-linked-list.h"
#include "server/dns.h"
typedef struct zonefile_tree_node {
    char* value;
    int8_t is_apex;
    ZoneList list;
    size_t child_count;
    struct zonefile_tree_node** children;
    struct zonefile_tree_node* parent;
} ZoneFileListTree, *ZoneFileListTreePtr;

ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val);

ZoneFileListTreePtr zoneFileTreeCreateNode(char* val);

ExitStatus zoneFileTreeAddChild(ZoneFileListTreePtr parent, ZoneFileListTreePtr child);

void zoneFileTreeDelete(ZoneFileListTreePtr node);

uint8_t isInZone(ZoneFileListTreePtr root, StringListPtr labels, ZoneFileListTreePtr* zone, ZoneFileListTreePtr* name);

#endif // ZONE_FILE_TREE_H