#ifndef ZONE_FILE_TREE_H
#define ZONE_FILE_TREE_H

#include "zone-entry-list.h"
typedef struct zonefile_tree_node {
    char* value;
    int8_t is_origin;
    ZoneList list;
    size_t child_count;
    struct zonefile_tree_node** children;
    struct zonefile_tree_node* parent;
} ZoneFileListTree, *ZoneFileListTreePtr;

ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val);

ZoneFileListTreePtr zoneFileTreeCreateNode(char* val);

ExitStatus zoneFileTreeAddChild(ZoneFileListTreePtr parent, ZoneFileListTreePtr child);

void zoneFileTreeDelete(ZoneFileListTreePtr node);

#endif // ZONE_FILE_TREE_H