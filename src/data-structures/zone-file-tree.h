#include "zone-entry-list.h"
typedef struct zonefile_tree_node {
    char* value;
    int8_t is_origin;
    ZoneListPtr list;
    size_t child_count;
    struct zonefile_tree_node** children;
    struct zonefile_tree_node* parent;
} ZoneFileListTree, *ZoneFileListTreePtr;