#include <stdio.h>
#include <string.h>
#include "error.h"
#include <stdint.h>

typedef struct blocklist_tree_node {
    char* value;
    size_t child_count;
    uint8_t is_blocked;
    struct blocklist_tree_node** children;
} BlockListTree, *BlockListTreePtr;

BlockListTreePtr blockListFindNode(BlockListTreePtr node, const char* val);

BlockListTreePtr blockListCreateNode(const char* val, uint8_t is_blocked);

ExitStatus blockListAddChild(BlockListTreePtr parent, BlockListTreePtr child);

void blockListDeleteTree(BlockListTreePtr node);
