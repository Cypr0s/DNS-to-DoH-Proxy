#include <stdio.h>
#include <string.h>
#include "error.h"

typedef struct blacklist_tree_node {
    char* value;
    size_t child_count;
    struct blacklist_tree_node** children;
} BlockListTree, *BlockListTreePtr;

BlockListTreePtr blockListFindNode(BlockListTreePtr node, const char* val);

BlockListTreePtr blockListCreateNode(const char* val);

ExitStatus blockListAddChild(BlockListTreePtr parent, BlockListTreePtr child);

void blockListDeleteTree(BlockListTreePtr node);
