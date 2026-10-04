#ifndef BLOCK_LIST_TREE_H
#define BLOCK_LIST_TREE_H

#include <stdio.h>
#include <string.h>
#include "error.h"
#include <stdint.h>
#include "data-structures/string-linked-list.h"
#include <strings.h>

typedef struct blocklist_tree_node {
    char* value;
    size_t child_count;
    uint8_t is_blocked;
    struct blocklist_tree_node** children;
} BlockListTree, *BlockListTreePtr;

BlockListTreePtr blockListTreeFindNode(BlockListTreePtr node, char* val);

BlockListTreePtr blockListTreeCreateNode(char* val, uint8_t is_blocked);

ExitStatus blockListTreeAddChild(BlockListTreePtr parent, BlockListTreePtr child);

void blockListTreeDelete(BlockListTreePtr node);

uint8_t isBlocked(BlockListTreePtr root, StringListPtr labels);

#endif // BLOCK_LIST_TREE_H
