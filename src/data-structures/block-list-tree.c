#include "data-structures/block-list-tree.h"


// https://github.com/Cypr0s/CyprSH/blob/main/src/data-structures/abstract-syntax-tree.c simplified
BlockListTreePtr blockListFindNode(BlockListTreePtr node, const char* val) {
    if(node == NULL) {
        return NULL;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        if(!strcmp(node->children[i]->value, val)) {
            return node->children[i];
        }
    }
    return NULL;
}

BlockListTreePtr blockListCreateNode(const char* val) {
    BlockListTreePtr node = malloc(sizeof(BlockListTree));

    if(node == NULL) {
        return NULL;
    }

    node->value = val;
    node->child_count = 0;
    node->children = NULL;
    return node;
}

ExitStatus blockListAddChild(BlockListTreePtr parent, BlockListTreePtr child) {
    if(parent == NULL || child == NULL) {
        return STATUS_FAILURE;
    }

    BlockListTreePtr* new_children = realloc(parent->children, sizeof(BlockListTreePtr) * (parent->child_count + 1));

    if(new_children == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    parent->children = new_children;
    parent->children[parent->child_count] = child;
    parent->child_count++;

    return STATUS_SUCCESS;
}


void blockListDeleteTree(BlockListTreePtr node) {
    if(node == NULL) {
        return;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        blockListDeleteTree(node->children[i]);
    }
    free(node->children);
    free(node->value);
    free(node);
}