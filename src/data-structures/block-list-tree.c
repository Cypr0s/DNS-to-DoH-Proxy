#include "data-structures/block-list-tree.h"


// https://github.com/Cypr0s/CyprSH/blob/main/src/data-structures/abstract-syntax-tree.c simplified
BlockListTreePtr blockListTreeFindNode(BlockListTreePtr node, char* val) {
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

BlockListTreePtr blockListTreeCreateNode(char* val, uint8_t is_blocked) {
    BlockListTreePtr node = (BlockListTreePtr) malloc(sizeof(BlockListTree));

    if(node == NULL) {
        return NULL;
    }

    node->value = val;
    node->child_count = 0;
    node->children = NULL;
    node->is_blocked = is_blocked;
    return node;
}


ExitStatus blockListTreeAddChild(BlockListTreePtr parent, BlockListTreePtr child) {
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


void blockListTreeDelete(BlockListTreePtr node) {
    if(node == NULL) {
        return;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        blockListTreeDelete(node->children[i]);
    }
    free(node->children);
    free(node->value);
    free(node);
}


static uint8_t domainIsBlocked(BlockListTreePtr root, StringListPtr labels) {
    BlockListTreePtr node = root;
    StringListIterator it;
    stringListIterInit(&it, labels);

    char* label;
    while((label = stringListIterNext(&it)) != NULL) {
        node = zoneFileTreeFindNode(node, label);
        if(node == NULL) {
            return 0;
        }

        if(node->is_blocked) {
            return 1;
        }
    }
    return 0;
}