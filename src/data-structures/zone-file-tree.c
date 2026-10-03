#include "data-structures/zone-file-tree.h"

ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val) {
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

ZoneFileListTreePtr zoneFileTreeCreateNode(char* val) {
    ZoneFileListTreePtr node = (ZoneFileListTreePtr) malloc(sizeof(ZoneFileListTree));

    if(node == NULL) {
        return NULL;
    }

    node->value = val;
    zoneListInit(&(node->list));
    node->child_count = 0;
    node->children = NULL;
    node->parent = NULL;

    return node;
}


ExitStatus zoneFileTreeAddChild(ZoneFileListTreePtr parent, ZoneFileListTreePtr child) {
    if(parent == NULL || child == NULL) {
        return STATUS_FAILURE;
    }

    ZoneFileListTreePtr* new_children = realloc(parent->children, sizeof(ZoneFileListTreePtr) * (parent->child_count + 1));

    if(new_children == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    parent->children = new_children;
    parent->children[parent->child_count] = child;
    parent->child_count++;

    child->parent = parent;

    return STATUS_SUCCESS;
}


void zoneFileTreeDelete(ZoneFileListTreePtr node) {
    if(node == NULL) {
        return;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        zoneFileTreeDelete(node->children[i]);
    }

    free(node->children);
    free(node->value);

    zoneListDestroy(&(node->list));

    free(node);
}

static uint8_t isInZone(ZoneFileListTreePtr root, StringListPtr labels, ZoneFileListTreePtr* zone, ZoneFileListTreePtr* name) {
    *zone = NULL;
    ZoneFileListTreePtr node = root;
    StringListIterator it;
    stringListIterInit(&it, labels);

    char* label;
    while((label = stringListIterNext(&it)) != NULL) {
        node = zoneFileTreeFindNode(node, label);
        if(node == NULL) {
            break;
        }

        if(node->is_apex) {
            *zone = node;
        }
    }
    *name = node;
    // name outside
    if(*zone == NULL) {
        return 0;
    }
    return 1;
}