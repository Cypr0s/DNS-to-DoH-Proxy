#include "data-structures/zone-file-tree.h"

ZoneFileListTreePtr zoneFileTreeFindNode(ZoneFileListTreePtr node, char* val) {
    if(node == NULL) {
        return NULL;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        if(!strcasecmp(node->children[i]->value, val)) {
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
    node->full_domain_name = NULL;
    node->full_domain_name_size = 0;
    node->is_apex = 0;
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

    return STATUS_SUCCESS;
}


void zoneFileTreeDelete(ZoneFileListTreePtr node) {
    if(node == NULL) {
        return;
    }

    for(size_t i = 0; i < node->child_count; i++) {
        zoneFileTreeDelete(node->children[i]);
    }
    if(node->children != NULL) {
        free(node->children);
    }
    if(node->value != NULL) {
        free(node->value);
    }

    if(node->full_domain_name != NULL) {
        free(node->full_domain_name);
    }

    zoneListDestroy(&(node->list));
    free(node);
}

uint8_t isInZone(ZoneFileListTreePtr root, StringListPtr labels, ZoneFileListTreePtr* zone, ZoneFileListTreePtr* name) {
    *zone = NULL; // reset zone, very nice bugs <3
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