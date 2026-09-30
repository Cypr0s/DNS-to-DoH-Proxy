#include "data-structures/zone-entry-list.h"

void zoneListInit(ZoneListPtr list) {
    list->head = NULL;
}

ExitStatus zoneListInsert(ZoneListPtr list, ZoneEntryPtr zone_entry) {
    ZoneNodePtr node = (ZoneNodePtr) malloc(sizeof(ZoneNode));
    if(node == NULL) {
        return STATUS_MALLOC_FAILURE;
    }
    node->zone_entry = zone_entry;
    node->next = list->head;
    list->head = node;
    return STATUS_SUCCESS;
}


void zoneListPop(ZoneListPtr list) {
    if(list->head == NULL) {
        return;
    }

    ZoneNodePtr tmp = list->head->next;
    free(list->head);
    list->head = tmp;
}


void zoneListDestroy(ZoneListPtr list) {
    while(list->head != NULL) {
        zoneListPop(list);
    }
}


void zoneListIterInit(ZoneListIteratorPtr it, ZoneListPtr list) {
    it->curr = list->head;
}


ZoneEntryPtr zoneListIterNext(ZoneListIteratorPtr it) {
    if(it->curr == NULL) {
        return NULL;
    }
    ZoneNodePtr tmp = it->curr;
    it->curr = it->curr->next;
    return tmp->zone_entry;
}
