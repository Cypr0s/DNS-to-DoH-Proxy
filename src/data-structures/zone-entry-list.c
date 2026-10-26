/**
 * @file    zone-entry-list.c
 * @author  Kristian Luptak
 * @brief   Contains implementation API of zone entry list
 *          
 * @date    2026-10-23
 */

#include "data-structures/zone-entry-list.h"


void zoneListCtor(ZoneListPtr list) {
    list->head = NULL;
}


ExitStatus zoneListInsert(ZoneListPtr list, ZoneEntryPtr zone_entry) {
    ZoneNodePtr node = (ZoneNodePtr) malloc(sizeof(ZoneNode));
    if(node == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }
    node->zone_entry = *zone_entry;
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


void zoneListDtor(ZoneListPtr list) {
    while(list->head != NULL) {
        zoneListPop(list);
    }
}


void zoneListIterCtor(ZoneListIteratorPtr it, ZoneListPtr list) {
    it->curr = list->head;
}



ZoneEntryPtr zoneListIterNext(ZoneListIteratorPtr it) {
    if(it->curr == NULL) {
        return NULL;
    }
    ZoneNodePtr tmp = it->curr;
    it->curr = it->curr->next;
    return &tmp->zone_entry;
}


ZoneEntryPtr getEntry(ZoneListPtr list, int8_t entry_type) {
    ZoneNodePtr current = list->head;
    while(current != NULL) {
        if(current->zone_entry.entry_type == entry_type) {
            return &current->zone_entry;
        }
        current = current->next;
    }
    return NULL;
}
