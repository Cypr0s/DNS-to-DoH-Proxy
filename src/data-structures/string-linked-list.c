/**
 * @file    string-linked-list.c
 * @author  Kristian Luptak
 * @brief   Contains definitions of string linked list struct
 *          
 * @date    2026-10-23
 */

#include "data-structures/string-linked-list.h"


void stringListCtor(StringListPtr list) {
    list->head = NULL;
}

/**
 * @brief           
 * 
 * @param list 
 * @param data 
 * @return ExitStatus
 */
ExitStatus stringListInsert(StringListPtr list, char* data) {
    StringNodePtr node = (StringNodePtr) malloc(sizeof(StringNode));
    if(node == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }
    node->data = data;
    node->next = list->head;
    list->head = node;
    return STATUS_SUCCESS;
}

void stringListPop(StringListPtr list) {
    if(list->head == NULL) {
        return;
    }

    StringNodePtr tmp = list->head->next;
    free(list->head);
    list->head = tmp;
}

void stringListDtor(StringListPtr list) {
    while(list->head != NULL) {
        stringListPop(list);
    }
}


void stringListIterCtor(StringListIteratorPtr it, StringListPtr list) {
    it->curr = list->head;
}


char* stringListIterNext(StringListIteratorPtr it) {
    if(it->curr == NULL) {
        return NULL;
    }
    StringNodePtr tmp = it->curr;
    it->curr = it->curr->next;
    return tmp->data;
}

void stringListDtorFree(StringListPtr list) {
    while(list->head != NULL) {
        free(list->head->data);
        stringListPop(list);
    }
    list->head = NULL;
}

void stringListReverse(StringListPtr list) {
    StringNodePtr prev = NULL;
    StringNodePtr curr = list->head;

    while(curr != NULL) {
        StringNodePtr next = curr->next;
        curr->next = prev;
        prev = curr;
        curr = next;
    }

    list->head = prev;
}