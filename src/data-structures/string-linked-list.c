#include "data-structures/string-linked-list.h"

void stringListInit(StringListPtr list) {
    list->head = NULL;
}

ExitStatus stringListInsert(StringListPtr list, const char* data) {
    NodePtr node = (NodePtr) malloc(sizeof(Node));
    if(node == NULL) {
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

    NodePtr tmp = list->head->next;
    free(list->head);
    list->head = tmp;
}

void stringListDestroy(StringListPtr list) {
    while(list->head != NULL) {
        stringListPop(list);
    }
}


void stringListIterInit(StringListIteratorPtr it, StringListPtr list) {
    it->curr = list->head;
}


char* stringListIterNext(StringListIteratorPtr it) {
    if(it->curr == NULL) {
        return NULL;
    }
    NodePtr tmp = it->curr;
    it->curr = it->curr->next;
    return tmp->data;
}

void stringListDestroyFree(StringListPtr list) {
    while(list->head != NULL) {
        free(list->head->data);
        stringListPop(list);
    }
}