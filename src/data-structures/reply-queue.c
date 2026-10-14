#include "data-structures/reply-queue.h"

void tcpReplyQueueInit(TCPReplyQueuePtr queue) {
    queue->head = NULL;
    queue->tail = NULL;
}

ExitStatus tcpReplyQueuePush(TCPReplyQueuePtr queue, char* reply, size_t reply_size, char* log) {
    TCPReply *new_reply = malloc(sizeof(TCPReply));
    if(new_reply == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    new_reply->data = malloc(reply_size + TCP_MESSAGE_SIZE_BYTES);
    if(new_reply->data == NULL) {
        free(new_reply);
        return STATUS_MALLOC_FAILURE;
    }

    uShortToBytes((uint16_t)reply_size, new_reply->data);

    memcpy(new_reply->data + TCP_MESSAGE_SIZE_BYTES, reply, reply_size);

    new_reply->size = reply_size + TCP_MESSAGE_SIZE_BYTES;
    new_reply->sent = 0;
    strncpy(new_reply->log, log, sizeof(new_reply->log) - 1);
    new_reply->log[sizeof(new_reply->log) - 1] = '\0';
    new_reply->next = NULL;

    if(queue->tail == NULL) {
        queue->head = new_reply;
        queue->tail = new_reply;
    } else {
        queue->tail->next = new_reply;
        queue->tail = new_reply;
    }

    return STATUS_SUCCESS;
}


void tcpReplyQueueDelete(TCPReplyQueuePtr queue) {
    if(queue->head == NULL) {
        return;
    }

    TCPReply *reply = queue->head;
    queue->head = reply->next;

    if(queue->head == NULL) {
        queue->tail = NULL;
    }

    free(reply->data);
    free(reply);
}


void tcpReplyQueueClean(TCPReplyQueue *queue) {
    while(queue->head != NULL) {
        tcpReplyQueueDelete(queue);
    }
}

TCPReplyPtr tcpReplyQueueGet(TCPReplyQueuePtr queue) {
    return queue->head;
}