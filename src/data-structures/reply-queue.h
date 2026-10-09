#ifndef REPLY_QUEUE_H
#define REPLY_QUEUE_H

#include <stdio.h>
#include "error.h"
#include "common.h"
#include <stdint.h>
#include "util/string.h"

typedef struct TCPReply {
    char* data;
    size_t size;
    size_t sent;
    struct TCPReply *next;
} TCPReply, *TCPReplyPtr;


typedef struct {
    TCPReplyPtr head;
    TCPReplyPtr tail;
} TCPReplyQueue, *TCPReplyQueuePtr;

void tcpReplyQueueInit(TCPReplyQueuePtr queue);

ExitStatus tcpReplyQueuePush(TCPReplyQueuePtr queue, char* reply, size_t reply_size);

void tcpReplyQueueDelete(TCPReplyQueuePtr queue);

void tcpReplyQueueClean(TCPReplyQueuePtr queue);

TCPReplyPtr tcpReplyQueueGet(TCPReplyQueuePtr queue);

#endif