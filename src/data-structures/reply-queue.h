#include <stdio.h>
#include "error.h"
#include "common.h"
#include <stdint.h>

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

static TCPReplyPtr tcpReplyQueueGet(TCPReplyQueuePtr queue);