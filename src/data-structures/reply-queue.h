/**
 * @file    reply-queue.h
 * @author  Kristian Luptak
 * @brief   Contains declarations of reply queue struct
 *          
 * @date    2026-10-23
 */

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
    char log[LOG_LINE_MAX];
    struct TCPReply *next;
} TCPReply, *TCPReplyPtr;


typedef struct {
    TCPReplyPtr head;
    TCPReplyPtr tail;
} TCPReplyQueue, *TCPReplyQueuePtr;


/**
 * @brief       Initiates tcp reply queue
 * 
 * @param queue Target queue
 */
void tcpReplyQueueCtor(TCPReplyQueuePtr queue);


/**
 * @brief               Adds item into queue
 * 
 * @param queue         Target 
 * @param reply         Created reply 
 * @param reply_size    Reply size (bytes)
 * @param log           Create log line which will be printed after its sent
 * @return ExitStatus 
 */
ExitStatus tcpReplyQueuePush(TCPReplyQueuePtr queue, char* reply, size_t reply_size, char* log);


/**
 * @brief       Destroys and frees first element in the queue        
 * 
 * @param queue Target queue
 */
void tcpReplyQueueDelete(TCPReplyQueuePtr queue);


/**
 * @brief       Destroys whole queue       
 * 
 * @param queue Target queue
 */
void tcpReplyQueueDtor(TCPReplyQueuePtr queue);


/**
 * @brief       Returns first in queue         
 * 
 * @param queue Target queue
 * @return      reply or null
 */
TCPReplyPtr tcpReplyQueueGet(TCPReplyQueuePtr queue);

#endif