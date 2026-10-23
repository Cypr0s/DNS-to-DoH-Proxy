/**
 * @file    connection-dynamic-arr.h
 * @author  Kristian Luptak
 * @brief   Contains declaration API of connecction vector
 *          
 * @date    2026-10-23
 */

#ifndef CONNECTION_DYNAMIC_ARR_H
#define CONNECTION_DYNAMIC_ARR_H

#include <stdio.h>
#include "common.h"
#include <poll.h>
#include "error.h"
#include <unistd.h> // close
#include <stdint.h>
#include <sys/socket.h>
#include "data-structures/reply-queue.h"
#include <time.h>

typedef enum {
    UDP_LISTEN,
    TCP_LISTEN,
    TCP_CLIENT,
} ConnectionType;

typedef struct {
    struct timespec last_event;
    ConnectionType type;
    struct sockaddr_storage address;
    int32_t address_size;
    TCPReplyQueue reply_queue;
    char message_buffer[DNS_QUERY_MAX_SIZE + TCP_MESSAGE_SIZE_BYTES];
    uint16_t currently_received;
    uint16_t message_size;
} Connection, *ConnectionPtr;

typedef struct {
    struct pollfd* poll_fds;        // poll_fds share index with connection
    ConnectionPtr connections;
    size_t capacity;
    size_t curr_size;
} ConnectionVector, *ConnectionVectorPtr;


/**
 * @brief           Initializes vector which will store connection fd, client connectios
 * 
 * @param vector    target vector
 * @return          ExitStatus SUCCESS | MALLOC
 */
ExitStatus connectionVectorCtor(ConnectionVectorPtr vector);


/**
 * @brief           Inserts connection and its corresponding pollfd into vector
 * 
 * @param vector    Target vector
 * @param poll_fd   poll fd
 * @param con       connection
 * @return          ExitStatus SUCCES | MALLOC
 */
ExitStatus connectionVectorInsert(ConnectionVectorPtr vector, struct pollfd poll_fd, Connection con);


/**
 * @brief           Deletes entry from both vector based on input FD(both connection and poll fd gets deleted)
 * 
 * @param vector    Target vector
 * @param fd        input fd
 * @return          ExitStatus SUCCES | MALLOC
 */
ExitStatus connectionVectorDelete(ConnectionVectorPtr vector, int fd);


/**
 * @brief           Cleans whole vector of connections
 * 
 * @param vector    Target vector
 */
void connectionVectorDtor(ConnectionVectorPtr vector);

#endif // CONNECTION_DYNAMIC_ARR_H
