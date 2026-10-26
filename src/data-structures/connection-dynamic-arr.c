/**
 * @file    connection-dynamic-arr.c
 * @author  Kristian Luptak
 * @brief   Contains implementation API of connecction vector
 *          
 * @date    2026-10-23
 */

#include "data-structures/connection-dynamic-arr.h"

ExitStatus connectionVectorCtor(ConnectionVectorPtr vector) {
    // poll FDS
    vector->poll_fds = malloc(VECTOR_DEFAULT_SIZE * sizeof(struct pollfd));
    if(vector->poll_fds == NULL) {
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    // client connections
    vector->connections = malloc(VECTOR_DEFAULT_SIZE * sizeof(Connection));
    if(vector->connections == NULL) {
        free(vector->poll_fds);
        PRINT_ERROR("Memory allocation failure");
        return STATUS_MALLOC_FAILURE;
    }

    vector->capacity = VECTOR_DEFAULT_SIZE;
    vector->curr_size = 0;
    return STATUS_SUCCESS;
} // connectionVectorInit


ExitStatus connectionVectorInsert(ConnectionVectorPtr vector, struct pollfd poll_fd, Connection con) {
    if(vector == NULL) {
        return STATUS_FAILURE;
    }

    // upsize vector
    if(vector->curr_size == vector->capacity) {
        size_t new_capacity = vector->capacity * VECTOR_UPSIZE_DOWNSIZE;
        // new fds
        struct pollfd* new_poll_fds = realloc(vector->poll_fds, new_capacity * sizeof(struct pollfd));
        if(new_poll_fds == NULL) {
            PRINT_ERROR("Memory allocation failure");
            return STATUS_MALLOC_FAILURE;
        }

        // new connections
        ConnectionPtr new_connections = realloc(vector->connections, new_capacity * sizeof(Connection));
        if(new_connections == NULL) {
            PRINT_ERROR("Memory allocation failure");
            vector->poll_fds = new_poll_fds;
            return STATUS_MALLOC_FAILURE;
        }

        vector->poll_fds = new_poll_fds;
        vector->connections = new_connections;
        vector->capacity = new_capacity;
    }

    // add connection
    vector->poll_fds[vector->curr_size] = poll_fd;
    vector->connections[vector->curr_size] = con;
    vector->curr_size++;
    return STATUS_SUCCESS;
} // connectionVectorInsert


ExitStatus connectionVectorDelete(ConnectionVectorPtr vector, int fd) {
    if(vector == NULL) {
        return STATUS_FAILURE;
    }

    // find index
    size_t i;
    for(i = 0; i < vector->curr_size; i++) {
        if(vector->poll_fds[i].fd == fd) {
            break;
        }
    }
    
    if(i == vector->curr_size) {
        return STATUS_SUCCESS;
    }
    // destroy whole connection
    close(vector->poll_fds[i].fd);
    tcpReplyQueueDtor(&vector->connections[i].reply_queue);
    if(i != vector->curr_size - 1) {
        vector->poll_fds[i] = vector->poll_fds[vector->curr_size - 1];
        vector->connections[i] = vector->connections[vector->curr_size - 1];
    }

    vector->curr_size--;

    // downsize vector
    size_t new_capacity = vector->capacity / VECTOR_UPSIZE_DOWNSIZE;

    if(vector->curr_size < new_capacity && new_capacity >= VECTOR_DEFAULT_SIZE) {
        struct pollfd *new_poll_fds = realloc(vector->poll_fds, new_capacity * sizeof(struct pollfd));
        if(new_poll_fds == NULL) {
            PRINT_ERROR("Memory allocation failure");
            return STATUS_MALLOC_FAILURE;
        }

        ConnectionPtr new_connections = realloc(vector->connections,new_capacity * sizeof(Connection));
        if(new_connections == NULL) {
            vector->poll_fds = new_poll_fds;
            PRINT_ERROR("Memory allocation failure");
            return STATUS_MALLOC_FAILURE;
        }
        vector->poll_fds = new_poll_fds;
        vector->connections = new_connections;
        vector->capacity = new_capacity;
    }

    return STATUS_SUCCESS;
} // connectionVectorDelete


void connectionVectorDtor(ConnectionVectorPtr vector) {
    if(vector != NULL && vector->connections != NULL && vector->poll_fds != NULL) {
        for(size_t i = 0; i < vector->curr_size; i++) {
            close(vector->poll_fds[i].fd);
            tcpReplyQueueDtor(&vector->connections[i].reply_queue);
        }
        free(vector->poll_fds);
        free(vector->connections);
        vector->poll_fds = NULL;
        vector->curr_size = 0;
        vector->capacity = 0;
        vector->connections = NULL;
    }
} // connectionVectorClean