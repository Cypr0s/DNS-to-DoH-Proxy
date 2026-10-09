#include "data-structures/connection-dynamic-arr.h"

ExitStatus connectionVectorInit(ConnectionVectorPtr vector) {
    vector->poll_fds = malloc(VECTOR_DEFAULT_SIZE * sizeof(struct pollfd));
    if(vector->poll_fds == NULL) {
        return STATUS_MALLOC_FAILURE;
    }

    vector->connections = malloc(VECTOR_DEFAULT_SIZE * sizeof(Connection));
    if (vector->connections == NULL) {
        free(vector->poll_fds);
        vector->poll_fds = NULL;
        return STATUS_MALLOC_FAILURE;
    }

    vector->capacity = VECTOR_DEFAULT_SIZE;
    vector->curr_size = 0;
    return STATUS_SUCCESS;
}

ExitStatus connectionVectorInsert(ConnectionVectorPtr vector, struct pollfd poll_fd, Connection con) {
    if(vector == NULL) {
        return STATUS_SUCCESS;
    }

    if(vector->curr_size == vector->capacity) {
        size_t new_capacity = vector->capacity * VECTOR_UPSIZE_DOWNSIZE;
        struct pollfd* new_poll_fds = realloc(vector->poll_fds, new_capacity * sizeof(struct pollfd));
        if(new_poll_fds == NULL) {
            return STATUS_MALLOC_FAILURE;
        }
        ConnectionPtr new_connections = realloc(vector->connections, new_capacity * sizeof(Connection));

        if (new_connections == NULL) {
            vector->poll_fds = new_poll_fds;
            return STATUS_MALLOC_FAILURE;
        }

        vector->poll_fds = new_poll_fds;
        vector->connections = new_connections;
        vector->capacity = new_capacity;
    }

    vector->poll_fds[vector->curr_size] = poll_fd;
    vector->connections[vector->curr_size] = con;
    vector->curr_size++;
    return STATUS_SUCCESS;
}


ExitStatus connectionVectorDelete(ConnectionVectorPtr vector, int fd) {
    if(vector == NULL) {
        return STATUS_SUCCESS;
    }

    size_t i;
    for (i = 0; i < vector->curr_size; i++) {
        if (vector->poll_fds[i].fd == fd) {
            break;
        }
    }
    
    if (i == vector->curr_size) {
        return STATUS_SUCCESS;
    }

    close(vector->poll_fds[i].fd);
    tcpReplyQueueClean(&vector->connections[i].reply_queue);
    if(i != vector->curr_size - 1) {
        vector->poll_fds[i] = vector->poll_fds[vector->curr_size - 1];
        vector->connections[i] = vector->connections[vector->curr_size - 1];
    }

    vector->curr_size--;

    size_t new_capacity = vector->capacity / VECTOR_UPSIZE_DOWNSIZE;

    if(vector->curr_size < new_capacity && new_capacity >= VECTOR_DEFAULT_SIZE) {
        struct pollfd *new_poll_fds = realloc(vector->poll_fds, new_capacity * sizeof(struct pollfd));

        if (new_poll_fds == NULL) {
            return STATUS_MALLOC_FAILURE;
        }

        ConnectionPtr new_connections = realloc(vector->connections,new_capacity * sizeof(Connection));
        if (new_connections == NULL) {
            vector->poll_fds = new_poll_fds;
            return STATUS_MALLOC_FAILURE;
        }
        vector->poll_fds = new_poll_fds;
        vector->connections = new_connections;
        vector->capacity = new_capacity;
    }

    return STATUS_SUCCESS;
}


void connectionVectorClean(ConnectionVectorPtr vector) {
    if(vector != NULL && vector->connections != NULL && vector->poll_fds != NULL) {
        for(size_t i = 0; i < vector->curr_size; i++) {
            close(vector->poll_fds[i].fd);
            tcpReplyQueueClean(&vector->connections[i].reply_queue);
        }
        free(vector->poll_fds);
        free(vector->connections);
        vector->poll_fds = NULL;
        vector->curr_size = 0;
        vector->capacity = 0;
        vector->connections = NULL;
    }
}