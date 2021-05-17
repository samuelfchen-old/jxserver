#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <dirent.h>
#include <time.h>

#define MAX_EVENTS 16
#define PACKET_SIZE 10000
#define NCPUS get_nprocs()

#define ECHO_IN 0x00
#define ECHO_OUT 0x10
#define LIST_IN 0x20
#define LIST_OUT 0x30
#define SIZE_IN 0x40
#define SIZE_OUT 0x50
#define FILE_IN 0x60
#define FILE_OUT 0x70
#define SHUT_IN 0x80
#define ERROR_OUT 0xF0

#define HEADER_COMP 0x08

// #define DEBUG_TIME // Time main function
// #define DEBUG_FILE // See how many packets were sent by each conn

#define is_comp(h) (((h) & 0x08) >> 3)  // If header is compressed
#define req_comp(h) (((h) & 0x04) >> 2) // If header requires compression

// Data struct sent to thread functions
struct conn_data {
    int fd;
    int epoll_fd;
    struct compression_data* compression;
    char* dir;
    uint8_t header;
    struct request* req_head;
};

// Request info
struct request {
    struct request* next;
    struct request* prev;
    pthread_mutex_t lock;
    uint32_t id;
    char* filename;
    uint64_t length;
    uint64_t offset;
    uint64_t cursor;
    uint8_t* buffer;
};

// Message info
struct message {
    uint8_t header;
    uint64_t length;
    uint8_t* payload;
};

uint64_t swap_bytes(const uint64_t *input);
struct message* new_message();
void write_message(struct message* m, struct conn_data* conn);
struct request* new_request();
void clean_requests(struct request* head);
void rearm(struct conn_data* conn);

#endif
