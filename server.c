#include "server.h"
#include "compression.h"
#include "thread_pool.h"
#include "performance-parameters.h"

/**
 * Swap byte order of uint64_t (if necessary)
 */
uint64_t swap_bytes(const uint64_t *input) {
    int num = 42;
    if(*(char *)&num == 42) {
        // local byte order is Little Endian (needs swapping)
        uint64_t rval;
        uint8_t *data = (uint8_t *)&rval;

        data[0] = *input >> 56;
        data[1] = *input >> 48;
        data[2] = *input >> 40;
        data[3] = *input >> 32;
        data[4] = *input >> 24;
        data[5] = *input >> 16;
        data[6] = *input >> 8;
        data[7] = *input >> 0;

        return rval;
    } else {
        //Big Endian
        return *input;
    }
}

/**
 * Decode message (sets to itself)
 * @return             message ptr
 */
struct message* decode_self(struct message* m, struct compression_data* compression) {
    struct message* t = new_message();
    decode(m, t, compression);
    t->header = m->header;
    free(m->payload);
    free(m);
    return t;
}

/**
 * Encode message (sets to itself)
 * @return             message ptr
 */
struct message* encode_self(struct message* m, struct compression_data* compression) {
    struct message* t = new_message();
    encode(m, t, compression);
    // t->header = m->header;
    free(m->payload);
    free(m);
    return t;
}

/**
 * Create new message
 */
struct message* new_message() {
    struct message* m = malloc(sizeof(struct message));
    m->header = 0;
    m->payload = NULL;
    m->length = 0;
    return m;
}

/**
 * Write message to client
 */
void write_message(struct message* m, struct conn_data* conn) {
    write(conn->fd, &m->header, 1); // write header
    uint64_t n_retlen = swap_bytes(&m->length);
    write(conn->fd, &n_retlen, 8);
    write(conn->fd, m->payload, m->length); // write payload
}

/**
 * Create new request
 */
struct request* new_request() {
    struct request* req = malloc(sizeof(struct request));
    req->id = 0;
    req->next = NULL;
    req->prev = NULL;
    req->filename = NULL;
    req->buffer = NULL;
    return req;
}

/**
 * Clean request linked list
 */
void clean_requests(struct request* head) {
    struct request* temp;
    while (head != NULL) {
        temp = head->next;
        free(head->filename);
        free(head->buffer);
        free(head);
        head = temp;
    }
}

/**
 * Rearm event
 */
void rearm(struct conn_data* conn) {
    // rearm fd
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLONESHOT;
    event.data.fd = conn->fd;
    if (epoll_ctl(conn->epoll_fd, EPOLL_CTL_MOD, conn->fd, &event) == -1)
        perror("Epoll_ctl: listen sock");
}

/**
 * Sends error message
 */
void error_c(void* data) {
    struct conn_data* conn = (struct conn_data*) data;
    uint8_t rethead = ERROR_OUT;
    write(conn->fd, &rethead, 1);
    uint64_t retlen = 0;
    write(conn->fd, &retlen, 8);

    close(conn->fd);
    free(data);
    return;
}

/**
 * Echoes payload back to client
 */
void echo_c(void* data) {
    struct conn_data* conn = (struct conn_data*) data;
    struct message* m = new_message();

    // Read in message
    uint64_t rawlength;
    read(conn->fd, &rawlength, 8);

    m->header = conn->header;
    m->length = swap_bytes(&rawlength);
    m->payload = (uint8_t*)malloc(sizeof(uint8_t) * m->length);
    read(conn->fd, m->payload, m->length);

    // Create return message
    struct message* r = new_message();

    // Encode / Decode if necessary, change header
    if (is_comp(m->header) && !req_comp(m->header)) {
        decode(m, r, conn->compression);
        r->header = ECHO_OUT;
        free(m->payload);
    } else if (!is_comp(m->header) && req_comp(m->header)) {
        encode(m, r, conn->compression);
        r->header = ECHO_OUT;
        r->header |= HEADER_COMP;
        free(m->payload);
    } else{
        r->header = ECHO_OUT;
        if (req_comp(m->header)) r->header |= HEADER_COMP;
        r->payload = m->payload;
        r->length = m->length;
    }

    write_message(r, conn);

    free(r->payload);
    free(r);
    free(m);

    // rearm
    rearm(conn);

    free(data);
    return;
}

/**
 * List directory
 */
void list_c(void* data) {
    struct conn_data* conn = (struct conn_data*) data;

    // read in length of 0
    uint64_t rawlength;
    read(conn->fd, &rawlength, 8);

    struct message* r = new_message();

    r->header = LIST_OUT;
    // Open and read out directory
    struct dirent *dir;
    DIR* d = opendir(conn->dir);

    r->payload = malloc(0);
    size_t temp_len;
    r->length = 0;

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {
                temp_len = strlen(dir->d_name) + 1;

                r->payload = realloc(r->payload, r->length + temp_len);
                for (int i = 0; i < temp_len; i++) {
                    r->payload[r->length + i] = dir->d_name[i];
                }
                r->length += temp_len;
            }
        }
        closedir(d);
    }

    // Return NULL byte if no files
    if (r->length == 0) {
        r->payload = malloc(1);
        r->payload[0] = '\0';
        r->length = 1;
    }

    // Encode if necessary
    if (req_comp(conn->header)) {
        r = encode_self(r, conn->compression);
    }

    write_message(r, conn);

    free(r->payload);
    free(r);

    rearm(conn);
    free(data);

    return;
}

/**
 * Get file size
 */
void size_c(void* data) {
    struct conn_data* conn = (struct conn_data*) data;
    struct message* m = new_message();

    // Read in message
    uint64_t rawlength;
    read(conn->fd, &rawlength, 8);

    m->length = swap_bytes(&rawlength);
    m->header = conn->header;
    m->payload = (uint8_t*)malloc(sizeof(uint8_t) * m->length);
    read(conn->fd, m->payload, m->length);

    // Decode if necessary
    if (is_comp(m->header)) {
        m = decode_self(m, conn->compression);
    }

    // read in file
    char* path = malloc(strlen(conn->dir) + m->length + 1);
    strcpy(path, conn->dir);
    strcat(path, "/");
    strcat(path, (char*) m->payload);

    FILE* fp = fopen(path, "rb");

    uint64_t filelen;
    if (fp == NULL) {
        error_c(conn);
        free(m->payload);
        free(m);
        return;
    } else {
        fseek(fp, 0, SEEK_END);
        filelen = ftell(fp);
    }

    fclose(fp);
    free(path);

    // Set return message
    struct message* r = new_message();

    r->header = SIZE_OUT;
    r->length = 8;
    uint64_t* n_filelen = malloc(sizeof(uint64_t));
    *n_filelen = swap_bytes(&filelen);
    r->payload = (uint8_t *)n_filelen;

    // Encode if necessary
    if (req_comp(m->header)) {
        r = encode_self(r, conn->compression);
    }

    write_message(r, conn);

    free(r->payload);
    free(r);
    free(m->payload);
    free(m);

    rearm(conn);
    free(data);
    return;
}

/**
 * Retrieve file
 */
void retrieve_c (void* data) {
    struct conn_data* conn = (struct conn_data*) data;
    struct message* m = new_message();

    // Read in message
    uint64_t rawlength;
    read(conn->fd, &rawlength, 8);

    m->header = conn->header;
    m->length = swap_bytes(&rawlength);
    m->payload = (uint8_t*)malloc(sizeof(uint8_t) * m->length);
    read(conn->fd, m->payload, m->length);

    // Decode if necessary
    if (is_comp(m->header)) {
        m = decode_self(m, conn->compression);
    }

    // extract info from payload
    uint32_t id = *(uint32_t*)(m->payload);
    uint64_t* n_offset = (uint64_t*) (m->payload + 4);
    uint64_t* n_length = (uint64_t*) (m->payload + 12);
    char* filename = (char*) (m->payload + 20);
    uint64_t offset = swap_bytes(n_offset);
    uint64_t length = swap_bytes(n_length);

    // attempt to open file, return error if unable
    // read in file
    char* path = malloc(strlen(conn->dir) + strlen(filename) + 2);
    strcpy(path, conn->dir);
    strcat(path, "/");
    strcat(path, filename);

    FILE* fp = fopen(path, "rb");
    free(path);
    if (fp == NULL) {
        error_c(conn);
        free(m->payload);
        free(m);
        return;
    }

    // check offset and length, error if necessary
    fseek(fp, 0, SEEK_END);
    long filelen = ftell(fp);
    rewind(fp);
    if (offset + length > filelen) {
        error_c(conn);
        free(m->payload);
        free(m);
        return;
    }

    // search for the request
    struct request* req = NULL;
    bool id_error = false;
    struct request* curr = conn->req_head;
    struct request* temp;
    while (1) {
        pthread_mutex_lock(&curr->lock);
        // if matching id found
        if (id == curr->id) {
            // check if the request has been fulfilled already
            if (curr->cursor >= curr->length) {
                if (!(strcmp(filename, curr->filename) == 0 && offset == curr->offset
                && length == curr->length)) {
                    // create new request under this session id
                    curr->length = length;
                    curr->offset = offset;
                    curr->cursor = 0;
                    curr->filename = realloc(curr->filename, m->length - 20);
                    curr->id = id;
                    memcpy(curr->filename, filename, m->length - 20);
                }

                req = curr;
            } else {
                // if unfulfilled, check if attr matches
                if (strcmp(filename, curr->filename) == 0 && offset == curr->offset
                && length == curr->length) {
                    req = curr;
                } else {
                    // Invalid request error
                    id_error = true;
                }
            }
            pthread_mutex_unlock(&curr->lock);
            break;
        }

        // check if next exists
        if (curr->next == NULL) {
            // no next, make it and build the buffer (create new request)
            curr->next = new_request();
            curr->next->next = NULL;
            curr->next->prev = curr;

            pthread_mutex_init(&curr->next->lock, NULL);
            req = curr->next;

            pthread_mutex_lock(&req->lock);
            pthread_mutex_unlock(&curr->lock);
            req->length = length;
            req->offset = offset;
            req->cursor = 0;
            req->filename = strdup(filename);
            req->id = id;

            // build buffer, read in necessary bytes
            req->buffer = malloc(length);
            fseek(fp, offset, SEEK_SET);
            fread(req->buffer, 1, length, fp);
            pthread_mutex_unlock(&req->lock);
            break;
        }

        // move to next request
        temp = curr->next;
        pthread_mutex_unlock(&curr->lock);
        curr = temp;
    }

    fclose(fp);

    // handle invalid requests
    if (id_error) {
        error_c(conn);
        free(m->payload);
        free(m);
        return;
    }

    // create return message
    struct message* r = new_message();
    r->header = FILE_OUT;
    r->payload = malloc(20 + length);
    r->length = 0;
    struct message* c = new_message();

    uint64_t writelen, writeoff, writecur, n_writelen, n_writeoff;
    bool written = false; // flag to check if thread wrote anything
    #ifdef DEBUG_FILE
        int numwritten = 0;
    #endif

    // Keep sending packets till buffer empty
    while (1) {
        pthread_mutex_lock(&req->lock);
        // Check if buffer is empty or not
        if (req->cursor >= req->length) {
            pthread_mutex_unlock(&req->lock);
            break;
        }

        // set flag
        written = true;

        // Set offset and length
        writeoff = req->offset + req->cursor;
        if (req->cursor + PACKET_SIZE > req->length)
            writelen = req->length - req->cursor;
        else writelen = PACKET_SIZE;

        r->length = 20 + writelen;
        writecur = req->cursor;
        req->cursor += PACKET_SIZE; // advance cursor

        n_writeoff = swap_bytes(&writeoff);
        n_writelen = swap_bytes(&writelen);

        // Set r's payload
        memcpy(r->payload, &req->id, 4);
        memcpy(r->payload+4, &n_writeoff, 8);
        memcpy(r->payload+12, &n_writelen, 8);
        memcpy(r->payload+20, req->buffer + writecur, writelen);

        #ifdef DEBUG_FILE
            numwritten++;
        #endif

        pthread_mutex_unlock(&req->lock);

        // encode if necessary and write
        if (req_comp(m->header) || COMPRESSION_RATIO >= 1.25) {
            encode(r, c, conn->compression);
            write_message(c, conn);
        } else {
            write_message(r, conn);
        }
        // Release mutex control to allow other threads to lock
        usleep(1);
    }

    #ifdef DEBUG_FILE
        printf("Conn %u wrote %u times\n", conn->fd, numwritten);
    #endif

    // If thread did not send anything
    if (!written) {
        // write empty
        write(conn->fd, &r->header, 1); // write header
        uint64_t n_retlen = swap_bytes(&r->length);
        write(conn->fd, &n_retlen, 8);
    }

    // free all the messages
    free(c->payload);
    free(c);
    free(r->payload);
    free(r);
    free(m->payload);
    free(m);

    // rearm
    rearm(conn);

    free(data);
    return;
}

int main(int argc, char const *argv[]) {

    #ifdef DEBUG_TIME
        clock_t begin = clock();
    #endif

    // read config
    assert(argc == 2);

    FILE* fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    long filelen = ftell(fp);
    rewind(fp);

    char* directory = (char *)malloc(filelen - 5);

    unsigned long addr;
    unsigned short port;

    fread(&addr, 4, 1, fp);
    fread(&port, 2, 1, fp);
    fread(directory, filelen-6, 1, fp);
    directory[filelen-6] = '\0';

    fclose(fp);

    // read in bitcodes
    struct compression_data* compression = malloc(sizeof(struct compression_data));
    read_dict(compression);
    build_tree(compression);

    // Initialise server connection
    int serversocket_fd = -1;
    int clientsocket_fd = -1;
    int option = 1;

    struct sockaddr_in address;

    serversocket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(serversocket_fd < 0) perror("Could not create socket");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = addr;
    address.sin_port = port;

    setsockopt(serversocket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
        &option, sizeof(int));

    if(bind(serversocket_fd, (struct sockaddr*) &address,
        sizeof(struct sockaddr_in)))
        perror("Could not bind socket");

    // create epoll
    int event_count;
    struct epoll_event event, events[MAX_EVENTS];
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) perror("Failed to create epoll file descriptor");

    // add server socket to epoll
    event.events = EPOLLIN;
    event.data.fd = serversocket_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, serversocket_fd, &event) == -1)
        perror("Epoll_ctl: listen sock");

    // make accept non blocking
    int flags = fcntl(serversocket_fd, F_GETFL, 0);
    fcntl(serversocket_fd, F_SETFL, flags | O_NONBLOCK);

    listen(serversocket_fd, SOMAXCONN);

    // create thread pool
    tpool_t* tp = tpool_create(CPUS * 2);

    // create request list head
    struct request* req_head = new_request();

    pthread_mutex_init(&req_head->lock, NULL);

    int shutdown_flag = 0;

    while (!shutdown_flag) {
        event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (event_count < 0) perror("Error in epoll_wait");

        for (int i = 0; i < event_count; i++) {
            int socketfd = events[i].data.fd;
            if (socketfd == serversocket_fd) {
                // New client
                uint32_t addrlen = sizeof(struct sockaddr_in);
                clientsocket_fd = accept(serversocket_fd,
                (struct sockaddr*) &address, &addrlen);

                event.events = EPOLLIN | EPOLLONESHOT;
                event.data.fd = clientsocket_fd;

                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clientsocket_fd, &event) == -1)
                    perror("Epoll_ctl: client sock");
            } else {
                // Message from client

                // read in the header
                uint8_t header;
                // if (read(socketfd, &header, 1)) {
                if (read(socketfd, &header, 1) == 0) {
                    close(socketfd);
                } else {
                    struct conn_data* data = malloc(sizeof(struct conn_data));
                    data->fd = socketfd;
                    data->compression = compression;
                    data->dir = directory;
                    data->header = header;
                    data->epoll_fd = epoll_fd;
                    data->req_head = req_head;
                    // Decide which function to perform
                    switch (header&0xF0) {
                        case ECHO_IN:
                            //echo
                            // tpool_add_work(tp, echo_c, data);
                            echo_c(data);
                            break;
                        case LIST_IN:
                            //dir list
                            // tpool_add_work(tp, list_c, data);
                            list_c(data);
                            break;
                        case SIZE_IN:
                            // file size query
                            // tpool_add_work(tp, size_c, data);
                            size_c(data);
                            break;
                        case FILE_IN:
                            // retrieve file
                            tpool_add_work(tp, retrieve_c, data);
                            break;
                        case SHUT_IN:
                            // shutdown
                            shutdown_flag = 1;
                            tpool_destroy(tp);
                            free(data);
                            break;
                        default:
                            // error
                            // tpool_add_work(tp, error_c, data);
                            error_c(data);
                            break;
                    }
                    // stop handling client messages if shutdown called
                    if (shutdown_flag) break;
                }
            }
        }
    }

    // Cleanup
    close(epoll_fd);
    close(serversocket_fd);
    shutdown(serversocket_fd, SHUT_RDWR);

    clean_compression(compression);
    free(directory);

    clean_requests(req_head);

    #ifdef DEBUG_TIME
        clock_t end = clock();
        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
        printf("Time taken: %f\n", time_spent);
    #endif

    return 0;
}
