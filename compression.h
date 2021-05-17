#ifndef COMPRESSION_H
#define COMPRESSION_H

// Bitcode data
struct bitcode {
    uint8_t byte;
    uint8_t length;
    uint8_t arrlen;
    uint8_t* code;
};

// Node in bitcode tree
struct node {
    struct bitcode* bitcode;
    struct node* left;
    struct node* right;
};

// Array of bitcodes
struct compression_data {
    struct bitcode codes[256];
    struct node* root;
};

void read_dict(struct compression_data* data);
void print_code(struct bitcode* c);
int bit_check (unsigned char c, int n);
void build_tree(struct compression_data* data);
void clean_compression(struct compression_data* data);

void encode(struct message* in, struct message* out, struct compression_data* data);
void decode(struct message* in, struct message* out, struct compression_data* data);

#endif
