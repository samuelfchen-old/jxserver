#include "server.h"
#include "compression.h"

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
    (byte & 0x80 ? '1' : '0'), \
    (byte & 0x40 ? '1' : '0'), \
    (byte & 0x20 ? '1' : '0'), \
    (byte & 0x10 ? '1' : '0'), \
    (byte & 0x08 ? '1' : '0'), \
    (byte & 0x04 ? '1' : '0'), \
    (byte & 0x02 ? '1' : '0'), \
    (byte & 0x01 ? '1' : '0')

/**
 * Read in dictionary
 */
void read_dict(struct compression_data* data) {
    // open byte
    FILE* fp = fopen("compression.dict", "rb");
    // get length
    fseek(fp, 0, SEEK_END);
    long filelen = ftell(fp);
    rewind(fp);
    // read into byte array
    uint8_t* buf = (uint8_t*) malloc((filelen+1));
    fread(buf, filelen, 1, fp);
    fclose(fp);

    // read out the data
    uint8_t byte = 0;
    int cursor = 0;
    int offset = 0;
    while (cursor < filelen - 1) {
        struct bitcode* curr = &data->codes[byte];
        curr->byte = byte;

        // read in the length
        curr->length = (buf[cursor] << offset) |  (buf[cursor+1] >> (8-offset));
        cursor++;

        // calculate length of byte array for bitcode
        if ((curr->length % 8) == 0) {
            curr->arrlen = curr->length / 8;
        } else {
            curr->arrlen = curr->length / 8 + 1;
        }

        curr->code = (uint8_t*) malloc(curr->arrlen );

        // read in the bitcode
        for (int i = 0; i < curr->arrlen; i++) {
            curr->code[i] = (buf[cursor] << offset) |  (buf[cursor+1] >> (8-offset));
            cursor++;
        } cursor--;

        // updates offset based on if cursor goes into the next byte or not
        int old_offset = offset;
        offset = (offset + curr->length) % 8;
        if (offset <= old_offset) cursor++;

        byte++;
    }

    free(buf);

    return;
}

void print_code(struct bitcode* c) {
    printf("length of 0x%02x: %d \tarrlen: %u\t", c->byte, c->length, c->arrlen);
    printf("0b");
    for (int j = 0; j < c->arrlen; j++) {
        printf(BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(c->code[j]));
    } printf("\n");
    return;
}

/**
 * Checks if the nth bit is set in c
 */
int bit_check (unsigned char c, int n) {
    static unsigned char mask[] = {128, 64, 32, 16, 8, 4, 2, 1};
    return ((c & mask[n]) != 0);
}

struct node* init_node() {
    struct node* n = (struct node*) malloc(sizeof(struct node));
    n->left = NULL;
    n->right = NULL;
    n->bitcode = NULL;
    return n;
}

/**
 * Builds bitcode tree (left = 1, right = 0)
 */
void build_tree(struct compression_data* data) {
    data->root = init_node();
    // Iterate through all 256 bitcodes
    for (int i = 0; i < 256; i++) {
        struct bitcode* curr = &data->codes[i];
        struct node* cursor = data->root;
        int lim;
        // Traverse down the tree for each bitcode
        for (int j = 0; j < curr->arrlen; j++) {
            if (j == curr->arrlen - 1) lim = curr->length % 8;
            else lim = 8;

            for (int k = 0; k < lim; k++) {
                if (bit_check(curr->code[j], k)) {
                    // go left
                    if (cursor->left == NULL) cursor->left = init_node();
                        cursor = cursor->left;
                } else {
                    // go right
                    if (cursor->right == NULL) cursor->right = init_node();
                    cursor = cursor->right;
                }
            }
        }
        cursor->bitcode = curr;
    }
}

void print_tree(struct node* n) {
    if (n == NULL) return;
    if (n->bitcode != NULL && n->bitcode->arrlen < 3) {
        print_code(n->bitcode);
    }
    print_tree(n->left);
    print_tree(n->right);
}

/**
 * Encodes message 'in' to the payload of 'out'
 */
void encode(struct message* in, struct message* out, struct compression_data* data) {
    // struct message* out = malloc(sizeof(struct message));
    out->header = in->header;
    out->header |= HEADER_COMP;

    // calculate array length
    int out_index = 0;

    int total_bits = 0;
    for (int i = 0; i < in->length; i++) {
        total_bits += data->codes[in->payload[i]].length;
    }

    out->length = (uint64_t) total_bits / 8;
    if (total_bits % 8 != 0) out->length += 1;
    out->length += 1;

    free(out->payload);
    out->payload = malloc(sizeof(uint8_t) * out->length);

    memset(out->payload, 0, out->length);
    int offset = 0;

    struct bitcode* curr;

    for (int i = 0; i < in->length; i++) {
        curr = &data->codes[in->payload[i]];
        // for each of the bytes in the bitcode
        for (int j = 0; j < curr->arrlen; j++) {
            // last byte of bitcode (could change offset)
            if (j == curr->arrlen - 1) {
                uint8_t last = curr->code[curr->arrlen - 1];
                int remaining = curr->length % 8;
                if (remaining == 0) remaining = 8;
                // set all the garbage bytes to 0
                for (int k = 0; k < (8-remaining)%8; k++) {
                    // clear a single bit
                    last &= ~(1 << k);
                }

                if (offset + remaining < 8) {
                    // doesnt go into next byte
                    out->payload[out_index] |= last >> offset;
                } else {
                    // goes into next byte
                    out->payload[out_index] |= last >> offset;
                    out->payload[out_index + 1] |= last << (8 - offset);
                    out_index++;
                }
                // update offset
                offset = (offset + remaining) % 8;
            } else {
                // doesnt change offset
                out->payload[out_index] |= curr->code[j] >> offset;
                out->payload[out_index + 1] |= curr->code[j] << (8 - offset);
                out_index++;
            }
        }
    }

  // set padding
  out->payload[out->length - 1] = (8 - (total_bits % 8)) % 8;

  return;
}

/**
 * Decodes message 'in' to the payload of 'out'
 */
void decode(struct message* in, struct message* out, struct compression_data* data) {
    // Set the header of out
    out->header = in->header;

    int out_index = 0;

    int out_capacity = in->length;
    free(out->payload);
    out->payload = malloc(out_capacity);

    // traverse tree to find the bitcode
    struct node* cursor = data->root;
    for (int i = 0; i < in->length - 1; i++) {
        for (int j = 0; j < 8; j++) {
            if (bit_check(in->payload[i], j)) {
                // go left
                cursor = cursor->left;
            } else {
                // go right
                cursor = cursor->right;
            }
            // Leaf node: must be a bitcode
            if (cursor->left == NULL && cursor->right == NULL) {
                out_index++;
                if (out_index == out_capacity) {
                    out_capacity *= 2;
                    out->payload = realloc(out->payload, out_capacity);
                }
                out->payload[out_index - 1] = cursor->bitcode->byte;

                cursor = data->root;
            }
        }
    }

    out->length = out_index;
    return;
}

void clean_tree(struct node* n) {
    if (n == NULL) return;
    clean_tree(n->left);
    clean_tree(n->right);
    free(n);
}

// Clean all compresion data
void clean_compression(struct compression_data* data) {
    // clean array
    for (int i = 0; i < 256; i++) {
        free(data->codes[i].code);
    }
    clean_tree(data->root);
    free(data);
}
