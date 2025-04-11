#include "utils.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Random number generator
int secure_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return (r == len) ? 0 : -1;
}

// Read file
ssize_t read_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen failed"); // Add this line
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fprintf(stderr, "File is empty or invalid\n"); // Add this
        fclose(f);
        return -1;
    }

    *out_buf = malloc(fsize);
    if (!*out_buf) {
        fprintf(stderr, "Memory allocation failed\n"); // Add this
        fclose(f);
        return -1;
    }

    size_t read = fread(*out_buf, 1, fsize, f);
    fclose(f);

    if (read != (size_t)fsize) {
        fprintf(stderr, "Read %zu bytes, expected %ld\n", read, fsize); // Add this
        free(*out_buf);
        return -1;
    }

    *out_len = fsize;
    return fsize;
}

// Write file
int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
}

// Hash file
int hash_file(const char *path, uint8_t hash[SHA256_BLOCK_SIZE]) {  // Fixed duplicate declaration
    uint8_t *buf = NULL;
    size_t len;
    if (read_file(path, &buf, &len) < 0) return -1;  // Changed read_real to read_file
    sha256(buf, len, hash);
    free(buf);
    return 0;
}

// Save signature
int save_signature(const char *path, const uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]) {
    return write_file(path, (const uint8_t *)signature, LAMPORT_N * SHA256_BLOCK_SIZE);
}

// Load signature
int load_signature(const char *path, uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]) {
    uint8_t *buf = NULL;
    size_t len;
    if (read_file(path, &buf, &len) < 0) return -1;
    
    if (len != LAMPORT_N * SHA256_BLOCK_SIZE) {
        free(buf);
        return -1;
    }
    
    memcpy(signature, buf, len);  // Changed mem to memcpy
    free(buf);
    return 0;
}
