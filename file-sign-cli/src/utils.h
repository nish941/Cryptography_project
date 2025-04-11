#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "lamport.h"
#include "sha256.h"  // Added for SHA256_BLOCK_SIZE

// File I/O
ssize_t read_file(const char *path, uint8_t **out_buf, size_t *out_len);
int write_file(const char *path, const uint8_t *data, size_t len);

// Hashing and signatures
int hash_file(const char *path, uint8_t hash[SHA256_BLOCK_SIZE]);
int save_signature(const char *path, const uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]);
int load_signature(const char *path, uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]);

// Security
int secure_random(uint8_t *buf, size_t len);

#endif
