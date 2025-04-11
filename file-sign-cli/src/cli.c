#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "lamport.h"
#include "sha256.h"
#include "utils.h"

void printf_usage() {
    printf("Usage:\n");
    printf("  --gen-keys <private_key> <public_key>\n");
    printf("  --sign <private_key> <file_to_sign> <signature_output>\n");
    printf("  --verify <public_key> <file> <signature>\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf_usage();
        return 1;
    }

    // --gen-keys block
    if (strcmp(argv[1], "--gen-keys") == 0 && argc == 4) {
        lamport_keypair_t kp;
        if (lamport_keygen(&kp) != 0) {  // FIXED: Added missing ") != 0"
            fprintf(stderr, "Error: Key generation failed.\n");
            return 1;
        }
        if (save_keypair(argv[2], argv[3], &kp) != 0) {
            fprintf(stderr, "Error: Saving keypair failed.\n");
            return 1;
        }
        printf("Keypair generated successfully.\n");
    }

    // --sign block
    else if (strcmp(argv[1], "--sign") == 0 && argc == 5) {
        lamport_keypair_t kp;
        if (load_private_key(argv[2], &kp) != 0) {  // FIXED: Added "!= 0"
            fprintf(stderr, "Error: Loading private key failed.\n");
            return 1;
        }

        // Read file
        uint8_t *file_data = NULL;
        size_t file_length;
        if (read_file(argv[3], &file_data, &file_length) < 0) {
            fprintf(stderr, "Error: Reading file failed.\n");
            return 1;
        }

        // Hash file
        uint8_t hash[SHA256_BLOCK_SIZE];
        sha256(file_data, file_length, hash);
        free(file_data);

        // Generate signature
        uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
        lamport_sign(&kp, hash, signature);
        if (save_signature(argv[4], signature) != 0) {
            fprintf(stderr, "Error: Saving signature failed.\n");
            return 1;
        }
        printf("File signed successfully.\n");
    }

    // --verify block
    else if (strcmp(argv[1], "--verify") == 0 && argc == 5) {
        lamport_keypair_t kp;
        if (load_public_key(argv[2], &kp) != 0) {  // FIXED: Added "!= 0"
            fprintf(stderr, "Error: Loading public key failed.\n");
            return 1;
        }

        // Load signature
        uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
        if (load_signature(argv[4], signature) != 0) {
            fprintf(stderr, "Error: Loading signature failed.\n");
            return 1;
        }

        // Hash file
        uint8_t file_hash[SHA256_BLOCK_SIZE];
        if (hash_file(argv[3], file_hash) != 0) {  // FIXED: Changed "hash" to "file_hash"
            fprintf(stderr, "Error: Hashing file failed.\n");
            return 1;
        }

        // Verify
        if (lamport_verify(&kp, file_hash, signature)) {
            printf("Signature is VALID.\n");
        } else {
            printf("Signature is INVALID.\n");
        }
    }

    else {
        printf_usage();
        return 1;
    }

    return 0;
}
