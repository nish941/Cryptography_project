#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "lamport.h"
#include "sha256.h"
#include "utils.h"

void print_usage() {
    printf("Usage:\n");
    printf("  file-sign --gen-keys <private_key> <public_key>\n");
    printf("  file-sign --sign <private_key> <input_file> <signature_file>\n");
    printf("  file-sign --verify <public_key> <input_file> <signature_file>\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "--gen-keys") == 0) {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        lamport_keypair_t kp;
        if (lamport_keygen(&kp) != 0) {
            fprintf(stderr, "Error: Key generation failed.\n");
            return 1;
        }
        if (save_keypair(argv[2], argv[3], &kp) != 0) {
            fprintf(stderr, "Error: Saving keypair failed.\n");
            return 1;
        }
        printf("Keypair generated and saved successfully.\n");
    } 
    else if (strcmp(argv[1], "--sign") == 0) {
        if (argc != 5) {
            print_usage();
            return 1;
        }
        lamport_keypair_t kp;
        if (load_private_key(argv[2], &kp) != 0) {
            fprintf(stderr, "Error: Loading private key failed.\n");
            return 1;
        }

        uint8_t *file_data = NULL;
        size_t file_length;
        if (read_file(argv[3], &file_data, &file_length) < 0) {
            fprintf(stderr, "Error: Reading input file failed.\n");
            return 1;
        }

        uint8_t file_hash[SHA256_BLOCK_SIZE];
        sha256(file_data, file_length, file_hash);
        free(file_data);

        uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
        lamport_sign(&kp, file_hash, signature);

        if (save_signature(argv[4], signature) != 0) {
            fprintf(stderr, "Error: Saving signature failed.\n");
            return 1;
        }
        printf("File signed successfully.\n");
    } 
    else if (strcmp(argv[1], "--verify") == 0) {
        if (argc != 5) {
            print_usage();
            return 1;
        }
        lamport_keypair_t kp;
        if (load_public_key(argv[2], &kp) != 0) {
            fprintf(stderr, "Error: Loading public key failed.\n");
            return 1;
        }

        // Read and hash file
        uint8_t *file_data = NULL;
        size_t file_length;
        if (read_file(argv[3], &file_data, &file_length) < 0) {
            fprintf(stderr, "Error: Reading input file failed.\n");
            return 1;
        }
        uint8_t file_hash[SHA256_BLOCK_SIZE];
        sha256(file_data, file_length, file_hash);
        free(file_data);

        // Load signature
        uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE];
        if (load_signature(argv[4], signature) != 0) {
            fprintf(stderr, "Error: Loading signature failed.\n");
            return 1;
        }

        if (lamport_verify(&kp, file_hash, signature)) {
            printf("Signature is valid.\n");
        } else {
            printf("Signature is invalid!\n");
        }
    } 
    else {
        print_usage();
        return 1;
    }
    return 0;
}
