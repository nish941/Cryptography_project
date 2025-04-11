#ifndef LAMPORT_H
#define LAMPORT_H
#include <stdint.h>
#include "sha256.h"
#define LAMPORT_N 256
#define SHA256_BLOCK_SIZE 32

typedef struct {
	uint8_t priv[2][LAMPORT_N][SHA256_BLOCK_SIZE];
	uint8_t pub[2][LAMPORT_N][SHA256_BLOCK_SIZE];
} lamport_keypair_t;

int lamport_keygen(lamport_keypair_t *kp);

int lamport_sign(const lamport_keypair_t *kp,
		const uint8_t hash[SHA256_BLOCK_SIZE],
		uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]);

int lamport_verify(const lamport_keypair_t *kp,
		const uint8_t hash[SHA256_BLOCK_SIZE],
		const uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]);
int save_keypair(const char *priv_path, const char *pub_path, const lamport_keypair_t *kp);
int load_private_key(const char *path, lamport_keypair_t *kp);
int load_public_key(const char *path, lamport_keypair_t *kp);
#endif //LAMPORT_H
