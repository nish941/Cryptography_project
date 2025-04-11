#include "lamport.h"
#include "sha256.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Key generation
int lamport_keygen(lamport_keypair_t *kp) {
    for (int i = 0; i < LAMPORT_N; ++i) {
        if (secure_random(kp->priv[0][i], SHA256_BLOCK_SIZE) != 0 || 
            secure_random(kp->priv[1][i], SHA256_BLOCK_SIZE) != 0) {
            return -1;
        }
        sha256(kp->priv[0][i], SHA256_BLOCK_SIZE, kp->pub[0][i]);
        sha256(kp->priv[1][i], SHA256_BLOCK_SIZE, kp->pub[1][i]);
    }
    return 0;
}

// Signing
int lamport_sign(const lamport_keypair_t *kp, const uint8_t hash[SHA256_BLOCK_SIZE], 
                uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]) {
    for (int i = 0; i < LAMPORT_N; ++i) {
        int bit = (hash[i/8] >> (7 - (i%8))) & 1;
        memcpy(signature[i], kp->priv[bit][i], SHA256_BLOCK_SIZE);
    }
    return 0;
}

// Verification
int lamport_verify(const lamport_keypair_t *kp, const uint8_t hash[SHA256_BLOCK_SIZE], 
                const uint8_t signature[LAMPORT_N][SHA256_BLOCK_SIZE]) {
    uint8_t temp[SHA256_BLOCK_SIZE];
    for (int i = 0; i < LAMPORT_N; ++i) {
        int bit = (hash[i/8] >> (7 - (i%8))) & 1;
        sha256(signature[i], SHA256_BLOCK_SIZE, temp);
        if (memcmp(temp, kp->pub[bit][i], SHA256_BLOCK_SIZE) != 0) {
            return 0; // Verification failed
        }
    }
    return -1; // Verification succeeded
}

// Save keypair to files
int save_keypair(const char *priv_path, const char *pub_path, const lamport_keypair_t *kp) {
    FILE *fpriv = fopen(priv_path, "wb");
    FILE *fpub = fopen(pub_path, "wb");
    if (!fpriv || !fpub) {
        if (fpriv) fclose(fpriv);
        if (fpub) fclose(fpub);
        return -1;
    }

    fwrite(kp->priv, sizeof(kp->priv), 1, fpriv);
    fwrite(kp->pub, sizeof(kp->pub), 1, fpub);

    fclose(fpriv);
    fclose(fpub);
    return 0;
}

// Load private key
int load_private_key(const char *priv_path, lamport_keypair_t *kp) {
    FILE *fpriv = fopen(priv_path, "rb");
    if (!fpriv) return -1;
    fread(kp->priv, sizeof(kp->priv), 1, fpriv);
    fclose(fpriv);
    return 0;
}

// Load public key
int load_public_key(const char *pub_path, lamport_keypair_t *kp) {
    FILE *fpub = fopen(pub_path, "rb");
    if (!fpub) return -1;
    fread(kp->pub, sizeof(kp->pub), 1, fpub);
    fclose(fpub);
    return 0;
}

// Load full keypair
int load_keypair(const char *priv_path, const char *pub_path, lamport_keypair_t *kp) {
    if (load_private_key(priv_path, kp) != 0) return -1;
    if (load_public_key(pub_path, kp) != 0) return -1;
    return 0;
}
