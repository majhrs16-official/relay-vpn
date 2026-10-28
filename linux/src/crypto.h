#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define PSK_ITERATIONS 100000
#define PSK_SALT       "vpn-relay-psk-v1"
#define KEY_LEN        32
#define NONCE_LEN      12
#define TAG_LEN        16

/* Deriva una clave AES-256 (PBKDF2-HMAC-SHA256) desde el passphrase.
   Devuelve 0 en OK, -1 en error. Equivalente al deriveKey de CryptoUtils.java. */
int psk_derive(const char *pass, unsigned char key[KEY_LEN]);

/* Cifra con AES-256-GCM: out = nonce || ciphertext || tag.
   out debe tener plen + NONCE_LEN + TAG_LEN. Devuelve el largo o -1. */
int aes_gcm_encrypt(const unsigned char *plain, size_t plen,
                    const unsigned char *key, unsigned char *out);

/* Descifra in = nonce || ciphertext || tag. Devuelve largo o -1 si no autentica. */
int aes_gcm_decrypt(const unsigned char *in, size_t inlen,
                    const unsigned char *key, unsigned char *out);

#endif