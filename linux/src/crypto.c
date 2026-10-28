#include "crypto.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int psk_derive(const char *pass, unsigned char key[KEY_LEN]) {
	const char *salt = PSK_SALT;
	return PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
	                         (const unsigned char *)salt, (int)strlen(salt),
	                         PSK_ITERATIONS, EVP_sha256(), KEY_LEN, key) ? 0 : -1;
}

int aes_gcm_encrypt(const unsigned char *plain, size_t plen,
                    const unsigned char *key, unsigned char *out) {
	int ok = 0;
	unsigned char tag[TAG_LEN];
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (RAND_bytes(out, NONCE_LEN) != 1 ||                         // out[0..NONCE_LEN) = nonce
	    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
	    EVP_EncryptInit_ex(ctx, NULL, NULL, key, out) != 1) {
		goto done;
	}

	int len = 0;
	if (EVP_EncryptUpdate(ctx, out + NONCE_LEN, &len, plain, (int)plen) != 1) goto done;
	size_t total = (size_t)NONCE_LEN + (size_t)len;

	if (EVP_EncryptFinal_ex(ctx, out + (int)total, &len) != 1) goto done;
	total += (size_t)len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
	memcpy(out + total, tag, TAG_LEN);
	ok = (int)(total + TAG_LEN);

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok ? ok : -1;
}

int aes_gcm_decrypt(const unsigned char *in, size_t inlen,
                    const unsigned char *key, unsigned char *out) {
	if (inlen < NONCE_LEN + TAG_LEN) return -1;

	int ok = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
	    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
	    EVP_DecryptInit_ex(ctx, NULL, NULL, key, in) != 1) {
		goto done;
	}

	int len = 0;
	size_t ctlen = inlen - NONCE_LEN - TAG_LEN;
	if (EVP_DecryptUpdate(ctx, out, &len, in + NONCE_LEN, (int)ctlen) != 1) goto done;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)(in + inlen - TAG_LEN)) != 1) goto done;

	int fin = 0;
	if (EVP_DecryptFinal_ex(ctx, out + len, &fin) != 1) goto done;
	ok = (int)((size_t)len + (size_t)fin);

done:
	EVP_CIPHER_CTX_free(ctx);
	return ok ? ok : -1;
}