#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include "encryption.h"

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void derive_key_iv(const char *master_password,
                   const unsigned char *salt,
                   unsigned char *key,
                   unsigned char *iv)
{
    // 32‑byte key
    if (!PKCS5_PBKDF2_HMAC(master_password, strlen(master_password),
                           salt, SALT_SIZE,
                           10000, EVP_sha256(),
                           32, key))
        handleErrors();

    // 16‑byte IV (use a different iteration count)
    if (!PKCS5_PBKDF2_HMAC(master_password, strlen(master_password),
                           salt, SALT_SIZE,
                           10001, EVP_sha256(),
                           16, iv))
        handleErrors();
}

// encrypt
int encrypt_password(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Decrypt ciphertext into plaintext
int decrypt_password(unsigned char *ciphertext, int ciphertext_len,
                     unsigned char *key, unsigned char *iv,
                     unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "❌ Failed to create cipher context\n");
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // This is where bad padding or corrupted data shows up:
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}