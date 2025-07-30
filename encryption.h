#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
#define SALT_SIZE 16

void handleErrors();
int encrypt_password(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt_password(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void derive_key_iv(const char *master_password, const unsigned char *salt, unsigned char *key, unsigned char *iv);

#endif
