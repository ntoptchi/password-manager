#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "encryption.h"
#include "login.h"

extern unsigned char global_key[32];
extern unsigned char global_iv[16];

#define HASH_FILE ".masterpass"
#define PW_LEN      16   // default generated password length
#define CHARSET     "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                    "abcdefghijklmnopqrstuvwxyz" \
                    "0123456789" \
                    "!@#$%^&*()-_=+[]{};:,.<>/?"

// Convert raw bytes → hex string
static void bytes_to_hex(const unsigned char *bytes, int len, char *hex_out) {
    for (int i = 0; i < len; i++)
        sprintf(hex_out + 2*i, "%02x", bytes[i]);
    hex_out[2*len] = '\0';
}

// Convert hex string → raw bytes
static void hex_to_bytes(const char *hex, unsigned char *bytes, int *out_len) {
    *out_len = strlen(hex) / 2;
    for (int i = 0; i < *out_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bytes[i]);  
    }
}

static void hash_to_hex(const unsigned char *hash, char *hex_output) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex_output + 2*i, "%02x", hash[i]);
    hex_output[2*SHA256_DIGEST_LENGTH] = '\0';
}

static void generate_password(char *out, size_t length) {
    size_t charset_len = strlen(CHARSET);
    unsigned char buf[length];
    if (RAND_bytes(buf, length) != 1) {
        fprintf(stderr, "(!) Failed to generate secure random bytes.\n");
        exit(1);
    }
    for (size_t i = 0; i < length; i++) {
        out[i] = CHARSET[ buf[i] % charset_len ];
    }
    out[length] = '\0';
}

// Prompt for master password and hash it
void hash_password_input(char *hex_hash_out, char *input_buffer) {
    printf("Enter master password: ");
    fgets(input_buffer, 100, stdin);
    input_buffer[strcspn(input_buffer, "\n")] = '\0';

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input_buffer, strlen(input_buffer), hash);
    hash_to_hex(hash, hex_hash_out);
}

// Create login by saving hashed password
void create_login() {
    // --- 1) Declare locals ---
    FILE *f;
    char choice;
    char input[100], confirm[100];
    unsigned char salt[SALT_SIZE];
    char salt_hex[SALT_SIZE*2 + 1];
    unsigned char hash_bin[SHA256_DIGEST_LENGTH];
    char hash_hex[SHA256_DIGEST_LENGTH*2 + 1];

    // --- 2) Overwrite prompt if it already exists ---
    f = fopen(HASH_FILE, "r");
    if (f) {
        fclose(f);
        printf("⚠️  Login already exists. Overwrite? (y/n): ");
        choice = getchar(); getchar();
        if (choice != 'y' && choice != 'Y') {
            printf("Aborting. Use option 1 to login.\n");
            return;
        }
        remove(HASH_FILE);
    }

    // --- 3) Ask generate vs manual ---
    printf("Create master password:\n");
    printf("  1) Enter my own\n");
    printf("  2) Generate a secure one (%d chars)\n", PW_LEN);
    printf("Choose 1 or 2: ");
    choice = getchar(); getchar();

    if (choice == '2') {
        generate_password(input, PW_LEN);
        printf("Generated password: %s\nUse this? (y/n): ", input);
        choice = getchar(); getchar();
        if (choice != 'y' && choice != 'Y')
            choice = '1';
    }

    // --- 4) Manual entry path with validation ---
    if (choice == '1') {
        while (1) {
            printf("Enter master password (min 16 chars, incl. upper, lower, digit, symbol): ");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = '\0';

            int len = strlen(input);
            if (len < 16) {
                printf("❌ Too short. Must be at least 16 characters.\n");
                continue;
            }
            int has_upper=0, has_lower=0, has_digit=0, has_symbol=0;
            for (int i = 0; i < len; i++) {
                unsigned char c = input[i];
                if      (isupper(c)) has_upper = 1;
                else if (islower(c)) has_lower = 1;
                else if (isdigit(c)) has_digit = 1;
                else                 has_symbol = 1;
            }
            if (!has_upper || !has_lower || !has_digit || !has_symbol) {
                printf("❌ Must include upper, lower, digit, and symbol.\n");
                continue;
            }

            // Confirmation
            printf("Confirm master password: ");
            fgets(confirm, sizeof(confirm), stdin);
            confirm[strcspn(confirm, "\n")] = '\0';
            if (strcmp(input, confirm) != 0) {
                printf("❌ Passwords do not match.\n");
                continue;
            }
            break;  // valid password chosen
        }
    }

    // --- 5) Generate & encode salt ---
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        perror("Failed to generate salt");
        return;
    }
    bytes_to_hex(salt, SALT_SIZE, salt_hex);

    // --- 6) PBKDF2‑hash the password with salt ---
    if (!PKCS5_PBKDF2_HMAC(input, strlen(input),
                           salt, SALT_SIZE,
                           10000, EVP_sha256(),
                           SHA256_DIGEST_LENGTH, hash_bin)) {
        handleErrors();
    }
    hash_to_hex(hash_bin, hash_hex);

    // --- 7) Store salt + hash ---
    f = fopen(HASH_FILE, "w");
    if (!f) {
        perror("Failed to save login");
        return;
    }
    fprintf(f, "%s\n%s\n", salt_hex, hash_hex);
    fclose(f);

    printf("✅ Login created successfully.\n");
}


// Verify login
int login() {
        // 1) Open the file
    FILE *f = fopen(HASH_FILE, "r");
    if (!f) {
        printf("⚠️  No login found. Please create one first.\n");
        return 0;
    }

    // 2) Read salt and stored hash
    char salt_hex[SALT_SIZE*2 + 2];
    char stored_hash_hex[SHA256_DIGEST_LENGTH*2 + 2];
    if (!fgets(salt_hex, sizeof(salt_hex), f) ||
        !fgets(stored_hash_hex, sizeof(stored_hash_hex), f)) {
        fclose(f);
        printf("❌ Corrupted .masterpass file\n");
        return 0;
    }
    fclose(f);

    // 3) Strip newline/carriage returns
    salt_hex[strcspn(salt_hex, "\r\n")] = '\0';
    stored_hash_hex[strcspn(stored_hash_hex, "\r\n")] = '\0';

    // 4) Convert salt hex → bytes
    unsigned char salt[SALT_SIZE];
    int salt_len = 0;
    hex_to_bytes(salt_hex, salt, &salt_len);

    // 5) Prompt for password
    char input[100];
    printf("Enter master password: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0';

    // 6) PBKDF2‑hash the entered password with the salt
    unsigned char hash_bin[SHA256_DIGEST_LENGTH];
    if (!PKCS5_PBKDF2_HMAC(input, strlen(input),
                           salt, SALT_SIZE,
                           10000, EVP_sha256(),
                           SHA256_DIGEST_LENGTH, hash_bin)) {
        handleErrors();
    }

    // 7) Convert that hash → hex
    char hash_hex[SHA256_DIGEST_LENGTH*2 + 1];
    hash_to_hex(hash_bin, hash_hex);

    // 8) Compare
    if (strcmp(hash_hex, stored_hash_hex) != 0) {
        printf("❌ Incorrect password.\n");
        return 0;
    }

    printf("✅ Login successful.\n");

    // 9) Derive key & IV for AES from the same salt
    derive_key_iv(input, salt, global_key, global_iv);
    return 1;
}


