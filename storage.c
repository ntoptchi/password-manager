#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "encryption.h"

extern unsigned char global_key[32];
extern unsigned char global_iv[16];

void hex_to_bytes(const char *hex, unsigned char *bytes, int *len) {
    int i;
    *len = strlen(hex) / 2;
    for (i = 0; i < *len; i++) {
        sscanf(&hex[i*2], "%2hhx", &bytes[i]);
    }
}

void update_entry() {
    char target[100];
    printf("Enter website to update: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0';

    FILE *f = fopen("passwords.dat", "r");
    if (!f) {
        printf("⚠️  No entries found. Your password manager is empty.\n");
        return;
    }
    FILE *temp = fopen("temp.dat", "w");
    if (!temp) {
        perror("Failed to open temp file");
        fclose(f);
        return;
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        // parse the stored line
        char copy[512];
        strcpy(copy, line);
        char *site     = strtok(copy, "|");
        char *username = strtok(NULL, "|");
        char *hexpass  = strtok(NULL, "\r\n");

        if (site && strcmp(site, target) == 0) {
            found = 1;

            // decrypt existing password
            unsigned char ciphertext[128], decrypted[128];
            int clen = 0, dlen = 0;
            hex_to_bytes(hexpass, ciphertext, &clen);
            dlen = decrypt_password(ciphertext, clen, global_key, global_iv, decrypted);
            if (dlen < 0) {
                // fallback: skip updating a corrupted entry
                fputs(line, temp);
                continue;
            }
            decrypted[dlen] = '\0';

            // prompt for new values
            char newuser[100], newpass[100];
            printf("Current username: %s\n", username);
            printf("Enter new username (leave blank to keep): ");
            fgets(newuser, sizeof(newuser), stdin);
            newuser[strcspn(newuser, "\n")] = '\0';
            if (strlen(newuser) == 0) strcpy(newuser, username);

            printf("Enter new password (leave blank to keep): ");
            fgets(newpass, sizeof(newpass), stdin);
            newpass[strcspn(newpass, "\n")] = '\0';
            if (strlen(newpass) == 0) {
                strcpy(newpass, (char*)decrypted);
            }

            // re‑encrypt the (possibly) new password
            unsigned char newcipher[128];
            int newclen = encrypt_password((unsigned char*)newpass, strlen(newpass),
                                           global_key, global_iv, newcipher);

            // write updated line
            fprintf(temp, "%s|%s|", site, newuser);
            for (int i = 0; i < newclen; i++) {
                fprintf(temp, "%02x", newcipher[i]);
            }
            fprintf(temp, "\n");
        } else {
            // keep original line
            fputs(line, temp);
        }
    }

    fclose(f);
    fclose(temp);

    // replace the store
    remove("passwords.dat");
    rename("temp.dat", "passwords.dat");

    if (found)
        printf("✅ Entry for '%s' updated.\n", target);
    else
        printf("⚠️ No entries found for '%s'.\n", target);
}

void delete_entry() {
    char target[100];
    printf("Enter website to delete: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0';

    FILE *f = fopen("passwords.dat", "r");
    if (!f) {
        printf("⚠️  No entries found. Your password manager is empty.\n");
        return;
    }

    FILE *temp = fopen("temp.dat", "w");
    if (!temp) {
        perror("Failed to open temp file");
        fclose(f);
        return;
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        // make a copy for parsing
        char copy[512];
        strcpy(copy, line);

        char *site = strtok(copy, "|");
        if (site && strcmp(site, target) == 0) {
            found = 1;
            continue;  // skip writing this entry
        }
        // keep this line
        fputs(line, temp);
    }

    fclose(f);
    fclose(temp);

    // replace original file
    remove("passwords.dat");
    rename("temp.dat", "passwords.dat");

    if (found)
        printf("✅ Deleted all entries for '%s'.\n", target);
    else
        printf("⚠️  No entries found for '%s'.\n", target);
}





void master_password(){
    char masterpwd[100];

    printf("Enter master password: ");
    fgets(masterpwd, sizeof(masterpwd),stdin);
    masterpwd[strcspn(masterpwd, "\n")] = '\0';

    FILE *f = fopen("hashes.txt", "a");
    if (f == NULL) {
        printf("Failed to open file");
        return;
    }

    fprintf(f, "%s\n",masterpwd);
    fclose(f);
    printf("Entry added.\n");
                                  
}

extern unsigned char global_key[32];
extern unsigned char global_iv[16];

void add_entry() {
    char site[100], username[100], password[100];
    unsigned char ciphertext[128];
    int encrypted_len;

    printf("Enter website: ");
    fgets(site, sizeof(site), stdin); site[strcspn(site, "\n")] = '\0';

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin); username[strcspn(username, "\n")] = '\0';

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin); password[strcspn(password, "\n")] = '\0';

     encrypted_len = encrypt_password((unsigned char *)password, strlen(password),
                            global_key, global_iv, ciphertext); 

    FILE *f = fopen("passwords.dat", "a");
    if (f == NULL) {
        perror("Failed to open file");
        return;
    }

    fprintf(f, "%s|%s|", site, username);
    for (int i = 0; i < encrypted_len; i++) {
        fprintf(f, "%02x", ciphertext[i]); // hex format
    }
    fprintf(f, "\n");
    fclose(f);

    printf("Entry added.\n");
}


void view_entries() {
    FILE *f = fopen("passwords.dat", "r");
    if (!f) {
        printf("⚠️ No entries found. Your password manager is empty.\n");
        return;
    }

    // Check empty file
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) {
        fclose(f);
        printf("⚠️ No entries found. Your password manager is empty.\n");
        return;
    }
    rewind(f);

    char line[512];
    int shown = 0;

    while (fgets(line, sizeof(line), f)) {
        // parse fields
        char *site     = strtok(line, "|");
        char *username = strtok(NULL, "|");
        char *hexpass  = strtok(NULL, "\r\n");
        // split on both \r and \n to drop any stray carriage returns
        


        if (!site || !username || !hexpass) 
            continue;

        // hex → bytes
        unsigned char ciphertext[128], decrypted[128];
        int ciphertext_len = 0, decrypted_len = 0;
        hex_to_bytes(hexpass, ciphertext, &ciphertext_len);

        // decrypt; returns -1 on failure
        decrypted_len = decrypt_password(ciphertext, ciphertext_len,
                                         global_key, global_iv, decrypted);
        if (decrypted_len < 0) {
            // bad data or wrong key—skip safely
            continue;
        }

        // null‑terminate only now
        decrypted[decrypted_len] = '\0';

        printf("Site: %s | Username: %s | Password: %s\n",
               site, username, decrypted);
        shown = 1;
    }
    fclose(f);

    if (!shown)
        printf("⚠️ No valid entries to show (all entries may be corrupted or use wrong key).\n");
}
