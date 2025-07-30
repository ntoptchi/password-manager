#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "encryption.h"
#include "login.h"

unsigned char global_key[32];
unsigned char global_iv[16];

void login_menu() {
    int choice;
    while (1) {
        printf("=== Password Manager ===\n");
        printf("1. Login\n");
        printf("2. Create login\n");
        printf("3. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);
        getchar(); // consume newline

        if (choice == 1) {
            if (login()) break;
        } else if (choice == 2) {
            create_login();
        } else if (choice == 3) {
            printf("Exiting...\n");
            exit(0);
        } else {
            printf("Invalid choice.\n");
        }
    }
}


void show_menu() {
    printf("=== Password Manager ===\n");
    printf("1. Add entry\n");
    printf("2. View entries\n");
    printf("3. Delete an Entry\n");
    printf("4. Update entry\n");   
    printf("5. Exit\n");           
    printf("Choose an option: ");
}

int main() {
    int choice;
    login_menu();

    
    while (1) {
        show_menu();
        scanf("%d", &choice);
        getchar(); // consume newline

        switch (choice) {
            case 1: add_entry(); break;
            case 2: view_entries(); break;
            case 3: delete_entry(); break;  
            case 4: update_entry(); break;
            case 5: printf("Exiting..."); return 0;          
            default: printf("Invalid.\n");
        }
    }
 
}



