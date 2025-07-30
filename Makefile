CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS = -lssl -lcrypto

SRC = main.c storage.c encryption.c login.c
OBJ = $(SRC:.c=.o)

all: password_manager

password_manager: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o password_manager
