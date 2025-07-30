# C Password Manager

A secure, command-line password manager written in C, featuring:

* **Master-password authentication** using SHA-256 hashing (no plaintext storage).
* **AES-256-CBC encryption** of credentials via OpenSSL (PBKDF2 for key derivation).
* **CRUD operations** on entries: Add, View, Delete, and Update by website.
* **Secure password generation** (random, meets complexity requirements).
* **Input validation**: minimum length (≥ 16), must include uppercase, lowercase, digit, symbol.
* **Session management**: login menu with create/login options.

---

## Prerequisites

* GCC with C99 support
* OpenSSL development libraries
* Make utility

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

---

## Building

Clone this repository and run:

```bash
make clean
make
```

This produces the `password_manager` executable.

---

## Usage

### Startup Menu

```text
=== Password Manager ===
1. Login
2. Create login
3. Exit
Choose an option:
```

#### Create Login

* Option `2`: Set a new master password.

  * Enter **1** to type your own (must be ≥16 chars, include upper, lower, digit, symbol).
  * Enter **2** to generate a secure password (default 16 chars).
  * Confirmation and overwrite prompts included.

#### Login

* Option `1`: Enter existing master password to derive encryption key/IV.

### Main Menu

```text
=== Password Manager ===
1. Add entry
2. View entries
3. Delete entry
4. Update entry
5. Exit
Choose an option:
```

* **Add entry**: Store new credentials (site, username, password).
* **View entries**: List decrypted credentials.
* **Delete entry**: Remove all entries for a given website.
* **Update entry**: Modify username/password for a given website.
* **Exit**: Quit the program.

---

## File Storage

* Encrypted credentials saved in `passwords.dat` (hex-encoded ciphertext per line).
* Master hash saved in `.masterpass` (SHA-256 hex string).

To reset all data:

```bash
rm passwords.dat .masterpass
```

---

## Security Notes

* Uses **PBKDF2-HMAC-SHA256** to derive key and IV from master password with static salt (for demo).
* Credentials encrypted with **AES-256-CBC** and proper padding.
* Master password stored only as a SHA-256 hash.
* **Do not** hardcode salts or keys in production; use random per-install salts and secure storage.

---

