# Password Manager Project

## Overview

This project is a **secure password manager** built in Python using **SQLite for storage** and **Fernet encryption for password protection**.

It introduces a **master password system** derived using PBKDF2 to secure all stored credentials.

The goal is to ensure that even if the database file is accessed, the stored passwords remain encrypted and unusable without the correct master password.

## Features

### Master Password System

* Key derivation using **PBKDF2 + SHA256 + salt**
* The master password is never stored on disk.
* Database unlock only with correct master password

### Database Management

* Creates a local SQLite database
* Automatically generates required tables:

    passwords → stores encrypted credentials

    metadata → stores encryption salt and verification data
* The database can only be accessed after entering the correct master password
* The system verifies correctness by attempting to decrypt a stored encrypted challenge
* If the password is wrong → access is denied

### Password Operations

* Add a new password (encrypted before storage)
* Retrieve and decrypt a password for a specific site
* Update an existing password
* Delete a stored password
* Display all stored credentials (decrypted in memory only)

---

## Security Design

* Passwords are encrypted using **Fernet symmetric encryption**
* Master password is **never stored directly**
* A **random salt** is generated per database
* Master password is validated using a **decryption challenge (verification token)**
* Iteration count (600,000) improves brute-force resistance

## How to Run

###  Install dependencies

```bash
pip install cryptography
```

### Run the program

```bash
python main.py
```

---

## Important Execution Rules

To use the system correctly:

### First-time setup

1. Create a database (option 3)
2. Set a master password (option 1)
```
Create DB → Set Master Password → Use Features
```

### if already created

1. Load database (option 4)
2. Load master password (option 2)
3. Perform password operations
```
Load DB → Load Master Password → Use Features
```

## Correct Usage Flow

You must load the database **before** loading the master password.

You cannot access passwords without unlocking the database first.

---


