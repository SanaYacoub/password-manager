from cryptography.fernet import Fernet, InvalidToken
import os
import sqlite3
from contextlib import contextmanager
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class passwordManager:
    
    # --- INITIALIZATION ---
    def __init__(self):
        self.key = None
        self.fernet = None  
        self.db_path = None
    
    # --- SECURITY CHECKS ---
    def _check_key(self):
        if self.fernet is None:
            raise ValueError("Master password not set or incorrect")

    def _check_db(self):
        if self.db_path is None:
            raise RuntimeError("No database loaded")

    # --- KEY DERIVATION (PBKDF2) ---    
    def _derive_key(self, master_password: str, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    # --- MASTER PASSWORD MANAGEMENT ---
    def create_master_password(self, master_password):
        self._check_db()
        salt = os.urandom(16)
        new_key = self._derive_key(master_password, salt)
        
        # Création du jeton de validation
        temp_fernet = Fernet(new_key)
        challenge = os.urandom(32)
        verifier_blob = temp_fernet.encrypt(challenge).decode()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            # On remplace le hash par le jeton chiffré
            cursor.execute(
                "INSERT INTO metadata (id, salt, master_hash) VALUES (1, ?, ?)",
                (salt, verifier_blob)
            )
            conn.commit()
        
        self.key = new_key
        self.fernet = temp_fernet
        print("[INFO] Master password set successfully.")

    def load_master_password(self, master_password):
        self._check_db()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT salt, master_hash FROM metadata WHERE id = 1")
            row = cursor.fetchone()

        if not row:
            raise RuntimeError("Master password not set for this database")

        salt, stored_verifier = row
        potential_key = self._derive_key(master_password, salt)
        
        try:
            # vérifier que le déchiffrement fonctionne
            test_fernet = Fernet(potential_key)
            test_fernet.decrypt(stored_verifier.encode())

            self.key = potential_key
            self.fernet = test_fernet
            print("[INFO] Database unlocked.")

        except InvalidToken:
            raise ValueError("Invalid master password")

    # --- DATABASE CONNECTION ---
    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    # --- DATABASE FILE MANAGEMENT ---
    def create_database(self, path):
        if os.path.exists(path):
            raise FileExistsError(f"Database already exists: {path}")
        self.db_path = path
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, password TEXT NOT NULL)")
            cursor.execute("CREATE TABLE metadata (id INTEGER PRIMARY KEY, salt BLOB NOT NULL, master_hash TEXT NOT NULL)")
            conn.commit()
        print(f"[INFO] Database created at {path}")

    def load_database(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Database not found: {path}")
        self.db_path = path
        print(f"[INFO] Database {path} loaded.")

    # --- PASSWORD CRUD OPERATIONS ---
    def add_password(self, site, password):
        self._check_db()
        self._check_key()
        encrypted = self.fernet.encrypt(password.encode()).decode()
        with self._get_connection() as conn:
            conn.execute("INSERT INTO passwords (site, password) VALUES (?, ?)", (site, encrypted))
            conn.commit()

    def get_password(self, site):
        self._check_db()
        self._check_key()
        with self._get_connection() as conn:
            result = conn.execute("SELECT password FROM passwords WHERE site = ?", (site,)).fetchone()
            if not result: raise KeyError(f"No password found for site: {site}")
            return self.fernet.decrypt(result[0].encode()).decode()
   
    def update_password(self, site, new_password):
        self._check_db()
        self._check_key()

        encrypted = Fernet(self.key).encrypt(new_password.encode()).decode()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE passwords SET password = ? WHERE site = ?",
                (encrypted, site)
            )

            conn.commit()

            if cursor.rowcount == 0:
                raise KeyError(f"No password found for site: {site}")
    
    
    def delete_password(self, site):
        self._check_db()
        self._check_key()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("DELETE FROM passwords WHERE site = ?", (site,))
            conn.commit()

            if cursor.rowcount == 0:
                raise KeyError(f"No password found for site: {site}")
    
    # --- DATA VISUALIZATION ---
    def show_all_passwords(self):
        self._check_db()
        self._check_key()
        with self._get_connection() as conn:
            rows = conn.execute("SELECT id, site, password FROM passwords").fetchall()
            if not rows:
                print("[INFO] Database is empty")
                return

            print("\n--- PASSWORDS IN DATABASE ---")
            for row in rows:
                dec = self.fernet.decrypt(row[2].encode()).decode()
                print(f"ID: {row[0]} | Site: {row[1]} | Password: {dec}")