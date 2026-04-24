from cryptography.fernet import Fernet, InvalidToken
import os
import sqlite3

class passwordManager:
    
    def __init__(self):
        self.key = None
        self.db_path = None
    
    def _check_key(self):
        if self.key is None:
            raise ValueError("Encryption key not loaded")
        
    # key used for encryption and decryption
    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)

    def load_key(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Key file not found: {path}")

        with open(path, 'rb') as f:
            self.key = f.read()
    
    def create_database(self, path):
        if os.path.exists(path):
            raise FileExistsError(f"Database already exists: {path}")

        self.db_path = path

        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()

            cursor.execute("""
            CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                password TEXT NOT NULL
            )
            """)

            conn.commit()
            conn.close()

        except Exception as e:
            raise RuntimeError(f"Failed to create database: {e}")
             
    def load_database(self, path):
        self._check_key()
        self.db_path = path

        if not os.path.exists(path):
            raise FileNotFoundError(f"Database not found: {path}")


        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()

            cursor.execute("SELECT site, password FROM passwords")

            for site, encrypted in cursor.fetchall():
                try:
                    Fernet(self.key).decrypt(encrypted.encode())
                
                # clé incorrecte ou fichier chiffré avec autre clé
                except InvalidToken:
                    has_decryption_error = True
                    raise ValueError(
                        "Invalid key provided: unable to decrypt database. "
                        "The key does not match this database."
                    )

                except Exception:
                    print(f"[WARNING] Corrupted entry for {site}, skipping")

            conn.close()

        except Exception as e:
            raise RuntimeError(f"Failed to load database: {e}")

    def add_password(self, site, password):
        self._check_key()

        if self.db_path is not None:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                encrypted = Fernet(self.key).encrypt(password.encode()).decode()

                cursor.execute(
                    "INSERT INTO passwords (site, password) VALUES (?, ?)",
                    (site, encrypted)
                )

                conn.commit()
                conn.close()

            except Exception as e:
                print(f"[ERROR] Failed to save password: {e}")
    
    def get_password(self, site):
        self._check_key()
        
        if self.db_path is None:
            raise RuntimeError("No database loaded")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT password FROM passwords WHERE site = ?", (site,))
            result = cursor.fetchone()

            conn.close()

            if not result:
                raise KeyError(f"No password found for site: {site}")

            return Fernet(self.key).decrypt(result[0].encode()).decode()

        except Exception as e:
            raise RuntimeError(f"Error retrieving password: {e}")
    
    def show_all_passwords(self):
        self._check_key()

        if self.db_path is None:
            raise RuntimeError("No database loaded")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT id, site, password FROM passwords")
            rows = cursor.fetchall()

            conn.close()

            if not rows:
                print("[INFO] Database is empty")
                return

            print("\n--- PASSWORDS IN DATABASE ---")
            for row in rows:
                decrypted = Fernet(self.key).decrypt(row[2].encode()).decode()
                print(f"ID: {row[0]} | Site: {row[1]} | Password: {decrypted}")

        except Exception as e:
            raise RuntimeError(f"Failed to read database: {e}")
        

