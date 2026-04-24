from cryptography.fernet import Fernet, InvalidToken
import os

class passwordManager:
    
    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
    
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
    
    def create_password_file(self, path, initial_values=None):
        if os.path.exists(path):
            raise FileExistsError(f"Password file already exists: {path}")
        self.password_file = path

        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_password(key, value)
             
    def load_password_file(self, path):
        self.password_file = path

        if not os.path.exists(path):
            raise FileNotFoundError(f"Password file not found: {path}")

        has_decryption_error = False

        try:
            with open(path, 'r') as f:
                for line in f:
                    if ":" not in line:
                        continue  

                    site, encrypted = line.split(":", 1)

                    try:
                        decrypted = Fernet(self.key).decrypt(encrypted.encode()).decode()
                        self.password_dict[site] = decrypted

                    except InvalidToken:
                        # clé incorrecte ou fichier chiffré avec autre clé
                        has_decryption_error = True
                        raise ValueError(
                            "Invalid key provided: unable to decrypt password file. "
                            "The key does not match this file."
                        )

                    except Exception:
                        print(f"[WARNING] Corrupted entry for {site}, skipping")

            if has_decryption_error:
                self.password_dict.clear()

        except Exception as e:
            raise RuntimeError(f"Failed to load password file: {e}")

    def add_password(self, site, password):
        self.password_dict[site] = password

        if self.password_file is not None:
            with open(self.password_file, 'a+') as f:
                encrypted = Fernet(self.key).encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")
    
    def get_password(self, site):
        if site not in self.password_dict:
            raise KeyError(f"No password found for site: {site}")
        return self.password_dict[site]
    

