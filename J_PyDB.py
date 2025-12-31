import os
import threading
import base64
import hashlib
import hmac
import secrets
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken

class J_PyDBError(Exception): pass
class TransactionError(J_PyDBError): pass

class J_PyDB:
    """
    A simple JSON-like DB where each table is a folder and each value is a .txt file.
    Supports optional AES-GCM password encryption via Fernet (master key).
    Also supports hashing option (PBKDF2-HMAC-SHA256) for values such as passwords.
    Also supports binary file storage with write_file and read_file.

    Usage examples:
        # set a master key (for encryption)
        J_PyDB.setMasterKey("your passphrase here")

        db = J_PyDB(base_path="data_folder")
        db.create_db("Website")
        db.create_table("Website", "Users")

        # store plaintext
        db.write_value("Website", "Users", "alice", value="hello")

        # store encrypted (requires setMasterKey)
        db.write_value("Website", "Users", "alice_secret", value="topsecret", encrypt=True)

        # store hashed (PBKDF2 + salt)
        db.write_value("Website", "Users", "alice_pw", value="Pa$$w0rd!", hash=True)

        # verify hashed value
        ok = db.verify_value("Website", "Users", "alice_pw", "Pa$$w0rd!")

        # read & decrypt
        secret = db.read_value("Website", "Users", "alice_secret", decrypt=True)

    Important:
        - If both encrypt=True and hash=True are passed to write_value, a J_PyDBError is raised.
        - Hashed values are stored as a structured string:
            HASH$pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
        - Encrypted values are stored as:
            FERNET$<fernet_token>
          For backwards compatibility, existing plain fernet tokens (starting with 'gAAAA') are accepted by decrypt.
    """

    # Class-wide Fernet
    _master_key: Optional[bytes] = None
    _fernet: Optional[Fernet] = None

    # Hashing defaults
    DEFAULT_HASH_ALGO = "pbkdf2_sha256"
    DEFAULT_PBKDF2_ITERS = 100_000
    SALT_BYTES = 16

    @classmethod
    def setMasterKey(cls, passphrase: str):
        """
        Derive a 32-byte key from passphrase (via SHA-256), then URL-safe base64.
        Must be called before any J_PyDB() instantiation if you want encryption.
        """
        digest = hashlib.sha256(passphrase.encode('utf-8')).digest()
        cls._master_key = base64.urlsafe_b64encode(digest)
        try:
            cls._fernet = Fernet(cls._master_key)
        except Exception:
            raise J_PyDBError("Invalid passphrase for master key")

    @classmethod
    def unsetMasterKey(cls):
        cls._master_key = None
        cls._fernet = None

    @classmethod
    def set_default_hash_iterations(cls, iters: int):
        if iters < 1:
            raise ValueError("Iterations must be positive")
        cls.DEFAULT_PBKDF2_ITERS = iters

    def __init__(self, base_path: str = "."):
        # master key not required if you won't use encrypt=True, but prior code did require it.
        # We'll relax that: only require it when trying to encrypt.
        self.base_path = os.path.abspath(base_path)
        self._lock = threading.RLock()
        self._transactions = {}
        self._fernet = self.__class__._fernet

    # --- Encryption Helpers ---
    def encrypt_secure(self, plaintext: str) -> str:
        if self._fernet is None:
            raise J_PyDBError("Master key not set. Call J_PyDB.setMasterKey() first.")
        token = self._fernet.encrypt(plaintext.encode('utf-8'))
        # store with explicit prefix for clarity & compatibility
        return "FERNET$" + token.decode('utf-8')

    def decrypt_secure(self, token_str: str) -> str:
        """
        Accepts either:
          - stored format "FERNET$<token>"
          - or legacy raw token (starts with 'gAAAA' typical for Fernet)
        """
        if self._fernet is None:
            raise J_PyDBError("Master key not set. Call J_PyDB.setMasterKey() first.")
        token = token_str
        if token.startswith("FERNET$"):
            token = token.split("FERNET$", 1)[1]
        # attempt decrypt
        try:
            data = self._fernet.decrypt(token.encode('utf-8'))
            return data.decode('utf-8')
        except InvalidToken:
            raise J_PyDBError("Decryption failed: invalid token")

    # --- Hashing Helpers ---
    @classmethod
    def _make_salt(cls, nbytes: int = SALT_BYTES) -> bytes:
        return secrets.token_bytes(nbytes)

    @classmethod
    def hash_value(cls, plaintext: str, iterations: Optional[int] = None, salt: Optional[bytes] = None) -> str:
        """
        Returns a stored hash string:
            HASH$pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
        """
        if iterations is None:
            iterations = cls.DEFAULT_PBKDF2_ITERS
        if salt is None:
            salt = cls._make_salt()
        if not isinstance(salt, (bytes, bytearray)):
            raise J_PyDBError("salt must be bytes")
        dk = hashlib.pbkdf2_hmac('sha256', plaintext.encode('utf-8'), salt, iterations)
        salt_b64 = base64.urlsafe_b64encode(salt).decode('utf-8')
        hash_b64 = base64.urlsafe_b64encode(dk).decode('utf-8')
        return f"HASH${cls.DEFAULT_HASH_ALGO}${iterations}${salt_b64}${hash_b64}"

    @classmethod
    def verify_hash_string(cls, stored_hash_str: str, plaintext: str) -> bool:
        """
        Verify the stored hash string against plaintext.
        """
        try:
            parts = stored_hash_str.split('$')
            if len(parts) != 5 or parts[0] != "HASH":
                return False
            _, algo, iters_s, salt_b64, hash_b64 = parts
            if algo != cls.DEFAULT_HASH_ALGO:
                # currently we only support pbkdf2_sha256
                return False
            iterations = int(iters_s)
            salt = base64.urlsafe_b64decode(salt_b64.encode('utf-8'))
            expected = base64.urlsafe_b64decode(hash_b64.encode('utf-8'))
            dk = hashlib.pbkdf2_hmac('sha256', plaintext.encode('utf-8'), salt, iterations)
            return hmac.compare_digest(dk, expected)
        except Exception:
            return False

    # --- Path utils ---
    def _db_path(self, db): return os.path.join(self.base_path, db)
    def _table_path(self, db, tbl): return os.path.join(self._db_path(db), tbl)
    def _value_path(self, db, tbl, *keys):
        *dirs, leaf = keys
        dirp = os.path.join(self._table_path(db, tbl), *dirs)
        return dirp, os.path.join(dirp, f"{leaf}.txt")
    def _file_path(self, db, tbl, *keys):
        *dirs, leaf = keys
        dirp = os.path.join(self._table_path(db, tbl), *dirs)
        return dirp, os.path.join(dirp, leaf)  # keep original filename

    # --- DB/Table mgmt ---
    def create_db(self, db):
        with self._lock:
            os.makedirs(self._db_path(db), exist_ok=True)

    def drop_db(self, db):
        with self._lock:
            path = self._db_path(db)
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    for f in files:
                        os.remove(os.path.join(root, f))
                    for d in dirs:
                        os.rmdir(os.path.join(root, d))
                os.rmdir(path)
                return True
            return False

    def list_databases(self):
        if not os.path.isdir(self.base_path):
            return []
        return [d for d in os.listdir(self.base_path) if os.path.isdir(os.path.join(self.base_path, d))]

    def create_table(self, db, tbl):
        with self._lock:
            if not os.path.isdir(self._db_path(db)):
                raise J_PyDBError(f"DB '{db}' does not exist")
            os.makedirs(self._table_path(db, tbl), exist_ok=True)

    def drop_table(self, db, tbl):
        with self._lock:
            path = self._table_path(db, tbl)
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path, topdown=False):
                    for f in files:
                        os.remove(os.path.join(root, f))
                    for d in dirs:
                        os.rmdir(os.path.join(root, d))
                os.rmdir(path)
                return True
            return False

    def list_tables(self, db):
        path = self._db_path(db)
        if not os.path.isdir(path):
            raise J_PyDBError(f"DB '{db}' does not exist")
        return [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]

    # --- Value ops ---
    def write_value(self, db, tbl, *keys, value=None, encrypt: bool = False, hash: bool = False,
                    hash_iterations: Optional[int] = None, overwrite: bool = True):
        """
        Write a textual value to disk.
          - encrypt=True -> encrypt with class master key (Fernet). Requires setMasterKey().
          - hash=True -> store a PBKDF2 hashed value (not reversible). Useful for passwords.
          - If both encrypt and hash are True -> raises J_PyDBError (ambiguous).
        """
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        if encrypt and hash:
            raise J_PyDBError("Cannot both encrypt and hash the same value (choose one).")
        with self._lock:
            if not os.path.isdir(self._table_path(db, tbl)):
                raise J_PyDBError(f"Table '{tbl}' not in DB '{db}'")
            dirp, filepath = self._value_path(db, tbl, *keys)
            os.makedirs(dirp, exist_ok=True)

            if value is None:
                to_write = ''
            else:
                if hash:
                    iters = hash_iterations if hash_iterations is not None else self.DEFAULT_PBKDF2_ITERS
                    to_write = self.__class__.hash_value(str(value), iterations=iters)
                elif encrypt:
                    to_write = self.encrypt_secure(str(value))
                else:
                    to_write = str(value)

            # If overwrite is false and file exists -> raise
            if not overwrite and os.path.exists(filepath):
                raise J_PyDBError("File already exists and overwrite=False")

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(to_write)

    def read_value(self, db, tbl, *keys, decrypt: bool = False) -> str:
        """
        Read textual value. If decrypt=True and the stored value is encrypted, returns plaintext.
        If decrypt=True for a hashed value -> raises J_PyDBError.
        """
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        _, filepath = self._value_path(db, tbl, *keys)
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Missing value file: {filepath}")
        data = open(filepath, 'r', encoding='utf-8').read()
        # detect hash
        if data.startswith("HASH$"):
            if decrypt:
                raise J_PyDBError("Stored value is a non-reversible hash; cannot decrypt")
            return data
        # detect explicit FERNET$ prefix or legacy token starting with 'gAAAA'
        if data.startswith("FERNET$") or data.startswith("gAAAA"):
            if decrypt:
                return self.decrypt_secure(data)
            return data
        # otherwise plain text
        if decrypt:
            # plaintext isn't encrypted so nothing to do
            return data
        return data

    # --- Verification helper ---
    def verify_value(self, db, tbl, *keys, plaintext: str) -> bool:
        """
        Verify the stored value against given plaintext.
        - If stored is a hash -> verify PBKDF2 match.
        - If stored is encrypted -> decrypt and compare.
        - If stored is plaintext -> direct compare.
        """
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        _, filepath = self._value_path(db, tbl, *keys)
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Missing value file: {filepath}")
        stored = open(filepath, 'r', encoding='utf-8').read()
        if stored.startswith("HASH$"):
            return self.__class__.verify_hash_string(stored, plaintext)
        if stored.startswith("FERNET$") or stored.startswith("gAAAA"):
            # decrypt and compare
            try:
                dec = self.decrypt_secure(stored)
                return hmac.compare_digest(dec, plaintext)
            except J_PyDBError:
                return False
        # plaintext compare
        return hmac.compare_digest(stored, plaintext)

    # --- File ops (binary) ---
    def write_file(self, db, tbl, *keys, file_path):
        """
        Store a binary file under the given keys. Keeps original filename.
        """
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key for file storage")
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Source file not found: {file_path}")
        with self._lock:
            dirp, target = self._file_path(db, tbl, *keys)
            os.makedirs(dirp, exist_ok=True)
            with open(file_path, 'rb') as src, open(target, 'wb') as dst:
                dst.write(src.read())

    def read_file(self, db, tbl, *keys):
        """
        Read a binary file stored under the given keys. Returns bytes.
        """
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key for file retrieval")
        _, target = self._file_path(db, tbl, *keys)
        if not os.path.isfile(target):
            raise FileNotFoundError(f"File not found: {target}")
        with open(target, 'rb') as f:
            return f.read()

    def delete_value(self, db, tbl, *keys):
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        with self._lock:
            _, filepath = self._value_path(db, tbl, *keys)
            if os.path.exists(filepath):
                os.remove(filepath)
                dirp = os.path.dirname(filepath)
                while dirp and dirp != self._table_path(db, tbl) and not os.listdir(dirp):
                    os.rmdir(dirp)
                    dirp = os.path.dirname(dirp)
                return True
            return False

    def exists(self, db, tbl, *keys):
        try:
            self.read_value(db, tbl, *keys)
            return True
        except (FileNotFoundError, IsADirectoryError):
            dirp = os.path.join(self._table_path(db, tbl), *keys)
            return os.path.isdir(dirp)

    def list_keys(self, db, tbl, *prefix_keys):
        dirp = os.path.join(self._table_path(db, tbl), *prefix_keys)
        if not os.path.isdir(dirp): return []
        items = []
        for name in os.listdir(dirp):
            full = os.path.join(dirp, name)
            if os.path.isdir(full): items.append(name)
            else: items.append(name)
        return items

    # --- Bulk import/export ---
    def export_table(self, db, tbl):
        if not os.path.isdir(self._table_path(db, tbl)):
            raise J_PyDBError(f"Table '{tbl}' missing in DB '{db}'")
        def rec(path):
            out = {}
            for nm in os.listdir(path):
                full = os.path.join(path, nm)
                if os.path.isdir(full): out[nm] = rec(full)
                else:
                    with open(full, 'rb') as f:
                        try:
                            # try text decode
                            data = f.read()
                            text = data.decode('utf-8')
                            out[nm] = text
                        except Exception:
                            f.seek(0)
                            out[nm] = f.read()  # binary
            return out
        return rec(self._table_path(db, tbl))

    def import_table(self, db, tbl, data: dict):
        with self._lock:
            if not os.path.isdir(self._db_path(db)):
                raise J_PyDBError(f"DB '{db}' does not exist")
            self.drop_table(db, tbl)
            self.create_table(db, tbl)
            def rec(pref, subtree):
                for k, v in subtree.items():
                    if isinstance(v, dict): rec(pref+[k], v)
                    else:
                        if isinstance(v, (bytes, bytearray)):
                            # write binary
                            dirp, target = self._file_path(db, tbl, *pref, k)
                            os.makedirs(dirp, exist_ok=True)
                            with open(target, 'wb') as f:
                                f.write(v)
                        else:
                            self.write_value(db, tbl, *(*pref, k), value=v)
            rec([], data)

    # --- Transactions ---
    def begin(self, db):
        if db in self._transactions:
            raise TransactionError("Tx already open")
        if not os.path.isdir(self._db_path(db)):
            raise J_PyDBError(f"DB '{db}' missing")
        self._transactions[db] = {'writes':[], 'deletes':[]}

    def commit(self, db):
        if db not in self._transactions:
            raise TransactionError("No open tx")
        tx = self._transactions.pop(db)
        for tbl, keys, val in tx['writes']:
            # val is raw value; default write_value (no encrypt/hash) to maintain API simplicity
            self.write_value(db, tbl, *keys, value=val)
        for tbl, keys in tx['deletes']:
            self.delete_value(db, tbl, *keys)

    def rollback(self, db):
        if db not in self._transactions:
            raise TransactionError("No open tx")
        del self._transactions[db]
