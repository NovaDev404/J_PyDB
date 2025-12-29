import os
import threading
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

class J_PyDBError(Exception): pass
class TransactionError(J_PyDBError): pass

class J_PyDB:
    """
    A simple JSON-like DB where each table is a folder and each value is a .txt file.
    Supports optional AES-GCM password encryption via Fernet.
    Also supports binary file storage with write_file and read_file.

    Usage:
        J_PyDB.setMasterKey("your passphrase here")
        db = J_PyDB(base_path="data_folder")
        db.create_db("Website")
        db.create_table("Website", "Users")
        db.write_value("Website", "Users", "alice", value="Pa$$w0rd!", encrypt=True)
        secret = db.read_value("Website", "Users", "alice", decrypt=True)
        # File operations (binary)
        db.write_file("Website", "Users", "alice_pic", file_path="path/to/image.png")
        data = db.read_file("Website", "Users", "alice_pic")  # returns bytes
        with open("out.png", "wb") as f:
            f.write(data)
    """
    # Class-wide Fernet
    _master_key: bytes = None
    _fernet: Fernet = None

    @classmethod
    def setMasterKey(cls, passphrase: str):
        """
        Derive a 32-byte key from passphrase (via SHA-256), then URL-safe base64.
        Must be called before any J_PyDB() instantiation.
        """
        digest = hashlib.sha256(passphrase.encode('utf-8')).digest()
        cls._master_key = base64.urlsafe_b64encode(digest)
        try:
            cls._fernet = Fernet(cls._master_key)
        except Exception:
            raise J_PyDBError("Invalid passphrase for master key")

    def __init__(self, base_path="."):
        if self.__class__._fernet is None:
            raise J_PyDBError("Master key not set. Call J_PyDB.setMasterKey() first.")
        self.base_path = os.path.abspath(base_path)
        self._lock = threading.RLock()
        self._transactions = {}
        self._fernet = self.__class__._fernet

    # --- Encryption Helpers ---
    def encrypt_secure(self, plaintext: str) -> str:
        token = self._fernet.encrypt(plaintext.encode('utf-8'))
        return token.decode('utf-8')

    def decrypt_secure(self, token: str) -> str:
        try:
            data = self._fernet.decrypt(token.encode('utf-8'))
            return data.decode('utf-8')
        except InvalidToken:
            raise J_PyDBError("Decryption failed: invalid token")

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
    def write_value(self, db, tbl, *keys, value=None, encrypt=False):
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        with self._lock:
            if not os.path.isdir(self._table_path(db, tbl)):
                raise J_PyDBError(f"Table '{tbl}' not in DB '{db}'")
            dirp, filepath = self._value_path(db, tbl, *keys)
            os.makedirs(dirp, exist_ok=True)
            to_write = self.encrypt_secure(str(value)) if encrypt and value is not None else value
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(to_write if to_write is not None else '')

    def read_value(self, db, tbl, *keys, decrypt=False):
        if len(keys) < 1:
            raise J_PyDBError("Need at least one key")
        _, filepath = self._value_path(db, tbl, *keys)
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Missing value file: {filepath}")
        data = open(filepath, 'r', encoding='utf-8').read()
        return self.decrypt_secure(data) if decrypt else data

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
                            text = f.read().decode('utf-8')
                            out[nm] = text
                        except Exception:
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
            self.write_value(db, tbl, *keys, value=val)
        for tbl, keys in tx['deletes']:
            self.delete_value(db, tbl, *keys)

    def rollback(self, db):
        if db not in self._transactions:
            raise TransactionError("No open tx")
        del self._transactions[db]
