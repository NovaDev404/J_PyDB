# J_PyDB

A tiny, file-system-backed JSON-like DB for simple projects — each **database** is a folder, each **table** is a subfolder, and each value is a `.txt` file. Supports optional encryption via `cryptography.fernet` and binary file storage. Simple, safe, and great for prototypes, tooling, or tiny apps. ⚡️✨

---

## Features
- Filesystem-first: no external DB required.
- Optional encryption using a passphrase (Fernet / AES-GCM under the hood).
- Binary file storage (`write_file` / `read_file`).
- Table / DB create, drop, list.
- Read / write / delete values.
- Export / import entire tables (including binary blobs).
- Basic in-memory transactions (`begin`, `commit`, `rollback`).
- Thread-safe operations via an `RLock`.

---

## Requirements
- Python 3.8+ (recommended)
- `cryptography` package

Install required package:
~~~bash
pip install cryptography
~~~

---

## Quickstart

1. Set a master key (required) — this derives a Fernet key from your passphrase:
~~~python
from J_PyDB import J_PyDB, J_PyDBError

# MUST call before creating any J_PyDB instance
J_PyDB.setMasterKey("super-secret-passphrase")
db = J_PyDB(base_path="data_folder")

# create DB + table
db.create_db("Website")
db.create_table("Website", "Users")

# write & read a plain value
db.write_value("Website", "Users", "alice", value="hello world")
print(db.read_value("Website", "Users", "alice"))  # "hello world"

# write & read an encrypted value
db.write_value("Website", "Users", "secret_user", value="Pa$$w0rd!", encrypt=True)
print(db.read_value("Website", "Users", "secret_user", decrypt=True))  # "Pa$$w0rd!"
~~~

---

## Examples

### Binary files
~~~python
# store a binary file (keeps the original filename)
db.write_file("Website", "Users", "alice_pic", file_path="path/to/image.png")

# read it back (returns bytes)
img_bytes = db.read_file("Website", "Users", "alice_pic")
with open("out.png", "wb") as f:
    f.write(img_bytes)
~~~

### Export / Import table
~~~python
# export a table into a nested dict (text values as str, binary as bytes)
table_data = db.export_table("Website", "Users")

# import back (drop/create will be performed)
db.import_table("Website", "ImportedUsers", table_data)
~~~

### Transactions
~~~python
try:
    db.begin("Website")
    # operations during transaction are staged in-memory (writes/deletes recorded)
    # (Note: the commit applies them via the public write_value/delete_value methods)
    db._transactions["Website"]["writes"].append(("Users", ("temp",), "tempval"))
    # ... more staging ...
    db.commit("Website")
except Exception as e:
    db.rollback("Website")
    raise
~~~

> ⚠️ Transaction model: transactions are in-memory records in `self._transactions`. On `commit` the staged writes are executed through `write_value` and deletes through `delete_value`. The transaction system is intentionally simple — it's primarily intended to provide grouped operations rather than full ACID semantics.

---

## API Reference (summary)

**Exceptions**
- `J_PyDBError` — base DB error
- `TransactionError` — transaction-specific error

**Class methods**
- `J_PyDB.setMasterKey(passphrase: str)` — derive and set the class-wide Fernet key. **Must** be called before creating a `J_PyDB` instance that uses encryption.

**Constructor**
- `J_PyDB(base_path=".")` — create instance rooted at `base_path`. Raises `J_PyDBError` if master key not set.

**DB / Table management**
- `create_db(db)` — create database folder
- `drop_db(db)` — delete database and contents
- `list_databases()` -> list of DB names
- `create_table(db, tbl)` — create table
- `drop_table(db, tbl)` — delete table and contents
- `list_tables(db)` -> list of tables in DB

**Value operations**
- `write_value(db, tbl, *keys, value=None, encrypt=False)` — store text value under nested keys (final key becomes `*.txt`). If `encrypt=True`, value is encrypted with Fernet.
- `read_value(db, tbl, *keys, decrypt=False)` -> str — read value; use `decrypt=True` to decrypt.
- `delete_value(db, tbl, *keys)` -> bool — delete value file (and remove empty directories up to table root).
- `exists(db, tbl, *keys)` -> bool — checks if value exists (or directory exists for nested keys).
- `list_keys(db, tbl, *prefix_keys)` -> list of entries (files and subdirs)

**File (binary) operations**
- `write_file(db, tbl, *keys, file_path)` — stores binary file keeping original filename.
- `read_file(db, tbl, *keys)` -> bytes — reads binary file.

**Bulk**
- `export_table(db, tbl)` -> dict — recursive dump of table (text as str, binaries as bytes)
- `import_table(db, tbl, data: dict)` — recreate table from exported structure

**Transactions**
- `begin(db)` — begin transaction (simple in-memory staging)
- `commit(db)` — commit staged operations
- `rollback(db)` — discard staged operations

---

## Behavioural notes & gotchas

- **Master key requirement**: `J_PyDB.setMasterKey(...)` must be called *before* instantiating `J_PyDB`. If not, the constructor will raise `J_PyDBError`.
- **Encryption**: Uses `cryptography.fernet`. The passphrase is hashed with SHA-256 and then URL-safe base64 encoded to 32 bytes for Fernet. Keep your passphrase safe — losing it means encrypted data is unrecoverable.
- **Text vs binary detection**: `export_table` attempts a UTF-8 decode for files; if decoding fails, the binary is returned as raw bytes.
- **Atomicity**: File writes use plain open/write — this library is minimal and not intended for heavy concurrent DB workloads. It does use an `RLock` internally to reduce races, but it's not a replacement for a real DB for concurrent heavy writes.
- **Filenames**: Values are stored as `leaf.txt`. Binary files preserve the original filename (no `.txt` appended).
- **Transactions**: are lightweight — they stage operations and apply them on `commit`. They don't provide rollback of already-applied OS-level filesystem changes (use with care).

---

## Security tips
- Use a strong passphrase with `setMasterKey`.
- Ensure file permissions on the `base_path` are restricted (e.g., `chmod 700` on UNIX).
- Remember: anyone with the master passphrase (or access to the key material) can decrypt all encrypted entries.

---

## Example full script
~~~python
# minimal_example.py
from J_PyDB import J_PyDB, J_PyDBError

J_PyDB.setMasterKey("please-use-a-strong-passphrase")
db = J_PyDB(base_path="my_db_folder")

db.create_db("App")
db.create_table("App", "Users")

# create user with encrypted password
db.write_value("App", "Users", "john_doe", value="s3cret", encrypt=True)

# read it back
pwd = db.read_value("App", "Users", "john_doe", decrypt=True)
print("Decrypted password:", pwd)
~~~

---

## Contributing
Pull requests welcome! Keep changes small & well documented. If you want to add stronger transaction semantics, locks or file-atomic writes, open an issue and let's chat.

---

## License
MIT — feel free to reuse, remix, and improve. Please keep the original attribution if you redistribute.

---
