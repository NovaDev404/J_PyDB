# J_PyDB

A tiny, file-system-backed JSON-like DB for simple projects — each **database** is a folder, each **table** is a subfolder, and each value is a `.txt` file. Supports optional encryption via `cryptography.fernet`, secure hashing (PBKDF2-SHA256) for non-reversible values like passwords, and binary file storage. Simple, safe, and great for prototypes, tooling, or tiny apps. ⚡️✨

---

## Features
- Filesystem-first: no external DB required.
- Optional encryption using a passphrase (Fernet / AES-GCM under the hood).
- Optional non-reversible hashing (PBKDF2-HMAC-SHA256) for values such as passwords.
- Binary file storage (`write_file` / `read_file`).
- Table / DB create, drop, list.
- Read / write / delete values.
- Export / import entire tables (including binary blobs).
- Basic in-memory transactions (`begin`, `commit`, `rollback`).
- Thread-safe operations via an `RLock`.

---

## Requirements
- Python 3.8+ (recommended)
- `cryptography` package (only required if you plan to use `encrypt=True`)

Install required package:

~~~
pip install cryptography
~~~

---

## Quickstart

> Note: The constructor **no longer requires** a master key. You only need to call `J_PyDB.setMasterKey(...)` if you want to use encryption (`encrypt=True`). Hashing uses Python stdlib and does not require `cryptography`.

~~~
from J_PyDB import J_PyDB, J_PyDBError

# OPTIONAL: set a master key if you want encrypt/decrypt support
J_PyDB.setMasterKey("super-secret-passphrase")
# You can remove the master key later with:
# J_PyDB.unsetMasterKey()

db = J_PyDB(base_path="data_folder")

# create DB + table
db.create_db("Website")
db.create_table("Website", "Users")

# write & read a plain value
db.write_value("Website", "Users", "alice", value="hello world")
print(db.read_value("Website", "Users", "alice"))  # "hello world"

# write & read an encrypted value (requires setMasterKey)
db.write_value("Website", "Users", "secret_user", value="Pa$$w0rd!", encrypt=True)
print(db.read_value("Website", "Users", "secret_user", decrypt=True))  # "Pa$$w0rd!"

# store a hashed value (non-reversible) - great for passwords
db.write_value("Website", "Users", "alice_pw", value="Pa$$w0rd!", hash=True)

# verify a hashed value (returns True/False)
is_ok = db.verify_value("Website", "Users", "alice_pw", "Pa$$w0rd!")
print("Password ok?", is_ok)
~~~

---

## Value storage formats & compatibility 🔐

- **Hashed values** are stored as:

~~~
HASH$pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
~~~

These are **non-reversible** — use `verify_value(...)` to compare plaintext against the stored hash.

- **Encrypted values** are stored as:

~~~
FERNET$<fernet_token>
~~~

For backwards compatibility, raw Fernet tokens (legacy strings beginning `gAAAA`) are also accepted.

- **Plain text** is stored as-is (a simple string in the `*.txt` file).

**Important:** `write_value(..., encrypt=True, hash=True)` is invalid — pick one (encrypt _or_ hash).

---

## Examples

### Binary files
~~~
# store a binary file (keeps the original filename)
db.write_file("Website", "Users", "alice_pic", file_path="path/to/image.png")

# read it back (returns bytes)
img_bytes = db.read_file("Website", "Users", "alice_pic")
with open("out.png", "wb") as f:
    f.write(img_bytes)
~~~

### Export / Import table
~~~
# export a table into a nested dict (text values as str, binary as bytes)
table_data = db.export_table("Website", "Users")

# import back (drop/create will be performed)
db.import_table("Website", "ImportedUsers", table_data)
~~~

### Hashing & verification
~~~
# store hashed password (PBKDF2-HMAC-SHA256)
db.write_value("App", "Users", "bob_pw", value="hunter2", hash=True)

# verify it later
ok = db.verify_value("App", "Users", "bob_pw", "hunter2")  # True
bad = db.verify_value("App", "Users", "bob_pw", "wrong")   # False
~~~

### Transactions
~~~
try:
    db.begin("Website")
    # stage ops manually (internal structure used by this tiny tx model)
    db._transactions["Website"]["writes"].append(("Users", ("temp",), "tempval"))
    db.commit("Website")
except Exception:
    db.rollback("Website")
~~~

> ⚠️ Transaction model: transactions are in-memory records in `self._transactions`. On `commit` the staged writes are executed through `write_value` and deletes through `delete_value`. This is intentionally simple — it's for grouped operations, not full ACID semantics.

---

## API Reference (summary)

**Exceptions**
- `J_PyDBError` — base DB error
- `TransactionError` — transaction-specific error

**Class methods**
- `J_PyDB.setMasterKey(passphrase: str)` — derive and set the class-wide Fernet key for encryption.
- `J_PyDB.unsetMasterKey()` — remove the class-wide Fernet key (disable encrypt/decrypt capability).
- `J_PyDB.set_default_hash_iterations(iters: int)` — adjust PBKDF2 iteration count (default is 100_000).

**Constructor**
- `J_PyDB(base_path=".")` — create instance rooted at `base_path`. **Master key is optional**; only required when you call `write_value(..., encrypt=True)` or `read_value(..., decrypt=True)`.

**DB / Table management**
- `create_db(db)` — create database folder
- `drop_db(db)` — delete database and contents
- `list_databases()` -> list of DB names
- `create_table(db, tbl)` — create table
- `drop_table(db, tbl)` — delete table and contents
- `list_tables(db)` -> list of tables in DB

**Value operations**
- `write_value(db, tbl, *keys, value=None, encrypt=False, hash=False, hash_iterations=None, overwrite=True)`  
  Store text under nested keys (final key becomes `*.txt`). Use `encrypt=True` to encrypt with the master Fernet key; use `hash=True` to store a PBKDF2 hash (non-reversible). If both flags are True, an error is raised.
- `read_value(db, tbl, *keys, decrypt=False)` -> str  
  Read value. If the stored value was encrypted, pass `decrypt=True` to get plaintext. You **cannot** decrypt hashed values.
- `verify_value(db, tbl, *keys, plaintext: str)` -> bool  
  Verify a plaintext against the stored value: works with hashed, encrypted, and plaintext storage.
- `delete_value(db, tbl, *keys)` -> bool — delete value file (and remove empty directories up to table root).
- `exists(db, tbl, *keys)` -> bool — checks if value exists (or directory exists for nested keys).
- `list_keys(db, tbl, *prefix_keys)` -> list of entries (files and subdirs).

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

- **Master key requirement**: `setMasterKey(...)` is optional. You only need to call it if you want to use encryption (`encrypt=True` / `decrypt=True`). If you attempt encryption without a master key, an exception will be raised.
- **Hashing vs encryption**: Hashing (PBKDF2) is non-reversible — use it for password verification, not for data you need back. Encryption (Fernet) is reversible but requires safe storage of the passphrase.
- **Hash format**: The stored hash string is structured:  

~~~
HASH$pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
~~~

Do **not** attempt to decrypt hashed values; use `verify_value`.
- **Backward compatibility**: Encrypted values stored with older versions (raw Fernet tokens starting `gAAAA`) are still supported.
- **Text vs binary detection**: `export_table` attempts a UTF-8 decode for files; if decoding fails, the binary is returned as raw bytes.
- **Atomicity**: File writes use plain open/write — this library is minimal and not intended for heavy concurrent DB workloads. It uses an `RLock` internally but it's not a replacement for a real DB under heavy concurrent writes.
- **Filenames**: Values are stored as `leaf.txt`. Binary files preserve the original filename (no `.txt` appended).
- **Transactions**: are lightweight — they stage operations and apply them on `commit`. They don't provide rollback of already-applied OS-level filesystem changes.

---

## Security tips 🔒
- Use a strong passphrase with `setMasterKey` if you use encryption.
- For hashed values, use a high iteration count (default 100,000). Increase via `J_PyDB.set_default_hash_iterations(...)` as hardware improves.
- Keep the `base_path` file permissions restricted (e.g., `chmod 700` on UNIX).
- Never store the passphrase in source control.
- Remember: hashed values are non-reversible; encrypted values are only as safe as your passphrase.

---

## Example full script
~~~
# minimal_example.py
from J_PyDB import J_PyDB, J_PyDBError

# optional; only required if you plan to use encrypt/decrypt
J_PyDB.setMasterKey("please-use-a-strong-passphrase")

db = J_PyDB(base_path="my_db_folder")
db.create_db("App")
db.create_table("App", "Users")

# encrypted password (reversible)
db.write_value("App", "Users", "john_secret", value="s3cret", encrypt=True)
print("Decrypted:", db.read_value("App", "Users", "john_secret", decrypt=True))

# hashed password (non-reversible)
db.write_value("App", "Users", "john_pw", value="s3cret", hash=True)
print("Verify:", db.verify_value("App", "Users", "john_pw", "s3cret"))
~~~

---

## Contributing
Pull requests welcome! Keep changes small & well documented. If you want to add stronger transaction semantics, file-atomic writes, alternative hashing algorithms (bcrypt/scrypt/argon2), or metadata-sidecars (`value.meta.json`) next to value files, open an issue and let's chat — happy to collab. 🎉

---

## License
MIT — feel free to reuse, remix, and improve. Please keep the original attribution if you redistribute.

---
