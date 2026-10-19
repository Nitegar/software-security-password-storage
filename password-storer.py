from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()  # Argon2id, random salt, RFC 9106 defaults

# Registration: store this string in your database
hashed = ph.hash("my-password")

# Login
def login(stored_hash: str, attempt: str) -> bool:
    try:
        ph.verify(stored_hash, attempt)
    except VerifyMismatchError:
        return False
    if ph.check_needs_rehash(stored_hash):
        new_hash = ph.hash(attempt)  # save this back to the DB
    return True