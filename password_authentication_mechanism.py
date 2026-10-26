from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from password_validator import PasswordValidator
from getpass import getpass
from pathlib import Path
import unicodedata
import hashlib
import urllib.request
import urllib.error
from limits import parse
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=1,
    salt_len=16
)

limiter = FixedWindowRateLimiter(MemoryStorage())
rule = parse("10/minute")
account = "nist-testuser"

val = PasswordValidator().min(15).max(128)
file = Path("hash_log.txt")

def is_pwned(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    request = urllib.request.Request("https://api.pwnedpasswords.com/range/" + sha1[:5], headers = {"User-Agent": "NIST-Prototype/1.0", "Add-Padding": "true"})

    with urllib.request.urlopen(request, timeout = 5) as response:
        lines = response.read().decode("ascii").splitlines()
    
    return any(
        suffix == sha1[5:] and int(count) > 0
        for line in lines
        for suffix, count in [line.split(":")]
    )

mode = input("Select one of the following:\n1: register\n2: log in\nMode: ")

if mode == "1":
    if file.exists():
        print("Password already registered.")
        exit(1)

    password = unicodedata.normalize("NFC", getpass("Please enter a new password: "))

    if not val.validate(password):
        print("Password must contain at least 15 characters.")
        exit(1)
    
    try:
        if is_pwned(password):
            print("Password is compromised. Choose a different, unique passphrase.")
            exit(1)
    except urllib.error.URLError:
        print("Password validation check is unavailable. Registration denied.")
        exit(1)

    file.write_text(ph.hash(password), encoding="utf-8")
    print("Registration successful.")

elif mode == "2":
    if not file.exists():
        print("No registered password found.")
        exit(1)

    hashedval = file.read_text(encoding="utf-8").strip()

    while limiter.test(rule, account):
        password = unicodedata.normalize("NFC", getpass("Please enter your password: "))

        try:
            ph.verify(hashedval, password)
            print("Login successful.")
            break
        except VerifyMismatchError:
            limiter.hit(rule, account)
            print("Invalid password.")
    else:
        print("Too many failed attempts. Please try again later.")
else:
    print("Invalid mode.")