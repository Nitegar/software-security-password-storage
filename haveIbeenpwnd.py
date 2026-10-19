import hashlib
import requests

def pwned_count(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
    r.raise_for_status()
    for line in r.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0

print(pwned_count("password"))  # appears in breaches many times