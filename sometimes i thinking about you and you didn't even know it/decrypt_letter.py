#!/usr/bin/env python3
"""
decrypt_letter.py — dekripsi artefak terenkripsi Nankila.vhdx
(challenge "sometimes i thinking about you and you didn't even know it")

    python3 decrypt_letter.py [file.enc]

Skema enkripsi didapat dari artefak PowerShell history:
  key    = SHA256("nankila_moon")
  iv     = MD5(MachineGuid)          # 4f7c2d91-8a13-4b56-bc21-91e6a8d74320
  cipher = AES-CBC, padding PKCS7
"""
import hashlib
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_STRING  = b"nankila_moon"
MACHINEGUID = "4f7c2d91-8a13-4b56-bc21-91e6a8d74320"


def decrypt(path: str) -> bytes:
    key = hashlib.sha256(KEY_STRING).digest()
    iv  = hashlib.md5(MACHINEGUID.encode("utf-8")).digest()

    ct = open(path, "rb").read()
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = dec.update(ct) + dec.finalize()

    # buang padding PKCS7
    n = pt[-1]
    if 1 <= n <= 16 and pt[-n:] == bytes([n]) * n:
        pt = pt[:-n]
    return pt


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "$R4Z28QQ.enc"
    text = decrypt(target).decode("utf-8", errors="replace")
    print(text)

    # ekstrak pesan tersembunyi: akrostikon (huruf pertama tiap baris)
    secret = "".join(line[0] for line in text.splitlines() if line.strip())
    print("\n[+] Pesan tersembunyi:", secret.upper())
