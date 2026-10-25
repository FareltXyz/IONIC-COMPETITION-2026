#!/usr/bin/env python3
"""
Solver untuk challenge forensik "sometimes i thinking about you and you didn't even know it"
(IONIC 2026 — PENS CTF).

Terhubung otomatis ke instance netcat dan menjawab seluruh 10 pertanyaan
berdasarkan hasil investigasi disk image Nankila.vhdx (lih. writeup.md).

Penggunaan:
    python3 solver.py                                # default: chall.ctf.tccpens.id 30229
    python3 solver.py --host 10.10.10.5 --port 1337  # sesuaikan instance sendiri
    HOST=... PORT=... python3 solver.py              # lewat env var juga bisa
"""

import argparse
import os
import re
import socket
import sys
import time

# ─── Jawaban hasil forensik (urutan harus sesuai pertanyaan server) ───────────
ANSWERS = [
    "$R4Z28QQ.enc",                                        # 1/10 nama file terenkripsi saat ini (di Recycle Bin)
    "AES-CBC",                                             # 2/10 algoritma enkripsi
    "06-10-2026_09:17:14 UTC",                             # 3/10 waktu aktivitas mencurigakan (UTC)
    "M:\\Users\\Valthea\\Documents\\letters",              # 4/10 direktori target skrip
    ".txt",                                                # 5/10 ekstensi file yang ditarget
    "MachineGuid",                                         # 6/10 registry config yang dipakai
    "4f7c2d91-8a13-4b56-bc21-91e6a8d74320",                # 7/10 nilai MachineGuid
    "nankila_moon",                                        # 8/10 string untuk pembentukan key
    "M:\\Users\\Valthea\\Documents\\letters\\love_letter.txt",  # 9/10 path asli file terhapus
    "ALWAYSLOVEYOUINEVERYUNIVERSE",                        # 10/10 pesan rahasia akrostikon surat
]

DEFAULT_HOST = "chall.ctf.tccpens.id"
DEFAULT_PORT = 30229


def recv_until(s: socket.socket) -> str:
    """Baca data dari socket sampai idle singkat atau koneksi ditutup."""
    data = b""
    s.settimeout(0.8)
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode(errors="replace")


def main() -> int:
    p = argparse.ArgumentParser(description="Auto-solver kuis forensik IONIC")
    p.add_argument("--host", default=os.environ.get("HOST", DEFAULT_HOST),
                   help=f"host instance (default: {DEFAULT_HOST})")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("PORT", DEFAULT_PORT)),
                   help=f"port instance (default: {DEFAULT_PORT})")
    args = p.parse_args()

    print(f"[*] Koneksi ke {args.host}:{args.port} ...")
    try:
        s = socket.create_connection((args.host, args.port), timeout=15)
    except OSError as e:
        print(f"[!] Gagal koneksi: {e}")
        return 1

    banner = recv_until(s)
    print(banner)

    try:
        for i, ans in enumerate(ANSWERS, 1):
            s.sendall(ans.encode() + b"\n")

            # tunggu respon server sampai muncul prompt pertanyaan berikutnya
            deadline = time.time() + 15
            resp = ""
            while time.time() < deadline:
                if resp.rstrip().endswith(">"):
                    break
                s.settimeout(1.0)
                try:
                    more = s.recv(4096)
                    if not more:
                        break
                    resp += more.decode(errors="replace")
                except socket.timeout:
                    continue
            print(f"[Q{i}] {ans}  →  {'✓' if 'Correct!' in resp else '✗'}")
            for line in resp.splitlines():
                line = line.strip()
                if line:
                    print("     ", line)
            if "Wrong answer" in resp:
                print("[!] Jawaban salah — stop demi keamanan seri.")
                return 1
            if "FLAG:" in resp:
                m = re.search(r"FLAG:\s*(\{?[^}\n]+\}?)", resp)
                flag = m.group(1) if m else "?"
                print(f"\n[+] FLAG: {flag}\n")
                return 0
    except (ConnectionResetError, BrokenPipeError):
        print("[!] Koneksi ditutup oleh server.")
        return 1
    finally:
        s.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
