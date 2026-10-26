#!/usr/bin/env python3
"""
Complete Standalone Solver for CTF Challenge: getting-info
==========================================================
Alur penyelesaian end-to-end langsung dari file `info.pcap`:
1. Parse `info.pcap` dan ambil TCP payload pada paket terakhir (Frame 7679:
   192.168.1.42:44444 -> 10.0.0.99:8080, 58 byte).
2. XOR repeating-key menggunakan hex key dari hint: `13374299ABCD` (6 byte).
3. Dekompresi stream zlib (`78 da ...`) -> menghasilkan 57 byte data biner.
4. Parse struktur hasil dekompresi:
   - Offset 0..3 : `de ad be ef` (4-byte magic header)
   - Offset 4..7 : `31 00 00 00` (uint32 little-endian = 49 byte = matriks 7x7)
   - Offset 8..56: 49 byte matriks 7x7 hasil transposisi 2D (baris + kolom)
5. Deduksi otomatis permutasi kolom (`col_perm`) secara unik dari format
   `IONIC{...}` + null-padding, lalu susun blok baris 7-karakter menjadi flag.
"""

from itertools import permutations
from pathlib import Path
import struct
import zlib


def extract_last_tcp_payload(pcap_path: Path) -> bytes:
    """Membaca file PCAP secara langsung dan mengambil TCP payload paket terakhir."""
    raw = pcap_path.read_bytes()
    magic = struct.unpack_from("<I", raw, 0)[0]
    endian = "<" if magic == 0xA1B2C3D4 else ">"

    offset = 24  # Global PCAP header = 24 byte
    last_pkt = b""
    frame_count = 0
    while offset < len(raw):
        _, _, incl_len, _ = struct.unpack_from(f"{endian}IIII", raw, offset)
        offset += 16
        last_pkt = raw[offset : offset + incl_len]
        offset += incl_len
        frame_count += 1

    # Ethernet (14 byte) + IPv4 header + TCP header -> TCP payload
    ip_header_len = (last_pkt[14] & 0x0F) * 4
    tcp_offset = 14 + ip_header_len
    tcp_header_len = ((last_pkt[tcp_offset + 12] >> 4) & 0x0F) * 4
    payload = last_pkt[tcp_offset + tcp_header_len :]
    print(f"[+] Total paket di PCAP : {frame_count}")
    print(f"[+] Frame {frame_count} payload ({len(payload)} byte): {payload.hex()}")
    return payload


def solve() -> None:
    pcap_file = Path(__file__).with_name("info.pcap")
    ciphertext = extract_last_tcp_payload(pcap_file)

    # Step 1: CyberChef Recipe -> XOR(Key=13374299ABCD, Hex) -> Zlib Inflate
    xor_key = bytes.fromhex("13374299ABCD")
    zlib_stream = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(ciphertext))
    decompressed = zlib.decompress(zlib_stream)

    magic, body_len = struct.unpack_from(">I", decompressed, 0)[0], struct.unpack_from("<I", decompressed, 4)[0]
    body = decompressed[8:]
    assert magic == 0xDEADBEEF and body_len == len(body) == 49

    print(f"[+] Zlib stream header  : {zlib_stream[:2].hex()} (valid zlib)")
    print(f"[+] Decompressed header : magic=0x{magic:08x}, body_len={body_len} (7x7 matrix)")

    # Tampilkan matriks 7x7 mentah
    rows = [body[r * 7 : (r + 1) * 7] for r in range(7)]
    print("\n[+] Matriks 7x7 teracak (body):")
    for idx, r in enumerate(rows):
        vis = " ".join(chr(b) if 32 <= b < 127 else "·" for b in r)
        print(f"    Row {idx}: {vis}")

    # Step 2: Cari semua permutasi kolom (dari 7! = 5040 kemungkinan) yang valid:
    # - Row 0 setelah di-unscramble harus diawali b"IONIC{"
    # - Row 1 (berisi '}' dan 1 karakter terakhir + 5 null byte) harus menjadi [char, '}', 0, 0, 0, 0, 0]
    valid_col_perms = []
    for perm in permutations(range(7)):
        # perm[bc] = kolom asli untuk kolom teracak bc
        unscramble = lambda row: bytes(row[perm.index(c)] for c in range(7))
        r0 = unscramble(rows[0])
        r1 = unscramble(rows[1])
        if r0.startswith(b"IONIC{") and r1[1:2] == b"}" and r1[2:] == b"\x00" * 5 and r1[0] != 0:
            valid_col_perms.append(perm)

    assert len(valid_col_perms) == 1, f"Expected unique col_perm, got {len(valid_col_perms)}"
    col_perm = valid_col_perms[0]
    print(f"\n[+] Permutasi kolom unik ditemukan (1 dari 5040): {list(col_perm)}")

    unscrambled_rows = [
        bytes(row[col_perm.index(c)] for c in range(7))
        for row in rows
    ]
    print("\n[+] Hasil unscramble kolom pada tiap baris 7-byte:")
    for idx, ur in enumerate(unscrambled_rows):
        print(f"    Row {idx}: {ur!r}")

    # Baris yang posisinya sudah pasti dari struktur panjang flag (37 byte + 12 byte NUL):
    # - Posisi 0 (byte 0..6)  = Row 0  -> b'IONIC{n'
    # - Posisi 5 (byte 35..41)= Row 1  -> b'3}\x00\x00\x00\x00\x00'
    # - Posisi 6 (byte 42..48)= Row 5  -> b'\x00\x00\x00\x00\x00\x00\x00'
    # Tersisa 4 baris tengah (Row 2, 3, 4, 6) -> hanya 4! = 24 kemungkinan urutan:
    middle_indices = [2, 3, 4, 6]
    print("\n[+] 24 kandidat penyusunan 4 blok tengah:")
    for order in permutations(middle_indices):
        candidate_bytes = (
            unscrambled_rows[0]
            + b"".join(unscrambled_rows[i] for i in order)
            + unscrambled_rows[1]
            + unscrambled_rows[5]
        )
        candidate = candidate_bytes.rstrip(b"\x00").decode()
        print(f"    order {[0, *order, 1, 5]} -> {candidate}")

    # Urutan yang membentuk kalimat bahasa Inggris utuh ("no_strings_attached_just_noise" dalam leetspeak)
    row_order = [0, 3, 4, 2, 6, 1, 5]
    final_flag = (
        b"".join(unscrambled_rows[i] for i in row_order)
        .rstrip(b"\x00")
        .decode()
    )
    print(f"\n[✓] FINAL FLAG: {final_flag}")


if __name__ == "__main__":
    solve()
