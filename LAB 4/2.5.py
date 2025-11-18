from typing import List, Optional
import sys
import re
from secrets import token_bytes
import binascii

PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

def bits_from_bytes(data: bytes) -> List[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]

def bytes_from_bits(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i - 1] for i in table]

def left_rotate(bits: List[int], n: int) -> List[int]:
    n = n % len(bits)
    return bits[n:] + bits[:n]

def wrap(s: str, size: int) -> List[str]:
    return [s[i:i+size] for i in range(0, len(s), size)]

def group(s: str, size: int) -> str:
    return " ".join(wrap(s, size))

def print_table(title: str, table: List[int], cols: int):
    print(f"\n{title}:")
    for i in range(0, len(table), cols):
        row = table[i:i+cols]
        print("  " + " ".join(f"{v:2d}" for v in row))

def bits_to_str(bits: List[int]) -> str:
    return "".join(str(b) for b in bits)

def bits_to_hex(bits: List[int]) -> str:
    pad = (-len(bits)) % 4
    if pad:
        bits = [0]*pad + list(bits)
    h = hex(int(bits_to_str(bits), 2))[2:]
    if len(h) % 2 == 1:
        h = "0" + h
    return h.upper()

def parse_input_as_key_plus56(s: str) -> Optional[List[int]]:
    s = s.strip()
    if re.fullmatch(r"[01]{56}", s):
        return [int(ch) for ch in s]
    if re.fullmatch(r"[0-9A-Fa-f]{14}", s):
        val = int(s, 16)
        bin_s = f"{val:056b}"
        return [int(ch) for ch in bin_s]
    return None

def parse_input_as_key64(s: str) -> Optional[bytes]:
    s = s.strip()
    if len(s) == 8 and all(0x00 <= ord(c) <= 0x7F for c in s):
        return s.encode("ascii")
    if re.fullmatch(r"[0-9A-Fa-f]{16}", s):
        return binascii.unhexlify(s)
    return None

def pc1_drop_parity(key64: bytes) -> List[int]:
    bits64 = bits_from_bytes(key64)
    return permute(bits64, PC1)

def derive_round_keys_from_Kplus(K_plus: List[int]):
    assert len(K_plus) == 56
    C = K_plus[:28]
    D = K_plus[28:]
    rounds = []

    print("\nInitial K+ (56 bits)")
    kplus_str = bits_to_str(K_plus)
    print("K+ (bin):", group(kplus_str, 7))
    print("K+ (hex):", bits_to_hex(K_plus))

    print("\nSplitting into C0 and D0 (each 28 bits)")
    print("C0 (bin):", group(bits_to_str(C), 7))
    print("D0 (bin):", group(bits_to_str(D), 7))

    for i, shift in enumerate(SHIFTS, start=1):
        C_before = C[:]
        D_before = D[:]

        C = left_rotate(C, shift)
        D = left_rotate(D, shift)

        CD = C + D
        Ki = permute(CD, PC2)

        rounds.append({
            "i": i,
            "shift": shift,
            "C_before": C_before,
            "D_before": D_before,
            "C": C[:],
            "D": D[:],
            "Ki": Ki
        })

    print("\nRound-by-round details")
    for r in rounds:
        print(f"\nRound {r['i']} (left shift = {r['shift']})")
        print("C_{i-1} (bin):", group(bits_to_str(r["C_before"]), 7))
        print("D_{i-1} (bin):", group(bits_to_str(r["D_before"]), 7))
        print("C_i    (bin):", group(bits_to_str(r["C"]), 7))
        print("D_i    (bin):", group(bits_to_str(r["D"]), 7))
        print("K_i    (bin):", group(bits_to_str(r["Ki"]), 6))
        print("K_i    (hex):", bits_to_hex(r["Ki"]))

    return rounds

def main():
    print("DES Round Keys Generator")
    print_table("PC-1 (64->56)", PC1, 7)
    print_table("PC-2 (56->48)", PC2, 6)
    print("\nRotation schedule (left shifts for rounds 1..16):")
    print("  " + " ".join(str(s) for s in SHIFTS))

    print("\nInput options:")
    print("  1) 8 ASCII chars (e.g., password) for K+ computed via PC-1")
    print("  2) 16 hex chars (64-bit key, incl. parity) for K+ via PC-1")
    print("  3) 56-bit K+ as 56 bits (0/1) or as 14 hex chars (56 bits)")

    s = input("\nEnter key / K+ (or leave empty to generate random 8-byte key): ").strip()

    if s == "":
        key64 = token_bytes(8)
        print("Generated random 64-bit key (hex):", key64.hex().upper())
        K_plus = pc1_drop_parity(key64)
    else:
        K_plus = parse_input_as_key_plus56(s)
        if K_plus is None:
            key64 = parse_input_as_key64(s)
            if key64 is None:
                print("ERROR: Could not parse input. Provide 8 ASCII chars, 16 hex chars, or 56-bit K+ (bits/14-hex).")
                sys.exit(1)
            print("Provided 64-bit key (hex):", key64.hex().upper())
            K_plus = pc1_drop_parity(key64)
        else:
            print("Parsed input as K+ (56 bits).")

    derive_round_keys_from_Kplus(K_plus)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")