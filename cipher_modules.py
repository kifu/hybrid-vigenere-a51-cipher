from __future__ import annotations

import struct
from typing import Union


# =============================================================================
#  VIGENÈRE CIPHER (BYTE-LEVEL, 0–255)
# =============================================================================

class VigenereCipher:
    def __init__(self, key: Union[str, bytes]) -> None:
        if isinstance(key, str):
            key = key.encode("utf-8")
        if len(key) == 0:
            raise ValueError("Kunci Vigenere tidak boleh kosong.")
        self.key: bytes = key

    def encrypt(self, plaintext: bytes) -> bytes:
        key = self.key
        key_len = len(key)
        return bytes(
            (plaintext[i] + key[i % key_len]) % 256
            for i in range(len(plaintext))
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        key = self.key
        key_len = len(key)
        return bytes(
            (ciphertext[i] - key[i % key_len]) % 256
            for i in range(len(ciphertext))
        )


# =============================================================================
#  A5/1 STREAM CIPHER
# =============================================================================

class A51Cipher:
    # Panjang masing-masing register (bit)
    R1_BITS: int = 19
    R2_BITS: int = 22
    R3_BITS: int = 23

    # Posisi clock bit (0-indexed dari LSB)
    R1_CLOCK: int = 8
    R2_CLOCK: int = 10
    R3_CLOCK: int = 10

    # Mask untuk membatasi panjang register
    R1_MASK: int = (1 << R1_BITS) - 1  # 0x7FFFF
    R2_MASK: int = (1 << R2_BITS) - 1  # 0x3FFFFF
    R3_MASK: int = (1 << R3_BITS) - 1  # 0x7FFFFF

    def __init__(self, key: int) -> None:
        if not (0 <= key < (1 << 64)):
            raise ValueError("Kunci A5/1 harus berupa integer 64-bit (0 ≤ key < 2^64).")
        self.key: int = key

    @staticmethod
    def _parity(value: int) -> int:
        p = 0
        while value:
            p ^= 1
            value &= value - 1  # Hapus bit 1 paling kanan
        return p

    @staticmethod
    def _majority(a: int, b: int, c: int) -> int:
        return (a & b) | (a & c) | (b & c)

    def _clock_r1(self, r1: int) -> int:
        feedback = self._parity(r1 & 0x00072000)
        # 0x72000 = bit 18 (0x40000) | bit 17 (0x20000) | bit 16 (0x10000) | bit 13 (0x2000)
        return ((r1 << 1) | feedback) & self.R1_MASK

    def _clock_r2(self, r2: int) -> int:
        feedback = self._parity(r2 & 0x00300000)
        # 0x300000 = bit 21 (0x200000) | bit 20 (0x100000)
        return ((r2 << 1) | feedback) & self.R2_MASK

    def _clock_r3(self, r3: int) -> int:
        feedback = self._parity(r3 & 0x00700080)
        # 0x700080 = bit 22 (0x400000) | bit 21 (0x200000) | bit 20 (0x100000) | bit 7 (0x80)
        return ((r3 << 1) | feedback) & self.R3_MASK

    def _get_bit(self, register: int, position: int) -> int:
        return (register >> position) & 1

    def _initialize_registers(self) -> tuple[int, int, int]:
        r1, r2, r3 = 0, 0, 0

        # Fase 1: Key Loading (64 siklus) 
        for i in range(63, -1, -1):
            key_bit = (self.key >> i) & 1

            # Clock semua register (tanpa majority)
            r1 = self._clock_r1(r1)
            r2 = self._clock_r2(r2)
            r3 = self._clock_r3(r3)

            # XOR bit kunci ke bit 0 masing-masing register
            r1 ^= key_bit
            r2 ^= key_bit
            r3 ^= key_bit

        # Fase 2: Warm-up (100 siklus dengan majority clocking) 
        for _ in range(100):
            r1, r2, r3 = self._clock_with_majority(r1, r2, r3)

        return r1, r2, r3

    def _clock_with_majority(
        self, r1: int, r2: int, r3: int
    ) -> tuple[int, int, int]:
        # Baca clock bit masing-masing register
        cb1 = self._get_bit(r1, self.R1_CLOCK)
        cb2 = self._get_bit(r2, self.R2_CLOCK)
        cb3 = self._get_bit(r3, self.R3_CLOCK)

        m = self._majority(cb1, cb2, cb3)

        if cb1 == m:
            r1 = self._clock_r1(r1)
        if cb2 == m:
            r2 = self._clock_r2(r2)
        if cb3 == m:
            r3 = self._clock_r3(r3)

        return r1, r2, r3

    def _generate_keystream(self, length_bytes: int) -> bytes:
        r1, r2, r3 = self._initialize_registers()

        keystream = bytearray(length_bytes)
        for byte_idx in range(length_bytes):
            byte_val = 0
            for bit_idx in range(8):
                # Clock dengan majority rule
                r1, r2, r3 = self._clock_with_majority(r1, r2, r3)

                # Output bit = XOR dari MSB ketiga register
                out_bit = (
                    self._get_bit(r1, self.R1_BITS - 1)
                    ^ self._get_bit(r2, self.R2_BITS - 1)
                    ^ self._get_bit(r3, self.R3_BITS - 1)
                )
                byte_val = (byte_val << 1) | out_bit

            keystream[byte_idx] = byte_val

        return bytes(keystream)

    def encrypt(self, plaintext: bytes) -> bytes:
        keystream = self._generate_keystream(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Dekripsi = enkripsi ulang (XOR bersifat involutory)
        return self.encrypt(ciphertext)

def key_str_to_64bit(key_string: str) -> int:
    key_bytes = key_string.encode("utf-8")

    folded = bytearray(8)
    for i, b in enumerate(key_bytes):
        folded[i % 8] ^= b

    return struct.unpack(">Q", bytes(folded))[0]

# ========================================================================
#   SELF-TEST
# ========================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SELF-TEST: cipher_modules.py")
    print("=" * 60)

    test_data = b"The quick brown fox jumps over the lazy dog. 1234567890!@#"

    # Test Vigenere
    print("\n[1] Vigenere Cipher (byte-level)")
    vig = VigenereCipher(b"KUNCI_RAHASIA")
    ct_vig = vig.encrypt(test_data)
    pt_vig = vig.decrypt(ct_vig)
    status_vig = "PASS" if pt_vig == test_data else "FAIL"
    print(f"    Encrypt-Decrypt : {status_vig}")
    print(f"    Plaintext  (hex): {test_data[:16].hex()}...")
    print(f"    Ciphertext (hex): {ct_vig[:16].hex()}...")

    # Test A5/1
    print("\n[2] A5/1 Stream Cipher")
    a51_key = key_str_to_64bit("SECRET64")
    a51 = A51Cipher(a51_key)
    ct_a51 = a51.encrypt(test_data)
    pt_a51 = a51.decrypt(ct_a51)
    status_a51 = "PASS" if pt_a51 == test_data else "FAIL"
    print(f"    Encrypt-Decrypt : {status_a51}")
    print(f"    Plaintext  (hex): {test_data[:16].hex()}...")
    print(f"    Ciphertext (hex): {ct_a51[:16].hex()}...")

    print("\n" + "=" * 60)
    print(f"  HASIL: Vigenere={status_vig}, A5/1={status_a51}")
    print("=" * 60)
