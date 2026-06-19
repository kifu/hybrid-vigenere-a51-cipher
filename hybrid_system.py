from __future__ import annotations

from cipher_modules import A51Cipher, VigenereCipher, key_str_to_64bit


class HybridCryptoSystem:
    def __init__(
        self,
        vigenere_key: str | bytes,
        a51_key: str | int,
    ) -> None:
        # Inisialisasi Vigenère
        self.vigenere = VigenereCipher(vigenere_key)

        # Inisialisasi A5/1
        if isinstance(a51_key, str):
            a51_key_int = key_str_to_64bit(a51_key)
        else:
            a51_key_int = a51_key
        self.a51 = A51Cipher(a51_key_int)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Lapisan 1: Vigenère
        intermediate = self.vigenere.encrypt(plaintext)

        # Lapisan 2: A5/1
        ciphertext = self.a51.encrypt(intermediate)

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Lapisan 1: A5/1 (kebalikan dari lapisan terakhir enkripsi)
        intermediate = self.a51.decrypt(ciphertext)

        # Lapisan 2: Vigenère (kebalikan dari lapisan pertama enkripsi)
        plaintext = self.vigenere.decrypt(intermediate)

        return plaintext

    def verify_roundtrip(self, data: bytes) -> bool:
        return self.decrypt(self.encrypt(data)) == data


# =============================================================================
#  SELF-TEST                                                                   
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SELF-TEST: hybrid_system.py")
    print("=" * 60)

    test_vectors = [
        b"",  # edge case: data kosong
        b"A",  # data 1 byte
        b"Hello, World!",  # data pendek
        b"The quick brown fox jumps over the lazy dog." * 10,  # data medium
        bytes(range(256)),  # semua nilai byte 0-255
    ]

    hcs = HybridCryptoSystem(
        vigenere_key="KUNCI_VIGENERE_RAHASIA",
        a51_key="KUNCI_A51_64BIT",
    )

    all_pass = True
    for i, data in enumerate(test_vectors):
        ct = hcs.encrypt(data)
        pt = hcs.decrypt(ct)
        status = "PASS" if pt == data else "FAIL"
        if status == "FAIL":
            all_pass = False

        size_label = f"{len(data)} byte"
        print(f"  Test {i+1} ({size_label:>10s}): {status}")

        # Tampilkan preview hex untuk data non-kosong
        if len(data) > 0:
            print(f"    Plaintext  (hex): {data[:12].hex()}...")
            print(f"    Ciphertext (hex): {ct[:12].hex()}...")

    print("\n" + "=" * 60)
    print(f"  HASIL KESELURUHAN: {'SEMUA LULUS' if all_pass else 'ADA YANG GAGAL'}")
    print("=" * 60)
