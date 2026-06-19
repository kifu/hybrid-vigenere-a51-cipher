from __future__ import annotations

import math
import unittest
from collections import Counter

from cipher_modules import A51Cipher, VigenereCipher, key_str_to_64bit
from hybrid_system import HybridCryptoSystem


def _shannon_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


# =============================================================================
#  TEST: VIGENERE CIPHER
# =============================================================================

class TestVigenereCipher(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = VigenereCipher(b"KUNCI_TEST")

    # Roundtrip Tests

    def test_roundtrip_basic(self) -> None:
        plaintext = b"Hello, World! Ini adalah pesan rahasia."
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_roundtrip_empty(self) -> None:
        self.assertEqual(self.cipher.encrypt(b""), b"")
        self.assertEqual(self.cipher.decrypt(b""), b"")

    def test_roundtrip_single_byte(self) -> None:
        for byte_val in [0, 1, 127, 128, 255]:
            data = bytes([byte_val])
            ct = self.cipher.encrypt(data)
            pt = self.cipher.decrypt(ct)
            self.assertEqual(pt, data, f"Gagal untuk byte {byte_val}")

    def test_roundtrip_all_bytes(self) -> None:
        data = bytes(range(256))
        ct = self.cipher.encrypt(data)
        pt = self.cipher.decrypt(ct)
        self.assertEqual(pt, data)

    def test_roundtrip_large_data(self) -> None:
        import os
        data = os.urandom(10 * 1024)
        ct = self.cipher.encrypt(data)
        pt = self.cipher.decrypt(ct)
        self.assertEqual(pt, data)

    # Property Tests

    def test_ciphertext_differs_from_plaintext(self) -> None:
        plaintext = b"AAAAAAAAAA"  # Data non-trivial
        ciphertext = self.cipher.encrypt(plaintext)
        self.assertNotEqual(ciphertext, plaintext)

    def test_ciphertext_same_length(self) -> None:
        for length in [0, 1, 10, 100, 1000]:
            data = bytes([42] * length)
            ct = self.cipher.encrypt(data)
            self.assertEqual(len(ct), length)

    def test_deterministic(self) -> None:
        plaintext = b"Deterministic test data"
        ct1 = self.cipher.encrypt(plaintext)
        ct2 = self.cipher.encrypt(plaintext)
        self.assertEqual(ct1, ct2)

    def test_different_keys_different_output(self) -> None:
        plaintext = b"Same plaintext, different keys"
        cipher_a = VigenereCipher(b"KEY_A")
        cipher_b = VigenereCipher(b"KEY_B")
        ct_a = cipher_a.encrypt(plaintext)
        ct_b = cipher_b.encrypt(plaintext)
        self.assertNotEqual(ct_a, ct_b)

    def test_string_key_accepted(self) -> None:
        cipher = VigenereCipher("StringKey")
        plaintext = b"Test data"
        ct = cipher.encrypt(plaintext)
        pt = cipher.decrypt(ct)
        self.assertEqual(pt, plaintext)

    # Error Handling 

    def test_empty_key_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            VigenereCipher(b"")

    def test_empty_string_key_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            VigenereCipher("")

    # Known Value Test 

    def test_known_value_manual(self) -> None:
        cipher = VigenereCipher(b"K")
        ct = cipher.encrypt(b"A")
        self.assertEqual(ct[0], (0x41 + 0x4B) % 256)


# =============================================================================
#  TEST: A5/1 CIPHER
# =============================================================================

class TestA51Cipher(unittest.TestCase):
    def setUp(self) -> None:
        self.key = key_str_to_64bit("TEST_KEY_64BIT")
        self.cipher = A51Cipher(self.key)

    # Roundtrip Tests

    def test_roundtrip_basic(self) -> None:
        plaintext = b"Hello from A5/1 stream cipher!"
        ct = self.cipher.encrypt(plaintext)
        pt = self.cipher.decrypt(ct)
        self.assertEqual(pt, plaintext)

    def test_roundtrip_empty(self) -> None:
        self.assertEqual(self.cipher.encrypt(b""), b"")

    def test_roundtrip_single_byte(self) -> None:
        data = b"\x00"
        ct = self.cipher.encrypt(data)
        pt = self.cipher.decrypt(ct)
        self.assertEqual(pt, data)

    def test_roundtrip_all_bytes(self) -> None:
        data = bytes(range(256))
        ct = self.cipher.encrypt(data)
        pt = self.cipher.decrypt(ct)
        self.assertEqual(pt, data)

    # XOR Properties 

    def test_xor_involution(self) -> None:
        plaintext = b"XOR involution test"
        double_encrypted = self.cipher.encrypt(self.cipher.encrypt(plaintext))
        self.assertEqual(double_encrypted, plaintext)

    def test_ciphertext_same_length(self) -> None:
        for length in [0, 1, 10, 100, 500]:
            data = bytes([0xAB] * length)
            ct = self.cipher.encrypt(data)
            self.assertEqual(len(ct), length)

    # Determinism

    def test_deterministic_keystream(self) -> None:
        plaintext = b"Deterministic keystream test"
        ct1 = self.cipher.encrypt(plaintext)
        ct2 = self.cipher.encrypt(plaintext)
        self.assertEqual(ct1, ct2)

    def test_different_keys_different_keystream(self) -> None:
        plaintext = b"Same data different keys"
        cipher_a = A51Cipher(0x0123456789ABCDEF)
        cipher_b = A51Cipher(0xFEDCBA9876543210)
        ct_a = cipher_a.encrypt(plaintext)
        ct_b = cipher_b.encrypt(plaintext)
        self.assertNotEqual(ct_a, ct_b)

    # Error Handling 

    def test_key_out_of_range_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            A51Cipher(1 << 64)  # Terlalu besar

    def test_negative_key_raises_error(self) -> None:
        with self.assertRaises(ValueError):
            A51Cipher(-1)

    def test_zero_key_accepted(self) -> None:
        cipher = A51Cipher(0)
        ct = cipher.encrypt(b"test")
        pt = cipher.decrypt(ct)
        self.assertEqual(pt, b"test")

    def test_max_key_accepted(self) -> None:
        cipher = A51Cipher((1 << 64) - 1)
        ct = cipher.encrypt(b"test")
        pt = cipher.decrypt(ct)
        self.assertEqual(pt, b"test")

    # Entropy Test 

    def test_ciphertext_high_entropy(self) -> None:
        # Plaintext rendah entropy (semua byte sama)
        plaintext = bytes([0x41] * 1024)
        ct = self.cipher.encrypt(plaintext)
        entropy = _shannon_entropy(ct)
        # Entropy harus > 6.0 bit/byte untuk 1KB data
        self.assertGreater(entropy, 6.0,
                           f"Entropy ciphertext terlalu rendah: {entropy:.4f}")


# =============================================================================
#  TEST: KEY CONVERSION UTILITY
# =============================================================================

class TestKeyConversion(unittest.TestCase):
    def test_consistent_output(self) -> None:
        k1 = key_str_to_64bit("MYKEY")
        k2 = key_str_to_64bit("MYKEY")
        self.assertEqual(k1, k2)

    def test_different_strings_different_keys(self) -> None:
        k1 = key_str_to_64bit("KEY_A")
        k2 = key_str_to_64bit("KEY_B")
        self.assertNotEqual(k1, k2)

    def test_output_is_64bit(self) -> None:
        for key_str in ["short", "a_very_long_key_string_that_exceeds_8_bytes"]:
            key_int = key_str_to_64bit(key_str)
            self.assertGreaterEqual(key_int, 0)
            self.assertLess(key_int, 1 << 64)

    def test_long_key_folded(self) -> None:
        # Kunci panjang harus tetap menghasilkan output valid
        key_int = key_str_to_64bit("A" * 100)
        self.assertGreaterEqual(key_int, 0)
        self.assertLess(key_int, 1 << 64)


# =============================================================================
#  TEST: HYBRID SYSTEM
# =============================================================================

class TestHybridSystem(unittest.TestCase):
    def setUp(self) -> None:
        self.hybrid = HybridCryptoSystem(
            vigenere_key="KUNCI_VIG_TEST",
            a51_key="KUNCI_A51_TEST",
        )

    # Roundtrip Tests 

    def test_roundtrip_basic(self) -> None:
        plaintext = b"Hybrid encryption system test data!"
        ct = self.hybrid.encrypt(plaintext)
        pt = self.hybrid.decrypt(ct)
        self.assertEqual(pt, plaintext)

    def test_roundtrip_empty(self) -> None:
        self.assertEqual(self.hybrid.decrypt(self.hybrid.encrypt(b"")), b"")

    def test_roundtrip_all_bytes(self) -> None:
        data = bytes(range(256))
        self.assertEqual(self.hybrid.decrypt(self.hybrid.encrypt(data)), data)

    def test_roundtrip_large_data(self) -> None:
        import os
        data = os.urandom(5 * 1024)
        self.assertEqual(self.hybrid.decrypt(self.hybrid.encrypt(data)), data)

    def test_verify_roundtrip_method(self) -> None:
        self.assertTrue(self.hybrid.verify_roundtrip(b"Test verify"))
        self.assertTrue(self.hybrid.verify_roundtrip(b""))
        self.assertTrue(self.hybrid.verify_roundtrip(bytes(range(256))))

    # Layering Verification

    def test_hybrid_differs_from_vigenere_alone(self) -> None:
        plaintext = b"Compare hybrid vs vigenere"
        ct_hybrid = self.hybrid.encrypt(plaintext)
        ct_vig = self.hybrid.vigenere.encrypt(plaintext)
        self.assertNotEqual(ct_hybrid, ct_vig)

    def test_hybrid_differs_from_a51_alone(self) -> None:
        plaintext = b"Compare hybrid vs a51"
        ct_hybrid = self.hybrid.encrypt(plaintext)
        ct_a51 = self.hybrid.a51.encrypt(plaintext)
        self.assertNotEqual(ct_hybrid, ct_a51)

    def test_encryption_order_matters(self) -> None:
        plaintext = b"Order verification test"

        # Enkripsi manual: Vigenere dulu, lalu A5/1
        step1 = self.hybrid.vigenere.encrypt(plaintext)
        expected = self.hybrid.a51.encrypt(step1)

        # Enkripsi via hybrid
        actual = self.hybrid.encrypt(plaintext)

        self.assertEqual(actual, expected)

    def test_decryption_reverse_order(self) -> None:
        plaintext = b"Reverse order verification"
        ciphertext = self.hybrid.encrypt(plaintext)

        # Dekripsi manual: A5/1 dulu, lalu Vigenere
        step1 = self.hybrid.a51.decrypt(ciphertext)
        expected = self.hybrid.vigenere.decrypt(step1)

        # Dekripsi via hybrid
        actual = self.hybrid.decrypt(ciphertext)

        self.assertEqual(actual, expected)
        self.assertEqual(actual, plaintext)

    # Key Variation 

    def test_different_vigenere_key_different_output(self) -> None:
        hybrid_a = HybridCryptoSystem("KEY_A", "SAME_A51")
        hybrid_b = HybridCryptoSystem("KEY_B", "SAME_A51")
        plaintext = b"Same plaintext"
        self.assertNotEqual(hybrid_a.encrypt(plaintext), hybrid_b.encrypt(plaintext))

    def test_different_a51_key_different_output(self) -> None:
        hybrid_a = HybridCryptoSystem("SAME_VIG", "A51_KEY_A")
        hybrid_b = HybridCryptoSystem("SAME_VIG", "A51_KEY_B")
        plaintext = b"Same plaintext"
        self.assertNotEqual(hybrid_a.encrypt(plaintext), hybrid_b.encrypt(plaintext))

    def test_integer_a51_key_accepted(self) -> None:
        hybrid = HybridCryptoSystem("VigKey", 0xDEADBEEFCAFEBABE)
        plaintext = b"Integer key test"
        self.assertEqual(hybrid.decrypt(hybrid.encrypt(plaintext)), plaintext)


# =============================================================================
#  ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
