from __future__ import annotations

import math
import os
import random
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

# Import modul lokal
from cipher_modules import A51Cipher, VigenereCipher, key_str_to_64bit
from hybrid_system import HybridCryptoSystem


# =============================================================================
#  KONFIGURASI EKSPERIMEN
# =============================================================================

# Ukuran file dummy yang akan diuji (dalam byte)
FILE_SIZES: dict[str, int] = {
    "10 KB":  10 * 1024,
    "50 KB":  50 * 1024,
    "100 KB": 100 * 1024,
    "500 KB": 500 * 1024,
}

# Tipe data input yang akan diuji
DATA_TYPES: list[str] = ["Random Binary", "English Text", "Structured Log"]

# Kunci-kunci yang digunakan dalam eksperimen
VIGENERE_KEY: str = "KUNCI_VIGENERE_RAHASIA_2026"
A51_KEY_STR: str = "KUNCI_A51_STREAM_64BIT"

# Jumlah iterasi per pengukuran (untuk rata-rata yang lebih stabil)
NUM_ITERATIONS: int = 3

# Direktori untuk menyimpan file dummy
DUMMY_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dummy_files")


# =============================================================================
#  DATA CLASS UNTUK MENYIMPAN HASIL EKSPERIMEN
# =============================================================================

@dataclass
class ExperimentResult:
    file_size_label: str        
    file_size_bytes: int       
    data_type: str              

    # Waktu enkripsi (ms)
    time_vigenere_enc: float = 0.0
    time_a51_enc: float = 0.0
    time_hybrid_enc: float = 0.0

    # Waktu dekripsi (ms)
    time_vigenere_dec: float = 0.0
    time_a51_dec: float = 0.0
    time_hybrid_dec: float = 0.0

    # Shannon Entropy ciphertext
    entropy_plaintext: float = 0.0
    entropy_vigenere: float = 0.0
    entropy_a51: float = 0.0
    entropy_hybrid: float = 0.0

    # Status verifikasi dekripsi
    verify_vigenere: bool = False
    verify_a51: bool = False
    verify_hybrid: bool = False


# =============================================================================
#  FUNGSI GENERATOR DATA
# =============================================================================

def generate_random_binary(size_bytes: int) -> bytes:
    return os.urandom(size_bytes)


def generate_english_text(size_bytes: int) -> bytes:
    paragraphs = [
        # Sastra klasik
        "The quick brown fox jumps over the lazy dog. "
        "This sentence contains every letter of the English alphabet at least once. "
        "It has been used as a pangram for testing typewriters and keyboards since the late 1800s. "
        "Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump. ",

        # Sains dan teknologi
        "Cryptography is the practice and study of techniques for secure communication "
        "in the presence of adversarial behavior. More generally, cryptography is about "
        "constructing and analyzing protocols that prevent third parties or the public "
        "from reading private messages. Modern cryptography exists at the intersection "
        "of the disciplines of mathematics, computer science, electrical engineering, "
        "communication science, and physics. ",

        # Keamanan informasi
        "Information security is the practice of protecting information by mitigating "
        "information risks. It is part of information risk management and typically "
        "involves preventing or reducing the probability of unauthorized or inappropriate "
        "access to data, or the unlawful use, disclosure, disruption, deletion, corruption, "
        "modification, inspection, recording, or devaluation of information. ",

        # Sejarah kriptografi
        "The history of cryptography dates back thousands of years. The earliest known "
        "use of cryptography is found in non-standard hieroglyphs carved into the wall "
        "of a tomb from the Old Kingdom of Egypt circa 1900 BC. The Spartans used a "
        "device called a scytale for transposition cipher around 700 BC. Julius Caesar "
        "used a substitution cipher now known as the Caesar cipher. ",

        # Filosofi dan matematika
        "Mathematics is the queen of the sciences and number theory is the queen of "
        "mathematics. The enchanting charms of this sublime science reveal themselves "
        "in all their beauty only to those who have the courage to go deeply into it. "
        "In mathematics the art of proposing a question must be held of higher value "
        "than solving it. Every good mathematician is at least half a philosopher. ",

        # Jaringan komputer
        "A computer network is a set of computers sharing resources located on or "
        "provided by network nodes. Computers use common communication protocols over "
        "digital interconnections to communicate with each other. These interconnections "
        "are made up of telecommunication network technologies based on physically wired "
        "optical and wireless radio frequency methods that may be arranged in a variety "
        "of network topologies. ",

        # Enkripsi modern
        "The Advanced Encryption Standard is a specification for the encryption of "
        "electronic data established by the National Institute of Standards and Technology "
        "in 2001. AES is a variant of the Rijndael block cipher developed by two Belgian "
        "cryptographers Vincent Rijmen and Joan Daemen. AES has been adopted by the "
        "United States government to protect classified information. ",

        # Umum
        "The development of digital computers and electronics after World War II made "
        "possible much more complex ciphers. Furthermore the advent of computers allowed "
        "for the encryption of any kind of data representable in any binary format unlike "
        "classical ciphers which only encrypted written language texts. ",
    ]

    # Gabungkan paragraf secara berulang hingga mencapai ukuran target
    text = ""
    while len(text.encode("utf-8")) < size_bytes:
        for para in paragraphs:
            text += para + "\n\n"
            if len(text.encode("utf-8")) >= size_bytes:
                break

    # Potong ke ukuran tepat
    encoded = text.encode("utf-8")
    return encoded[:size_bytes]


def generate_structured_log(size_bytes: int) -> bytes:
    # Gunakan seed tetap agar hasil reproducible antar eksperimen
    rng = random.Random(42)

    log_levels = ["INFO", "DEBUG", "WARN", "ERROR", "INFO", "INFO", "INFO", "DEBUG"]
    http_methods = ["GET", "POST", "PUT", "DELETE", "GET", "GET", "GET", "POST"]
    status_codes = ["200", "200", "200", "201", "301", "400", "403", "404", "500"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101",
        "curl/7.88.1",
        "Python-urllib/3.11",
        "PostmanRuntime/7.32.1",
    ]
    api_paths = [
        "/api/v1/users", "/api/v1/auth/login", "/api/v1/auth/logout",
        "/api/v1/products", "/api/v1/orders", "/api/v1/payments",
        "/api/v2/search", "/api/v2/analytics", "/health", "/metrics",
        "/api/v1/users/profile", "/api/v1/notifications",
        "/static/js/app.bundle.js", "/static/css/style.min.css",
        "/favicon.ico", "/robots.txt",
    ]
    modules = [
        "auth.service", "user.controller", "db.connection",
        "cache.redis", "api.gateway", "scheduler.cron",
        "payment.processor", "email.sender", "file.upload",
    ]
    messages = [
        "Request processed successfully",
        "User authenticated with valid credentials",
        "Database query executed in {ms}ms",
        "Cache hit for key: session_{id}",
        "Cache miss, fetching from database",
        "Connection pool: {n} active, {m} idle",
        "Rate limit check passed for client {ip}",
        "Scheduled task completed: cleanup_sessions",
        "File uploaded: {size}KB, type: application/pdf",
        "Email notification sent to user_{id}",
        "Payment transaction {txn} completed",
        "Retry attempt {n} for external API call",
        "Health check passed: all services operational",
        "Configuration reloaded from environment",
        "JWT token validated, expiry in {n} minutes",
        "WebSocket connection established from {ip}",
        "Background job queued: generate_report_{id}",
        "Middleware chain executed in {ms}ms",
    ]

    log_lines = []
    total_bytes = 0
    line_num = 0

    while total_bytes < size_bytes:
        line_num += 1

        # Pilih format log secara acak
        log_format = rng.choice(["app_log", "access_log", "app_log", "app_log"])

        if log_format == "access_log":
            # Format: Apache/Nginx combined log
            ip = f"{rng.randint(10,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            day = rng.randint(1, 28)
            hour = rng.randint(0, 23)
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            method = rng.choice(http_methods)
            path = rng.choice(api_paths)
            status = rng.choice(status_codes)
            resp_size = rng.randint(128, 65536)
            agent = rng.choice(user_agents)

            line = (
                f'{ip} - - [19/Jun/2026:{hour:02d}:{minute:02d}:{second:02d} +0700] '
                f'"{method} {path} HTTP/1.1" {status} {resp_size} '
                f'"-" "{agent}"\n'
            )
        else:
            # Format: Application log (structured)
            hour = rng.randint(0, 23)
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            ms = rng.randint(0, 999)
            level = rng.choice(log_levels)
            module = rng.choice(modules)
            msg_template = rng.choice(messages)

            # Isi placeholder dalam pesan
            msg = msg_template
            msg = msg.replace("{ms}", str(rng.randint(1, 500)))
            msg = msg.replace("{id}", str(rng.randint(1000, 99999)))
            msg = msg.replace("{n}", str(rng.randint(1, 50)))
            msg = msg.replace("{m}", str(rng.randint(1, 20)))
            msg = msg.replace("{size}", str(rng.randint(10, 5000)))
            msg = msg.replace("{ip}", f"{rng.randint(10,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}")
            msg = msg.replace("{txn}", f"TXN-{rng.randint(100000,999999)}")

            req_id = f"{rng.randint(0x1000,0xFFFF):04x}-{rng.randint(0x1000,0xFFFF):04x}"

            line = (
                f"2026-06-19T{hour:02d}:{minute:02d}:{second:02d}.{ms:03d}Z "
                f"[{level:<5s}] [{module:<20s}] [req-{req_id}] {msg}\n"
            )

        line_bytes = line.encode("utf-8")
        log_lines.append(line_bytes)
        total_bytes += len(line_bytes)

    # Gabungkan dan potong ke ukuran tepat
    result = b"".join(log_lines)
    return result[:size_bytes]


# Map nama tipe data ke fungsi generator
DATA_GENERATORS: dict[str, Callable[[int], bytes]] = {
    "Random Binary":  generate_random_binary,
    "English Text":   generate_english_text,
    "Structured Log": generate_structured_log,
}


# =============================================================================
#  FUNGSI UTILITAS
# =============================================================================

def save_dummy_file(filepath: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(data)


def calculate_shannon_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0

    # Hitung frekuensi setiap nilai byte
    freq = Counter(data)
    total = len(data)

    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return entropy


def measure_execution_time(
    func: Callable[[bytes], bytes],
    data: bytes,
    iterations: int = NUM_ITERATIONS,
) -> tuple[float, bytes]:
    total_time = 0.0
    result = b""

    for _ in range(iterations):
        start = time.perf_counter()
        result = func(data)
        end = time.perf_counter()
        total_time += (end - start)

    avg_time_ms = (total_time / iterations) * 1000  # Konversi ke milidetik
    return avg_time_ms, result


# =============================================================================
#  FUNGSI UTAMA EKSPERIMEN
# =============================================================================

def run_experiment(
    label: str,
    size_bytes: int,
    data_type: str,
    plaintext: bytes,
    vig: VigenereCipher,
    a51: A51Cipher,
    hybrid: HybridCryptoSystem,
) -> ExperimentResult:
    result = ExperimentResult(
        file_size_label=label,
        file_size_bytes=size_bytes,
        data_type=data_type,
    )

    # Entropy plaintext
    result.entropy_plaintext = calculate_shannon_entropy(plaintext)

    # Vigenere Saja
    print(f"      Vigenere...", end=" ", flush=True)
    result.time_vigenere_enc, ct_vig = measure_execution_time(vig.encrypt, plaintext)
    result.time_vigenere_dec, pt_vig = measure_execution_time(vig.decrypt, ct_vig)
    result.entropy_vigenere = calculate_shannon_entropy(ct_vig)
    result.verify_vigenere = (pt_vig == plaintext)
    print(f"{'[OK]' if result.verify_vigenere else '[FAIL]'}")

    # A5/1 Saja 
    print(f"      A5/1...", end=" ", flush=True)
    result.time_a51_enc, ct_a51 = measure_execution_time(a51.encrypt, plaintext)
    result.time_a51_dec, pt_a51 = measure_execution_time(a51.decrypt, ct_a51)
    result.entropy_a51 = calculate_shannon_entropy(ct_a51)
    result.verify_a51 = (pt_a51 == plaintext)
    print(f"{'[OK]' if result.verify_a51 else '[FAIL]'}")

    # Hybrid System
    print(f"      Hybrid...", end=" ", flush=True)
    result.time_hybrid_enc, ct_hyb = measure_execution_time(hybrid.encrypt, plaintext)
    result.time_hybrid_dec, pt_hyb = measure_execution_time(hybrid.decrypt, ct_hyb)
    result.entropy_hybrid = calculate_shannon_entropy(ct_hyb)
    result.verify_hybrid = (pt_hyb == plaintext)
    print(f"{'[OK]' if result.verify_hybrid else '[FAIL]'}")

    return result


# =============================================================================
#  FUNGSI CETAK TABEL MARKDOWN
# =============================================================================

def print_markdown_tables(
    all_results: dict[str, list[ExperimentResult]],
) -> None:
    table_num = 0

    for data_type, results in all_results.items():
        print(f"\n{'-' * 70}")
        print(f"  Tipe Data: {data_type}")
        print(f"{'-' * 70}")

        # Tabel: Waktu Enkripsi
        table_num += 1
        print(f"\n### Tabel {table_num}. Waktu Enkripsi - {data_type} (ms)\n")
        print("| Ukuran Data | Vigenere (ms) | A5/1 (ms) | Hybrid (ms) |")
        print("|:-----------:|:-------------:|:---------:|:-----------:|")
        for r in results:
            print(
                f"| {r.file_size_label:>9s} "
                f"| {r.time_vigenere_enc:>13.2f} "
                f"| {r.time_a51_enc:>9.2f} "
                f"| {r.time_hybrid_enc:>11.2f} |"
            )

        # Tabel: Waktu Dekripsi
        table_num += 1
        print(f"\n### Tabel {table_num}. Waktu Dekripsi - {data_type} (ms)\n")
        print("| Ukuran Data | Vigenere (ms) | A5/1 (ms) | Hybrid (ms) |")
        print("|:-----------:|:-------------:|:---------:|:-----------:|")
        for r in results:
            print(
                f"| {r.file_size_label:>9s} "
                f"| {r.time_vigenere_dec:>13.2f} "
                f"| {r.time_a51_dec:>9.2f} "
                f"| {r.time_hybrid_dec:>11.2f} |"
            )

        # Tabel: Shannon Entropy
        table_num += 1
        print(f"\n### Tabel {table_num}. Shannon Entropy - {data_type} (bit/byte)\n")
        print("| Ukuran Data | Plaintext | Vigenere | A5/1   | Hybrid |")
        print("|:-----------:|:---------:|:--------:|:------:|:------:|")
        for r in results:
            print(
                f"| {r.file_size_label:>9s} "
                f"| {r.entropy_plaintext:>9.4f} "
                f"| {r.entropy_vigenere:>8.4f} "
                f"| {r.entropy_a51:>6.4f} "
                f"| {r.entropy_hybrid:>6.4f} |"
            )

    # Tabel gabungan: Verifikasi Dekripsi
    table_num += 1
    print(f"\n{'-' * 70}")
    print(f"\n### Tabel {table_num}. Verifikasi Dekripsi - Semua Tipe Data\n")
    print("| Tipe Data | Ukuran | Vigenere | A5/1   | Hybrid |")
    print("|:----------|:------:|:--------:|:------:|:------:|")
    for data_type, results in all_results.items():
        for r in results:
            v = "Pass" if r.verify_vigenere else "Fail"
            a = "Pass" if r.verify_a51 else "Fail"
            h = "Pass" if r.verify_hybrid else "Fail"
            short_type = data_type[:12]
            print(f"| {short_type:<12s} | {r.file_size_label:>6s} | {v:>8s} | {a:>6s} | {h:>6s} |")

    # Tabel gabungan: Perbandingan Entropy antar Tipe Data
    table_num += 1
    print(f"\n### Tabel {table_num}. Perbandingan Entropy Plaintext vs Ciphertext Hybrid\n")
    print("| Tipe Data | Ukuran | Entropy Plaintext | Entropy Hybrid | Delta |")
    print("|:----------|:------:|:-----------------:|:--------------:|:-----:|")
    for data_type, results in all_results.items():
        for r in results:
            delta = r.entropy_hybrid - r.entropy_plaintext
            short_type = data_type[:12]
            print(
                f"| {short_type:<12s} "
                f"| {r.file_size_label:>6s} "
                f"| {r.entropy_plaintext:>17.4f} "
                f"| {r.entropy_hybrid:>14.4f} "
                f"| {delta:>+5.4f} |"
            )


def print_summary_analysis(
    all_results: dict[str, list[ExperimentResult]],
) -> None:
    print("\n" + "=" * 70)
    print("  RINGKASAN ANALISIS")
    print("=" * 70)

    for data_type, results in all_results.items():
        print(f"\n  --- {data_type} ---")

        # Analisis kecepatan
        print(f"  [SPEED] Waktu Enkripsi Hybrid:")
        for r in results:
            overhead = r.time_hybrid_enc - r.time_vigenere_enc
            ratio = r.time_hybrid_enc / r.time_vigenere_enc if r.time_vigenere_enc > 0 else float('inf')
            print(
                f"    {r.file_size_label}: {r.time_hybrid_enc:.2f} ms "
                f"({ratio:.1f}x vs Vigenere, overhead {overhead:.2f} ms)"
            )

        # Analisis entropy
        print(f"  [ENTROPY] Peningkatan dari Plaintext ke Hybrid:")
        for r in results:
            delta = r.entropy_hybrid - r.entropy_plaintext
            print(
                f"    {r.file_size_label}: {r.entropy_plaintext:.4f} -> {r.entropy_hybrid:.4f} "
                f"(delta {delta:+.4f} bit/byte)"
            )

    # Rata-rata entropy per tipe data
    print(f"\n  [SUMMARY] Entropy Rata-rata per Tipe Data:")
    print(f"  {'Tipe Data':<16s} | {'Plaintext':>10s} | {'Vigenere':>10s} | {'A5/1':>10s} | {'Hybrid':>10s}")
    print(f"  {'-'*16}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}-+-{'-'*10}")
    for data_type, results in all_results.items():
        avg_pt = sum(r.entropy_plaintext for r in results) / len(results)
        avg_vig = sum(r.entropy_vigenere for r in results) / len(results)
        avg_a51 = sum(r.entropy_a51 for r in results) / len(results)
        avg_hyb = sum(r.entropy_hybrid for r in results) / len(results)
        print(
            f"  {data_type:<16s} | {avg_pt:>10.4f} | {avg_vig:>10.4f} "
            f"| {avg_a51:>10.4f} | {avg_hyb:>10.4f}"
        )

    # Verifikasi keseluruhan
    all_verified = all(
        r.verify_vigenere and r.verify_a51 and r.verify_hybrid
        for results in all_results.values()
        for r in results
    )
    total_tests = sum(len(results) * 3 for results in all_results.values())
    status = "SEMUA BERHASIL" if all_verified else "ADA KEGAGALAN"
    print(f"\n  [TEST] Verifikasi Dekripsi: {status} ({total_tests}/{total_tests} passed)")


# =============================================================================
#  MAIN: ENTRY POINT
# =============================================================================

def main() -> None:
    print("=" * 70)
    print("  EXPERIMENT RUNNER")
    print("  Design and Performance Analysis of a Hybrid Encryption System")
    print("  Vigenere Cipher + A5/1 Stream Cipher")
    print("=" * 70)
    print(f"\n  Konfigurasi:")
    print(f"    Iterasi per pengukuran : {NUM_ITERATIONS}")
    print(f"    Kunci Vigenere         : {VIGENERE_KEY}")
    print(f"    Kunci A5/1 (string)    : {A51_KEY_STR}")
    print(f"    Ukuran data uji       : {', '.join(FILE_SIZES.keys())}")
    print(f"    Tipe data uji         : {', '.join(DATA_TYPES)}")

    # Inisialisasi cipher instances
    vig = VigenereCipher(VIGENERE_KEY)
    a51_key_int = key_str_to_64bit(A51_KEY_STR)
    a51 = A51Cipher(a51_key_int)
    hybrid = HybridCryptoSystem(
        vigenere_key=VIGENERE_KEY,
        a51_key=A51_KEY_STR,
    )

    print(f"\n  A5/1 Key (64-bit int)   : {a51_key_int} (0x{a51_key_int:016X})")

    # Kumpulkan hasil eksperimen per tipe data
    all_results: dict[str, list[ExperimentResult]] = {}

    for data_type in DATA_TYPES:
        generator = DATA_GENERATORS[data_type]
        results: list[ExperimentResult] = []

        print(f"\n{'=' * 70}")
        print(f"  TIPE DATA: {data_type}")
        print(f"{'=' * 70}")

        for label, size in FILE_SIZES.items():
            print(f"\n  [{label}] Generating {size:,} byte ({data_type})...")
            plaintext = generator(size)

            # Simpan file dummy ke disk
            type_suffix = data_type.lower().replace(" ", "_")
            dummy_path = os.path.join(
                DUMMY_DIR, f"dummy_{label.replace(' ', '')}_{type_suffix}.bin"
            )
            save_dummy_file(dummy_path, plaintext)
            print(f"    Disimpan: {dummy_path}")
            print(f"    Entropy plaintext: {calculate_shannon_entropy(plaintext):.4f} bit/byte")

            # Jalankan eksperimen
            result = run_experiment(label, size, data_type, plaintext, vig, a51, hybrid)
            results.append(result)

        all_results[data_type] = results

    # Cetak tabel Markdown
    print("\n\n" + "=" * 70)
    print("  HASIL EKSPERIMEN (FORMAT TABEL MARKDOWN)")
    print("=" * 70)
    print_markdown_tables(all_results)

    # Cetak ringkasan analisis
    print_summary_analysis(all_results)

    print("\n" + "=" * 70)
    print("  Eksperimen selesai. Tabel di atas dapat disalin ke makalah IEEE.")
    print("=" * 70)


if __name__ == "__main__":
    main()
