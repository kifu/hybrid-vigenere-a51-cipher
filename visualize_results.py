from __future__ import annotations

import math
import os
import random
import sys
import time
from collections import Counter
from typing import Callable

# Import modul lokal (untuk data generators)
from cipher_modules import A51Cipher, VigenereCipher, key_str_to_64bit
from hybrid_system import HybridCryptoSystem
from experiment_runner import (
    generate_random_binary,
    generate_english_text,
    generate_structured_log,
    DATA_TYPES,
    DATA_GENERATORS,
)

try:
    import matplotlib
    matplotlib.use("Agg") 
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("=" * 60)
    print("  ERROR: matplotlib belum terinstall.")
    print("  Jalankan: pip install matplotlib")
    print("=" * 60)
    sys.exit(1)


# =============================================================================
#  KONFIGURASI
# =============================================================================

FILE_SIZES: dict[str, int] = {
    "10 KB":  10 * 1024,
    "50 KB":  50 * 1024,
    "100 KB": 100 * 1024,
    "500 KB": 500 * 1024,
}

VIGENERE_KEY: str = "KUNCI_VIGENERE_RAHASIA_2026"
A51_KEY_STR: str = "KUNCI_A51_STREAM_64BIT"
NUM_ITERATIONS: int = 3
OUTPUT_DIR: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output_charts")

# Warna yang konsisten untuk setiap metode cipher
COLORS_METHOD = {
    "vigenere": "#2196F3",   # Biru
    "a51":     "#FF9800",    # Oranye
    "hybrid":  "#4CAF50",    # Hijau
}

# Warna untuk tipe data
COLORS_DATATYPE = {
    "Random Binary":  "#9C27B0",  # Ungu
    "English Text":   "#E91E63",  # Pink
    "Structured Log": "#009688",  # Teal
}

# Style global
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.labelsize": 12,
    "figure.facecolor": "white",
    "axes.facecolor": "#FAFAFA",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
})


# =============================================================================
#  UTILITAS
# =============================================================================

def calculate_shannon_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


def measure_time(func: Callable, data: bytes, iterations: int = NUM_ITERATIONS) -> tuple[float, bytes]:
    total = 0.0
    result = b""
    for _ in range(iterations):
        start = time.perf_counter()
        result = func(data)
        end = time.perf_counter()
        total += (end - start)
    return (total / iterations) * 1000, result


# =============================================================================
#  PENGUMPULAN DATA EKSPERIMEN
# =============================================================================

def collect_data() -> dict[str, dict]:
    vig = VigenereCipher(VIGENERE_KEY)
    a51 = A51Cipher(key_str_to_64bit(A51_KEY_STR))
    hybrid = HybridCryptoSystem(VIGENERE_KEY, A51_KEY_STR)

    labels = list(FILE_SIZES.keys())
    sizes_kb = [s // 1024 for s in FILE_SIZES.values()]

    all_data: dict[str, dict] = {}

    for data_type in DATA_TYPES:
        generator = DATA_GENERATORS[data_type]
        print(f"\n  --- {data_type} ---")

        enc_vig, enc_a51, enc_hyb = [], [], []
        dec_vig, dec_a51, dec_hyb = [], [], []
        ent_plain, ent_vig, ent_a51, ent_hyb = [], [], [], []

        for label, size in FILE_SIZES.items():
            print(f"    {label}...", end=" ", flush=True)
            plaintext = generator(size)

            ent_plain.append(calculate_shannon_entropy(plaintext))

            # Vigenere
            t_enc, ct = measure_time(vig.encrypt, plaintext)
            t_dec, _ = measure_time(vig.decrypt, ct)
            enc_vig.append(t_enc)
            dec_vig.append(t_dec)
            ent_vig.append(calculate_shannon_entropy(ct))

            # A5/1
            t_enc, ct = measure_time(a51.encrypt, plaintext)
            t_dec, _ = measure_time(a51.decrypt, ct)
            enc_a51.append(t_enc)
            dec_a51.append(t_dec)
            ent_a51.append(calculate_shannon_entropy(ct))

            # Hybrid
            t_enc, ct = measure_time(hybrid.encrypt, plaintext)
            t_dec, _ = measure_time(hybrid.decrypt, ct)
            enc_hyb.append(t_enc)
            dec_hyb.append(t_dec)
            ent_hyb.append(calculate_shannon_entropy(ct))

            print("[OK]")

        all_data[data_type] = {
            "labels": labels,
            "sizes_kb": sizes_kb,
            "enc": {"vigenere": enc_vig, "a51": enc_a51, "hybrid": enc_hyb},
            "dec": {"vigenere": dec_vig, "a51": dec_a51, "hybrid": dec_hyb},
            "entropy": {
                "plaintext": ent_plain,
                "vigenere": ent_vig,
                "a51": ent_a51,
                "hybrid": ent_hyb,
            },
        }

    return all_data


# =============================================================================
#  GRAFIK PER TIPE DATA
# =============================================================================

def plot_encryption_time(data: dict, data_type: str, output_path: str) -> None:
    labels = data["labels"]
    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))

    bars1 = ax.bar([i - width for i in x], data["enc"]["vigenere"], width,
                   label="Vigenere", color=COLORS_METHOD["vigenere"], edgecolor="white", linewidth=0.5)
    bars2 = ax.bar(x, data["enc"]["a51"], width,
                   label="A5/1", color=COLORS_METHOD["a51"], edgecolor="white", linewidth=0.5)
    bars3 = ax.bar([i + width for i in x], data["enc"]["hybrid"], width,
                   label="Hybrid", color=COLORS_METHOD["hybrid"], edgecolor="white", linewidth=0.5)

    ax.set_xlabel("Ukuran Data")
    ax.set_ylabel("Waktu Enkripsi (ms)")
    ax.set_title(f"Waktu Enkripsi - {data_type}")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="upper left", framealpha=0.9)

    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f"{height:.1f}",
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 4), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


def plot_decryption_time(data: dict, data_type: str, output_path: str) -> None:
    labels = data["labels"]
    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))

    bars1 = ax.bar([i - width for i in x], data["dec"]["vigenere"], width,
                   label="Vigenere", color=COLORS_METHOD["vigenere"], edgecolor="white", linewidth=0.5)
    bars2 = ax.bar(x, data["dec"]["a51"], width,
                   label="A5/1", color=COLORS_METHOD["a51"], edgecolor="white", linewidth=0.5)
    bars3 = ax.bar([i + width for i in x], data["dec"]["hybrid"], width,
                   label="Hybrid", color=COLORS_METHOD["hybrid"], edgecolor="white", linewidth=0.5)

    ax.set_xlabel("Ukuran Data")
    ax.set_ylabel("Waktu Dekripsi (ms)")
    ax.set_title(f"Waktu Dekripsi - {data_type}")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="upper left", framealpha=0.9)

    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f"{height:.1f}",
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 4), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


def plot_entropy(data: dict, data_type: str, output_path: str) -> None:
    labels = data["labels"]
    x = range(len(labels))
    width = 0.2

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar([i - 1.5 * width for i in x], data["entropy"]["plaintext"], width,
           label="Plaintext", color="#9E9E9E", edgecolor="white", linewidth=0.5)
    ax.bar([i - 0.5 * width for i in x], data["entropy"]["vigenere"], width,
           label="Vigenere", color=COLORS_METHOD["vigenere"], edgecolor="white", linewidth=0.5)
    ax.bar([i + 0.5 * width for i in x], data["entropy"]["a51"], width,
           label="A5/1", color=COLORS_METHOD["a51"], edgecolor="white", linewidth=0.5)
    ax.bar([i + 1.5 * width for i in x], data["entropy"]["hybrid"], width,
           label="Hybrid", color=COLORS_METHOD["hybrid"], edgecolor="white", linewidth=0.5)

    ax.set_xlabel("Ukuran Data")
    ax.set_ylabel("Shannon Entropy (bit/byte)")
    ax.set_title(f"Shannon Entropy - {data_type}")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="lower right", framealpha=0.9)

    # Garis referensi entropy maksimum
    ax.axhline(y=8.0, color="red", linestyle=":", linewidth=1, alpha=0.7)

    # Sesuaikan y-axis agar perbedaan terlihat
    all_ent = (data["entropy"]["plaintext"] + data["entropy"]["vigenere"] +
               data["entropy"]["a51"] + data["entropy"]["hybrid"])
    y_min = min(all_ent) - 0.2
    y_max = 8.1
    ax.set_ylim(max(0, y_min), y_max)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


def plot_scalability(data: dict, data_type: str, output_path: str) -> None:
    sizes = data["sizes_kb"]

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(sizes, data["enc"]["vigenere"], "o-", color=COLORS_METHOD["vigenere"],
            label="Vigenere", linewidth=2, markersize=8)
    ax.plot(sizes, data["enc"]["a51"], "s-", color=COLORS_METHOD["a51"],
            label="A5/1", linewidth=2, markersize=8)
    ax.plot(sizes, data["enc"]["hybrid"], "D-", color=COLORS_METHOD["hybrid"],
            label="Hybrid", linewidth=2, markersize=8)

    ax.set_xlabel("Ukuran Data (KB)")
    ax.set_ylabel("Waktu Enkripsi (ms)")
    ax.set_title(f"Skalabilitas - {data_type}")
    ax.legend(loc="upper left", framealpha=0.9)

    for method, marker_data in [
        ("vigenere", data["enc"]["vigenere"]),
        ("a51", data["enc"]["a51"]),
        ("hybrid", data["enc"]["hybrid"]),
    ]:
        for xi, yi in zip(sizes, marker_data):
            ax.annotate(f"{yi:.1f}", (xi, yi),
                        textcoords="offset points", xytext=(0, 10),
                        ha="center", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


# =============================================================================
#  GRAFIK PERBANDINGAN ANTAR TIPE DATA
# =============================================================================

def plot_cross_type_entropy(all_data: dict[str, dict], output_path: str) -> None:
    # Gunakan ukuran 100 KB (index 2)
    size_idx = 2
    data_types = list(all_data.keys())

    fig, ax = plt.subplots(figsize=(10, 6))

    x = range(len(data_types))
    width = 0.15

    # Plaintext, Vigenere, A5/1, Hybrid
    bar_groups = [
        ("Plaintext", "plaintext", "#9E9E9E"),
        ("Vigenere", "vigenere", COLORS_METHOD["vigenere"]),
        ("A5/1", "a51", COLORS_METHOD["a51"]),
        ("Hybrid", "hybrid", COLORS_METHOD["hybrid"]),
    ]

    for j, (label, key, color) in enumerate(bar_groups):
        values = [all_data[dt]["entropy"][key][size_idx] for dt in data_types]
        offset = (j - 1.5) * width
        bars = ax.bar([i + offset for i in x], values, width,
                      label=label, color=color, edgecolor="white", linewidth=0.5)

        # Label nilai
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.2f}",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Tipe Data Input")
    ax.set_ylabel("Shannon Entropy (bit/byte)")
    ax.set_title("Perbandingan Entropy antar Tipe Data (100 KB)")
    ax.set_xticks(x)
    ax.set_xticklabels(data_types)
    ax.legend(loc="lower right", framealpha=0.9)
    ax.axhline(y=8.0, color="red", linestyle=":", linewidth=1, alpha=0.7)

    # Y-axis yang baik untuk menunjukkan perbedaan
    all_vals = []
    for dt in data_types:
        for key in ["plaintext", "vigenere", "a51", "hybrid"]:
            all_vals.append(all_data[dt]["entropy"][key][size_idx])
    ax.set_ylim(min(all_vals) - 0.5, 8.2)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


def plot_cross_type_encryption_time(all_data: dict[str, dict], output_path: str) -> None:
    labels = list(FILE_SIZES.keys())
    data_types = list(all_data.keys())
    x = range(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))

    for j, dt in enumerate(data_types):
        values = all_data[dt]["enc"]["hybrid"]
        offset = (j - 1) * width
        bars = ax.bar([i + offset for i in x], values, width,
                      label=dt, color=list(COLORS_DATATYPE.values())[j],
                      edgecolor="white", linewidth=0.5)

        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(f"{height:.0f}",
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 4), textcoords="offset points",
                            ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("Ukuran Data")
    ax.set_ylabel("Waktu Enkripsi Hybrid (ms)")
    ax.set_title("Waktu Enkripsi Hybrid - Perbandingan antar Tipe Data")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="upper left", framealpha=0.9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


def plot_summary_table(all_data: dict[str, dict], output_path: str) -> None:
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis("off")

    table_data = []
    for dt in all_data:
        data = all_data[dt]
        for i, label in enumerate(data["labels"]):
            row = [
                dt[:12],
                label,
                f"{data['enc']['vigenere'][i]:.2f}",
                f"{data['enc']['a51'][i]:.2f}",
                f"{data['enc']['hybrid'][i]:.2f}",
                f"{data['entropy']['plaintext'][i]:.4f}",
                f"{data['entropy']['hybrid'][i]:.4f}",
                f"{data['entropy']['hybrid'][i] - data['entropy']['plaintext'][i]:+.4f}",
            ]
            table_data.append(row)

    col_labels = [
        "Tipe\nData", "Ukuran", "Enc Vig\n(ms)", "Enc A5/1\n(ms)",
        "Enc Hybrid\n(ms)", "Entropy\nPlaintext", "Entropy\nHybrid", "Delta\nEntropy",
    ]

    table = ax.table(
        cellText=table_data,
        colLabels=col_labels,
        loc="center",
        cellLoc="center",
    )

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1.0, 1.5)

    # Header styling
    for j in range(len(col_labels)):
        cell = table[0, j]
        cell.set_facecolor("#37474F")
        cell.set_text_props(color="white", fontweight="bold")

    # Alternating row colors + group by data type
    type_colors = {
        "Random Binar": "#F3E5F5",  # Light purple
        "English Text": "#FCE4EC",  # Light pink
        "Structured L": "#E0F2F1",  # Light teal
    }
    for i in range(len(table_data)):
        dt_key = table_data[i][0]
        bg_color = type_colors.get(dt_key, "#FFFFFF")
        if i % 2 == 1:
            # Slightly darker for alternating
            bg_color = "#E8E8E8" if bg_color == "#FFFFFF" else bg_color
        for j in range(len(col_labels)):
            table[i + 1, j].set_facecolor(bg_color)

    ax.set_title("Ringkasan Hasil Eksperimen - Semua Tipe Data",
                 fontsize=14, fontweight="bold", pad=20)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"    Disimpan: {output_path}")


# =============================================================================
#  MAIN
# =============================================================================

def main() -> None:
    print("=" * 60)
    print("  VISUALISASI HASIL EKSPERIMEN")
    print("  Hybrid Encryption System (Vigenere + A5/1)")
    print("  3 Tipe Data: Random Binary, English Text, Structured Log")
    print("=" * 60)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n  Output directory: {OUTPUT_DIR}")

    print("\n  [1] Mengumpulkan data eksperimen...")
    all_data = collect_data()

    chart_num = 1

    for data_type in DATA_TYPES:
        data = all_data[data_type]
        type_slug = data_type.lower().replace(" ", "_")

        print(f"\n  Membuat grafik untuk: {data_type}")

        print(f"    [{chart_num}] Waktu Enkripsi...")
        plot_encryption_time(data, data_type,
                             os.path.join(OUTPUT_DIR, f"{chart_num:02d}_{type_slug}_enc_time.png"))
        chart_num += 1

        print(f"    [{chart_num}] Waktu Dekripsi...")
        plot_decryption_time(data, data_type,
                             os.path.join(OUTPUT_DIR, f"{chart_num:02d}_{type_slug}_dec_time.png"))
        chart_num += 1

        print(f"    [{chart_num}] Shannon Entropy...")
        plot_entropy(data, data_type,
                     os.path.join(OUTPUT_DIR, f"{chart_num:02d}_{type_slug}_entropy.png"))
        chart_num += 1

        print(f"    [{chart_num}] Skalabilitas...")
        plot_scalability(data, data_type,
                         os.path.join(OUTPUT_DIR, f"{chart_num:02d}_{type_slug}_scalability.png"))
        chart_num += 1

    # Generate grafik perbandingan antar tipe data
    print(f"\n  Membuat grafik perbandingan antar tipe data...")

    print(f"    [{chart_num}] Cross-type Entropy...")
    plot_cross_type_entropy(all_data,
                            os.path.join(OUTPUT_DIR, f"{chart_num:02d}_cross_type_entropy.png"))
    chart_num += 1

    print(f"    [{chart_num}] Cross-type Encryption Time...")
    plot_cross_type_encryption_time(all_data,
                                    os.path.join(OUTPUT_DIR, f"{chart_num:02d}_cross_type_enc_time.png"))
    chart_num += 1

    print(f"    [{chart_num}] Tabel Ringkasan...")
    plot_summary_table(all_data,
                       os.path.join(OUTPUT_DIR, f"{chart_num:02d}_summary_table.png"))
    chart_num += 1

    total_charts = chart_num - 1
    print("\n" + "=" * 60)
    print(f"  Selesai! {total_charts} grafik telah disimpan ke:")
    print(f"  {OUTPUT_DIR}")
    print("=" * 60)
    print("\n  File yang dihasilkan:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        fpath = os.path.join(OUTPUT_DIR, f)
        size_kb = os.path.getsize(fpath) / 1024
        print(f"    - {f} ({size_kb:.1f} KB)")
    print()


if __name__ == "__main__":
    main()
