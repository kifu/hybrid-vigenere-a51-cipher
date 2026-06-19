# Hybrid Encryption System: Vigenère Cipher + A5/1 Stream Cipher

## Design and Performance Analysis of a Hybrid Encryption System Using a Combination of Vigenère Cipher and A5/1 Stream Cipher in Python

## Overview

This project implements and evaluates a hybrid encryption system that combines the **Vigenère Cipher** (byte-level, mod 256) with the **A5/1 Stream Cipher** (3 LFSRs, 64-bit key, majority clocking). The system is designed for academic experimentation and benchmarking.

### Hybrid Architecture

```
Encryption: Plaintext --> Vigenere Encrypt --> A5/1 Encrypt --> Ciphertext
Decryption: Ciphertext --> A5/1 Decrypt --> Vigenere Decrypt --> Plaintext
```

## Repository Structure

```
hybrid-vigenere-a51-cipher/
|-- cipher_modules.py       # Core: Vigenere (byte-level) & A5/1 implementations
|-- hybrid_system.py        # Hybrid system orchestration layer
|-- experiment_runner.py    # Automated benchmarking & Markdown table output
|-- test_ciphers.py         # 42 unit tests (roundtrip, edge cases, entropy)
|-- visualize_results.py    # Chart generation (15 PNG figures, 300 DPI)
|-- requirements.txt        # Python dependencies
|-- .gitignore              # Excludes dummy_files/, output_charts/, __pycache__/
|-- README.md               # This file
|-- dummy_files/            # (auto-generated) Test data files
`-- output_charts/          # (auto-generated) PNG charts for the paper
```

## Algorithm Specifications

### Vigenere Cipher (Byte-Level)

- Operates on full byte range (0-255), not just A-Z
- Encryption: `C[i] = (P[i] + K[i % len(K)]) mod 256`
- Decryption: `P[i] = (C[i] - K[i % len(K)]) mod 256`
- Supports arbitrary binary data (images, logs, executables)

### A5/1 Stream Cipher

- 3 LFSRs with lengths: **19**, **22**, and **23** bits
- 64-bit secret key initialization
- Majority clocking rule for irregular register stepping
- 100-cycle warm-up phase to eliminate linear correlations
- Output: XOR of MSBs from all three registers

## Experiment Design

### Input Data Types

Three distinct data types are used to evaluate cipher performance:

| Data Type          | Entropy        | Description                                        |
| ------------------ | -------------- | -------------------------------------------------- |
| **Random Binary**  | ~7.99 bit/byte | Pseudo-random data via `os.urandom()` (control)    |
| **English Text**   | ~4.43 bit/byte | Realistic English prose (crypto, science, history) |
| **Structured Log** | ~5.35 bit/byte | Apache/Nginx access logs + application logs        |

### Test Sizes

- 10 KB, 50 KB, 100 KB, 500 KB

### Metrics

- **Execution Time** (ms): Averaged over 3 iterations per measurement
- **Shannon Entropy** (bit/byte): Measures ciphertext randomness (max = 8.0)
- **Decryption Verification**: Roundtrip correctness (encrypt -> decrypt == original)

## Key Results

| Data Type      | Plaintext Entropy | Hybrid Entropy |   Delta   |
| -------------- | :---------------: | :------------: | :-------: |
| English Text   |       4.43        |      7.99      | **+3.56** |
| Structured Log |       5.35        |      7.99      | **+2.65** |
| Random Binary  |       7.99        |      7.99      |   ~0.00   |

- **36/36** experimental scenarios passed decryption verification
- **42/42** unit tests passed
- **15** publication-ready charts generated (300 DPI PNG)

## Quick Start

### Prerequisites

- Python 3.10+
- matplotlib (for visualization only)

### Installation

```bash
git clone https://github.com/kifu/hybrid-vigenere-a51-cipher.git
cd hybrid-vigenere-a51-cipher
pip install -r requirements.txt
```

### Run Unit Tests

```bash
python test_ciphers.py
# Expected: 42/42 tests OK
```

### Run Benchmarks

```bash
python experiment_runner.py
# Outputs: Markdown tables for all 3 data types (36 scenarios)
```

### Generate Charts

```bash
python visualize_results.py
# Outputs: 15 PNG charts in output_charts/ (300 DPI)
```

## Output Charts

The visualization script generates 15 publication-ready figures:

|   #   | Chart               | Description                              |
| :---: | ------------------- | ---------------------------------------- |
| 01-04 | Random Binary       | Enc time, Dec time, Entropy, Scalability |
| 05-08 | English Text        | Enc time, Dec time, Entropy, Scalability |
| 09-12 | Structured Log      | Enc time, Dec time, Entropy, Scalability |
|  13   | Cross-type Entropy  | Entropy comparison across all data types |
|  14   | Cross-type Enc Time | Hybrid encryption time across data types |
|  15   | Summary Table       | Combined results table                   |

## Author

  <table>
    <tbody>
      <tr>
        <td align="center" valign="top" width="14.28%"><a href="https://github.com/kifu"><img src="https://avatars.githubusercontent.com/u/136690241?v=4?s=100" width="100px;" alt="Andi Syaichul Mubaraq"/><br /><sub><b>Andi Syaichul Mubaraq</b></sub><br /><sub><b>18223139</b></sub></a><br /> </td>
      </tr>
    </tbody>
  </table>
</p>
