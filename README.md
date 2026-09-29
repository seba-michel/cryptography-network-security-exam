# cryptography-network-security-exam

ETTCS801 – Cryptography and Network Security · ULK Polytechnic Institute · Integrated Situation

A small security toolkit for a polytechnic's student-records scenario:
risk assessment, an AES-256-GCM + SHA-256 Python tool, laboratory firewall rules, and a LaTeX report.

> **Author:** `<ERIC UWITONZE + 4202670055>`  ·  **Repository:** `<YOUR GITHUB URL>`

## Project structure

```
cryptography-network-security-exam/
├── README.md                    <- this file
├── risk_assessment.md           <- Task 1: assets, vulnerabilities, ranking, controls
├── requirements.txt             <- Python dependency (cryptography)
├── .gitignore                   <- blocks *.key, *.pem etc. from being committed
├── src/secure_records.py        <- Task 2: encrypt / decrypt / SHA-256 integrity tool
├── data/sample_students.csv     <- FAKE sample records (no real student data)
├── firewall/
│   └── records_server_firewall.sh  <- Task 3: iptables rules (apply / remove / show)
├── filter_tests.md              <- Task 3d: commands, expected and actual results
├── tests/
│   ├── test_secure_records.py   <- automated unit tests
│   ├── run_demo.sh              <- reproducible end-to-end demo
│   └── crypto_demo_output.txt   <- recorded output of run_demo.sh
└── report/
    ├── report.tex               <- Task 5: LaTeX source
    └── report.pdf               <- compiled report
```

## 1. Installation

Requires Python 3.9+.

```bash
git clone <YOUR GITHUB URL>
cd cryptography-network-security-exam
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Running the encryption / integrity programme

The **key is stored outside the repository** (default `~/.ulk_keys/records.key`; override with `--key-path` or the
`RECORDS_KEY_PATH` environment variable). The tool refuses to create or use a key inside a git repository, and `.gitignore` blocks `*.key`.

```bash
# 1. create a 256-bit key (once)
python3 src/secure_records.py genkey

# 2. encrypt the sample file
python3 src/secure_records.py encrypt data/sample_students.csv students.enc

# 3. decrypt and verify it matches the original (SHA-256 comparison)
python3 src/secure_records.py decrypt students.enc students_decrypted.csv --original data/sample_students.csv

# 4. record a SHA-256 baseline, then detect later changes
python3 src/secure_records.py hash  data/sample_students.csv --baseline hashes.json
python3 src/secure_records.py check data/sample_students.csv --baseline hashes.json
```

Exit codes: `0` success/unchanged · `1` handled error (missing file, bad key, tampered data…) · `2` mismatch/modified file detected.
The program prints clear `[ERROR]` messages and never a raw Python traceback.

**Design notes:** AES-256-GCM is *authenticated* encryption (confidentiality + tamper detection); each file gets a fresh random
96-bit nonce; the file header is bound as associated data. SHA-256 baselines detect changes to files that are not encrypted.

## 3. Reproducing the tests

```bash
# unit tests (10 tests: round trip, tamper, wrong key, missing/empty/invalid files ...)
python3 -m unittest discover -s tests -v

# full demonstration; output is saved as evidence
bash tests/run_demo.sh | tee tests/crypto_demo_output.txt
```

## 4. Firewall (authorised laboratory only)

1. Edit the variables at the top of `firewall/records_server_firewall.sh` (`SERVER_IP`, `GUEST_NET`, `STAFF_NET`, `SERVICE_PORT`, `MODE`).
2. Preview: `./firewall/records_server_firewall.sh apply --dry-run`
3. Apply: `sudo ./firewall/records_server_firewall.sh apply` · Inspect: `... show` · Roll back: `sudo ... remove`
4. Run the three connection tests and record the results in `filter_tests.md`.

Rule logic (in order): keep established sessions → **drop all guest traffic** to the server → **allow staff network to the named service** → **drop every other inbound attempt to that service**.

## 5. LaTeX report

```bash
cd report && pdflatex report.tex && pdflatex report.tex
```

## Security notes
No passwords, keys or real student records are stored in this repository; all data in `data/` is fictitious.
