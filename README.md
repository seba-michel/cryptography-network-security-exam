# Cryptography and Network Security — Integrated Situation

## 1. Project Overview

This project was completed for the Cryptography and Network Security module.

The project addresses the security situation involving student records stored on a central server and file transfers between two campuses.

The project demonstrates:

- Risk assessment
- File encryption
- File decryption
- SHA-256 integrity verification
- Error handling
- Network traffic filtering
- Firewall testing
- Technical documentation using LaTeX

## 2. Project Structure

```text
cryptography-network-security-exam/
│
├── README.md
├── risk_assessment.md
├── encryption_tool.py
├── sample_student_records.txt
├── filter_tests.md
├── .gitignore
│
├── firewall/
│   └── firewall_rules.sh
│
└── report/
    ├── report.tex
    └── report.pdf
```

## 3. Requirements

Python 3 is required.

Install the required Python package:

```bash
pip install cryptography
```

## 4. Encryption Key

The encryption key must be kept outside this repository.

Example:

```bash
python encryption_tool.py key ../student_key.key
```

Do not upload the key to GitHub.

## 5. Generate an Encryption Key

```bash
python encryption_tool.py key ../student_key.key
```

## 6. Encrypt the Sample Student Record

```bash
python encryption_tool.py encrypt sample_student_records.txt encrypted.bin ../student_key.key
```

Expected result:

```text
Encrypted file saved to: encrypted.bin
```

## 7. Decrypt the Encrypted File

```bash
python encryption_tool.py decrypt encrypted.bin decrypted.txt ../student_key.key
```

Expected result:

```text
Decrypted file saved to: decrypted.txt
```

## 8. Verify Original and Decrypted Files

On Windows CMD:

```cmd
fc /b sample_student_records.txt decrypted.txt
```

On Linux:

```bash
cmp sample_student_records.txt decrypted.txt
```

The original and decrypted files should contain exactly the same data.

## 9. Calculate SHA-256

```bash
python encryption_tool.py hash sample_student_records.txt
```

Record the actual SHA-256 value in your test evidence.

After modifying the file, calculate the hash again. If the value changes, the modification has been detected.

## 10. Error Handling Tests

Test a missing file:

```bash
python encryption_tool.py encrypt missing.txt encrypted.bin ../student_key.key
```

The program should display an error without crashing.

Test invalid command/arguments:

```bash
python encryption_tool.py
```

The program should display usage instructions.

## 11. Firewall

The firewall configuration is stored in:

```text
firewall/firewall_rules.sh
```

IMPORTANT: Replace the placeholders in that file with the actual server IP, guest subnet, staff subnet and service port supplied by the assessor.

Firewall testing must be performed only in the authorized laboratory environment.

## 12. Firewall Test Evidence

The firewall tests are documented in:

```text
filter_tests.md
```

The final version must contain the actual commands and actual outputs obtained during the laboratory tests.

## 13. Technical Report

The LaTeX source is:

```text
report/report.tex
```

The compiled report should be:

```text
report/report.pdf
```

## 14. Security Notice

This repository must not contain:

- Encryption keys
- Passwords
- Real student records
- Other confidential information

Only the supplied sample data and authorized laboratory information should be used.

## 15. Reproducibility

Another user should be able to reproduce the Python encryption and integrity tests by:

1. Installing Python.
2. Installing the `cryptography` package.
3. Obtaining the encryption key securely outside the repository.
4. Running the commands in this README.
5. Performing the authorized firewall tests using the assessor-provided network values.

## 16. GitHub Repository

Repository:

`https://github.com/seba michel/cryptography-network-security-exam`
