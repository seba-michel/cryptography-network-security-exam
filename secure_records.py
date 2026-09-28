#!/usr/bin/env python3
"""secure_records.py - encryption and integrity toolkit for student record files.

Features
  * AES-256-GCM authenticated encryption / decryption
  * SHA-256 hashing with a baseline file to detect later modification
  * Graceful handling of missing files, bad keys and invalid input

The encryption key is NEVER stored in the repository. By default it lives in
~/.ulk_keys/records.key (override with --key-path or the RECORDS_KEY_PATH env var).
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency. Run: pip install -r requirements.txt")

NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit
MAGIC = b"ULK1"  # file header so we can recognise our own format
DEFAULT_KEY_PATH = Path(os.environ.get("RECORDS_KEY_PATH", Path.home() / ".ulk_keys" / "records.key"))
DEFAULT_BASELINE = Path("hashes.json")


class ToolkitError(Exception):
    """Expected, user-facing error (bad path, bad key, tampered file...)."""


# ---------- helpers ----------
def read_file(path):
    p = Path(path)
    if not p.exists():
        raise ToolkitError(f"File not found: {p}")
    if not p.is_file():
        raise ToolkitError(f"Not a regular file: {p}")
    try:
        return p.read_bytes()
    except PermissionError:
        raise ToolkitError(f"Permission denied reading: {p}")
    except OSError as exc:
        raise ToolkitError(f"Cannot read {p}: {exc}")


def write_file(path, data):
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    except PermissionError:
        raise ToolkitError(f"Permission denied writing: {p}")
    except OSError as exc:
        raise ToolkitError(f"Cannot write {p}: {exc}")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    p = Path(path)
    if not p.exists():
        raise ToolkitError(f"File not found: {p}")
    if not p.is_file():
        raise ToolkitError(f"Not a regular file: {p}")
    try:
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError as exc:
        raise ToolkitError(f"Cannot read {p}: {exc}")
    return h.hexdigest()


# ---------- key management ----------
def generate_key(key_path, force=False):
    key_path = Path(key_path)
    if key_path.exists() and not force:
        raise ToolkitError(f"Key already exists at {key_path} (use --force to overwrite; old data becomes unreadable).")
    key = AESGCM.generate_key(bit_length=256)
    write_file(key_path, key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key_path


def load_key(key_path):
    key = read_file(key_path)
    if len(key) != KEY_SIZE:
        raise ToolkitError(f"Invalid key in {key_path}: expected {KEY_SIZE} bytes, got {len(key)}.")
    return key


def refuse_key_inside_repo(key_path):
    """Safety check: the key must not sit inside a git repository."""
    p = Path(key_path).resolve()
    for parent in [p.parent, *p.parents]:
        if (parent / ".git").exists():
            raise ToolkitError(f"Key path {p} is inside a git repository. Keep the key outside the repo.")


# ---------- encryption ----------
def encrypt_file(src, dst, key_path):
    data = read_file(src)
    if not data:
        raise ToolkitError(f"Input file is empty: {src}")
    key = load_key(key_path)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
    write_file(dst, MAGIC + nonce + ciphertext)
    return sha256_bytes(data)


def decrypt_file(src, dst, key_path):
    blob = read_file(src)
    if len(blob) < len(MAGIC) + NONCE_SIZE + 16 or not blob.startswith(MAGIC):
        raise ToolkitError(f"{src} is not a valid encrypted file (wrong format or truncated).")
    key = load_key(key_path)
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    ciphertext = blob[len(MAGIC) + NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag:
        raise ToolkitError("Decryption failed: wrong key or the file has been tampered with.")
    write_file(dst, plaintext)
    return sha256_bytes(plaintext)


def verify_roundtrip(original, decrypted):
    h1, h2 = sha256_file(original), sha256_file(decrypted)
    return h1 == h2, h1, h2


# ---------- integrity baseline ----------
def load_baseline(path):
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise ToolkitError(f"Baseline file {p} is unreadable or corrupt: {exc}")


def record_hash(file, baseline_path):
    digest = sha256_file(file)
    baseline = load_baseline(baseline_path)
    baseline[str(Path(file))] = digest
    write_file(baseline_path, (json.dumps(baseline, indent=2) + "\n").encode())
    return digest


def check_hash(file, baseline_path):
    baseline = load_baseline(baseline_path)
    key = str(Path(file))
    if key not in baseline:
        raise ToolkitError(f"No baseline hash recorded for {file}. Run the 'hash' command first.")
    current = sha256_file(file)
    return current == baseline[key], baseline[key], current


# ---------- CLI ----------
def build_parser():
    p = argparse.ArgumentParser(description="Encrypt, decrypt and integrity-check student record files.")
    p.add_argument("--key-path", default=str(DEFAULT_KEY_PATH), help="location of the AES key (outside the repo)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkey", help="generate a new 256-bit key")
    g.add_argument("--force", action="store_true")

    e = sub.add_parser("encrypt", help="encrypt a file")
    e.add_argument("input")
    e.add_argument("output")

    d = sub.add_parser("decrypt", help="decrypt a file, optionally verify against the original")
    d.add_argument("input")
    d.add_argument("output")
    d.add_argument("--original", help="original file to compare against (SHA-256)")

    h = sub.add_parser("hash", help="compute SHA-256 and store it in the baseline file")
    h.add_argument("file")
    h.add_argument("--baseline", default=str(DEFAULT_BASELINE))

    c = sub.add_parser("check", help="detect whether a file changed since its baseline hash")
    c.add_argument("file")
    c.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    return p


def run(args):
    if args.cmd == "genkey":
        refuse_key_inside_repo(args.key_path)
        path = generate_key(args.key_path, args.force)
        print(f"[OK] Key created at {path} (keep it secret, never commit it).")
    elif args.cmd == "encrypt":
        refuse_key_inside_repo(args.key_path)
        digest = encrypt_file(args.input, args.output, args.key_path)
        print(f"[OK] Encrypted {args.input} -> {args.output}\n     Plaintext SHA-256: {digest}")
    elif args.cmd == "decrypt":
        refuse_key_inside_repo(args.key_path)
        digest = decrypt_file(args.input, args.output, args.key_path)
        print(f"[OK] Decrypted {args.input} -> {args.output}\n     Plaintext SHA-256: {digest}")
        if args.original:
            same, h1, h2 = verify_roundtrip(args.original, args.output)
            print(f"     Original  SHA-256: {h1}")
            if same:
                print("[OK] MATCH: decrypted file is identical to the original.")
                return 0
            print("[FAIL] MISMATCH: decrypted file differs from the original!")
            return 2
    elif args.cmd == "hash":
        digest = record_hash(args.file, args.baseline)
        print(f"[OK] SHA-256({args.file}) = {digest}\n     Stored in {args.baseline}")
    elif args.cmd == "check":
        same, expected, current = check_hash(args.file, args.baseline)
        print(f"     Expected: {expected}\n     Current : {current}")
        if same:
            print("[OK] UNCHANGED: file integrity verified.")
            return 0
        print("[ALERT] MODIFIED: file has changed since the baseline was recorded!")
        return 2
    return 0


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        return run(args)
    except ToolkitError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[ERROR] Interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # last-resort guard: never show a raw traceback
        print(f"[ERROR] Unexpected problem: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
