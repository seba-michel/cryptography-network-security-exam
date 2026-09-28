"""Automated tests. Run from the repo root:  python -m unittest discover -s tests -v"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import secure_records as sr  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_students.csv"


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())          # outside the repo -> key is never in git
        self.key = self.tmp / "test.key"
        self.enc = self.tmp / "records.enc"
        self.dec = self.tmp / "records.dec"
        self.base = self.tmp / "hashes.json"
        sr.generate_key(self.key)

    def test_encrypt_output_differs_from_plaintext(self):
        sr.encrypt_file(SAMPLE, self.enc, self.key)
        self.assertTrue(self.enc.exists())
        self.assertNotIn(b"Alice", self.enc.read_bytes())

    def test_roundtrip_matches_original(self):
        sr.encrypt_file(SAMPLE, self.enc, self.key)
        sr.decrypt_file(self.enc, self.dec, self.key)
        same, _, _ = sr.verify_roundtrip(SAMPLE, self.dec)
        self.assertTrue(same)

    def test_hash_detects_modification(self):
        work = self.tmp / "work.csv"
        work.write_bytes(SAMPLE.read_bytes())
        sr.record_hash(work, self.base)
        self.assertTrue(sr.check_hash(work, self.base)[0])
        work.write_text(work.read_text() + "S999,Intruder,None,1,4.0\n")
        self.assertFalse(sr.check_hash(work, self.base)[0])

    def test_missing_input_file(self):
        with self.assertRaises(sr.ToolkitError):
            sr.encrypt_file(self.tmp / "nope.csv", self.enc, self.key)

    def test_missing_key(self):
        with self.assertRaises(sr.ToolkitError):
            sr.encrypt_file(SAMPLE, self.enc, self.tmp / "absent.key")

    def test_wrong_key_rejected(self):
        sr.encrypt_file(SAMPLE, self.enc, self.key)
        other = self.tmp / "other.key"
        sr.generate_key(other)
        with self.assertRaises(sr.ToolkitError):
            sr.decrypt_file(self.enc, self.dec, other)

    def test_tampered_ciphertext_rejected(self):
        sr.encrypt_file(SAMPLE, self.enc, self.key)
        blob = bytearray(self.enc.read_bytes())
        blob[-1] ^= 0x01
        self.enc.write_bytes(bytes(blob))
        with self.assertRaises(sr.ToolkitError):
            sr.decrypt_file(self.enc, self.dec, self.key)

    def test_invalid_encrypted_file(self):
        junk = self.tmp / "junk.enc"
        junk.write_bytes(b"not encrypted")
        with self.assertRaises(sr.ToolkitError):
            sr.decrypt_file(junk, self.dec, self.key)

    def test_empty_file_and_directory(self):
        empty = self.tmp / "empty.csv"
        empty.write_bytes(b"")
        with self.assertRaises(sr.ToolkitError):
            sr.encrypt_file(empty, self.enc, self.key)
        with self.assertRaises(sr.ToolkitError):
            sr.encrypt_file(self.tmp, self.enc, self.key)

    def test_cli_returns_error_code_not_traceback(self):
        self.assertEqual(sr.main(["--key-path", str(self.key), "encrypt", "missing.csv", str(self.enc)]), 1)


if __name__ == "__main__":
    unittest.main()
