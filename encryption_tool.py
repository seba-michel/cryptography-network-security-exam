from pathlib import Path
import hashlib
import sys

from cryptography.fernet import Fernet, InvalidToken


def generate_key(key_file):
    """Generate and save a new Fernet encryption key."""
    key_path = Path(key_file)

    if key_path.exists():
        print(f"Key already exists: {key_path}")
        return

    key = Fernet.generate_key()
    key_path.write_bytes(key)

    print(f"New encryption key created: {key_path}")


def load_key(key_file):
    """Load an encryption key from a file."""
    key_path = Path(key_file)

    if not key_path.exists():
        raise FileNotFoundError(
            f"Encryption key not found: {key_path}"
        )

    return key_path.read_bytes()


def encrypt_file(input_file, output_file, key_file):
    """Encrypt a file using the supplied Fernet key."""
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    key = load_key(key_file)
    cipher = Fernet(key)

    data = input_path.read_bytes()
    encrypted_data = cipher.encrypt(data)

    output_path.write_bytes(encrypted_data)

    print(f"Encrypted file saved to: {output_path}")


def decrypt_file(input_file, output_file, key_file):
    """Decrypt a file using the supplied Fernet key."""
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: {input_path}"
        )

    key = load_key(key_file)
    cipher = Fernet(key)

    encrypted_data = input_path.read_bytes()

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError(
            "Decryption failed: invalid key or corrupted encrypted file."
        )

    output_path.write_bytes(decrypted_data)

    print(f"Decrypted file saved to: {output_path}")


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            block = file.read(4096)

            if not block:
                break

            sha256.update(block)

    return sha256.hexdigest()


def compare_files(file1, file2):
    """Return True if two files contain exactly the same bytes."""
    path1 = Path(file1)
    path2 = Path(file2)

    if not path1.exists():
        raise FileNotFoundError(f"File not found: {path1}")

    if not path2.exists():
        raise FileNotFoundError(f"File not found: {path2}")

    return path1.read_bytes() == path2.read_bytes()


def print_usage():
    print(
        """
Usage:

  Generate key:
    python encryption_tool.py key KEY_FILE

  Encrypt:
    python encryption_tool.py encrypt INPUT OUTPUT KEY_FILE

  Decrypt:
    python encryption_tool.py decrypt INPUT OUTPUT KEY_FILE

  SHA-256:
    python encryption_tool.py hash FILE

  Compare two files:
    python encryption_tool.py compare ORIGINAL DECRYPTED
"""
    )


def main():
    try:
        if len(sys.argv) < 2:
            print_usage()
            return

        command = sys.argv[1].lower()

        if command == "key":
            if len(sys.argv) != 3:
                print("ERROR: key command requires KEY_FILE.")
                print_usage()
                return

            generate_key(sys.argv[2])

        elif command == "encrypt":
            if len(sys.argv) != 5:
                print("ERROR: encrypt requires INPUT OUTPUT KEY_FILE.")
                print_usage()
                return

            encrypt_file(
                sys.argv[2],
                sys.argv[3],
                sys.argv[4]
            )

        elif command == "decrypt":
            if len(sys.argv) != 5:
                print("ERROR: decrypt requires INPUT OUTPUT KEY_FILE.")
                print_usage()
                return

            decrypt_file(
                sys.argv[2],
                sys.argv[3],
                sys.argv[4]
            )

        elif command == "hash":
            if len(sys.argv) != 3:
                print("ERROR: hash requires FILE.")
                print_usage()
                return

            file_hash = calculate_sha256(sys.argv[2])
            print(f"SHA-256: {file_hash}")

        elif command == "compare":
            if len(sys.argv) != 4:
                print("ERROR: compare requires ORIGINAL DECRYPTED.")
                print_usage()
                return

            if compare_files(sys.argv[2], sys.argv[3]):
                print("PASS: Original and decrypted files match.")
            else:
                print("FAIL: Original and decrypted files do not match.")

        else:
            print(f"ERROR: Unknown command: {command}")
            print_usage()

    except FileNotFoundError as error:
        print(f"ERROR: {error}")

    except ValueError as error:
        print(f"ERROR: {error}")

    except Exception as error:
        print(f"ERROR: {error}")


if __name__ == "__main__":
    main()
