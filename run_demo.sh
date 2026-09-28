#!/usr/bin/env bash
# Reproducible end-to-end demo. Run from the repo root:  bash tests/run_demo.sh | tee tests/crypto_demo_output.txt
# The key is created OUTSIDE the repository (in a temp/home directory).
set -u
KEY="${RECORDS_KEY_PATH:-$HOME/.ulk_keys/records.key}"
PY="python3 src/secure_records.py --key-path $KEY"
WORK=$(mktemp -d)
BASE="$WORK/hashes.json"

run() { echo; echo "\$ $*"; eval "$@"; echo "(exit code: $?)"; }

echo "=== 1. Generate key (stored outside repo) ==="
[ -f "$KEY" ] || run "$PY genkey"
echo "=== 2. Encrypt sample student record file ==="
run "$PY encrypt data/sample_students.csv $WORK/students.enc"
run "od -An -tx1 -N32 $WORK/students.enc"
echo "=== 3. Decrypt and verify against original ==="
run "$PY decrypt $WORK/students.enc $WORK/students_decrypted.csv --original data/sample_students.csv"
echo "=== 4. SHA-256 baseline and change detection ==="
cp data/sample_students.csv "$WORK/students_live.csv"
run "$PY hash $WORK/students_live.csv --baseline $BASE"
run "$PY check $WORK/students_live.csv --baseline $BASE"
echo "S999,Intruder,None,1,4.0" >> "$WORK/students_live.csv"
echo "(file modified: one record appended)"
run "$PY check $WORK/students_live.csv --baseline $BASE"
echo "=== 5. Error handling ==="
run "$PY encrypt does_not_exist.csv $WORK/x.enc"
run "python3 src/secure_records.py --key-path /nonexistent.key decrypt $WORK/students.enc $WORK/x.csv"
printf 'garbage' > "$WORK/bad.enc"
run "$PY decrypt $WORK/bad.enc $WORK/x.csv"
: > "$WORK/empty.csv"
run "$PY encrypt $WORK/empty.csv $WORK/x.enc"
rm -rf "$WORK"
