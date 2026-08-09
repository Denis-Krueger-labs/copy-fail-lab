#!/usr/bin/env python3

import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path


BASELINE_FILE = Path("/etc/copyfail-detector/suid-known-good.tsv")
CHECK_INTERVAL_SECONDS = 0.25


CAT_OK = r"""
 /\_/\
( •.• )   MORI: privileged binaries look normal.
 > ^ <
"""

CAT_ALERT = r"""
 /\_/\
( Ò.Ó )   MORI: INTEGRITY VIOLATION.
 > ^ <
"""

CAT_RECOVERED = r"""
 /\_/\
( -.- )   MORI: fine. the file is normal again.
 > ^ <
"""


def timestamp():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file_handle:
        while chunk := file_handle.read(65536):
            sha256.update(chunk)

    return sha256.hexdigest()


def load_baseline():
    """Load expected hashes from the protected TSV baseline."""
    protected_files = {}

    with BASELINE_FILE.open("r", encoding="utf-8") as baseline:
        for line in baseline:
            line = line.strip()

            if not line or line.startswith("sha256"):
                continue

            expected_hash, file_path = line.split(maxsplit=1)
            protected_files[file_path] = expected_hash

    return protected_files


def main():
    protected_files = load_baseline()

    print(CAT_OK)
    print(f"[{timestamp()}] Watching {len(protected_files)} privileged files")
    print(f"[{timestamp()}] Baseline: {BASELINE_FILE}")
    print(f"[{timestamp()}] Check interval: {CHECK_INTERVAL_SECONDS} seconds")
    print()

    files_in_alert_state = set()

    while True:
        for file_path, expected_hash in protected_files.items():

            try:
                current_hash = calculate_sha256(file_path)

            except (FileNotFoundError, PermissionError) as error:
                print(CAT_ALERT)
                print(f"[{timestamp()}] ERROR")
                print(f"path={file_path}")
                print(f"reason={error}")
                print()
                continue

            if current_hash != expected_hash:

                if file_path not in files_in_alert_state:
                    print(CAT_ALERT)
                    print(f"[{timestamp()}] ALERT")
                    print(f"path={file_path}")
                    print(f"expected={expected_hash}")
                    print(f"observed={current_hash}")
                    print()

                    files_in_alert_state.add(file_path)

            elif file_path in files_in_alert_state:

                print(CAT_RECOVERED)
                print(f"[{timestamp()}] RECOVERED")
                print(f"path={file_path}")
                print(f"observed={current_hash}")
                print()

                files_in_alert_state.remove(file_path)

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
