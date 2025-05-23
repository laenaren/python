'''
"Write a script that scans a Git repo for hardcoded secrets 
(e.g., AWS keys) and flags them."

Edge cases:
file currupted
no secrets found
'''

import os
import re

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key)?(.{0,20})?['\"]?[0-9a-zA-Z/+]{40}['\"]?",
    "Generic API Key": r"(?i)(api[_-]?key|token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,45}['\"]",
    "Private Key Block": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
}
INCLUDE_EXTENSIONS = {'.py', '.js', '.ts', '.go', '.env', '.yaml', '.yml', '.tf', '.json'}


def is_valid_file(filename):
    return any(filename.endswith(ext) for ext in INCLUDE_EXTENSIONS)

def scan_file(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            for name, pattern in PATTERNS.items():
                if re.search(pattern, line):
                    print(f"[!] Potential {name} in {filepath}:{i} => {line.strip()}")

def scan_repo(root_dir):
    for dirpath, _, filenames in os.walk(root_dir):
        if '.git' in dirpath:
            continue
        for file in filenames:
            full_path = os.path.join(dirpath, file)
            if is_valid_file(full_path):
                scan_file(full_path)

if __name__ == "__main__":
    print("Scanning for hardcoded secrets...")
    scan_repo(".")
    print("Scan complete.")
