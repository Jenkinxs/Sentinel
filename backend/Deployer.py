import os
from pathlib import Path

import yara_x


def scan(rules_file, scan_directory, logger=None):
    """Scan a directory using a compiled YARA rule from the rules/ directory."""
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    ## Resolve rules directory relative to project root
    base_dir = Path(__file__).resolve().parents[1]
    rules_path = base_dir / "rules"

    with open(rules_path / rules_file, encoding="utf-8") as f:
        rule_uncompiled = f.read()

    rules = yara_x.compile(rule_uncompiled)

    results = {}

    for root, dirs, files in os.walk(scan_directory):
        for filename in files:
            filepath = os.path.join(root, filename)

            try:
                with open(filepath, "rb") as f:
                    data = f.read()

                scanner = yara_x.Scanner(rules)
                matches = scanner.scan(data)

                if matches.matching_rules:
                    results[filepath] = matches.matching_rules

            except Exception as e:
                log(f"Error scanning {filepath}: {e}")

    return results
