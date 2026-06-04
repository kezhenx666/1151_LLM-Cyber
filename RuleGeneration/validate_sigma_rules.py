#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "falsepositives",
    "level",
}


def top_level_keys(text: str) -> set[str]:
    keys = set()
    for line in text.splitlines():
        if not line.strip() or line.startswith((" ", "-")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+):", line)
        if match:
            keys.add(match.group(1))
    return keys


def has_nested_key(text: str, parent: str, child: str) -> bool:
    lines = text.splitlines()
    in_parent = False
    parent_indent = 0
    for line in lines:
        if re.match(rf"^{re.escape(parent)}:\s*$", line):
            in_parent = True
            parent_indent = len(line) - len(line.lstrip(" "))
            continue
        if in_parent:
            indent = len(line) - len(line.lstrip(" "))
            if line.strip() and indent <= parent_indent:
                return False
            if re.match(rf"^\s+{re.escape(child)}:", line):
                return True
    return False


def validate_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    keys = top_level_keys(text)
    errors = []
    warnings = []

    missing = sorted(REQUIRED_TOP_LEVEL - keys)
    for key in missing:
        errors.append(f"missing top-level field: {key}")

    if "detection" in keys and not has_nested_key(text, "detection", "condition"):
        errors.append("missing detection.condition")

    if "logsource" in keys and not (
        has_nested_key(text, "logsource", "category")
        or has_nested_key(text, "logsource", "product")
        or has_nested_key(text, "logsource", "service")
    ):
        errors.append("logsource should contain at least category, product, or service")

    rule_id_line = next((line for line in text.splitlines() if line.startswith("id:")), "")
    if rule_id_line and not re.search(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        rule_id_line,
    ):
        warnings.append("id does not look like a UUID")

    if "tags" not in keys:
        warnings.append("no ATT&CK tags present")

    return {
        "path": str(path),
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "top_level_keys": sorted(keys),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate generated Sigma YAML rules with basic schema checks.")
    parser.add_argument("--rules-dir", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rules = sorted(args.rules_dir.glob("*.yml")) + sorted(args.rules_dir.glob("*.yaml"))
    results = [validate_file(path) for path in rules]
    summary = {
        "rules_dir": str(args.rules_dir),
        "rule_count": len(results),
        "valid_count": sum(1 for item in results if item["valid"]),
        "invalid_count": sum(1 for item in results if not item["valid"]),
        "results": results,
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["rule_count", "valid_count", "invalid_count"]}, ensure_ascii=False, indent=2))
    print(f"wrote: {args.out_json}")


if __name__ == "__main__":
    main()
