#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from generate_sigma_rules import dump_yaml, generate_rules, slugify


def find_attack_json(ioc_file: Path, attack_dir: Path) -> Path | None:
    candidates = [
        attack_dir / f"{ioc_file.stem}.attack.json",
        attack_dir / f"{ioc_file.stem.removesuffix('.iocs')}.attack.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch generate Sigma rules from IoC JSON and ATT&CK JSON folders.")
    parser.add_argument("--ioc-dir", type=Path, required=True)
    parser.add_argument("--attack-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rules_dir = args.out_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    skipped = []
    ioc_files = sorted(args.ioc_dir.glob("*.iocs.json"))

    for ioc_file in ioc_files:
        attack_file = find_attack_json(ioc_file, args.attack_dir)
        if attack_file is None:
            skipped.append({"ioc_json": str(ioc_file), "reason": "missing attack json"})
            print(f"[SKIP] {ioc_file.name}: missing attack JSON")
            continue

        ioc_json = json.loads(ioc_file.read_text(encoding="utf-8"))
        attack_json = json.loads(attack_file.read_text(encoding="utf-8"))
        rules = generate_rules(ioc_json, attack_json)
        report_id = str(ioc_json.get("report_id") or ioc_file.stem)
        report_entries = []

        for rule in rules:
            filename = f"{slugify(report_id)}.{slugify(rule['id'])}.sigma.yml"
            out_path = rules_dir / filename
            out_path.write_text(dump_yaml(rule) + "\n", encoding="utf-8")
            entry = {
                "path": str(out_path),
                "title": rule["title"],
                "id": rule["id"],
                "level": rule.get("level"),
                "logsource": rule.get("logsource"),
                "tags": rule.get("tags", []),
            }
            manifest.append(
                {
                    "report_id": report_id,
                    "ioc_json": str(ioc_file),
                    "attack_json": str(attack_file),
                    **entry,
                }
            )
            report_entries.append(entry)

        print(f"[OK] {ioc_file.name}: {len(report_entries)} Sigma rules")

    summary = {
        "ioc_dir": str(args.ioc_dir),
        "attack_dir": str(args.attack_dir),
        "rules_dir": str(rules_dir),
        "report_count": len(ioc_files),
        "reports_with_rules": len({item["report_id"] for item in manifest}),
        "rule_count": len(manifest),
        "skipped": skipped,
        "rules": manifest,
    }
    summary_path = args.out_dir / "all_sigma_manifest.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote: {summary_path}")
    print(json.dumps({k: summary[k] for k in ["report_count", "reports_with_rules", "rule_count"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
