#!/usr/bin/env python3
import argparse
import ast
import csv
import json
from pathlib import Path
from typing import Any


def attack_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]).upper()
    return ""


def build_search_document(item: dict[str, Any]) -> str:
    parts = [
        item["technique_id"],
        item["name"],
        item["name"],
        item["name"],
        item.get("description", ""),
        " ".join(item.get("tactics", [])),
        " ".join(item.get("platforms", [])),
        " ".join(item.get("data_sources", [])),
        " ".join(item.get("permissions_required", [])),
        " ".join(item.get("examples", [])),
    ]
    return "\n".join(part for part in parts if part)


def normalize_attack_id(value: str) -> str:
    return value.strip().strip("'\"").upper()


def parse_labels(raw: str) -> set[str]:
    try:
        value = ast.literal_eval(raw)
    except Exception:
        value = [part.strip() for part in raw.split(",")]
    if isinstance(value, str):
        value = [value]
    return {normalize_attack_id(str(item)) for item in value if str(item).strip()}


def load_training_examples(dataset_root: Path | None, examples_per_technique: int) -> dict[str, list[str]]:
    examples: dict[str, list[str]] = {}
    if not dataset_root or examples_per_technique <= 0:
        return examples

    train_files = sorted(dataset_root.glob("datasets/**/*_train.tsv"))
    for path in train_files:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            for row in reader:
                text = " ".join((row.get("text1") or "").split())
                if not text:
                    continue
                for label in parse_labels(row.get("labels", "[]")):
                    bucket = examples.setdefault(label, [])
                    if len(bucket) < examples_per_technique and text not in bucket:
                        bucket.append(text)

    return examples


def build_kb(stix_path: Path, examples_root: Path | None = None, examples_per_technique: int = 0) -> list[dict[str, Any]]:
    examples_by_technique = load_training_examples(examples_root, examples_per_technique)
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    techniques = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = attack_id(obj)
        if not technique_id:
            continue

        item = {
            "technique_id": technique_id,
            "stix_id": obj.get("id", ""),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "permissions_required": obj.get("x_mitre_permissions_required", []),
            "examples": examples_by_technique.get(technique_id, []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "url": "",
        }

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("url"):
                item["url"] = ref["url"]
                break

        item["search_document"] = build_search_document(item)
        techniques.append(item)

    return sorted(techniques, key=lambda item: item["technique_id"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a compact MITRE ATT&CK technique knowledge base from Enterprise ATT&CK STIX JSON."
    )
    parser.add_argument("--stix-json", type=Path, required=True)
    parser.add_argument("--out-jsonl", type=Path, required=True)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument(
        "--examples-root",
        type=Path,
        help="Optional Security-TTP-Mapping dataset root. *_train.tsv examples are added to the search document.",
    )
    parser.add_argument("--examples-per-technique", type=int, default=0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    kb = build_kb(args.stix_json, args.examples_root, args.examples_per_technique)
    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)

    with args.out_jsonl.open("w", encoding="utf-8") as handle:
        for item in kb:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(kb, ensure_ascii=False, indent=2), encoding="utf-8")

    tactic_counts: dict[str, int] = {}
    for item in kb:
        for tactic in item.get("tactics", []):
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    summary = {
        "stix_json": str(args.stix_json),
        "out_jsonl": str(args.out_jsonl),
        "technique_count": len(kb),
        "subtechnique_count": sum(1 for item in kb if item.get("is_subtechnique")),
        "techniques_with_training_examples": sum(1 for item in kb if item.get("examples")),
        "examples_per_technique_limit": args.examples_per_technique,
        "tactic_counts": dict(sorted(tactic_counts.items())),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
