#!/usr/bin/env python3
import argparse
import json
import random
import re
from pathlib import Path
from typing import Any

import yaml


SYSTEM_MESSAGE = (
    "You generate Sigma rule drafts from CTI-derived IoC and ATT&CK context. "
    "Output JSON only. Do not invent IoCs or ATT&CK technique IDs. "
    "The post-processing validator will add rule id, author, and date."
)


REQUIRED_SIGMA_FIELDS = {"title", "description", "logsource", "detection", "falsepositives", "level"}


def compact(value: Any, max_chars: int = 1200) -> Any:
    if isinstance(value, str):
        text = re.sub(r"\s+", " ", value).strip()
        return text[: max_chars - 3].rstrip() + "..." if len(text) > max_chars else text
    return value


def attack_mappings(tags: list[str]) -> list[dict[str, Any]]:
    tactic_tags = [tag for tag in tags if tag.startswith("attack.") and not re.match(r"attack\.t\d", tag)]
    technique_tags = [tag for tag in tags if re.match(r"attack\.t\d", tag)]
    tactics = [tag.removeprefix("attack.") for tag in tactic_tags]
    return [
        {
            "technique_id": tag.removeprefix("attack.").upper(),
            "technique_name": "",
            "tactics": tactics,
            "confidence": 1.0,
        }
        for tag in technique_tags
    ]


def collect_leaf_values(value: Any, out: list[str]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            collect_leaf_values(item, out)
    elif isinstance(value, list):
        for item in value:
            collect_leaf_values(item, out)
    elif isinstance(value, (str, int, float)):
        text = str(value).strip()
        if text and len(text) <= 240 and not text.lower().startswith("selection"):
            out.append(text)


def indicator_candidates(rule: dict[str, Any]) -> list[dict[str, str]]:
    values: list[str] = []
    collect_leaf_values(rule.get("detection", {}), values)
    candidates = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        if re.fullmatch(r"[a-fA-F0-9]{32}", value):
            typ = "md5"
        elif re.fullmatch(r"[a-fA-F0-9]{40}", value):
            typ = "sha1"
        elif re.fullmatch(r"[a-fA-F0-9]{64}", value):
            typ = "sha256"
        elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
            typ = "ipv4"
        elif "." in value and "/" not in value and " " not in value:
            typ = "domain_or_path"
        elif "/" in value or "\\" in value:
            typ = "path_or_url"
        else:
            typ = "string"
        candidates.append({"type": typ, "value": value})
        if len(candidates) >= 25:
            break
    return candidates


def canonical_output(rule: dict[str, Any]) -> dict[str, Any]:
    output = {
        "title": compact(rule.get("title", "")),
        "status": rule.get("status", "experimental"),
        "description": compact(rule.get("description", "")),
        "logsource": rule.get("logsource", {}),
        "detection": rule.get("detection", {}),
        "falsepositives": rule.get("falsepositives", ["Unknown"]),
        "level": rule.get("level", "medium"),
    }
    tags = rule.get("tags") or []
    if tags:
        output["tags"] = tags
    fields = rule.get("fields") or []
    if fields:
        output["fields"] = fields
    return output


def build_user_payload(rule: dict[str, Any], path: Path) -> dict[str, Any]:
    tags = rule.get("tags") or []
    return {
        "task": "Generate a Sigma rule draft from this CTI detection context.",
        "source_rule_path": str(path),
        "report_context": {
            "title": compact(rule.get("title", "")),
            "description": compact(rule.get("description", "")),
            "references": rule.get("references", [])[:5],
        },
        "ioc_candidates": indicator_candidates(rule),
        "attack_mappings": attack_mappings(tags),
        "logsource_hint": rule.get("logsource", {}),
        "required_output": {
            "format": "json",
            "fields": [
                "title",
                "status",
                "description",
                "logsource",
                "detection",
                "falsepositives",
                "level",
                "tags",
                "fields",
            ],
            "do_not_generate": ["id", "author", "date"],
        },
    }


def load_rule(path: Path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not REQUIRED_SIGMA_FIELDS.issubset(set(data)):
        return None
    if not isinstance(data.get("detection"), dict) or "condition" not in data["detection"]:
        return None
    return data


def make_chat_record(rule: dict[str, Any], path: Path) -> dict[str, Any]:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": json.dumps(build_user_payload(rule, path), ensure_ascii=False)},
            {"role": "assistant", "content": json.dumps(canonical_output(rule), ensure_ascii=False)},
        ],
        "metadata": {
            "source": "SigmaHQ",
            "source_path": str(path),
            "title": rule.get("title", ""),
            "tags": rule.get("tags", []),
            "logsource": rule.get("logsource", {}),
        },
    }


def split_records(records: list[dict[str, Any]], seed: int, train_ratio: float, val_ratio: float) -> dict[str, list[dict[str, Any]]]:
    rng = random.Random(seed)
    shuffled = records[:]
    rng.shuffle(shuffled)
    train_end = int(len(shuffled) * train_ratio)
    val_end = train_end + int(len(shuffled) * val_ratio)
    return {
        "train": shuffled[:train_end],
        "validation": shuffled[train_end:val_end],
        "test": shuffled[val_end:],
    }


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a chat fine-tuning dataset for Sigma rule generation.")
    parser.add_argument("--sigma-rules-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, default=48)
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(args.sigma_rules_dir.rglob("*.yml")) + sorted(args.sigma_rules_dir.rglob("*.yaml")):
        rule = load_rule(path)
        if rule is None:
            continue
        records.append(make_chat_record(rule, path))
        if args.limit and len(records) >= args.limit:
            break

    splits = split_records(records, args.seed, args.train_ratio, args.val_ratio)
    for name, split in splits.items():
        write_jsonl(args.out_dir / f"sigma_generation_{name}.jsonl", split)

    summary = {
        "source_dir": str(args.sigma_rules_dir),
        "record_count": len(records),
        "splits": {name: len(split) for name, split in splits.items()},
        "format": "chat_messages_jsonl",
        "target": "sigma_rule_draft_json",
        "notes": [
            "Assistant output intentionally excludes id, author, and date.",
            "Post-processing should add deterministic metadata and run Sigma validation.",
        ],
    }
    (args.out_dir / "dataset_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
