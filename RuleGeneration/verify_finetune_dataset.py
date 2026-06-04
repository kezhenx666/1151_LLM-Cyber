#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


REQUIRED_OUTPUT_FIELDS = {"title", "status", "description", "logsource", "detection", "falsepositives", "level"}


def verify_file(path: Path) -> dict:
    errors = []
    count = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_no}: invalid JSONL record: {exc}")
            continue
        messages = record.get("messages")
        if not isinstance(messages, list) or len(messages) != 3:
            errors.append(f"line {line_no}: messages must contain system/user/assistant")
            continue
        roles = [message.get("role") for message in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"line {line_no}: unexpected roles {roles}")
        try:
            user_payload = json.loads(messages[1].get("content", ""))
        except json.JSONDecodeError:
            errors.append(f"line {line_no}: user content is not JSON")
            user_payload = {}
        try:
            assistant_payload = json.loads(messages[2].get("content", ""))
        except json.JSONDecodeError:
            errors.append(f"line {line_no}: assistant content is not JSON")
            assistant_payload = {}
        missing = REQUIRED_OUTPUT_FIELDS - set(assistant_payload)
        if missing:
            errors.append(f"line {line_no}: assistant output missing {sorted(missing)}")
        if "id" in assistant_payload or "author" in assistant_payload or "date" in assistant_payload:
            errors.append(f"line {line_no}: assistant output should not include id/author/date")
        if not user_payload.get("attack_mappings") and not user_payload.get("ioc_candidates"):
            errors.append(f"line {line_no}: user payload lacks attack mappings and IoC candidates")
    return {
        "path": str(path),
        "records": count,
        "valid": not errors,
        "error_count": len(errors),
        "errors": errors[:50],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify Sigma generation fine-tuning JSONL files.")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    files = sorted(args.data_dir.glob("*.jsonl"))
    results = [verify_file(path) for path in files]
    summary = {
        "data_dir": str(args.data_dir),
        "file_count": len(results),
        "record_count": sum(item["records"] for item in results),
        "valid": all(item["valid"] for item in results),
        "results": results,
    }
    args.out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["file_count", "record_count", "valid"]}, ensure_ascii=False, indent=2))
    print(f"wrote: {args.out_json}")


if __name__ == "__main__":
    main()
