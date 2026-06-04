#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


REQUIRED_FIELDS = {"title", "description", "logsource", "detection", "falsepositives", "level"}


def load_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
                if limit and len(rows) >= limit:
                    break
    return rows


def parse_expected(record: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    messages = record["messages"]
    user_payload = json.loads(messages[1]["content"])
    expected = json.loads(messages[2]["content"])
    prompt_messages = messages[:2]
    return prompt_messages, {"user_payload": user_payload, "expected": expected}


def extract_json_object(text: str) -> tuple[dict[str, Any] | None, str]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned), cleaned
    except Exception:
        pass

    start = cleaned.find("{")
    if start == -1:
        return None, cleaned

    depth = 0
    in_string = False
    escape = False
    for index, char in enumerate(cleaned[start:], start=start):
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = cleaned[start : index + 1]
                try:
                    return json.loads(candidate), candidate
                except Exception:
                    return None, cleaned
    return None, cleaned


def flatten_values(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            out.extend(flatten_values(item))
    elif isinstance(value, list):
        for item in value:
            out.extend(flatten_values(item))
    elif isinstance(value, (str, int, float)):
        out.append(str(value))
    return out


def attack_tags(rule: dict[str, Any]) -> set[str]:
    return {str(tag).lower() for tag in rule.get("tags", []) if str(tag).lower().startswith("attack.t")}


def score_prediction(pred: dict[str, Any] | None, expected: dict[str, Any], user_payload: dict[str, Any]) -> dict[str, Any]:
    if pred is None:
        return {
            "valid_json": False,
            "required_fields_complete": False,
            "detection_condition_valid": False,
            "logsource_exact": False,
            "attack_tag_recall": 0.0,
            "ioc_preservation": 0.0,
        }

    required_complete = REQUIRED_FIELDS.issubset(set(pred))
    detection = pred.get("detection")
    detection_condition_valid = isinstance(detection, dict) and bool(detection.get("condition"))
    logsource_exact = pred.get("logsource") == expected.get("logsource")

    expected_tags = attack_tags(expected)
    pred_tags = attack_tags(pred)
    attack_recall = len(expected_tags & pred_tags) / len(expected_tags) if expected_tags else 1.0

    expected_iocs = [str(item.get("value", "")) for item in user_payload.get("ioc_candidates", []) if item.get("value")]
    generated_text = json.dumps(pred, ensure_ascii=False)
    if expected_iocs:
        ioc_preservation = sum(1 for value in expected_iocs if value in generated_text) / len(expected_iocs)
    else:
        ioc_preservation = 1.0

    return {
        "valid_json": True,
        "required_fields_complete": required_complete,
        "detection_condition_valid": detection_condition_valid,
        "logsource_exact": logsource_exact,
        "attack_tag_recall": round(attack_recall, 4),
        "ioc_preservation": round(ioc_preservation, 4),
    }


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = [row["metrics"] for row in results]
    count = len(metrics)
    if count == 0:
        return {}

    bool_fields = ["valid_json", "required_fields_complete", "detection_condition_valid", "logsource_exact"]
    summary = {"sample_count": count}
    for field in bool_fields:
        summary[f"{field}_rate"] = round(sum(1 for m in metrics if m[field]) / count, 4)
    for field in ["attack_tag_recall", "ioc_preservation"]:
        summary[f"avg_{field}"] = round(sum(float(m[field]) for m in metrics) / count, 4)
    return summary


def load_model(model_name_or_path: str, adapter_name_or_path: str | None):
    tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_name_or_path,
        trust_remote_code=True,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
    )
    if adapter_name_or_path:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, adapter_name_or_path)
    model.eval()
    return tokenizer, model


def generate(tokenizer, model, messages: list[dict[str, str]], max_new_tokens: int) -> str:
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated = output_ids[0][inputs["input_ids"].shape[-1] :]
    return tokenizer.decode(generated, skip_special_tokens=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a Sigma generation model on held-out chat JSONL.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--adapter")
    parser.add_argument("--test-jsonl", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--max-new-tokens", type=int, default=512)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = load_jsonl(args.test_jsonl, args.limit)
    tokenizer, model = load_model(args.model, args.adapter)

    results = []
    for index, row in enumerate(rows, start=1):
        messages, parsed = parse_expected(row)
        raw = generate(tokenizer, model, messages, args.max_new_tokens)
        pred, extracted = extract_json_object(raw)
        metrics = score_prediction(pred, parsed["expected"], parsed["user_payload"])
        results.append(
            {
                "index": index,
                "metrics": metrics,
                "expected_title": parsed["expected"].get("title"),
                "prediction_title": pred.get("title") if isinstance(pred, dict) else None,
                "raw_output": raw,
                "extracted_output": extracted,
            }
        )
        print(json.dumps({"index": index, **metrics}, ensure_ascii=False))

    output = {
        "model": args.model,
        "adapter": args.adapter,
        "test_jsonl": str(args.test_jsonl),
        "limit": args.limit,
        "summary": aggregate(results),
        "results": results,
    }
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2))
    print(f"wrote: {args.out_json}")


if __name__ == "__main__":
    main()
