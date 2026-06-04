#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import requests

from evaluate_ttp_baseline import TfidfRetriever, load_dataset, load_kb, normalize_attack_id


SYSTEM_PROMPT = """You are a cyber threat intelligence analyst.

Your task is to map CTI evidence to MITRE ATT&CK Enterprise techniques.
Use only the candidate techniques provided in the prompt.
Do not invent technique IDs.
Return JSON only.
"""


def compact_description(text: str, max_chars: int = 900) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def kb_by_id(kb: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {normalize_attack_id(item["technique_id"]): item for item in kb}


def enrich_candidates(candidates: list[dict[str, Any]], kb_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = []
    for candidate in candidates:
        technique_id = normalize_attack_id(candidate["technique_id"])
        item = kb_index.get(technique_id, {})
        enriched.append(
            {
                "technique_id": technique_id,
                "name": item.get("name", candidate.get("name", "")),
                "retrieval_score": candidate.get("score", 0.0),
                "tactics": item.get("tactics", candidate.get("tactics", [])),
                "description": compact_description(item.get("description", "")),
                "known_examples": item.get("examples", [])[:3],
                "url": item.get("url", ""),
            }
        )
    return enriched


def build_user_prompt(evidence: str, candidates: list[dict[str, Any]]) -> str:
    payload = {
        "task": "Select the MITRE ATT&CK techniques that are supported by the evidence.",
        "rules": [
            "Choose zero or more techniques from candidate_techniques only.",
            "A technique must be supported by explicit behavior in the evidence.",
            "Do not select a technique only because a keyword appears in the name.",
            "If none of the candidates are supported, return an empty selected_techniques list.",
            "Return JSON only using the requested schema.",
        ],
        "output_schema": {
            "selected_techniques": [
                {
                    "technique_id": "Txxxx or Txxxx.xxx",
                    "name": "Technique name",
                    "confidence": 0.0,
                    "reason": "Short evidence-grounded reason",
                    "evidence": "Exact or paraphrased supporting evidence",
                }
            ],
            "rejected_candidates": [
                {
                    "technique_id": "Txxxx",
                    "reason": "Why this candidate is not supported",
                }
            ],
        },
        "evidence": evidence,
        "candidate_techniques": candidates,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM response does not contain a JSON object")
    return json.loads(text[start : end + 1])


def validate_llm_result(result: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    candidate_ids = {normalize_attack_id(item["technique_id"]) for item in candidates}
    selected = []
    rejected = []
    errors = []

    for item in result.get("selected_techniques", []):
        technique_id = normalize_attack_id(str(item.get("technique_id", "")))
        if technique_id not in candidate_ids:
            errors.append(f"rejected hallucinated technique_id: {technique_id}")
            continue
        selected.append(
            {
                "technique_id": technique_id,
                "name": str(item.get("name", "")),
                "confidence": float(item.get("confidence", 0.0) or 0.0),
                "reason": str(item.get("reason", "")),
                "evidence": str(item.get("evidence", "")),
            }
        )

    for item in result.get("rejected_candidates", []):
        technique_id = normalize_attack_id(str(item.get("technique_id", "")))
        if technique_id in candidate_ids:
            rejected.append(
                {
                    "technique_id": technique_id,
                    "reason": str(item.get("reason", "")),
                }
            )

    return {
        "selected_techniques": selected,
        "rejected_candidates": rejected,
        "validation_errors": errors,
    }


def call_openai_compatible(
    *,
    api_base: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout: int,
) -> dict[str, Any]:
    response = requests.post(
        api_base.rstrip("/"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    content = data["choices"][0]["message"]["content"]
    return extract_json_object(content)


def call_ollama(
    *,
    api_base: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    timeout: int,
) -> dict[str, Any]:
    response = requests.post(
        f"{api_base.rstrip('/')}/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temperature,
            },
        },
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    return extract_json_object(data["message"]["content"])


def map_one(
    *,
    evidence: str,
    retriever: TfidfRetriever,
    kb_index: dict[str, dict[str, Any]],
    top_k: int,
    provider: str,
    api_base: str,
    api_key: str,
    model: str,
    temperature: float,
    timeout: int,
) -> dict[str, Any]:
    retrieved = retriever.search(evidence, top_k=top_k)
    candidates = enrich_candidates(retrieved, kb_index)
    user_prompt = build_user_prompt(evidence, candidates)

    record: dict[str, Any] = {
        "evidence": evidence,
        "retrieved_candidates": candidates,
        "llm_provider": provider,
    }

    if provider == "prompt-only":
        record["system_prompt"] = SYSTEM_PROMPT
        record["user_prompt"] = user_prompt
        record["selected_techniques"] = []
        record["validation_errors"] = ["prompt_only_mode_no_llm_called"]
        return record

    if provider == "openai-compatible":
        raw_result = call_openai_compatible(
            api_base=api_base,
            api_key=api_key,
            model=model,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=temperature,
            timeout=timeout,
        )
        validated = validate_llm_result(raw_result, candidates)
        record["raw_llm_result"] = raw_result
        record.update(validated)
        return record

    if provider == "ollama":
        raw_result = call_ollama(
            api_base=api_base,
            model=model,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=temperature,
            timeout=timeout,
        )
        validated = validate_llm_result(raw_result, candidates)
        record["raw_llm_result"] = raw_result
        record.update(validated)
        return record

    raise ValueError(f"Unsupported provider: {provider}")


def calculate_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = 0
    exact_hit = 0
    family_hit = 0
    selected_count = 0
    gold_count = 0

    for record in records:
        labels = {normalize_attack_id(label) for label in record.get("labels", [])}
        if not labels:
            continue
        selected = {
            normalize_attack_id(item["technique_id"])
            for item in record.get("selected_techniques", [])
        }
        evaluated += 1
        selected_count += len(selected)
        gold_count += len(labels)
        if labels & selected:
            exact_hit += 1

        selected_families = {item.split(".", 1)[0] for item in selected}
        label_families = {item.split(".", 1)[0] for item in labels}
        if label_families & selected_families:
            family_hit += 1

    return {
        "evaluated_samples": evaluated,
        "sample_exact_hit_rate": round(exact_hit / evaluated, 4) if evaluated else None,
        "sample_family_hit_rate": round(family_hit / evaluated, 4) if evaluated else None,
        "avg_selected_per_sample": round(selected_count / evaluated, 4) if evaluated else None,
        "avg_gold_per_sample": round(gold_count / evaluated, 4) if evaluated else None,
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_existing_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        handle.flush()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a RAG-based MITRE ATT&CK TTP mapper with prompt-only or OpenAI-compatible LLM mode."
    )
    parser.add_argument("--kb-jsonl", type=Path, required=True)
    parser.add_argument("--text")
    parser.add_argument("--dataset-tsv", type=Path)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--provider", choices=["prompt-only", "openai-compatible", "ollama"], default="prompt-only")
    parser.add_argument(
        "--api-base",
        default=os.getenv("LLM_API_BASE", os.getenv("OLLAMA_API_BASE", "http://192.168.28.151:11434")),
        help="OpenAI-compatible Chat Completions endpoint or Ollama server base URL.",
    )
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", os.getenv("OLLAMA_MODEL", "")))
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--out-jsonl", type=Path, required=True)
    parser.add_argument("--metrics-out", type=Path)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Append to an existing output JSONL and skip row IDs that already completed.",
    )
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--retry-sleep", type=float, default=5.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.text and not args.dataset_tsv:
        raise SystemExit("Provide --text or --dataset-tsv")
    if args.provider == "openai-compatible" and (not args.api_key or not args.model):
        raise SystemExit("--provider openai-compatible requires --api-key/LLM_API_KEY and --model/LLM_MODEL")
    if args.provider == "ollama" and not args.model:
        args.model = "gpt-oss:20b"

    kb = load_kb(args.kb_jsonl)
    retriever = TfidfRetriever(kb)
    index = kb_by_id(kb)

    inputs = []
    if args.text:
        inputs.append({"row_id": 1, "text": args.text, "labels": set()})
    if args.dataset_tsv:
        inputs.extend(load_dataset(args.dataset_tsv)[: args.limit])

    records = load_existing_records(args.out_jsonl) if args.resume else []
    completed_ids = {record.get("row_id") for record in records}
    if not args.resume and args.out_jsonl.exists():
        args.out_jsonl.unlink()

    total_inputs = len(inputs)
    for position, item in enumerate(inputs, start=1):
        if item["row_id"] in completed_ids:
            print(f"[SKIP] {position}/{total_inputs} row_id={item['row_id']} already exists")
            continue

        mapped = None
        last_error = None
        started = time.time()
        for attempt in range(1, args.max_retries + 2):
            try:
                mapped = map_one(
                    evidence=item["text"],
                    retriever=retriever,
                    kb_index=index,
                    top_k=args.top_k,
                    provider=args.provider,
                    api_base=args.api_base,
                    api_key=args.api_key,
                    model=args.model,
                    temperature=args.temperature,
                    timeout=args.timeout,
                )
                break
            except Exception as exc:
                last_error = exc
                print(
                    f"[ERROR] {position}/{total_inputs} row_id={item['row_id']} "
                    f"attempt={attempt}: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                if attempt <= args.max_retries:
                    time.sleep(args.retry_sleep)

        if mapped is None:
            candidates = enrich_candidates(
                retriever.search(item["text"], top_k=args.top_k),
                index,
            )
            mapped = {
                "evidence": item["text"],
                "retrieved_candidates": candidates,
                "llm_provider": args.provider,
                "selected_techniques": [],
                "rejected_candidates": [],
                "validation_errors": [
                    f"{type(last_error).__name__}: {last_error}"
                    if last_error
                    else "unknown_error"
                ],
            }

        mapped["row_id"] = item["row_id"]
        mapped["labels"] = sorted(item.get("labels", []))
        mapped["runtime_seconds"] = round(time.time() - started, 3)
        records.append(mapped)
        append_jsonl(args.out_jsonl, mapped)
        selected = [entry["technique_id"] for entry in mapped.get("selected_techniques", [])]
        print(
            f"[OK] {position}/{total_inputs} row_id={item['row_id']} "
            f"selected={selected} seconds={mapped['runtime_seconds']}"
        )

    print(f"wrote: {args.out_jsonl}")

    if args.metrics_out:
        metrics = {
            "provider": args.provider,
            "top_k": args.top_k,
            "input_count": len(records),
            "metrics": calculate_metrics(records),
            "note": (
                "Metrics are meaningful only when provider calls an LLM. "
                "prompt-only mode intentionally has no selected techniques."
            ),
        }
        args.metrics_out.parent.mkdir(parents=True, exist_ok=True)
        args.metrics_out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"wrote: {args.metrics_out}")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as exc:
        print(f"HTTP error from LLM endpoint: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text[:2000], file=sys.stderr)
        raise
