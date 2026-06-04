#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from evaluate_ttp_baseline import TfidfRetriever, load_kb, normalize_attack_id
from rag_ttp_mapper import (
    enrich_candidates,
    kb_by_id,
    map_one,
)


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def chunk_text(text: str, max_chars: int, overlap: int) -> list[str]:
    text = collapse_ws(text)
    if len(text) <= max_chars:
        return [text] if text else []

    chunks = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(text):
            break
        start = max(0, end - overlap)
    return chunks


def add_evidence(
    rows: list[dict[str, Any]],
    *,
    source: str,
    section_title: str,
    text: str,
    max_chars: int,
    overlap: int,
    min_chars: int,
) -> None:
    for index, chunk in enumerate(chunk_text(text, max_chars=max_chars, overlap=overlap), start=1):
        if len(chunk) < min_chars:
            continue
        rows.append(
            {
                "source": source,
                "section_title": section_title or "unknown",
                "chunk_index": index,
                "text": chunk,
            }
        )


def extract_evidence(
    report: dict[str, Any],
    *,
    include_ioc_evidence: bool,
    max_chars: int,
    overlap: int,
    min_chars: int,
    max_evidence: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for section in report.get("sections", []):
        add_evidence(
            rows,
            source="section",
            section_title=section.get("section_title", "unknown"),
            text=section.get("text", ""),
            max_chars=max_chars,
            overlap=overlap,
            min_chars=min_chars,
        )

    if include_ioc_evidence:
        for ioc in report.get("iocs", []):
            for evidence in ioc.get("evidence", []):
                add_evidence(
                    rows,
                    source=f"ioc_evidence:{ioc.get('type', 'unknown')}:{ioc.get('normalized_value', ioc.get('value', ''))}",
                    section_title=evidence.get("section_title", ioc.get("section", "unknown")),
                    text=evidence.get("content", ""),
                    max_chars=max_chars,
                    overlap=overlap,
                    min_chars=min_chars,
                )
            if ioc.get("context"):
                add_evidence(
                    rows,
                    source=f"ioc_context:{ioc.get('type', 'unknown')}:{ioc.get('normalized_value', ioc.get('value', ''))}",
                    section_title=ioc.get("section", "unknown"),
                    text=ioc.get("context", ""),
                    max_chars=max_chars,
                    overlap=overlap,
                    min_chars=min_chars,
                )

    threat_context = report.get("threat_context") or {}
    behaviors = threat_context.get("behaviors") or []
    if behaviors:
        add_evidence(
            rows,
            source="threat_context",
            section_title="threat_context",
            text="; ".join(str(item) for item in behaviors),
            max_chars=max_chars,
            overlap=overlap,
            min_chars=1,
        )

    seen = set()
    deduped = []
    for row in rows:
        key = row["text"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    return deduped[:max_evidence] if max_evidence > 0 else deduped


def aggregate_mappings(
    report: dict[str, Any],
    mapping_records: list[dict[str, Any]],
    kb_index: dict[str, dict[str, Any]],
    provider: str,
    top_k: int,
) -> dict[str, Any]:
    by_technique: dict[str, dict[str, Any]] = {}

    for record in mapping_records:
        evidence_row = record.get("evidence_metadata", {})
        for selected in record.get("selected_techniques", []):
            technique_id = normalize_attack_id(selected.get("technique_id", ""))
            if not technique_id:
                continue

            kb_item = kb_index.get(technique_id, {})
            item = by_technique.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": selected.get("name") or kb_item.get("name", ""),
                    "tactics": kb_item.get("tactics", []),
                    "confidence": 0.0,
                    "evidence": [],
                    "reasons": [],
                    "source": f"rag+{provider}",
                },
            )
            item["confidence"] = max(item["confidence"], float(selected.get("confidence", 0.0) or 0.0))
            if selected.get("reason"):
                item["reasons"].append(selected["reason"])
            item["evidence"].append(
                {
                    "source": evidence_row.get("source", "unknown"),
                    "section_title": evidence_row.get("section_title", "unknown"),
                    "chunk_index": evidence_row.get("chunk_index"),
                    "text": selected.get("evidence") or record.get("evidence", ""),
                }
            )

    tactic_counts: dict[str, int] = {}
    for item in by_technique.values():
        item["confidence"] = round(item["confidence"], 4)
        item["reasons"] = sorted(set(item["reasons"]))
        for tactic in item.get("tactics", []):
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    mappings = sorted(by_technique.values(), key=lambda item: item["technique_id"])
    return {
        "schema_version": "attack-mapping-v1",
        "report_id": report.get("report_id"),
        "report_title": report.get("report_title"),
        "source_type": report.get("source_type", "pdf"),
        "provider": provider,
        "top_k": top_k,
        "ttp_mappings": mappings,
        "mapping_summary": {
            "evidence_count": len(mapping_records),
            "technique_count": len(mappings),
            "tactic_counts": dict(sorted(tactic_counts.items())),
            "validation_error_count": sum(1 for record in mapping_records if record.get("validation_errors")),
        },
        "mapping_records": mapping_records,
    }


def map_report(
    report: dict[str, Any],
    *,
    retriever: TfidfRetriever,
    kb_index: dict[str, dict[str, Any]],
    top_k: int,
    provider: str,
    api_base: str,
    api_key: str,
    model: str,
    temperature: float,
    timeout: int,
    max_retries: int,
    retry_sleep: float,
    include_ioc_evidence: bool,
    max_chars: int,
    overlap: int,
    min_chars: int,
    max_evidence: int,
) -> dict[str, Any]:
    evidence_rows = extract_evidence(
        report,
        include_ioc_evidence=include_ioc_evidence,
        max_chars=max_chars,
        overlap=overlap,
        min_chars=min_chars,
        max_evidence=max_evidence,
    )

    mapping_records = []
    total = len(evidence_rows)
    for position, row in enumerate(evidence_rows, start=1):
        mapped = None
        last_error = None
        started = time.time()
        for attempt in range(1, max_retries + 2):
            try:
                mapped = map_one(
                    evidence=row["text"],
                    retriever=retriever,
                    kb_index=kb_index,
                    top_k=top_k,
                    provider=provider,
                    api_base=api_base,
                    api_key=api_key,
                    model=model,
                    temperature=temperature,
                    timeout=timeout,
                )
                break
            except Exception as exc:
                last_error = exc
                print(
                    f"[ERROR] evidence={position}/{total} attempt={attempt}: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                if attempt <= max_retries:
                    time.sleep(retry_sleep)

        if mapped is None:
            mapped = {
                "evidence": row["text"],
                "retrieved_candidates": enrich_candidates(retriever.search(row["text"], top_k=top_k), kb_index),
                "llm_provider": provider,
                "selected_techniques": [],
                "rejected_candidates": [],
                "validation_errors": [
                    f"{type(last_error).__name__}: {last_error}" if last_error else "unknown_error"
                ],
            }

        mapped["evidence_metadata"] = row
        mapped["runtime_seconds"] = round(time.time() - started, 3)
        mapping_records.append(mapped)
        selected = [item["technique_id"] for item in mapped.get("selected_techniques", [])]
        print(f"[OK] evidence={position}/{total} selected={selected} seconds={mapped['runtime_seconds']}")

    return aggregate_mappings(report, mapping_records, kb_index, provider, top_k)


def input_files(input_json: Path | None, input_dir: Path | None) -> list[Path]:
    paths = []
    if input_json:
        paths.append(input_json)
    if input_dir:
        paths.extend(sorted(input_dir.glob("*.iocs.json")))
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Map enriched CTI/IoC JSON reports to ATT&CK JSON using the TTP RAG mapper."
    )
    parser.add_argument("--kb-jsonl", type=Path, required=True)
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--input-dir", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--provider", choices=["prompt-only", "openai-compatible", "ollama"], default="prompt-only")
    parser.add_argument(
        "--api-base",
        default=os.getenv("LLM_API_BASE", os.getenv("OLLAMA_API_BASE", "http://192.168.28.151:11434")),
    )
    parser.add_argument("--api-key", default=os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", ""))
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", os.getenv("OLLAMA_MODEL", "")))
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--retry-sleep", type=float, default=5.0)
    parser.add_argument("--include-ioc-evidence", action="store_true")
    parser.add_argument("--max-chars", type=int, default=1200)
    parser.add_argument("--overlap", type=int, default=150)
    parser.add_argument("--min-chars", type=int, default=80)
    parser.add_argument("--max-evidence", type=int, default=8)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    paths = input_files(args.input_json, args.input_dir)
    if not paths:
        raise SystemExit("Provide --input-json or --input-dir")
    if args.provider == "openai-compatible" and (not args.api_key or not args.model):
        raise SystemExit("--provider openai-compatible requires --api-key/LLM_API_KEY and --model/LLM_MODEL")
    if args.provider == "ollama" and not args.model:
        args.model = "gpt-oss:20b"

    kb = load_kb(args.kb_jsonl)
    retriever = TfidfRetriever(kb)
    index = kb_by_id(kb)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    combined = []
    total_reports = len(paths)
    for report_index, path in enumerate(paths, start=1):
        out_path = args.out_dir / f"{path.stem}.attack.json"
        if args.resume and out_path.exists():
            try:
                existing = json.loads(out_path.read_text(encoding="utf-8"))
                combined.append(
                    {
                        "input": str(path),
                        "output": str(out_path),
                        "report_id": existing.get("report_id"),
                        "report_title": existing.get("report_title"),
                        "mapping_summary": existing.get("mapping_summary", {}),
                        "status": "skipped_existing",
                    }
                )
                print(f"[SKIP] report={report_index}/{total_reports} existing: {out_path}")
                continue
            except Exception:
                pass

        print(f"[REPORT] {report_index}/{total_reports}: {path.name}")
        report = json.loads(path.read_text(encoding="utf-8"))
        mapped = map_report(
            report,
            retriever=retriever,
            kb_index=index,
            top_k=args.top_k,
            provider=args.provider,
            api_base=args.api_base,
            api_key=args.api_key,
            model=args.model,
            temperature=args.temperature,
            timeout=args.timeout,
            max_retries=args.max_retries,
            retry_sleep=args.retry_sleep,
            include_ioc_evidence=args.include_ioc_evidence,
            max_chars=args.max_chars,
            overlap=args.overlap,
            min_chars=args.min_chars,
            max_evidence=args.max_evidence,
        )
        out_path.write_text(json.dumps(mapped, ensure_ascii=False, indent=2), encoding="utf-8")
        combined.append(
            {
                "input": str(path),
                "output": str(out_path),
                "report_id": mapped.get("report_id"),
                "report_title": mapped.get("report_title"),
                "mapping_summary": mapped.get("mapping_summary", {}),
                "status": "mapped",
            }
        )
        print(f"wrote: {out_path}")

    combined_path = args.out_dir / "all_reports_attack_summary.json"
    combined_path.write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote: {combined_path}")


if __name__ == "__main__":
    main()
