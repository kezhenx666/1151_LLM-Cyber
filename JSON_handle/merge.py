#!/usr/bin/env python3
"""
Batch merge IoC JSON files and PDF parser JSON files.

Input:
  --ioc-dir      Folder containing IoC extractor JSON files.
  --parser-dir   Folder containing PDF parser/layout JSON files.
  --out-dir      Folder to save merged JSON files.

Matching rule:
  - Match files by filename stem.
  - Example:
      yoooo/report_001.json
      openpdf/report_001.json
      => merged/report_001.json

Output:
  - One merged JSON per matched pair.
  - Filename keeps the original IoC JSON filename.
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any


IP_PORT_REGEX = re.compile(
    r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s*[:：]\s*(?P<port>\d{1,5})\b"
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def dump_json(data: dict[str, Any], path: Path) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def refang(text: str) -> str:
    replacements = [
        (r"hxxps\s*[:：]\s*/\s*/", "https://"),
        (r"hxxp\s*[:：]\s*/\s*/", "http://"),
        (r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}", "."),
        (r"\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+", "."),
        (r"\[\s*:\s*\]|\(\s*:\s*\)", ":"),
        (r"\[\s*at\s*\]|\(\s*at\s*\)", "@"),
    ]

    out = text or ""
    for pattern, repl in replacements:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)

    return out


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", refang(text or "")).strip()


def flatten_parser_elements(parser_json: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Flatten parser JSON elements.

    It handles:
      - kids
      - list items
      - nested kids inside list items
    """
    out: list[dict[str, Any]] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            out.append(item)

            for key in ("kids", "list items"):
                children = item.get(key, []) or []
                for child in children:
                    walk(child)

        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(parser_json.get("kids", []))
    return out


def build_sections(elements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Build sections using heading + following text blocks.

    Example:
      heading: Appendix IOC
      paragraph: hash hash hash ip:port

    Becomes:
      {
        "section_title": "Appendix IOC",
        "text": "hash hash hash ip:port"
      }
    """
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for el in elements:
        typ = el.get("type")
        content = normalize_text(el.get("content", ""))

        if not content:
            continue

        if typ == "heading":
            if current and current.get("texts"):
                sections.append({
                    "section_title": current["section_title"],
                    "text": " ".join(current["texts"]),
                })

            current = {
                "section_title": content,
                "texts": [],
            }

        elif typ in {"paragraph", "caption", "list item"}:
            if current is None:
                current = {
                    "section_title": "unknown",
                    "texts": [],
                }

            current["texts"].append(content)

    if current and current.get("texts"):
        sections.append({
            "section_title": current["section_title"],
            "text": " ".join(current["texts"]),
        })

    return sections


def find_matching_section(
    ioc: dict[str, Any],
    sections: list[dict[str, Any]]
) -> dict[str, Any] | None:
    value = str(ioc.get("normalized_value") or ioc.get("value") or "")
    if not value:
        return None

    value_norm = normalize_text(value).lower()

    for section in sections:
        text_norm = normalize_text(section.get("text", "")).lower()
        if value_norm in text_norm:
            return section

    return None


def extract_port_for_ip(ip: str, text: str) -> str | None:
    for match in IP_PORT_REGEX.finditer(text or ""):
        if match.group("ip") == ip:
            return match.group("port")

    return None


def normalize_source(source: Any, extra: str | None = None) -> list[str]:
    parts: set[str] = set()

    if isinstance(source, str):
        parts.update(s.strip() for s in re.split(r"[+/,]", source) if s.strip())

    elif isinstance(source, list):
        for item in source:
            parts.update(normalize_source(item))

    if extra:
        parts.add(extra)

    return sorted(parts)


def calculate_confidence(
    ioc: dict[str, Any],
    matched: bool,
    section_title: str | None,
    has_port: bool
) -> float:
    base = float(ioc.get("confidence", 0.6) or 0.6)

    if matched:
        base = max(base, 0.75)

    if section_title and "ioc" in section_title.lower():
        base = max(base, 0.85)

    if has_port:
        base = max(base, 0.90)

    return round(base, 2)


def enrich_iocs(
    ioc_json: dict[str, Any],
    sections: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for ioc in ioc_json.get("iocs", []):
        ioc_type = str(ioc.get("type", ""))
        normalized_value = str(ioc.get("normalized_value") or ioc.get("value", ""))

        key = (ioc_type, normalized_value)
        if key in seen:
            continue

        seen.add(key)

        matched_section = find_matching_section(ioc, sections)

        if matched_section:
            section_title = matched_section.get("section_title", "unknown")
            section_text = matched_section.get("text", "")
        else:
            section_title = ioc.get("section", "unknown")
            section_text = ""

        out: dict[str, Any] = {
            "type": ioc.get("type"),
            "value": ioc.get("value"),
            "normalized_value": ioc.get("normalized_value", ioc.get("value")),
            "section": section_title or "unknown",
            "context": ioc.get("context", ""),
            "source": normalize_source(
                ioc.get("source"),
                "pdf_layout_parser" if matched_section else None
            ),
        }

        port = None

        if out["type"] == "ipv4":
            port = extract_port_for_ip(
                str(out["normalized_value"]),
                section_text or str(out["context"])
            )

            if port:
                out["port"] = port
                out["network_indicator"] = {
                    "ip": out["normalized_value"],
                    "port": int(port),
                    "role": "possible_c2",
                }

        out["confidence"] = calculate_confidence(
            ioc=ioc,
            matched=bool(matched_section),
            section_title=section_title,
            has_port=bool(port),
        )

        evidence = [
            {
                "source": "regex_ioc_extractor",
                "section_title": ioc.get("section", "unknown"),
                "content": ioc.get("context", ""),
            }
        ]

        if matched_section:
            evidence.append({
                "source": "pdf_layout_parser",
                "section_title": matched_section.get("section_title"),
                "content": matched_section.get("text", ""),
            })

        out["evidence"] = [
            item for item in evidence
            if item.get("content")
        ]

        enriched.append(out)

    return sorted(
        enriched,
        key=lambda x: (
            str(x.get("type")),
            str(x.get("normalized_value"))
        )
    )


def summarize_iocs(iocs: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}

    for item in iocs:
        typ = item.get("type", "unknown")
        summary[typ] = summary.get(typ, 0) + 1

    return summary


def build_threat_context(
    sections: list[dict[str, Any]],
    iocs: list[dict[str, Any]]
) -> dict[str, Any]:
    full_text = " ".join(section.get("text", "") for section in sections)

    actor_terms = [
        "APT-C-56",
        "Transparent Tribe",
        "APT36",
        "ProjectM",
        "C-Major",
        "SideCopy",
        "Sidewinder",
    ]

    malware_terms = [
        "CrimsonRAT",
        "RAT",
        "Dropper",
    ]

    behaviors_map = {
        "macro": "malicious macro execution",
        "Dropper": ".NET dropper",
        "C&C": "C2 communication",
        "download": "file download or RAT download",
        "auto-start": "auto-start persistence",
        "Enumerate processes": "process enumeration",
        "screenshots": "screenshot capture",
        "file": "file operation",
        "user information": "user information collection",
    }

    c2 = []

    for item in iocs:
        if item.get("type") == "ipv4" and item.get("port"):
            c2.append({
                "ip": item["normalized_value"],
                "port": int(item["port"]),
                "role": "possible_c2",
            })

    return {
        "actor_aliases": [
            term for term in actor_terms
            if term.lower() in full_text.lower()
        ],
        "malware": [
            term for term in malware_terms
            if term.lower() in full_text.lower()
        ],
        "behaviors": sorted({
            label
            for key, label in behaviors_map.items()
            if key.lower() in full_text.lower()
        }),
        "c2": c2,
    }


def merge_one(
    ioc_json: dict[str, Any],
    parser_json: dict[str, Any]
) -> dict[str, Any]:
    elements = flatten_parser_elements(parser_json)
    sections = build_sections(elements)
    iocs = enrich_iocs(ioc_json, sections)

    merged = {
        "schema_version": "cti-enriched-lite-v1",
        "report_id": ioc_json.get("report_id"),
        "report_title": (
            ioc_json.get("report_title")
            or parser_json.get("title")
            or parser_json.get("file name")
        ),
        "source_type": ioc_json.get("source_type", "pdf"),
        "source": ioc_json.get("source", ""),
        "year": ioc_json.get("year", ""),
        "original_link": ioc_json.get("original_link", ""),
        "pdf_file": ioc_json.get("pdf_file") or parser_json.get("file name"),
        "page_count": ioc_json.get("page_count"),
        "text_length": ioc_json.get("text_length"),
        "extraction_errors": ioc_json.get("extraction_errors", []),
        "sections": sections,
        "iocs": iocs,
        "ioc_summary": summarize_iocs(iocs),
        "threat_context": build_threat_context(sections, iocs),
        "merge_notes": {
            "base_json": "ioc_extractor_json",
            "enrichment_json": "pdf_layout_parser_json",
            "dedup_key": ["type", "normalized_value"],
            "removed_fields": [
                "page_number",
                "bbox",
                "parser_element_id",
                "element_type",
                "font",
                "font_size",
                "text_color",
            ],
            "llm_usage": (
                "Use iocs as detection candidates, evidence as grounding text, "
                "sections as report context, and threat_context as behavioral context."
            ),
        },
    }

    return merged


def find_parser_file(ioc_file: Path, parser_dir: Path) -> Path | None:
    """
    Find parser JSON using the same filename stem.

    Example:
      yoooo/report_001.iocs.json
      openpdf/report_001.json

    This function tries:
      1. Exact same filename
      2. Same stem + .json
      3. Remove .iocs suffix, then match .json
    """
    candidates = [
        parser_dir / ioc_file.name,
        parser_dir / f"{ioc_file.stem}.json",
    ]

    if ioc_file.stem.endswith(".iocs"):
        base_stem = ioc_file.stem.removesuffix(".iocs")
        candidates.append(parser_dir / f"{base_stem}.json")

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def batch_merge(ioc_dir: Path, parser_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    ioc_files = sorted(ioc_dir.glob("*.json"))

    total = 0
    merged = 0
    skipped = 0

    for ioc_file in ioc_files:
        total += 1

        parser_file = find_parser_file(ioc_file, parser_dir)

        if parser_file is None:
            skipped += 1
            print(f"[SKIP] No parser JSON found for: {ioc_file.name}")
            continue

        try:
            ioc_json = load_json(ioc_file)
            parser_json = load_json(parser_file)

            merged_json = merge_one(ioc_json, parser_json)

            out_file = out_dir / ioc_file.name
            dump_json(merged_json, out_file)

            merged += 1
            print(f"[OK] {ioc_file.name} + {parser_file.name} -> {out_file.name}")

        except Exception as exc:
            skipped += 1
            print(f"[ERROR] {ioc_file.name}: {type(exc).__name__}: {exc}")

    print()
    print("Batch merge finished")
    print(f"Total IoC JSON files: {total}")
    print(f"Merged: {merged}")
    print(f"Skipped/Error: {skipped}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch merge IoC JSON folder and PDF parser JSON folder."
    )

    parser.add_argument(
        "--ioc-dir",
        type=Path,
        required=True,
        help="Folder containing IoC extractor JSON files, e.g. yoooo",
    )

    parser.add_argument(
        "--parser-dir",
        type=Path,
        required=True,
        help="Folder containing PDF parser JSON files, e.g. openpdf",
    )

    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Folder for merged output JSON files",
    )

    args = parser.parse_args()

    batch_merge(
        ioc_dir=args.ioc_dir,
        parser_dir=args.parser_dir,
        out_dir=args.out_dir,
    )


if __name__ == "__main__":
    main()
