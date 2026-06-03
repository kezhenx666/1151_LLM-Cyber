#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import re
from pathlib import Path

from pypdf import PdfReader
import tldextract


IP_REGEX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
URL_REGEX = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"\]\)}]+", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24})\b"
)

TRAILING_PUNCT = ".,;:!?)>]}'\""
COMMON_BENIGN_DOMAINS = {
    "adobe.com",
    "ahnlab.com",
    "apple.com",
    "blackberry.com",
    "cafe24.com",
    "cert.pl",
    "cisa.gov",
    "cisecurity.org",
    "github.com",
    "githubusercontent.com",
    "gmail.com",
    "google.com",
    "microsoft.com",
    "mozilla.org",
    "nist.gov",
    "proofpoint.com",
    "twitter.com",
    "ukr.net",
    "w3.org",
    "wallup.net",
    "welivesecurity.com",
    "youtube.com",
}
FILELIKE_SUFFIXES = {"properties", "zip", "phone"}
FILELIKE_DOMAINS = {"sam.sa", "se.sa", "sy.sa", "win.phone"}
SUSPICIOUS_PARSE_ARTIFACT_DOMAINS = {"embassy.us", "ioamazon.com"}
PLACEHOLDER_IPS = {"1.1.1.1", "1.2.3.4", "2.2.2.2"}
COMMON_BENIGN_IPS = {"3.228.54.173"}
PLACEHOLDER_MARKERS = {
    "*",
    "[redacted",
    "redacted",
    "[base64",
    "base64-encoded",
    "[computer",
    "[username",
}


def refang(text: str) -> str:
    replacements = [
        (r"hxxps\s*[:：]\s*/\s*/", "https://"),
        (r"hxxp\s*[:：]\s*/\s*/", "http://"),
        (r"\[\s*:\s*\]", ":"),
        (r"\(\s*:\s*\)", ":"),
        (r"\[\s*\.\s*\]", "."),
        (r"\(\s*\.\s*\)", "."),
        (r"\{\s*\.\s*\}", "."),
        (r"\[\s*dot\s*\]", "."),
        (r"\(\s*dot\s*\)", "."),
        (r"\s+dot\s+", "."),
        (r"\[\s*at\s*\]", "@"),
        (r"\(\s*at\s*\)", "@"),
    ]
    normalized = text
    for pattern, value in replacements:
        normalized = re.sub(pattern, value, normalized, flags=re.IGNORECASE)
    return normalized


def clean_value(value: str) -> str:
    return value.strip().strip(TRAILING_PUNCT)


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def context_window(text: str, start: int, end: int, size: int = 180) -> str:
    left = max(0, start - size)
    right = min(len(text), end + size)
    return collapse_ws(text[left:right])


def is_placeholder_value(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def is_masked_match(text: str, start: int, end: int) -> bool:
    nearby = text[max(0, start - 8): min(len(text), end + 8)].lower()
    return "*" in nearby or "[redacted" in nearby


def split_embedded_urls(value: str) -> list[str]:
    starts = [match.start() for match in re.finditer(r"(?i)(?:https?|ftp)://", value)]
    if len(starts) <= 1:
        return [value]
    starts.append(len(value))
    return [value[starts[index]:starts[index + 1]] for index in range(len(starts) - 1)]


def url_host(value: str) -> str:
    return re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value).split("/", 1)[0].split(":", 1)[0]


def should_keep_url(value: str) -> bool:
    if is_placeholder_value(value):
        return False
    host = url_host(value)
    domain = registered_domain(host)
    if domain in COMMON_BENIGN_DOMAINS:
        return False
    return bool(domain)


def should_keep_domain(value: str, domain: str, text: str, start: int, end: int) -> bool:
    if not domain or domain in COMMON_BENIGN_DOMAINS:
        return False
    if domain in SUSPICIOUS_PARSE_ARTIFACT_DOMAINS:
        return False
    if is_placeholder_value(value) or is_masked_match(text, start, end):
        return False
    extracted = tldextract.extract(value)
    if extracted.suffix in FILELIKE_SUFFIXES:
        return False
    if domain in FILELIKE_DOMAINS:
        return False
    if domain.startswith("com."):
        return False
    return True


def should_keep_ipv4(value: str, context: str) -> bool:
    if value in PLACEHOLDER_IPS:
        return False
    if value in COMMON_BENIGN_IPS:
        return False
    return is_public_ipv4(value)


def read_pdf_text(pdf_path: Path) -> tuple[str, int, list[str]]:
    errors = []
    chunks = []
    reader = PdfReader(str(pdf_path))
    for index, page in enumerate(reader.pages, start=1):
        try:
            page_text = page.extract_text() or ""
            chunks.append(f"\n\n[Page {index}]\n{page_text}")
        except Exception as exc:
            errors.append(f"page {index}: {type(exc).__name__}: {exc}")
    return "\n".join(chunks), len(reader.pages), errors


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        ip.version == 4
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def registered_domain(value: str) -> str:
    extracted = tldextract.extract(value)
    if not extracted.suffix or not extracted.domain:
        return ""
    return f"{extracted.domain}.{extracted.suffix}".lower()


def normalize_source(source: str | list[str]) -> list[str]:
    if isinstance(source, list):
        parts = source
    else:
        parts = re.split(r"[+/,]", source)
    return sorted({part.strip() for part in parts if part and part.strip()})


def add_ioc(items: dict, ioc_type: str, value: str, section: str, context: str, source: str):
    normalized = value.lower() if ioc_type in {"domain", "url"} else value.upper() if ioc_type == "cve" else value
    key = (ioc_type, normalized)
    if key not in items:
        items[key] = {
            "type": ioc_type,
            "value": value,
            "normalized_value": normalized,
            "section": section,
            "context": context,
            "confidence": 0.60,
            "source": normalize_source(source),
            "evidence": [
                {
                    "source": "regex_ioc_extractor",
                    "section_title": section,
                    "content": context,
                }
            ],
        }


def extract_iocs(text: str) -> list[dict]:
    normalized_text = refang(text)
    found = {}

    for match in URL_REGEX.finditer(normalized_text):
        raw_value = clean_value(match.group(0))
        for value in split_embedded_urls(raw_value):
            value = clean_value(value)
            if not should_keep_url(value):
                continue
            add_ioc(found, "url", value, "unknown", context_window(normalized_text, match.start(), match.end()), "regex")
            domain = registered_domain(url_host(value))
            if should_keep_domain(url_host(value), domain, normalized_text, match.start(), match.end()):
                add_ioc(found, "domain", domain, "unknown", context_window(normalized_text, match.start(), match.end()), "url_host")

    for match in IP_REGEX.finditer(normalized_text):
        value = clean_value(match.group(0))
        context = context_window(normalized_text, match.start(), match.end())
        if should_keep_ipv4(value, context):
            add_ioc(found, "ipv4", value, "unknown", context, "regex+ipaddress")

    for pattern, ioc_type in [
        (SHA256_REGEX, "sha256"),
        (SHA1_REGEX, "sha1"),
        (MD5_REGEX, "md5"),
        (CVE_REGEX, "cve"),
    ]:
        for match in pattern.finditer(normalized_text):
            value = clean_value(match.group(0))
            if len(set(value.lower())) <= 2 and ioc_type in {"md5", "sha1", "sha256"}:
                continue
            add_ioc(found, ioc_type, value, "unknown", context_window(normalized_text, match.start(), match.end()), "regex")

    for match in DOMAIN_REGEX.finditer(normalized_text):
        value = clean_value(match.group(0))
        domain = registered_domain(value)
        if should_keep_domain(value, domain, normalized_text, match.start(), match.end()):
            add_ioc(found, "domain", domain, "unknown", context_window(normalized_text, match.start(), match.end()), "regex+tldextract")

    return sorted(found.values(), key=lambda item: (item["type"], item["normalized_value"]))


def load_metadata(log_path: Path) -> dict:
    if not log_path.exists():
        return {}
    with log_path.open(encoding="utf-8") as handle:
        return {row["Saved File"]: row for row in csv.DictReader(handle)}


def summarize_iocs(iocs: list[dict]) -> dict[str, int]:
    summary = {}
    for item in iocs:
        summary[item["type"]] = summary.get(item["type"], 0) + 1
    return summary


def build_report_json(pdf_path: Path, meta: dict, pages: int, text_length: int, errors: list[str], iocs: list[dict]) -> dict:
    return {
        "schema_version": "cti-enriched-lite-v1",
        "report_id": pdf_path.stem,
        "report_title": meta.get("Title", pdf_path.stem),
        "source_type": "pdf",
        "source": meta.get("Source", ""),
        "year": meta.get("Year", ""),
        "original_link": meta.get("Link", ""),
        "pdf_file": str(pdf_path),
        "page_count": pages,
        "text_length": text_length,
        "extraction_errors": errors,
        "sections": [],
        "iocs": iocs,
        "ioc_summary": summarize_iocs(iocs),
        "threat_context": {},
        "merge_notes": {
            "base_json": "ioc_extractor_json",
            "enrichment_json": None,
            "dedup_key": ["type", "normalized_value"],
            "schema_policy": (
                "Raw extractor output uses the same enriched-compatible schema as "
                "the final merged output. Parser/layout enrichment can later fill "
                "sections, stronger evidence, threat_context, and adjusted confidence."
            ),
            "llm_usage": (
                "Use iocs as detection candidates and evidence/context as grounding "
                "text for later LLM validation or rule generation."
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdf-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    metadata = load_metadata(args.metadata) if args.metadata else {}
    combined = []

    for pdf_path in sorted(args.pdf_dir.glob("*.pdf")):
        text, pages, errors = read_pdf_text(pdf_path)
        iocs = extract_iocs(text)
        meta = metadata.get(pdf_path.name, {})
        report = build_report_json(
            pdf_path=pdf_path,
            meta=meta,
            pages=pages,
            text_length=len(text),
            errors=errors,
            iocs=iocs,
        )

        out_path = args.out_dir / f"{pdf_path.stem}.iocs.json"
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        combined.append(report)
        print(f"{pdf_path.name}: {len(iocs)} IoC candidates")

    combined_path = args.out_dir / "all_reports_iocs.json"
    combined_path.write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"combined: {combined_path}")


if __name__ == "__main__":
    main()
