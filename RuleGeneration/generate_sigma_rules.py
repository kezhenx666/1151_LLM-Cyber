#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SUPPORTED_IOC_TYPES = {"domain", "url", "ipv4", "md5", "sha1", "sha256"}
BENIGN_RULE_DOMAINS = {
    "adobe.com",
    "ahnlab.com",
    "apple.com",
    "cisa.gov",
    "github.com",
    "google.com",
    "microsoft.com",
    "nist.gov",
    "proofpoint.com",
    "qq.com",
    "twitter.com",
    "welivesecurity.com",
    "youtube.com",
}


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return value or "cti-report"


def stable_rule_id(report_id: str, rule_kind: str, values: list[str]) -> str:
    digest = hashlib.sha256((report_id + rule_kind + "|".join(sorted(values))).encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    text = str(value)
    if not text:
        return '""'
    if re.fullmatch(r"[A-Za-z0-9_.:/@+-]+", text):
        return text
    return json.dumps(text, ensure_ascii=False)


def dump_yaml(value: Any, indent: int = 0) -> str:
    pad = " " * indent
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.append(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.append(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{pad}{yaml_scalar(value)}"


def normalize_source(source: Any) -> list[str]:
    if isinstance(source, list):
        return [str(item) for item in source]
    if source:
        return [str(source)]
    return []


def collect_iocs(ioc_json: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in ioc_json.get("iocs", []):
        ioc_type = str(item.get("type", "")).lower()
        value = str(item.get("normalized_value") or item.get("value") or "").strip()
        if ioc_type not in SUPPORTED_IOC_TYPES or not value:
            continue
        if ioc_type == "domain" and value.lower() in BENIGN_RULE_DOMAINS:
            continue
        if ioc_type == "url" and any(domain in value.lower() for domain in BENIGN_RULE_DOMAINS):
            continue
        grouped.setdefault(ioc_type, []).append(item)
    return grouped


def attack_tags(attack_json: dict[str, Any]) -> list[str]:
    tags = set()
    for mapping in attack_json.get("ttp_mappings", []):
        for tactic in mapping.get("tactics", []):
            tags.add(f"attack.{str(tactic).replace('_', '-').lower()}")
        technique_id = str(mapping.get("technique_id", "")).lower()
        if technique_id:
            tags.add(f"attack.{technique_id}")
    return sorted(tags)


def rule_references(ioc_json: dict[str, Any], attack_json: dict[str, Any]) -> list[str]:
    refs = []
    for key in ("original_link", "source", "pdf_file"):
        value = ioc_json.get(key)
        if value and str(value).startswith(("http://", "https://")):
            refs.append(str(value))
    for mapping in attack_json.get("ttp_mappings", []):
        for evidence in mapping.get("evidence", []):
            source = evidence.get("source")
            if source and str(source).startswith(("http://", "https://")):
                refs.append(str(source))
    return sorted(set(refs))


def detection_for_ioc_type(ioc_type: str, values: list[str]) -> tuple[dict[str, Any], str, dict[str, str]]:
    if ioc_type == "ipv4":
        detection = {
            "selection_dst_ip": {"DestinationIp": values},
            "selection_dst_ip_alt": {"dst_ip": values},
            "condition": "selection_dst_ip or selection_dst_ip_alt",
        }
        logsource = {"category": "network_connection"}
        fields = {"field": "DestinationIp/dst_ip"}
    elif ioc_type == "domain":
        detection = {
            "selection_dns_query": {"query|contains": values},
            "selection_url_domain": {"url|contains": values},
            "condition": "selection_dns_query or selection_url_domain",
        }
        logsource = {"category": "dns"}
        fields = {"field": "query/url"}
    elif ioc_type == "url":
        detection = {
            "selection_url": {"url|contains": values},
            "selection_uri": {"cs-uri|contains": values},
            "condition": "selection_url or selection_uri",
        }
        logsource = {"category": "proxy"}
        fields = {"field": "url/cs-uri"}
    else:
        hash_field = {
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
        }[ioc_type]
        detection = {
            f"selection_{hash_field}": {f"hashes|contains": values},
            f"selection_file_hash_{hash_field}": {f"file.hash.{hash_field}": values},
            "condition": f"selection_{hash_field} or selection_file_hash_{hash_field}",
        }
        logsource = {"category": "file"}
        fields = {"field": f"hashes/file.hash.{hash_field}"}
    return detection, logsource, fields


def build_rule(ioc_json: dict[str, Any], attack_json: dict[str, Any], ioc_type: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    report_id = str(ioc_json.get("report_id") or attack_json.get("report_id") or "cti-report")
    report_title = str(ioc_json.get("report_title") or attack_json.get("report_title") or report_id)
    values = sorted({str(item.get("normalized_value") or item.get("value")) for item in items if item.get("normalized_value") or item.get("value")})
    detection, logsource, metadata = detection_for_ioc_type(ioc_type, values)
    tags = attack_tags(attack_json)

    title_type = {
        "ipv4": "IP Infrastructure",
        "domain": "Domain Infrastructure",
        "url": "URL Infrastructure",
        "md5": "MD5 Hash",
        "sha1": "SHA1 Hash",
        "sha256": "SHA256 Hash",
    }[ioc_type]

    rule = {
        "title": f"Detect {title_type} from {report_title}"[:120],
        "id": stable_rule_id(report_id, ioc_type, values),
        "status": "experimental",
        "description": (
            f"Detects {ioc_type} indicators extracted from CTI report '{report_title}'. "
            "Generated from Module A IoC JSON and Module B ATT&CK mapping output."
        ),
        "references": rule_references(ioc_json, attack_json),
        "author": "LLM-driven CTI-to-Detection Pipeline",
        "date": "2026/06/04",
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "fields": [metadata["field"]],
        "falsepositives": [
            "Indicators may appear in threat research, sandbox, or internal security testing traffic.",
            "Validate against local asset ownership and approved threat intelligence feeds.",
        ],
        "level": "high",
    }
    if not rule["references"]:
        rule.pop("references")
    if not rule["tags"]:
        rule.pop("tags")
    return rule


def generate_rules(ioc_json: dict[str, Any], attack_json: dict[str, Any]) -> list[dict[str, Any]]:
    grouped = collect_iocs(ioc_json)
    rules = []
    for ioc_type in ["ipv4", "domain", "url", "md5", "sha1", "sha256"]:
        if grouped.get(ioc_type):
            rules.append(build_rule(ioc_json, attack_json, ioc_type, grouped[ioc_type]))
    return rules


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Sigma rules from IoC JSON and ATT&CK JSON.")
    parser.add_argument("--ioc-json", type=Path, required=True)
    parser.add_argument("--attack-json", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ioc_json = json.loads(args.ioc_json.read_text(encoding="utf-8"))
    attack_json = json.loads(args.attack_json.read_text(encoding="utf-8"))
    args.out_dir.mkdir(parents=True, exist_ok=True)

    rules = generate_rules(ioc_json, attack_json)
    manifest = []
    report_id = str(ioc_json.get("report_id") or args.ioc_json.stem)
    for rule in rules:
        filename = f"{slugify(report_id)}.{slugify(rule['id'])}.sigma.yml"
        out_path = args.out_dir / filename
        out_path.write_text(dump_yaml(rule) + "\n", encoding="utf-8")
        manifest.append(
            {
                "path": str(out_path),
                "title": rule["title"],
                "id": rule["id"],
                "level": rule.get("level"),
                "logsource": rule.get("logsource"),
                "tags": rule.get("tags", []),
            }
        )
        print(f"wrote: {out_path}")

    manifest_path = args.out_dir / "sigma_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote: {manifest_path}")


if __name__ == "__main__":
    main()
