#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


DEFAULT_REPORT_IDS = [
    "CISA_aa23-347a-russian-foreign-intelligence-service-svr-exploiting-jetbrains-teamcity-cve-globally_0(12-13-2023)",
    "Ahnlab_HWP-Malware-Steganography-ScarCruft(02-21-2023)",
    "Proofpoint_Russia-Aligned-TA499-Beleaguers-Targets-Video-Call-Requests(03-07-2023)",
    "ESET_MQsTTang-MustangPandas-backdoor-Qt-MQTT(03-02-2023)",
    "Blackberry_AeroBlade-Targeting-US-Aerospace-Industry(11-30-2023)",
]

ANNOTATION_FIELDS = [
    "candidate_id",
    "report_id",
    "report_title",
    "type",
    "value",
    "normalized_value",
    "section",
    "context",
    "label",
    "reviewer_note",
]

MISSED_IOC_FIELDS = [
    "report_id",
    "type",
    "normalized_value",
    "evidence",
    "reviewer_note",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export a small IoC candidate subset for manual Week 15 review."
    )
    parser.add_argument("--combined-json", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--report-id",
        action="append",
        dest="report_ids",
        help="Report ID to include. Repeat for multiple reports. Defaults to a balanced five-report subset.",
    )
    return parser.parse_args()


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]):
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    selected_ids = args.report_ids or DEFAULT_REPORT_IDS

    reports = json.loads(args.combined_json.read_text(encoding="utf-8"))
    reports_by_id = {report["report_id"]: report for report in reports}

    missing = [report_id for report_id in selected_ids if report_id not in reports_by_id]
    if missing:
        raise SystemExit(f"Unknown report IDs: {missing}")

    annotation_rows = []
    manifest_reports = []
    for report_id in selected_ids:
        report = reports_by_id[report_id]
        manifest_reports.append(
            {
                "report_id": report_id,
                "report_title": report["report_title"],
                "pdf_file": report["pdf_file"],
                "candidate_count": len(report["iocs"]),
                "ioc_summary": report["ioc_summary"],
            }
        )
        for index, ioc in enumerate(report["iocs"], start=1):
            annotation_rows.append(
                {
                    "candidate_id": f"{report_id}::{index:03d}",
                    "report_id": report_id,
                    "report_title": report["report_title"],
                    "type": ioc["type"],
                    "value": ioc["value"],
                    "normalized_value": ioc["normalized_value"],
                    "section": ioc.get("section", ""),
                    "context": ioc.get("context", ""),
                    "label": "",
                    "reviewer_note": "",
                }
            )

    write_csv(args.out_dir / "candidate_annotations.csv", ANNOTATION_FIELDS, annotation_rows)
    write_csv(args.out_dir / "missed_iocs.csv", MISSED_IOC_FIELDS, [])

    manifest = {
        "purpose": "Week 15 IoC extraction evaluation subset",
        "allowed_labels": [
            "malicious",
            "benign",
            "placeholder",
            "false_positive",
            "uncertain",
        ],
        "positive_label": "malicious",
        "ignored_label": "uncertain",
        "reports": manifest_reports,
        "candidate_count": len(annotation_rows),
    }
    (args.out_dir / "subset_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"reports: {len(manifest_reports)}")
    print(f"candidates: {len(annotation_rows)}")
    print(f"annotations: {args.out_dir / 'candidate_annotations.csv'}")
    print(f"missed IoCs: {args.out_dir / 'missed_iocs.csv'}")
    print(f"manifest: {args.out_dir / 'subset_manifest.json'}")


if __name__ == "__main__":
    main()
