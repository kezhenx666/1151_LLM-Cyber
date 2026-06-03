#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


ALLOWED_LABELS = {
    "malicious",
    "benign",
    "placeholder",
    "false_positive",
    "uncertain",
}
NEGATIVE_LABELS = {"benign", "placeholder", "false_positive"}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build ground truth and calculate Week 15 IoC extraction metrics."
    )
    parser.add_argument("--annotations", type=Path, required=True)
    parser.add_argument("--missed-iocs", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser.parse_args()


def load_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def safe_div(numerator: int, denominator: int):
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def calculate_metrics(tp: int, fp: int, fn: int) -> dict:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    if precision is None or recall is None or precision + recall == 0:
        f1_score = None
    else:
        f1_score = round(2 * precision * recall / (precision + recall), 4)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
    }


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = load_csv(args.annotations)
    missed_rows = load_csv(args.missed_iocs)

    invalid = [
        row["candidate_id"]
        for row in rows
        if row["label"].strip() and row["label"].strip() not in ALLOWED_LABELS
    ]
    if invalid:
        raise SystemExit(f"Invalid labels in candidate_annotations.csv: {invalid[:10]}")

    reviewed = [row for row in rows if row["label"].strip()]
    unreviewed = [row for row in rows if not row["label"].strip()]
    uncertain = [row for row in reviewed if row["label"].strip() == "uncertain"]
    scored = [row for row in reviewed if row["label"].strip() != "uncertain"]
    positives = [row for row in scored if row["label"].strip() == "malicious"]
    negatives = [row for row in scored if row["label"].strip() in NEGATIVE_LABELS]

    clean_missed = [
        row
        for row in missed_rows
        if row["report_id"].strip()
        and row["type"].strip()
        and row["normalized_value"].strip()
    ]

    by_type = defaultdict(lambda: Counter({"tp": 0, "fp": 0, "fn": 0}))
    for row in positives:
        by_type[row["type"]]["tp"] += 1
    for row in negatives:
        by_type[row["type"]]["fp"] += 1
    for row in clean_missed:
        by_type[row["type"]]["fn"] += 1

    summary = {
        "review_status": {
            "candidate_count": len(rows),
            "reviewed_count": len(reviewed),
            "unreviewed_count": len(unreviewed),
            "uncertain_count": len(uncertain),
            "scored_candidate_count": len(scored),
            "missed_ioc_count": len(clean_missed),
            "complete": len(unreviewed) == 0,
        },
        "overall": calculate_metrics(
            tp=len(positives),
            fp=len(negatives),
            fn=len(clean_missed),
        ),
        "by_type": {
            ioc_type: calculate_metrics(
                tp=counts["tp"],
                fp=counts["fp"],
                fn=counts["fn"],
            )
            for ioc_type, counts in sorted(by_type.items())
        },
        "label_counts": dict(Counter(row["label"].strip() for row in reviewed)),
    }

    ground_truth = {
        "description": "Human-reviewed Week 15 IoC extraction ground truth",
        "review_status": summary["review_status"],
        "reports": {},
    }
    for row in positives:
        report = ground_truth["reports"].setdefault(
            row["report_id"],
            {"report_title": row["report_title"], "iocs": []},
        )
        report["iocs"].append(
            {
                "type": row["type"],
                "normalized_value": row["normalized_value"],
                "evidence": row["context"],
                "source": "reviewed_candidate",
                "reviewer_note": row["reviewer_note"],
            }
        )
    for row in clean_missed:
        report = ground_truth["reports"].setdefault(
            row["report_id"],
            {"report_title": "", "iocs": []},
        )
        report["iocs"].append(
            {
                "type": row["type"],
                "normalized_value": row["normalized_value"],
                "evidence": row["evidence"],
                "source": "manually_added_missed_ioc",
                "reviewer_note": row["reviewer_note"],
            }
        )

    metrics_path = args.out_dir / "evaluation_metrics.json"
    ground_truth_path = args.out_dir / "ground_truth.json"
    metrics_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    ground_truth_path.write_text(
        json.dumps(ground_truth, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"metrics: {metrics_path}")
    print(f"ground truth: {ground_truth_path}")
    if unreviewed:
        print("note: metrics are provisional until all candidate labels are filled.")


if __name__ == "__main__":
    main()
