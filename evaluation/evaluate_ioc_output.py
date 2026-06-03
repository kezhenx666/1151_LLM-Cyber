#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def normalize_value(ioc_type: str, value: str) -> str:
    value = value.strip()
    if ioc_type in {"domain", "url"}:
        return value.lower()
    if ioc_type == "cve":
        return value.upper()
    return value


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


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def load_predictions(output_dir: Path, report_ids: set[str]) -> dict[str, set[tuple[str, str]]]:
    predictions = {}
    for report_id in report_ids:
        path = output_dir / f"{report_id}.iocs.json"
        if not path.exists():
            raise SystemExit(f"Missing prediction file: {path}")
        report = json.loads(path.read_text(encoding="utf-8"))
        predictions[report_id] = {
            (ioc["type"], normalize_value(ioc["type"], ioc["normalized_value"]))
            for ioc in report.get("iocs", [])
        }
    return predictions


def load_ground_truth(path: Path) -> dict[str, set[tuple[str, str]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    truth = {}
    for report_id, report in data["reports"].items():
        truth[report_id] = {
            (ioc["type"], normalize_value(ioc["type"], ioc["normalized_value"]))
            for ioc in report.get("iocs", [])
        }
    return truth


def main():
    args = parse_args()
    truth = load_ground_truth(args.ground_truth)
    predictions = load_predictions(args.output_dir, set(truth))

    tp_items = []
    fp_items = []
    fn_items = []
    by_type = defaultdict(lambda: Counter({"tp": 0, "fp": 0, "fn": 0}))

    for report_id in sorted(truth):
        report_truth = truth[report_id]
        report_predictions = predictions[report_id]
        for item in sorted(report_predictions & report_truth):
            tp_items.append({"report_id": report_id, "type": item[0], "normalized_value": item[1]})
            by_type[item[0]]["tp"] += 1
        for item in sorted(report_predictions - report_truth):
            fp_items.append({"report_id": report_id, "type": item[0], "normalized_value": item[1]})
            by_type[item[0]]["fp"] += 1
        for item in sorted(report_truth - report_predictions):
            fn_items.append({"report_id": report_id, "type": item[0], "normalized_value": item[1]})
            by_type[item[0]]["fn"] += 1

    summary = {
        "output_dir": str(args.output_dir),
        "ground_truth": str(args.ground_truth),
        "report_count": len(truth),
        "overall": calculate_metrics(len(tp_items), len(fp_items), len(fn_items)),
        "by_type": {
            ioc_type: calculate_metrics(counts["tp"], counts["fp"], counts["fn"])
            for ioc_type, counts in sorted(by_type.items())
        },
        "details": {
            "true_positives": tp_items,
            "false_positives": fp_items,
            "false_negatives": fn_items,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["report_count", "overall", "by_type"]}, ensure_ascii=False, indent=2))
    print(f"wrote: {args.out}")


if __name__ == "__main__":
    main()
