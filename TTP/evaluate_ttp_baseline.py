#!/usr/bin/env python3
import argparse
import ast
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_+-]*|\d+(?:\.\d+)?")
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "been",
    "by",
    "can",
    "for",
    "from",
    "has",
    "have",
    "in",
    "into",
    "is",
    "it",
    "may",
    "of",
    "on",
    "or",
    "such",
    "that",
    "the",
    "their",
    "these",
    "this",
    "to",
    "use",
    "used",
    "using",
    "via",
    "with",
}


def tokenize(text: str) -> list[str]:
    tokens = [token.lower() for token in TOKEN_RE.findall(text or "")]
    return [token for token in tokens if len(token) > 1 and token not in STOPWORDS]


def normalize_attack_id(value: str) -> str:
    return value.strip().strip("'\"").upper()


def load_kb(path: Path) -> list[dict[str, Any]]:
    items = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                items.append(json.loads(line))
    if not items:
        raise SystemExit(f"Empty knowledge base: {path}")
    return items


def parse_labels(raw: str) -> set[str]:
    try:
        value = ast.literal_eval(raw)
    except Exception:
        value = [part.strip() for part in raw.split(",")]
    if isinstance(value, str):
        value = [value]
    return {normalize_attack_id(str(item)) for item in value if str(item).strip()}


def load_dataset(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for index, row in enumerate(reader, start=1):
            text = row.get("text1", "").strip()
            labels = parse_labels(row.get("labels", "[]"))
            if text and labels:
                rows.append({"row_id": index, "text": text, "labels": labels})
    return rows


class TfidfRetriever:
    def __init__(self, kb: list[dict[str, Any]]):
        self.kb = kb
        self.doc_vectors: list[dict[str, float]] = []
        self.doc_norms: list[float] = []
        self.idf: dict[str, float] = {}
        self.inverted: dict[str, list[tuple[int, float]]] = defaultdict(list)
        self._build()

    def _build(self) -> None:
        doc_tokens = [tokenize(item.get("search_document", "")) for item in self.kb]
        doc_freq: Counter[str] = Counter()
        for tokens in doc_tokens:
            doc_freq.update(set(tokens))

        doc_count = len(doc_tokens)
        self.idf = {
            token: math.log((doc_count + 1) / (freq + 1)) + 1.0
            for token, freq in doc_freq.items()
        }

        for doc_index, tokens in enumerate(doc_tokens):
            counts = Counter(tokens)
            vector = {
                token: (1.0 + math.log(count)) * self.idf[token]
                for token, count in counts.items()
            }
            norm = math.sqrt(sum(weight * weight for weight in vector.values())) or 1.0
            self.doc_vectors.append(vector)
            self.doc_norms.append(norm)
            for token, weight in vector.items():
                self.inverted[token].append((doc_index, weight))

    def search(self, query: str, top_k: int) -> list[dict[str, Any]]:
        counts = Counter(tokenize(query))
        if not counts:
            return []

        query_vector = {
            token: (1.0 + math.log(count)) * self.idf[token]
            for token, count in counts.items()
            if token in self.idf
        }
        query_norm = math.sqrt(sum(weight * weight for weight in query_vector.values())) or 1.0

        scores: defaultdict[int, float] = defaultdict(float)
        for token, query_weight in query_vector.items():
            for doc_index, doc_weight in self.inverted.get(token, []):
                scores[doc_index] += query_weight * doc_weight

        ranked = []
        for doc_index, score in scores.items():
            cosine = score / (query_norm * self.doc_norms[doc_index])
            item = self.kb[doc_index]
            ranked.append(
                {
                    "technique_id": item["technique_id"],
                    "name": item["name"],
                    "score": round(cosine, 6),
                    "tactics": item.get("tactics", []),
                }
            )

        return sorted(ranked, key=lambda item: item["score"], reverse=True)[:top_k]


def evaluate(rows: list[dict[str, Any]], retriever: TfidfRetriever, top_k: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    top_hits = Counter()
    label_recall_sum = Counter()
    reciprocal_rank_sum = 0.0
    evaluated = 0
    predictions = []

    for row in rows:
        results = retriever.search(row["text"], top_k=top_k)
        predicted_ids = [item["technique_id"] for item in results]
        labels = row["labels"]
        if not predicted_ids:
            continue

        evaluated += 1
        for k in (1, 3, 5, top_k):
            top = set(predicted_ids[:k])
            if labels & top:
                top_hits[k] += 1
            label_recall_sum[k] += len(labels & top) / len(labels)

        rr = 0.0
        for rank, technique_id in enumerate(predicted_ids, start=1):
            if technique_id in labels:
                rr = 1.0 / rank
                break
        reciprocal_rank_sum += rr

        predictions.append(
            {
                "row_id": row["row_id"],
                "text": row["text"],
                "labels": sorted(labels),
                "predictions": results,
            }
        )

    metrics = {
        "samples": len(rows),
        "evaluated_samples": evaluated,
        "top_1_hit_rate": round(top_hits[1] / evaluated, 4) if evaluated else 0.0,
        "top_3_hit_rate": round(top_hits[3] / evaluated, 4) if evaluated else 0.0,
        "top_5_hit_rate": round(top_hits[5] / evaluated, 4) if evaluated else 0.0,
        f"top_{top_k}_hit_rate": round(top_hits[top_k] / evaluated, 4) if evaluated else 0.0,
        "label_recall_at_1": round(label_recall_sum[1] / evaluated, 4) if evaluated else 0.0,
        "label_recall_at_3": round(label_recall_sum[3] / evaluated, 4) if evaluated else 0.0,
        "label_recall_at_5": round(label_recall_sum[5] / evaluated, 4) if evaluated else 0.0,
        f"label_recall_at_{top_k}": round(label_recall_sum[top_k] / evaluated, 4) if evaluated else 0.0,
        "mrr": round(reciprocal_rank_sum / evaluated, 4) if evaluated else 0.0,
    }
    return metrics, predictions


def dataset_files(dataset_root: Path) -> list[Path]:
    return sorted(dataset_root.glob("datasets/**/*.tsv"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a zero-shot ATT&CK TTP mapping baseline using TF-IDF retrieval over a technique KB."
    )
    parser.add_argument("--kb-jsonl", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument(
        "--write-predictions",
        action="store_true",
        help="Write per-row predictions for later error analysis.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    kb = load_kb(args.kb_jsonl)
    retriever = TfidfRetriever(kb)

    all_metrics = {
        "baseline": "tfidf_retrieval_over_attack_technique_kb",
        "kb_jsonl": str(args.kb_jsonl),
        "dataset_root": str(args.dataset_root),
        "top_k": args.top_k,
        "technique_count": len(kb),
        "splits": {},
    }

    for path in dataset_files(args.dataset_root):
        rows = load_dataset(path)
        metrics, predictions = evaluate(rows, retriever, top_k=args.top_k)
        split_name = str(path.relative_to(args.dataset_root))
        all_metrics["splits"][split_name] = metrics
        print(f"{split_name}: {json.dumps(metrics, ensure_ascii=False)}")

        if args.write_predictions:
            safe_name = split_name.replace("/", "__").replace(".tsv", ".predictions.jsonl")
            with (args.out_dir / safe_name).open("w", encoding="utf-8") as handle:
                for item in predictions:
                    handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    out_path = args.out_dir / "ttp_tfidf_baseline_metrics.json"
    out_path.write_text(json.dumps(all_metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote: {out_path}")


if __name__ == "__main__":
    main()
