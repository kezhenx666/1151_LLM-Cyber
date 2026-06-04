#!/usr/bin/env python3
"""LangGraph orchestration for the CTI-to-Detection pipeline.

Graph shape:

PDF / existing IoC JSON
  -> Node A: IoC extraction
  -> optional IoC retry with relaxed extraction
  -> Node B: ATT&CK TTP mapping
  -> optional TTP heuristic fallback
  -> Node C: Sigma rule generation
  -> optional deterministic rule retry if validation fails
  -> Output
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph


REPO_ROOT = Path(__file__).resolve().parents[1]
for subdir in ["IOC", "TTP", "RuleGeneration"]:
    path = str(REPO_ROOT / subdir)
    if path not in sys.path:
        sys.path.insert(0, path)

from IOC_parser import (  # noqa: E402
    CVE_REGEX,
    DOMAIN_REGEX,
    IP_REGEX,
    MD5_REGEX,
    SHA1_REGEX,
    SHA256_REGEX,
    URL_REGEX,
    add_ioc,
    build_report_json,
    clean_value,
    context_window,
    extract_iocs,
    read_pdf_text,
    refang,
    registered_domain,
    split_embedded_urls,
    summarize_iocs,
    url_host,
)
from evaluate_ttp_baseline import TfidfRetriever, load_kb, normalize_attack_id  # noqa: E402
from generate_sigma_rules import dump_yaml, generate_rules, slugify, stable_rule_id  # noqa: E402
from map_cti_to_attack import aggregate_mappings, map_report  # noqa: E402
from rag_ttp_mapper import kb_by_id  # noqa: E402
from validate_sigma_rules import validate_file  # noqa: E402


DEFAULT_ADAPTER = "jjhoada/qwen2.5-7b-sigma-generation-lora"
DEFAULT_BASE_MODEL = "Qwen/Qwen2.5-7B-Instruct"


class PipelineState(TypedDict, total=False):
    pdf_path: str
    input_ioc_json: str
    out_dir: str
    ioc_json_path: str
    attack_json_path: str
    rules_dir: str
    validation_json_path: str
    ioc_json: dict[str, Any]
    attack_json: dict[str, Any]
    rule_paths: list[str]
    validation_summary: dict[str, Any]
    ioc_attempts: int
    ttp_fallback_used: bool
    rule_attempts: int
    human_review_required: bool
    events: list[dict[str, Any]]
    errors: list[str]


def event(state: PipelineState, node: str, message: str, **extra: Any) -> None:
    state.setdefault("events", []).append({"node": node, "message": message, **extra})


def add_error(state: PipelineState, message: str) -> None:
    state.setdefault("errors", []).append(message)


def ensure_dirs(out_dir: Path) -> dict[str, Path]:
    paths = {
        "root": out_dir,
        "intermediate": out_dir / "intermediate",
        "rules": out_dir / "rules",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def relaxed_extract_iocs(text: str) -> list[dict[str, Any]]:
    """Second-pass extraction used when the strict extractor finds too few IoCs.

    The relaxed pass intentionally keeps more candidates and marks them with lower
    confidence. This gives a later LLM or human reviewer something to inspect.
    """

    normalized_text = refang(text)
    found: dict[tuple[str, str], dict[str, Any]] = {}

    for match in URL_REGEX.finditer(normalized_text):
        raw_value = clean_value(match.group(0))
        for value in split_embedded_urls(raw_value):
            value = clean_value(value)
            if not value:
                continue
            add_ioc(found, "url", value, "unknown", context_window(normalized_text, match.start(), match.end()), "pipeline_relaxed")
            domain = registered_domain(url_host(value))
            if domain:
                add_ioc(found, "domain", domain, "unknown", context_window(normalized_text, match.start(), match.end()), "pipeline_relaxed_url_host")

    for match in IP_REGEX.finditer(normalized_text):
        value = clean_value(match.group(0))
        add_ioc(found, "ipv4", value, "unknown", context_window(normalized_text, match.start(), match.end()), "pipeline_relaxed")

    for pattern, ioc_type in [
        (SHA256_REGEX, "sha256"),
        (SHA1_REGEX, "sha1"),
        (MD5_REGEX, "md5"),
        (CVE_REGEX, "cve"),
    ]:
        for match in pattern.finditer(normalized_text):
            value = clean_value(match.group(0))
            add_ioc(found, ioc_type, value, "unknown", context_window(normalized_text, match.start(), match.end()), "pipeline_relaxed")

    for match in DOMAIN_REGEX.finditer(normalized_text):
        value = clean_value(match.group(0))
        domain = registered_domain(value)
        if domain:
            add_ioc(found, "domain", domain, "unknown", context_window(normalized_text, match.start(), match.end()), "pipeline_relaxed")

    relaxed = []
    for item in found.values():
        item["confidence"] = min(float(item.get("confidence", 0.6)), 0.35)
        relaxed.append(item)
    return sorted(relaxed, key=lambda item: (item["type"], item["normalized_value"]))


def merge_iocs(primary: list[dict[str, Any]], fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for item in primary + fallback:
        key = (str(item.get("type")), str(item.get("normalized_value") or item.get("value")))
        if key not in merged:
            merged[key] = item
            continue
        existing_sources = merged[key].get("source", [])
        new_sources = item.get("source", [])
        if not isinstance(existing_sources, list):
            existing_sources = [existing_sources]
        if not isinstance(new_sources, list):
            new_sources = [new_sources]
        merged[key]["source"] = sorted({str(src) for src in existing_sources + new_sources if src})
    return sorted(merged.values(), key=lambda item: (item["type"], item["normalized_value"]))


def make_ioc_extraction_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        out_paths = ensure_dirs(Path(state["out_dir"]))
        state["ioc_attempts"] = int(state.get("ioc_attempts", 0)) + 1

        if state.get("input_ioc_json"):
            source_path = Path(state["input_ioc_json"])
            report = json.loads(source_path.read_text(encoding="utf-8"))
            report_stem = source_path.stem.removesuffix(".iocs")
            out_path = out_paths["intermediate"] / f"{report_stem}.iocs.json"
            write_json(out_path, report)
            state["ioc_json"] = report
            state["ioc_json_path"] = str(out_path)
            event(state, "ioc_extraction", "loaded existing IoC JSON", path=str(source_path), ioc_count=len(report.get("iocs", [])))
            return state

        pdf_path = Path(state["pdf_path"])
        text, pages, errors = read_pdf_text(pdf_path)
        iocs = extract_iocs(text)
        report = build_report_json(
            pdf_path=pdf_path,
            meta={},
            pages=pages,
            text_length=len(text),
            errors=errors,
            iocs=iocs,
        )
        report["pipeline_notes"] = {
            "node": "ioc_extraction",
            "strategy": "strict",
            "min_iocs": config.min_iocs,
        }
        out_path = out_paths["intermediate"] / f"{pdf_path.stem}.iocs.json"
        write_json(out_path, report)
        state["ioc_json"] = report
        state["ioc_json_path"] = str(out_path)
        event(state, "ioc_extraction", "strict extraction complete", ioc_count=len(iocs), errors=errors)
        return state

    return node


def make_ioc_retry_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        if state.get("input_ioc_json"):
            event(state, "ioc_retry", "skipped retry for existing IoC JSON")
            return state

        pdf_path = Path(state["pdf_path"])
        text, pages, errors = read_pdf_text(pdf_path)
        primary = state.get("ioc_json", {}).get("iocs", [])
        fallback = relaxed_extract_iocs(text)
        iocs = merge_iocs(primary, fallback)
        report = build_report_json(
            pdf_path=pdf_path,
            meta={},
            pages=pages,
            text_length=len(text),
            errors=errors,
            iocs=iocs,
        )
        report["pipeline_notes"] = {
            "node": "ioc_retry",
            "strategy": "strict+relaxed",
            "strict_count": len(primary),
            "relaxed_count": len(fallback),
            "merged_count": len(iocs),
        }
        out_path = Path(state["out_dir"]) / "intermediate" / f"{pdf_path.stem}.iocs.json"
        write_json(out_path, report)
        state["ioc_json"] = report
        state["ioc_json_path"] = str(out_path)
        state["ioc_attempts"] = int(state.get("ioc_attempts", 1)) + 1
        if len(iocs) < config.min_iocs:
            state["human_review_required"] = True
        event(state, "ioc_retry", "relaxed extraction complete", ioc_count=len(iocs), relaxed_count=len(fallback))
        return state

    return node


def route_after_ioc(config: argparse.Namespace):
    def route(state: PipelineState) -> str:
        ioc_count = len(state.get("ioc_json", {}).get("iocs", []))
        if ioc_count < config.min_iocs and int(state.get("ioc_attempts", 0)) <= config.max_ioc_retries:
            return "ioc_retry"
        return "ttp_mapping"

    return route


def make_ttp_mapping_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        kb = load_kb(config.kb_jsonl)
        retriever = TfidfRetriever(kb)
        index = kb_by_id(kb)
        report = state["ioc_json"]
        try:
            mapped = map_report(
                report,
                retriever=retriever,
                kb_index=index,
                top_k=config.top_k,
                provider=config.ttp_provider,
                api_base=config.api_base,
                api_key=config.api_key,
                model=config.ttp_model,
                temperature=config.ttp_temperature,
                timeout=config.timeout,
                max_retries=config.max_ttp_retries,
                retry_sleep=config.retry_sleep,
                include_ioc_evidence=config.include_ioc_evidence,
                max_chars=config.max_chars,
                overlap=config.overlap,
                min_chars=config.min_chars,
                max_evidence=config.max_evidence,
            )
        except Exception as exc:
            add_error(state, f"ttp_mapping failed: {type(exc).__name__}: {exc}")
            mapped = aggregate_mappings(report, [], index, config.ttp_provider, config.top_k)
            mapped["mapping_summary"]["validation_error_count"] += 1
            mapped["mapping_records"].append(
                {
                    "evidence": "",
                    "retrieved_candidates": [],
                    "selected_techniques": [],
                    "validation_errors": [f"{type(exc).__name__}: {exc}"],
                }
            )

        out_path = Path(state["out_dir"]) / "intermediate" / f"{report.get('report_id', 'report')}.attack.json"
        write_json(out_path, mapped)
        state["attack_json"] = mapped
        state["attack_json_path"] = str(out_path)
        event(
            state,
            "ttp_mapping",
            "TTP mapping complete",
            technique_count=mapped.get("mapping_summary", {}).get("technique_count", 0),
        )
        return state

    return node


def make_ttp_fallback_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        attack_json = state.get("attack_json", {})
        report = state["ioc_json"]
        ioc_types = {str(item.get("type")) for item in report.get("iocs", [])}
        fallback_ids = []
        if ioc_types & {"domain", "url", "ipv4"}:
            fallback_ids.extend(["T1071.001", "T1105"])
        elif ioc_types & {"md5", "sha1", "sha256"}:
            fallback_ids.append("T1204.002")

        kb = load_kb(config.kb_jsonl)
        index = kb_by_id(kb)
        mappings = []
        for technique_id in fallback_ids:
            item = index.get(normalize_attack_id(technique_id), {})
            mappings.append(
                {
                    "technique_id": technique_id,
                    "technique_name": item.get("name", ""),
                    "tactics": item.get("tactics", []),
                    "confidence": 0.35,
                    "evidence": [
                        {
                            "source": "heuristic_fallback",
                            "section_title": "ioc_summary",
                            "chunk_index": None,
                            "text": f"Fallback selected from IoC types: {sorted(ioc_types)}",
                        }
                    ],
                    "reasons": ["No LLM-supported mapping was selected; fallback based on IoC types."],
                    "source": "heuristic_fallback",
                }
            )

        tactic_counts: dict[str, int] = {}
        for mapping in mappings:
            for tactic in mapping.get("tactics", []):
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

        attack_json["ttp_mappings"] = mappings
        attack_json["mapping_summary"] = {
            **attack_json.get("mapping_summary", {}),
            "technique_count": len(mappings),
            "tactic_counts": dict(sorted(tactic_counts.items())),
            "fallback_used": True,
        }
        state["attack_json"] = attack_json
        state["ttp_fallback_used"] = True
        if not mappings:
            state["human_review_required"] = True
        out_path = Path(state["attack_json_path"])
        write_json(out_path, attack_json)
        event(state, "ttp_fallback", "heuristic fallback complete", technique_count=len(mappings))
        return state

    return node


def route_after_ttp(config: argparse.Namespace):
    def route(state: PipelineState) -> str:
        technique_count = int(state.get("attack_json", {}).get("mapping_summary", {}).get("technique_count", 0))
        if technique_count < config.min_techniques and not state.get("ttp_fallback_used"):
            return "ttp_fallback"
        return "rule_generation"

    return route


def sigma_system_prompt() -> str:
    return (
        "You generate Sigma rule drafts from CTI-derived IoC and ATT&CK context. "
        "Output JSON only. Do not invent IoCs or ATT&CK technique IDs."
    )


def prompt_for_sigma_model(ioc_json: dict[str, Any], attack_json: dict[str, Any], max_iocs: int = 12) -> list[dict[str, str]]:
    iocs = [
        {"type": item.get("type"), "value": item.get("normalized_value") or item.get("value")}
        for item in ioc_json.get("iocs", [])[:max_iocs]
    ]
    attack_context = [
        {
            "technique_id": item.get("technique_id"),
            "technique_name": item.get("technique_name"),
            "tactics": item.get("tactics", []),
        }
        for item in attack_json.get("ttp_mappings", [])
    ]
    ioc_types = {str(item.get("type")) for item in ioc_json.get("iocs", [])}
    if "url" in ioc_types:
        logsource = {"category": "proxy"}
    elif "domain" in ioc_types:
        logsource = {"category": "dns"}
    elif "ipv4" in ioc_types:
        logsource = {"category": "network_connection"}
    else:
        logsource = {"category": "process_creation", "product": "windows"}

    payload = {
        "task": "Generate a Sigma rule draft from this CTI detection context.",
        "report_context": {
            "title": ioc_json.get("report_title") or ioc_json.get("report_id"),
            "description": f"CTI report {ioc_json.get('report_title') or ioc_json.get('report_id')} contains indicators and ATT&CK mappings.",
        },
        "ioc_candidates": iocs,
        "attack_context": attack_context,
        "expected_logsource": logsource,
    }
    return [
        {"role": "system", "content": sigma_system_prompt()},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]


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


_MODEL_CACHE: dict[tuple[str, str], tuple[Any, Any]] = {}


def load_hf_lora_model(model_name: str, adapter_name: str) -> tuple[Any, Any]:
    key = (model_name, adapter_name)
    if key in _MODEL_CACHE:
        return _MODEL_CACHE[key]

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        trust_remote_code=True,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
    )
    model = PeftModel.from_pretrained(model, adapter_name)
    model.eval()
    _MODEL_CACHE[key] = (tokenizer, model)
    return tokenizer, model


def generate_with_hf_lora(config: argparse.Namespace, ioc_json: dict[str, Any], attack_json: dict[str, Any]) -> dict[str, Any]:
    import torch

    tokenizer, model = load_hf_lora_model(config.rule_model, config.rule_adapter)
    messages = prompt_for_sigma_model(ioc_json, attack_json)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=config.rule_max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated = output_ids[0][inputs["input_ids"].shape[-1] :]
    raw = tokenizer.decode(generated, skip_special_tokens=True)
    pred, extracted = extract_json_object(raw)
    if pred is None:
        raise ValueError(f"model did not return valid JSON: {extracted[:300]}")
    return pred


def finalize_model_rule(rule: dict[str, Any], ioc_json: dict[str, Any], attack_json: dict[str, Any]) -> dict[str, Any]:
    report_id = str(ioc_json.get("report_id") or "cti-report")
    values = [
        str(item.get("normalized_value") or item.get("value"))
        for item in ioc_json.get("iocs", [])[:12]
        if item.get("normalized_value") or item.get("value")
    ]
    rule.setdefault("title", f"Sigma Rule from {ioc_json.get('report_title') or report_id}")
    rule.setdefault("status", "experimental")
    rule.setdefault("description", f"Generated from CTI report {ioc_json.get('report_title') or report_id}.")
    rule.setdefault("falsepositives", ["Unknown"])
    rule.setdefault("level", "medium")
    rule["id"] = rule.get("id") or stable_rule_id(report_id, "hf_lora", values)
    rule["author"] = rule.get("author") or "LLM-driven CTI-to-Detection Pipeline"
    rule["date"] = rule.get("date") or "2026/06/04"
    if "tags" not in rule:
        tags = []
        for mapping in attack_json.get("ttp_mappings", []):
            technique_id = str(mapping.get("technique_id", "")).lower()
            if technique_id:
                tags.append(f"attack.{technique_id}")
        if tags:
            rule["tags"] = sorted(set(tags))
    return rule


def validate_rule_paths(rule_paths: list[str], out_json: Path) -> dict[str, Any]:
    results = [validate_file(Path(path)) for path in rule_paths]
    summary = {
        "rules_dir": str(out_json.parent),
        "rule_count": len(results),
        "valid_count": sum(1 for item in results if item["valid"]),
        "invalid_count": sum(1 for item in results if not item["valid"]),
        "results": results,
    }
    write_json(out_json, summary)
    return summary


def write_rules(rules: list[dict[str, Any]], report_id: str, rules_dir: Path) -> list[str]:
    rules_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for rule in rules:
        filename = f"{slugify(report_id)}.{slugify(rule['id'])}.sigma.yml"
        out_path = rules_dir / filename
        out_path.write_text(dump_yaml(rule) + "\n", encoding="utf-8")
        paths.append(str(out_path))
    return paths


def make_rule_generation_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        out_paths = ensure_dirs(Path(state["out_dir"]))
        state["rule_attempts"] = int(state.get("rule_attempts", 0)) + 1
        report_id = str(state["ioc_json"].get("report_id") or "cti-report")

        rules: list[dict[str, Any]]
        if config.rule_provider == "hf-lora":
            try:
                draft = generate_with_hf_lora(config, state["ioc_json"], state["attack_json"])
                rules = [finalize_model_rule(draft, state["ioc_json"], state["attack_json"])]
                event(state, "rule_generation", "generated Sigma draft with HF LoRA", adapter=config.rule_adapter)
            except Exception as exc:
                add_error(state, f"hf-lora rule generation failed: {type(exc).__name__}: {exc}")
                rules = []
        else:
            rules = generate_rules(state["ioc_json"], state["attack_json"])
            event(state, "rule_generation", "generated Sigma rules with deterministic generator", rule_count=len(rules))

        rule_paths = write_rules(rules, report_id, out_paths["rules"]) if rules else []
        validation_json = Path(state["out_dir"]) / "validation_results.json"
        validation = validate_rule_paths(rule_paths, validation_json)
        state["rules_dir"] = str(out_paths["rules"])
        state["rule_paths"] = rule_paths
        state["validation_json_path"] = str(validation_json)
        state["validation_summary"] = validation
        event(
            state,
            "rule_validation",
            "rule validation complete",
            rule_count=validation["rule_count"],
            invalid_count=validation["invalid_count"],
        )
        return state

    return node


def make_rule_retry_node(config: argparse.Namespace):
    def node(state: PipelineState) -> PipelineState:
        out_paths = ensure_dirs(Path(state["out_dir"]))
        report_id = str(state["ioc_json"].get("report_id") or "cti-report")
        rules = generate_rules(state["ioc_json"], state["attack_json"])
        rule_paths = write_rules(rules, report_id, out_paths["rules"])
        validation_json = Path(state["out_dir"]) / "validation_results.json"
        validation = validate_rule_paths(rule_paths, validation_json)
        state["rule_attempts"] = int(state.get("rule_attempts", 1)) + 1
        state["rule_paths"] = rule_paths
        state["validation_json_path"] = str(validation_json)
        state["validation_summary"] = validation
        if validation["invalid_count"]:
            state["human_review_required"] = True
        event(state, "rule_retry", "deterministic fallback complete", rule_count=len(rule_paths), invalid_count=validation["invalid_count"])
        return state

    return node


def route_after_rules(config: argparse.Namespace):
    def route(state: PipelineState) -> str:
        invalid = int(state.get("validation_summary", {}).get("invalid_count", 0))
        if invalid or not state.get("rule_paths"):
            if int(state.get("rule_attempts", 0)) <= config.max_rule_retries:
                return "rule_retry"
            state["human_review_required"] = True
        return END

    return route


def build_graph(config: argparse.Namespace):
    graph = StateGraph(PipelineState)
    graph.add_node("ioc_extraction", make_ioc_extraction_node(config))
    graph.add_node("ioc_retry", make_ioc_retry_node(config))
    graph.add_node("ttp_mapping", make_ttp_mapping_node(config))
    graph.add_node("ttp_fallback", make_ttp_fallback_node(config))
    graph.add_node("rule_generation", make_rule_generation_node(config))
    graph.add_node("rule_retry", make_rule_retry_node(config))

    graph.set_entry_point("ioc_extraction")
    graph.add_conditional_edges(
        "ioc_extraction",
        route_after_ioc(config),
        {"ioc_retry": "ioc_retry", "ttp_mapping": "ttp_mapping"},
    )
    graph.add_edge("ioc_retry", "ttp_mapping")
    graph.add_conditional_edges(
        "ttp_mapping",
        route_after_ttp(config),
        {"ttp_fallback": "ttp_fallback", "rule_generation": "rule_generation"},
    )
    graph.add_edge("ttp_fallback", "rule_generation")
    graph.add_conditional_edges(
        "rule_generation",
        route_after_rules(config),
        {"rule_retry": "rule_retry", END: END},
    )
    graph.add_conditional_edges(
        "rule_retry",
        route_after_rules(config),
        {"rule_retry": "rule_retry", END: END},
    )
    return graph.compile()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CTI-to-Detection pipeline with LangGraph.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pdf", type=Path, help="Input CTI PDF report.")
    source.add_argument("--input-ioc-json", type=Path, help="Existing IoC JSON to start from Module A output.")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--kb-jsonl", type=Path, default=REPO_ROOT / "TTP/data/attack_technique_kb_augmented.jsonl")

    parser.add_argument("--min-iocs", type=int, default=1)
    parser.add_argument("--max-ioc-retries", type=int, default=1)
    parser.add_argument("--min-techniques", type=int, default=1)

    parser.add_argument("--ttp-provider", choices=["prompt-only", "openai-compatible", "ollama"], default="prompt-only")
    parser.add_argument("--api-base", default="http://192.168.28.151:11434")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--ttp-model", default="gpt-oss:20b")
    parser.add_argument("--ttp-temperature", type=float, default=0.0)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-ttp-retries", type=int, default=1)
    parser.add_argument("--retry-sleep", type=float, default=5.0)
    parser.add_argument("--include-ioc-evidence", action="store_true")
    parser.add_argument("--max-chars", type=int, default=1200)
    parser.add_argument("--overlap", type=int, default=150)
    parser.add_argument("--min-chars", type=int, default=80)
    parser.add_argument("--max-evidence", type=int, default=3)

    parser.add_argument("--rule-provider", choices=["deterministic", "hf-lora"], default="deterministic")
    parser.add_argument("--rule-model", default=DEFAULT_BASE_MODEL)
    parser.add_argument("--rule-adapter", default=DEFAULT_ADAPTER)
    parser.add_argument("--rule-max-new-tokens", type=int, default=768)
    parser.add_argument("--max-rule-retries", type=int, default=1)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    initial_state: PipelineState = {
        "out_dir": str(args.out_dir),
        "human_review_required": False,
        "events": [],
        "errors": [],
    }
    if args.pdf:
        initial_state["pdf_path"] = str(args.pdf)
    if args.input_ioc_json:
        initial_state["input_ioc_json"] = str(args.input_ioc_json)

    app = build_graph(args)
    final_state = app.invoke(initial_state)
    state_path = args.out_dir / "pipeline_state.json"
    write_json(state_path, final_state)

    print(json.dumps(
        {
            "ioc_json": final_state.get("ioc_json_path"),
            "attack_json": final_state.get("attack_json_path"),
            "rules_dir": final_state.get("rules_dir"),
            "validation": final_state.get("validation_json_path"),
            "human_review_required": final_state.get("human_review_required", False),
            "errors": final_state.get("errors", []),
        },
        ensure_ascii=False,
        indent=2,
    ))
    print(f"wrote: {state_path}")


if __name__ == "__main__":
    main()
