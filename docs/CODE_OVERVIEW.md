# Important Code Overview

This document summarizes the important code files in the LLM-driven CTI-to-Detection Pipeline. It is intended for final report preparation, teammate handoff, and repository review.

## End-to-End Pipeline

```text
CTI PDF reports
  -> Module A: IoC extraction
  -> Module B: ATT&CK TTP mapping
  -> Module C: Sigma rule generation and validation
  -> LoRA fine-tuning dataset and Sigma generation model evaluation
```

## LangGraph Orchestration

### `Pipeline/langgraph_pipeline.py`

Main LangGraph pipeline script.

Responsibilities:

- Wrap Module A, Module B, and Module C as graph nodes.
- Add conditional routing for retry and fallback behavior.
- Record every node decision in `pipeline_state.json`.
- Support human-review flags when retry/fallback cannot produce enough evidence.
- Support deterministic Sigma generation and optional Hugging Face LoRA rule generation.

Graph shape:

```text
PDF Input or existing IoC JSON
    ↓
[Node A] IoC Extraction
    ↓
    ├─ if IoC count is too low
    │     → [Node A Retry] relaxed IoC extraction
    ↓
[Node B] TTP Mapping
    ↓
    ├─ if no ATT&CK technique is selected
    │     → [Node B Fallback] heuristic ATT&CK mapping
    ↓
[Node C] Rule Generation
    ↓
    ├─ if Sigma validation fails
    │     → [Node C Retry] deterministic Sigma generation
    ↓
Output
```

Quick deterministic demo:

```bash
python3 Pipeline/langgraph_pipeline.py \
  --input-ioc-json /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360 \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider prompt-only \
  --rule-provider deterministic
```

Node C with the released LoRA adapter:

```bash
python3 Pipeline/langgraph_pipeline.py \
  --input-ioc-json /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_hf_lora \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider prompt-only \
  --rule-provider hf-lora \
  --rule-model Qwen/Qwen2.5-7B-Instruct \
  --rule-adapter jjhoada/qwen2.5-7b-sigma-generation-lora
```

If the LoRA model cannot be loaded or the generated Sigma rule fails validation, the graph routes to deterministic rule generation as a fallback.

## Module A: IoC Extraction

### `IOC/IOC_parser.py`

Main IoC extraction script.

Responsibilities:

- Parse CTI PDF text.
- Normalize defanged indicators such as `hxxp://evil[.]com`.
- Extract IPv4, domains, URLs, MD5, SHA1, SHA256, and CVE values.
- Filter obvious benign/vendor domains, placeholder IPs, file-like artifacts, and redacted URLs.
- Produce enriched-compatible IoC JSON.

Typical command:

```bash
python3 IOC/IOC_parser.py \
  --pdf-dir /path/to/pdf_reports \
  --metadata /path/to/download_log.csv \
  --out-dir /path/to/ioc_json_output
```

Main output:

```text
*.iocs.json
all_reports_iocs.json
```

Important functions:

- `refang()`: normalizes defanged IoC text.
- `extract_iocs()`: extracts and deduplicates IoCs from report text.
- `extract_pdf_text()`: reads text from PDF files.
- `build_report_json()`: produces the final report-level IoC JSON object.

### `JSON_handle/merge.py`

Optional enrichment/merge script.

Responsibilities:

- Merge IoC extractor JSON with parser/layout JSON.
- Preserve report metadata.
- Add reconstructed sections and evidence text when available.
- Keep the final enriched schema stable for downstream modules.

Typical command:

```bash
python3 JSON_handle/merge.py \
  --ioc-dir /path/to/ioc_json_output \
  --parser-dir /path/to/parser_json_output \
  --out-dir /path/to/merged_output
```

## Module A Evaluation

### `evaluation/export_annotations.py`

Exports a small subset of extracted IoC candidates for manual review.

Output examples:

```text
candidate_annotations.csv
missed_iocs.csv
annotation_manifest.json
```

### `evaluation/evaluate_annotations.py`

Builds ground truth from reviewed annotation CSV files and calculates initial precision, recall, and F1.

### `evaluation/evaluate_ioc_output.py`

Compares an extractor output directory against a ground-truth JSON file.

Useful for comparing:

- regex-only baseline
- improved extractor baseline
- hybrid extraction outputs

## Module B: TTP Mapping

### `TTP/build_attack_kb.py`

Builds the MITRE ATT&CK technique knowledge base from ATT&CK STIX data.

Responsibilities:

- Read `enterprise-attack.json`.
- Extract active ATT&CK Enterprise techniques.
- Include technique ID, name, description, tactics, platforms, data sources, and URLs.
- Optionally augment technique entries with examples from Security-TTP-Mapping training data.

Typical command:

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /path/to/enterprise-attack.json \
  --out-json TTP/data/attack_technique_kb.json \
  --out-jsonl TTP/data/attack_technique_kb.jsonl
```

Augmented KB command:

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /path/to/enterprise-attack.json \
  --examples-root /path/to/security-ttp-mapping \
  --examples-per-technique 5 \
  --out-json TTP/data/attack_technique_kb_augmented.json \
  --out-jsonl TTP/data/attack_technique_kb_augmented.jsonl
```

### `TTP/evaluate_ttp_baseline.py`

TF-IDF retrieval baseline for ATT&CK technique mapping.

Responsibilities:

- Load Security-TTP-Mapping train/dev/test splits.
- Retrieve candidate ATT&CK techniques from the KB.
- Evaluate hit rate against gold technique labels.

Typical command:

```bash
python3 TTP/evaluate_ttp_baseline.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-root /path/to/security-ttp-mapping \
  --split test \
  --out-json TTP/results/ttp_tfidf_augmented_baseline_metrics.json
```

### `TTP/rag_ttp_mapper.py`

LLM/RAG mapper for labeled TTP mapping evaluation.

Responsibilities:

- Retrieve top-k ATT&CK candidates with the TF-IDF retriever.
- Send evidence and candidate techniques to an OpenAI-compatible or Ollama endpoint.
- Parse JSON output.
- Evaluate exact/family-level ATT&CK hits.

Typical command:

```bash
python3 TTP/rag_ttp_mapper.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-root /path/to/security-ttp-mapping \
  --split test \
  --provider ollama \
  --api-base http://192.168.28.151:11434 \
  --model gpt-oss:20b \
  --limit 725 \
  --out-jsonl /path/to/ollama_tram_test_725.jsonl \
  --out-metrics /path/to/ollama_tram_test_725_metrics.json
```

### `TTP/map_cti_to_attack.py`

Maps real Module A CTI IoC JSON files to ATT&CK JSON outputs.

Responsibilities:

- Read all report-level IoC JSON files.
- Build evidence chunks from sections and IoC evidence.
- Retrieve ATT&CK candidates.
- Use LLM/RAG to select supported techniques.
- Write one `.attack.json` output per report.

Typical command:

```bash
python3 TTP/map_cti_to_attack.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --input-dir /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_all_ollama \
  --provider ollama \
  --api-base http://192.168.28.151:11434 \
  --model gpt-oss:20b \
  --timeout 180 \
  --top-k 10 \
  --max-evidence 3 \
  --include-ioc-evidence \
  --resume
```

Important output:

```text
*.attack.json
all_reports_attack_summary.json
```

## Module C: Sigma Rule Generation

### `RuleGeneration/generate_sigma_rules.py`

Core Sigma rule generator.

Responsibilities:

- Read one IoC JSON file and one ATT&CK JSON file.
- Generate Sigma-style YAML rules for supported IoC types.
- Add stable UUID-like rule IDs.
- Add ATT&CK tags when mapped techniques are available.
- Avoid obvious benign domains.

Typical command:

```bash
python3 RuleGeneration/generate_sigma_rules.py \
  --ioc-json /path/to/report.iocs.json \
  --attack-json /path/to/report.attack.json \
  --out-dir /path/to/sigma_rules
```

### `RuleGeneration/generate_sigma_from_dirs.py`

Batch wrapper for full A+B to C rule generation.

Responsibilities:

- Match all `.iocs.json` files with corresponding `.attack.json` files.
- Generate Sigma rules for all reports.
- Write a manifest for generated rules.

Typical command:

```bash
python3 RuleGeneration/generate_sigma_from_dirs.py \
  --ioc-dir /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved \
  --attack-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_all_ollama \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_all
```

Important output:

```text
rules/*.sigma.yml
all_sigma_manifest.json
```

### `RuleGeneration/validate_sigma_rules.py`

Sigma rule validator used for generated YAML outputs.

Responsibilities:

- Check required Sigma top-level fields.
- Check `detection.condition`.
- Check basic `logsource` structure.
- Warn when ATT&CK tags are missing.

Typical command:

```bash
python3 RuleGeneration/validate_sigma_rules.py \
  --rules-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_all/rules \
  --out-json /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_all/validation_results.json
```

## Fine-Tuning Dataset and Model Evaluation

### `RuleGeneration/build_finetune_dataset.py`

Builds instruction-style JSONL records from SigmaHQ rules.

Responsibilities:

- Parse Sigma YAML rules.
- Convert detection fields into structured IoC-like candidates.
- Convert ATT&CK tags into technique mappings.
- Create `system/user/assistant` message records for SFT.
- Split into train/validation/test JSONL files.

Typical command:

```bash
python3 RuleGeneration/build_finetune_dataset.py \
  --sigma-rules-dir /home/johnson/1151_LLM-Cyber-artifacts/data/sigma_resources/sigma/rules \
  --out-dir RuleGeneration/fine_tune_data_full \
  --seed 42
```

Important output:

```text
sigma_generation_train.jsonl
sigma_generation_validation.jsonl
sigma_generation_test.jsonl
dataset_summary.json
```

### `RuleGeneration/verify_finetune_dataset.py`

Verifies the JSONL fine-tuning dataset.

Checks:

- each record is valid JSON
- message roles are `system`, `user`, `assistant`
- user and assistant contents are valid JSON strings
- assistant output contains required Sigma fields

Typical command:

```bash
python3 RuleGeneration/verify_finetune_dataset.py \
  --data-dir RuleGeneration/fine_tune_data_full \
  --out-json RuleGeneration/fine_tune_data_full/verification_results.json
```

### `RuleGeneration/evaluate_sigma_generation_model.py`

Evaluates a base or LoRA-adapted model on the Sigma generation test set.

Responsibilities:

- Load a Hugging Face causal language model.
- Optionally load a PEFT LoRA adapter.
- Generate Sigma JSON from test prompts.
- Calculate JSON validity, required field rate, detection condition rate, logsource match, ATT&CK recall, and IoC preservation.

Typical command:

```bash
python RuleGeneration/evaluate_sigma_generation_model.py \
  --model Qwen/Qwen2.5-7B-Instruct \
  --adapter jjhoada/qwen2.5-7b-sigma-generation-lora \
  --test-jsonl RuleGeneration/fine_tune_data_full/sigma_generation_test.jsonl \
  --out-json RuleGeneration/results/model_eval/qwen2_5_7b_full_lora_test50.json \
  --limit 50 \
  --max-new-tokens 512
```

## LLaMA-Factory Configs

### `RuleGeneration/llamafactory_configs/qwen2_5_7b_sigma_generation_smoke.yaml`

One-step smoke training config used to verify that the remote L40S environment works.

### `RuleGeneration/llamafactory_configs/qwen2_5_7b_sigma_generation_full.yaml`

Full Qwen2.5-7B LoRA training config for Sigma rule generation.

Remote output adapter:

```text
/LLaMA-Factory/saves/Qwen2.5-7B-Instruct/lora/sigma_generation_full
```

Hugging Face adapter:

```text
https://huggingface.co/jjhoada/qwen2.5-7b-sigma-generation-lora
```

### `RuleGeneration/huggingface_model_card_sigma_generation_lora.md`

Model card used for the Hugging Face LoRA adapter upload.

## Important Results

### TTP Mapping

```text
Full test evaluation: 725 samples
Exact hit rate: 0.4483
Family hit rate: 0.5876
```

### Full CTI Mapping

```text
43 / 43 reports mapped
115 total ATT&CK technique selections
```

### Sigma Rule Generation

```text
136 Sigma rules generated
136 / 136 rules valid
```

### Sigma Fine-Tuning

```text
Fine-tuning records: 3110
Train: 2488
Validation: 311
Test: 311
```

### Qwen2.5-7B Full LoRA Evaluation

```text
Valid JSON rate: 0.96
Required Sigma fields rate: 0.96
Detection condition rate: 0.96
Logsource exact match: 0.96
ATT&CK tag recall: 0.96
IoC preservation: 0.8174
```

## What To Read First

For a quick understanding of the codebase, read in this order:

1. `README.md`
2. `docs/PROJECT_HANDOFF_STATUS.md`
3. `IOC/IOC_parser.py`
4. `TTP/map_cti_to_attack.py`
5. `RuleGeneration/generate_sigma_from_dirs.py`
6. `RuleGeneration/build_finetune_dataset.py`
7. `RuleGeneration/evaluate_sigma_generation_model.py`
8. `Pipeline/langgraph_pipeline.py`
