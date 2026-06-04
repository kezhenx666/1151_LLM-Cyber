# LLM-driven CTI-to-Detection Pipeline

This repository contains the Module A, Module B, and initial Module C implementation for an LLM-driven CTI-to-Detection pipeline. It converts CTI PDF reports into structured IoC JSON, maps report evidence to MITRE ATT&CK techniques, and generates Sigma detection rules with validation.

## Overview

The project focuses on the first stage of the team pipeline:

![LLM-driven CTI-to-Detection Pipeline](docs/mermaid-diagram.png)

```text
CTI Report PDF/HTML
      ↓
Parser
      ├── IoC Extraction  ->  IoC JSON
      └── TTP Mapping     ->  ATT&CK JSON

IoC JSON + ATT&CK JSON
      ↓
Rule Generation
      ↓
Sigma Validator
      ↓
Final Detection Output
```

Module A is responsible for extracting Indicators of Compromise (IoCs), normalizing defanged indicators, reducing false positives, and producing stable IoC JSON for downstream modules. Module B maps CTI evidence to ATT&CK techniques with RAG and Ollama. Module C generates Sigma rules from IoC JSON and ATT&CK JSON, then validates the output.

## Repository Structure

```text
1151_LLM-Cyber/
├── IOC/
│   └── IOC_parser.py
│
├── JSON_handle/
│   └── merge.py
│
├── evaluation/
│   ├── export_annotations.py
│   ├── evaluate_annotations.py
│   └── evaluate_ioc_output.py
│
├── TTP/
│   ├── build_attack_kb.py
│   ├── evaluate_ttp_baseline.py
│   ├── map_cti_to_attack.py
│   ├── rag_ttp_mapper.py
│   ├── data/
│   │   ├── attack_technique_kb.json
│   │   ├── attack_technique_kb.jsonl
│   │   ├── attack_technique_kb_augmented.json
│   │   └── attack_technique_kb_augmented.jsonl
│   └── results/
│       ├── ttp_tfidf_baseline_metrics.json
│       └── ttp_tfidf_augmented_baseline_metrics.json
│
├── RuleGeneration/
│   ├── build_finetune_dataset.py
│   ├── evaluate_sigma_generation_model.py
│   ├── generate_sigma_from_dirs.py
│   ├── generate_sigma_rules.py
│   ├── validate_sigma_rules.py
│   ├── verify_finetune_dataset.py
│   ├── huggingface_model_card_sigma_generation_lora.md
│   ├── fine_tune_data/
│   │   ├── sigma_generation_train.jsonl
│   │   ├── sigma_generation_validation.jsonl
│   │   └── sigma_generation_test.jsonl
│   ├── fine_tune_data_full/
│   │   ├── sigma_generation_train.jsonl
│   │   ├── sigma_generation_validation.jsonl
│   │   └── sigma_generation_test.jsonl
│   ├── llamafactory_configs/
│   │   ├── qwen2_5_7b_sigma_generation_smoke.yaml
│   │   └── qwen2_5_7b_sigma_generation_full.yaml
│   └── results/
│       ├── cti_demo/
│       └── model_eval/
│
├── Pipeline/
│   ├── langgraph_pipeline.py
│   └── README.md
│
├── docs/
│   ├── CODE_OVERVIEW.md
│   ├── PROJECT_HANDOFF_STATUS.md
│   ├── WEEK15_ANNOTATION_GUIDE.md
│   ├── mermaid-diagram.png
│   └── screenshots/
│
└── README.md
```

Notes:

- `IOC/IOC_parser.py` is the improved Week 15 IoC extractor.
- `JSON_handle/merge.py` merges IoC JSON with PDF parser/layout JSON.
- `TTP/` contains the first Week 16 TTP mapping baseline.
- `RuleGeneration/` contains the first Sigma rule generation and validation implementation.
- `evaluation/` contains the annotation and metric scripts used in Week 15.
- `docs/WEEK15_ANNOTATION_GUIDE.md` explains the manual IoC review workflow in Chinese.
- `docs/CODE_OVERVIEW.md` summarizes the important code files, their responsibilities, and the main commands.
- `docs/PROJECT_HANDOFF_STATUS.md` records the latest end-to-end status, remote fine-tuning result, WebChat screenshots, and Hugging Face adapter link.

## Important Code Map

For a quick code walkthrough, start from:

| Stage | Important File | Purpose |
| --- | --- | --- |
| Module A | `IOC/IOC_parser.py` | Parse PDF reports and extract/refang/filter IoCs |
| Module A enrichment | `JSON_handle/merge.py` | Merge IoC JSON with optional parser/layout JSON |
| Module A evaluation | `evaluation/export_annotations.py` | Export IoC candidates for manual labeling |
| Module A evaluation | `evaluation/evaluate_annotations.py` | Build ground truth and calculate precision/recall/F1 |
| Module B KB | `TTP/build_attack_kb.py` | Convert MITRE ATT&CK STIX into a technique KB |
| Module B baseline | `TTP/evaluate_ttp_baseline.py` | Run TF-IDF ATT&CK mapping baseline |
| Module B RAG | `TTP/rag_ttp_mapper.py` | Run LLM/RAG ATT&CK mapping evaluation |
| Module B CTI mapping | `TTP/map_cti_to_attack.py` | Map all extracted CTI reports to ATT&CK JSON |
| Module C rule generation | `RuleGeneration/generate_sigma_from_dirs.py` | Batch generate Sigma rules from IoC and ATT&CK JSON |
| Module C validation | `RuleGeneration/validate_sigma_rules.py` | Validate generated Sigma YAML structure |
| Fine-tuning data | `RuleGeneration/build_finetune_dataset.py` | Build Sigma generation SFT JSONL from SigmaHQ rules |
| Model evaluation | `RuleGeneration/evaluate_sigma_generation_model.py` | Evaluate base/LoRA models for Sigma generation |
| Pipeline orchestration | `Pipeline/langgraph_pipeline.py` | Connect A/B/C as LangGraph nodes with retry/fallback logic |

Full code explanation:

```text
docs/CODE_OVERVIEW.md
```

Released LoRA adapter:

```text
https://huggingface.co/jjhoada/qwen2.5-7b-sigma-generation-lora
```

## Dependencies

Python packages used by the IoC extractor and TTP mapper:

```bash
python3 -m pip install pypdf tldextract urlextract requests langgraph
```

Main dependencies:

| Package | Purpose |
| --- | --- |
| `pypdf` | Extract text from PDF reports |
| `tldextract` | Normalize and validate registered domains |
| `urlextract` | URL extraction experiments and compatibility |
| `requests` | Call an OpenAI-compatible LLM endpoint for TTP RAG mapping |
| `langgraph` | Orchestrate Module A/B/C as a graph with retry and fallback edges |

Optional dependencies for Node C with the Hugging Face LoRA adapter:

```bash
python3 -m pip install transformers peft accelerate torch
```

## Step 1: IoC Extraction

The improved IoC extractor is located at:

```text
IOC/IOC_parser.py
```

It extracts:

- IPv4 addresses
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes
- CVE identifiers

It also includes Week 15 improvements:

- Defanged IoC normalization
- Adjacent/PDF-merged IPv4 matching, such as `80.85.157[.]3N/A`
- URL splitting when multiple URLs are merged by PDF text extraction
- Redacted and placeholder URL filtering
- Benign/vendor/contact domain filtering
- File-like domain artifact filtering, such as `s.zip` and `internal.properties`
- Placeholder IP filtering, such as `2.2.2.2`

### Usage

```bash
python3 IOC/IOC_parser.py \
  --pdf-dir /path/to/pdf_reports \
  --metadata /path/to/download_log.csv \
  --out-dir /path/to/ioc_json_output
```

The metadata CSV is optional. If provided, it should include fields such as report title, source, year, link, and saved filename.

### IoC JSON Output

Each PDF produces one `.iocs.json` file. A combined output is also generated as `all_reports_iocs.json`.

The extractor now uses the same enriched-compatible schema as the final merge output. This keeps the raw extractor output compatible with the teammate enrichment layer while preserving extractor metadata such as source, year, page count, and extraction errors.

Example raw extractor structure:

```json
{
  "schema_version": "cti-enriched-lite-v1",
  "report_id": "example_report",
  "report_title": "Example CTI Report",
  "source_type": "pdf",
  "source": "CISA",
  "year": "2023",
  "original_link": "https://example.com/report.pdf",
  "pdf_file": "/path/to/report.pdf",
  "page_count": 12,
  "text_length": 25000,
  "extraction_errors": [],
  "sections": [],
  "iocs": [
    {
      "type": "domain",
      "value": "matclick.com",
      "normalized_value": "matclick.com",
      "section": "unknown",
      "context": "GraphicalProton HTTPS C2 URL: https://matclick.com/wp-query.php",
      "confidence": 0.6,
      "source": ["regex", "tldextract"],
      "evidence": [
        {
          "source": "regex_ioc_extractor",
          "section_title": "unknown",
          "content": "GraphicalProton HTTPS C2 URL: https://matclick.com/wp-query.php"
        }
      ]
    }
  ],
  "ioc_summary": {
    "domain": 1
  },
  "threat_context": {},
  "merge_notes": {
    "base_json": "ioc_extractor_json",
    "enrichment_json": null,
    "dedup_key": ["type", "normalized_value"]
  }
}
```

## Step 2: PDF Structure Parsing

This repository does not include the full `opendataloader-pdf` package due to dependency and file-size considerations.

If PDF layout or section structure is required, install or set up:

```text
https://github.com/opendataloader-project/opendataloader-pdf
```

The parser output can then be merged with IoC JSON in Step 3.

## Step 3: JSON Enrichment / Merge

The merge script is located at:

```text
JSON_handle/merge.py
```

It merges:

1. IoC extractor JSON
2. PDF parser/layout JSON

The IoC extractor JSON is treated as the base data source. The PDF parser JSON is used as an enrichment source.

The merge process adds or updates:

- Reconstructed sections
- Evidence text
- Source information
- Confidence adjustment
- IP and port relationship
- Basic threat context
- Existing extractor metadata, including report source, year, original link, page count, text length, and extraction errors

### Merge Usage

```bash
python3 JSON_handle/merge.py \
  --ioc-dir /path/to/ioc_json_output \
  --parser-dir /path/to/parser_json_output \
  --out-dir /path/to/merged_output
```

Files are matched by filename stem.

Example:

```text
ioc_json/report_001.iocs.json
parser_json/report_001.json
        ↓
merged/report_001.iocs.json
```

The merged output format:

```json
{
  "schema_version": "cti-enriched-lite-v1",
  "report_id": "...",
  "report_title": "...",
  "source_type": "pdf",
  "source": "...",
  "year": "...",
  "original_link": "...",
  "pdf_file": "...",
  "page_count": 12,
  "text_length": 25000,
  "extraction_errors": [],
  "sections": [],
  "iocs": [],
  "ioc_summary": {},
  "threat_context": {},
  "merge_notes": {}
}
```

## Week 15 Evaluation Workflow

The Week 15 evaluation tools are in:

```text
evaluation/
```

### 1. Export Annotation CSV

```bash
python3 evaluation/export_annotations.py \
  --combined-json /path/to/all_reports_iocs.json \
  --out-dir /path/to/week15_evaluation
```

This creates:

```text
candidate_annotations.csv
missed_iocs.csv
subset_manifest.json
```

### 2. Manually Review Candidates

Open `candidate_annotations.csv` and fill the `label` column with:

```text
malicious
benign
placeholder
false_positive
uncertain
```

If the PDF contains real IoCs missed by the extractor, add them to `missed_iocs.csv`.

See:

```text
docs/WEEK15_ANNOTATION_GUIDE.md
```

### 3. Build Ground Truth and Evaluate Annotations

```bash
python3 evaluation/evaluate_annotations.py \
  --annotations /path/to/week15_evaluation/candidate_annotations.csv \
  --missed-iocs /path/to/week15_evaluation/missed_iocs.csv \
  --out-dir /path/to/week15_evaluation/results
```

This produces:

```text
ground_truth.json
evaluation_metrics.json
```

### 4. Compare IoC Output Against Ground Truth

```bash
python3 evaluation/evaluate_ioc_output.py \
  --output-dir /path/to/ioc_json_output \
  --ground-truth /path/to/week15_evaluation/results/ground_truth.json \
  --out /path/to/output_metrics.json
```

## Week 15 Evaluation Results

The reviewed evaluation subset used 5 CTI reports and 89 baseline IoC candidates.

### Baseline Result

| Metric | Result |
| --- | ---: |
| True Positive | 52 |
| False Positive | 37 |
| False Negative | 3 |
| Precision | 0.5843 |
| Recall | 0.9455 |
| F1-score | 0.7223 |

### Improved Baseline Result

| Metric | Result |
| --- | ---: |
| True Positive | 55 |
| False Positive | 0 |
| False Negative | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1-score | 1.0000 |

Important interpretation:

The improved extractor achieved perfect metrics only on the manually reviewed 5-report evaluation subset. This does not prove perfect performance on all 43 reports or unseen CTI reports. It does show that the Week 15 error patterns were successfully identified and fixed.

### Full 43-report Candidate Count

| Version | Total Candidates | Domain | IPv4 | URL | MD5 | SHA1 | SHA256 | CVE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 1608 | 688 | 95 | 238 | 259 | 30 | 254 | 44 |
| Improved baseline | 1455 | 611 | 116 | 141 | 259 | 30 | 254 | 44 |

URL and domain candidates decreased after filtering. IPv4 candidates increased because the improved regex recovered defanged or PDF-adjacent IP addresses that were previously missed.

## Module B: TTP Mapping Baseline

The first Module B implementation is located at:

```text
TTP/
```

It uses three external resources:

| Resource | Local Path | Purpose |
| --- | --- | --- |
| Security-TTP-Mapping | `/home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping` | Training/dev/test evaluation splits |
| MITRE / CTID TRAM | `/home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/tram` | Reference implementation for CTI-to-ATT&CK mapping |
| MITRE ATT&CK STIX data | `/home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/attack-stix-data` | Technique knowledge base for retrieval and future RAG |

### Build ATT&CK Technique KB

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/attack-stix-data/enterprise-attack/enterprise-attack.json \
  --out-jsonl TTP/data/attack_technique_kb.jsonl \
  --out-json TTP/data/attack_technique_kb.json
```

The current Enterprise ATT&CK KB contains:

| Item | Count |
| --- | ---: |
| Active techniques and sub-techniques | 697 |
| Sub-techniques | 475 |

For the LLM/RAG version, the KB is augmented with training examples from Security-TTP-Mapping:

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/attack-stix-data/enterprise-attack/enterprise-attack.json \
  --examples-root /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping \
  --examples-per-technique 8 \
  --out-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --out-json TTP/data/attack_technique_kb_augmented.json
```

The augmented KB has training examples for 484 techniques.

### Run TTP Mapping Baseline

```bash
python3 TTP/evaluate_ttp_baseline.py \
  --kb-jsonl TTP/data/attack_technique_kb.jsonl \
  --dataset-root /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_baseline_results \
  --top-k 10
```

This baseline is a deterministic TF-IDF retrieval system. It maps each CTI sentence or paragraph to the most similar ATT&CK techniques in the KB.

Selected baseline results:

| Dataset Split | Samples | Top-1 Hit | Top-5 Hit | Top-10 Hit | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| `procedures/procedure_test.tsv` | 1767 | 0.2926 | 0.5382 | 0.6389 | 0.3990 |
| `tram/tram_test.tsv` | 725 | 0.1903 | 0.3710 | 0.4690 | 0.2703 |
| `expert/expert_test.tsv` | 157 | 0.2229 | 0.4841 | 0.6178 | 0.3400 |

Selected augmented KB retrieval results:

| Dataset Split | Samples | Top-1 Hit | Top-5 Hit | Top-10 Hit | MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| `procedures/procedure_test.tsv` | 1767 | 0.2332 | 0.5252 | 0.6701 | 0.3562 |
| `tram/tram_test.tsv` | 725 | 0.1669 | 0.4166 | 0.5476 | 0.2704 |
| `expert/expert_test.tsv` | 157 | 0.3057 | 0.5605 | 0.6879 | 0.4113 |

The augmented KB improves top-k candidate coverage, which is useful for RAG because the LLM can only select techniques that appear in the retrieved candidate set.

The full metrics are stored at:

```text
TTP/results/ttp_tfidf_baseline_metrics.json
```

This version does not yet use an LLM. It provides a measurable retrieval baseline and a candidate-generation step for future LLM/RAG mapping:

```text
CTI evidence
      ↓
retrieve top-k ATT&CK candidate techniques
      ↓
LLM selects valid techniques with evidence
      ↓
ATT&CK JSON output
```

### LLM/RAG Mapper

The LLM/RAG mapper is located at:

```text
TTP/rag_ttp_mapper.py
```

Prompt-only mode generates grounded prompts and retrieved ATT&CK candidates without calling a model:

```bash
python3 TTP/rag_ttp_mapper.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-tsv /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping/datasets/tram/tram_test.tsv \
  --limit 3 \
  --top-k 10 \
  --provider prompt-only \
  --out-jsonl /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_baseline_results_augmented/rag_prompt_tram_test_3.jsonl
```

When an API key and model are available, it can call an OpenAI-compatible Chat Completions endpoint:

```bash
export LLM_API_KEY="..."
export LLM_MODEL="your-model-name"

python3 TTP/rag_ttp_mapper.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-tsv /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping/datasets/tram/tram_test.tsv \
  --limit 10 \
  --top-k 10 \
  --provider openai-compatible \
  --out-jsonl /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_llm_results/tram_test_10.jsonl \
  --metrics-out /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_llm_results/tram_test_10_metrics.json
```

The prompt requires JSON output and the script rejects hallucinated technique IDs that are not in the retrieved candidate list.

Remote Ollama mode is also supported:

```bash
python3 TTP/rag_ttp_mapper.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-tsv /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping/datasets/tram/tram_test.tsv \
  --limit 725 \
  --top-k 10 \
  --provider ollama \
  --api-base http://192.168.28.151:11434 \
  --model gpt-oss:20b \
  --timeout 180 \
  --resume \
  --out-jsonl /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_llm_results/ollama_tram_test_725.jsonl \
  --metrics-out /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_llm_results/ollama_tram_test_725_metrics.json
```

Full Ollama evaluation result on the 725-sample TRAM test split:

| Metric | Result |
| --- | ---: |
| Evaluated samples | 725 |
| Exact sample hit rate | 0.4483 |
| Family-level sample hit rate | 0.5876 |
| Average selected techniques per sample | 1.3959 |
| Average gold techniques per sample | 1.1738 |

Runtime note:

- 725 samples took about 2.9 hours of accumulated request runtime.
- Average runtime was about 14.39 seconds per sample.
- Median runtime was about 13.50 seconds per sample.
- No error rows were recorded in the completed 725-sample run.

### A-to-B CTI Integration

The TTP mapper can also consume Module A enriched IoC/CTI JSON and produce ATT&CK JSON for Module C:

```bash
python3 TTP/map_cti_to_attack.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --input-json /home/johnson/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_ollama \
  --provider ollama \
  --api-base http://192.168.28.151:11434 \
  --model gpt-oss:20b \
  --timeout 180 \
  --top-k 10 \
  --max-evidence 5
```

Example demo result from the 360 Transparent Tribe report:

| Metric | Result |
| --- | ---: |
| Evidence chunks mapped | 5 |
| Techniques selected | 4 |
| Validation errors | 0 |

Selected techniques:

| Technique | Name | Tactic |
| --- | --- | --- |
| `T1566.001` | Spearphishing Attachment | Initial Access |
| `T1683.001` | Written Content | Resource Development |
| `T1070.004` | File Deletion | Stealth |
| `T1083` | File and Directory Discovery | Discovery |

The demo ATT&CK JSON output is stored in:

```text
TTP/results/cti_demo/
```

## Module C: Sigma Rule Generation and Validation

Module C consumes:

```text
Module A IoC JSON + Module B ATT&CK JSON
```

and produces Sigma YAML detection rules.

### Generate Rules

```bash
python3 RuleGeneration/generate_sigma_rules.py \
  --ioc-json /home/johnson/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --attack-json /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_ollama/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.attack.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_360
```

### Validate Rules

```bash
python3 RuleGeneration/validate_sigma_rules.py \
  --rules-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_360 \
  --out-json /home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_360/validation_results.json
```

Demo result from the 360 Transparent Tribe report:

| Metric | Result |
| --- | ---: |
| Sigma rules generated | 2 |
| Valid rules | 2 |
| Invalid rules | 0 |

Generated rule types:

| IoC Type | Sigma Logsource |
| --- | --- |
| IPv4 | `network_connection` |
| MD5 | `file` |

The generated rules include ATT&CK tags from Module B, such as `attack.t1566.001`, `attack.t1070.004`, and `attack.t1083`.

### C Fine-tuning Dataset

Module C includes a full fine-tuning dataset built from SigmaHQ rules:

```bash
python3 RuleGeneration/build_finetune_dataset.py \
  --sigma-rules-dir /home/johnson/1151_LLM-Cyber-artifacts/data/sigma_resources/sigma/rules \
  --out-dir RuleGeneration/fine_tune_data_full
```

3132 YAML rules were found. 3110 valid fine-tuning records were generated. 22 were skipped due to unsupported or missing fields.

Full dataset split:

| Split | Records |
| --- | ---: |
| Train | 2488 |
| Validation | 311 |
| Test | 311 |
| Total | 3110 |

The dataset is verified with:

```bash
python3 RuleGeneration/verify_finetune_dataset.py \
  --data-dir RuleGeneration/fine_tune_data_full \
  --out-json RuleGeneration/fine_tune_data_full/verification_results.json
```

Verification result:

| Metric | Result |
| --- | ---: |
| JSONL files | 3 |
| Records | 3110 |
| Valid | true |

### C Model Fine-tuning and Evaluation

The full fine-tuning dataset was used to fine-tune Qwen2.5-7B-Instruct on a remote NVIDIA L40S GPU using LLaMA-Factory LoRA training.

Training configuration:

| Setting | Value |
| --- | --- |
| Base model | Qwen/Qwen2.5-7B-Instruct |
| Method | LoRA (rank 16, alpha 32) |
| Epochs | 3 |
| Effective batch size | 8 |
| Total steps | 933 |
| Train loss | 0.2066 |
| Training time | ~49 minutes on L40S |

Model evaluation results on the test split:

| Model | JSON Valid | Required Fields | Detection Condition | Logsource Exact | ATT&CK Recall | IoC Preservation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen2.5-1.5B base | 0.80 | 0.00 | 0.00 | 0.00 | 0.00 | 0.3167 |
| Qwen2.5-1.5B 50-step LoRA | 1.00 | 1.00 | 1.00 | 1.00 | 0.20 | 0.7189 |
| Qwen2.5-7B base | 1.00 | 1.00 | 1.00 | 0.40 | 0.20 | 0.8692 |
| **Qwen2.5-7B full LoRA (3 epochs)** | **0.96** | **0.96** | **0.96** | **0.96** | **0.96** | **0.8174** |

Fine-tuning on 3 epochs raised logsource exact match from 0.40 to 0.96 and ATT&CK tag recall from 0.20 to 0.96. These are the two most critical fields for a deployable Sigma detection rule.

Evaluation results are stored at:

```text
RuleGeneration/results/model_eval/
├── qwen2_5_1_5b_base_test5.json
├── qwen2_5_1_5b_smoke_lora_test5.json
├── qwen2_5_1_5b_local_mini_lora_test5.json
├── qwen2_5_7b_base_test5_remote.json
└── qwen2_5_7b_full_lora_test50.json
```

The fine-tuned model should generate Sigma rule draft JSON. Deterministic post-processing should add `id`, `author`, and `date`, then `RuleGeneration/validate_sigma_rules.py` should validate the final YAML.

## Integration Notes

The recommended Week 16 integrated flow is:

```text
CTI PDF
      ↓
IOC/IOC_parser.py
      ↓
IoC JSON
      ↓ 
opendataloader-pdf parser JSON
      ↓
JSON_handle/merge.py
      ↓
LLM-ready enriched CTI JSON
      ↓
TTP/map_cti_to_attack.py
      ↓
ATT&CK JSON
      ↓
RuleGeneration/generate_sigma_rules.py
      ↓
RuleGeneration/validate_sigma_rules.py
```

The current extractor is deterministic. LLM refinement can be added as a second-stage validation layer using the `context` field in each IoC entry.

Suggested LLM labels:

```text
malicious
benign
placeholder
false_positive
uncertain
```

## Limitations

- The reviewed ground truth currently covers only 5 reports.
- PDF text extraction can still merge or split table content incorrectly.
- The `section` field remains `unknown` unless parser JSON is merged.
- Filtering rules may need updates for new CTI report formats.
- LLM refinement is designed but not yet fully integrated into the execution pipeline.

## Full 43-Report Pipeline Results

The complete A-to-C pipeline was run on all 43 APT CTI reports.

Module B (TTP mapping) results:

| Metric | Result |
| --- | ---: |
| Reports processed | 43 / 43 |
| Total technique selections | 115 |
| Reports with zero techniques | 6 |
| Validation errors | 0 |

Module C (Sigma rule generation) results:

| Metric | Result |
| --- | ---: |
| Reports processed | 43 |
| Sigma rules generated | 136 |
| Valid rules | 136 |
| Invalid rules | 0 |

Full outputs are stored at:

```text
/home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_all_ollama/
/home/johnson/1151_LLM-Cyber-artifacts/outputs/sigma_rule_outputs_all/
```

## Recommended Next Steps

- Build a single `pipeline.py` that chains Modules A, B, and C end-to-end from a CTI PDF input to a set of Sigma rules.
- Evaluate the fine-tuned 7B model on a larger test slice (full 311-record test split) for a more robust comparison.
- Export and upload the LoRA adapter to Hugging Face or merge it into a standalone model for deployment.
