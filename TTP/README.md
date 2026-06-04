# Module B: TTP Mapping Baseline

This folder contains the first implementation for Module B of the LLM-driven CTI-to-Detection pipeline.

The goal of Module B is to map CTI report text or extracted evidence to MITRE ATT&CK techniques. This first version builds a technique knowledge base from MITRE ATT&CK STIX data and evaluates a deterministic retrieval baseline on the Security-TTP-Mapping dataset.

## Resources

The external resources are stored outside the repository:

```text
/home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/
├── security-ttp-mapping/
├── tram/
└── attack-stix-data/
```

| Resource | Purpose |
| --- | --- |
| `security-ttp-mapping` | Training/dev/test data for TTP mapping evaluation |
| `tram` | MITRE / CTID reference tool for CTI-to-ATT&CK mapping |
| `attack-stix-data` | MITRE ATT&CK technique knowledge base for RAG/retrieval |

## Step 1: Build ATT&CK Technique Knowledge Base

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/attack-stix-data/enterprise-attack/enterprise-attack.json \
  --out-jsonl TTP/data/attack_technique_kb.jsonl \
  --out-json TTP/data/attack_technique_kb.json
```

For the RAG version, build an augmented KB using labeled examples from the Security-TTP-Mapping training splits:

```bash
python3 TTP/build_attack_kb.py \
  --stix-json /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/attack-stix-data/enterprise-attack/enterprise-attack.json \
  --examples-root /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping \
  --examples-per-technique 8 \
  --out-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --out-json TTP/data/attack_technique_kb_augmented.json
```

The output contains active Enterprise ATT&CK techniques and sub-techniques with:

- technique ID
- name
- description
- tactics
- platforms
- data sources
- ATT&CK URL
- search document for retrieval

## Step 2: Run TF-IDF Retrieval Baseline

```bash
python3 TTP/evaluate_ttp_baseline.py \
  --kb-jsonl TTP/data/attack_technique_kb.jsonl \
  --dataset-root /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_baseline_results \
  --top-k 10
```

This evaluates a zero-shot baseline:

```text
input CTI sentence / paragraph
      ↓
TF-IDF retrieval over ATT&CK technique KB
      ↓
top-k candidate techniques
      ↓
compare against dataset labels
```

The baseline is deterministic and does not use an LLM yet. Its purpose is to provide a measurable starting point for Week 16.

To evaluate the augmented RAG KB:

```bash
python3 TTP/evaluate_ttp_baseline.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-root /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_baseline_results_augmented \
  --top-k 10
```

## Metrics

The evaluator reports:

- top-1 hit rate
- top-3 hit rate
- top-5 hit rate
- top-10 hit rate
- label recall at k
- MRR

For multi-label examples, a top-k hit is counted if at least one gold ATT&CK technique appears in the retrieved candidates. Label recall measures how many gold labels are recovered.

## Step 3: LLM/RAG Mapping

The LLM/RAG mapper retrieves ATT&CK candidates first and then asks an LLM to select only the techniques supported by the evidence.

```text
CTI evidence
      ↓
retrieve top-k ATT&CK techniques
      ↓
LLM selects valid techniques and explains evidence
      ↓
ATT&CK JSON output
```

This keeps deterministic retrieval as a grounding step and lets the LLM handle the semantic decision.

### Prompt-only Mode

Use this mode when no LLM API key is available. It produces grounded prompts and candidate techniques, but does not call a model:

```bash
python3 TTP/rag_ttp_mapper.py \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --dataset-tsv /home/johnson/1151_LLM-Cyber-artifacts/data/ttp_mapping_resources/security-ttp-mapping/datasets/tram/tram_test.tsv \
  --limit 3 \
  --top-k 10 \
  --provider prompt-only \
  --out-jsonl /home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_baseline_results_augmented/rag_prompt_tram_test_3.jsonl
```

### OpenAI-compatible LLM Mode

Use this mode with an OpenAI-compatible Chat Completions endpoint:

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

### Ollama Mode

Use this mode with the remote Ollama server:

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

The LLM is constrained to choose only from the retrieved candidate techniques. The script validates the model output and rejects hallucinated technique IDs.

## Step 4: Map Module A CTI JSON to ATT&CK JSON

Use `map_cti_to_attack.py` to connect Module A enriched IoC/CTI JSON with Module B:

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

This produces one `.attack.json` file per CTI report:

```text
/home/johnson/1151_LLM-Cyber-artifacts/outputs/ttp_mapping_cti_outputs_ollama/
├── 360_APT-C-56-TransparentTribe-camouflage-campaign(03-13-2023).iocs.attack.json
└── all_reports_attack_summary.json
```

Example demo result:

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

The demo output is stored in:

```text
TTP/results/cti_demo/
```

This output is the ATT&CK JSON interface that can be passed to Module C for Sigma rule generation.
