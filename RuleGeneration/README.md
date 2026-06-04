# Module C: Sigma Rule Generation and Validation

This folder contains the first implementation for Module C of the LLM-driven CTI-to-Detection pipeline.

Module C consumes:

1. Module A enriched IoC JSON
2. Module B ATT&CK JSON

It generates Sigma YAML rules and validates the generated rules with deterministic schema checks.

## Input

Example inputs:

```text
/home/johnson/360_APT-C-56-TransparentTribe-camouflage-campaign(03-13-2023).iocs.json
/home/johnson/ttp_mapping_cti_outputs_ollama/360_APT-C-56-TransparentTribe-camouflage-campaign(03-13-2023).iocs.attack.json
```

Module C uses:

| Source | Fields |
| --- | --- |
| IoC JSON | `iocs[].type`, `iocs[].normalized_value`, `report_id`, `report_title` |
| ATT&CK JSON | `ttp_mappings[].technique_id`, `technique_name`, `tactics`, `evidence` |

## Generate Sigma Rules

```bash
python3 RuleGeneration/generate_sigma_rules.py \
  --ioc-json /home/johnson/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --attack-json /home/johnson/ttp_mapping_cti_outputs_ollama/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.attack.json \
  --out-dir /home/johnson/sigma_rule_outputs_360
```

The generator creates one Sigma rule per supported IoC group:

| IoC Type | Logsource |
| --- | --- |
| `ipv4` | `network_connection` |
| `domain` | `dns` |
| `url` | `proxy` |
| `md5`, `sha1`, `sha256` | `file` |

Basic benign source/reference domains such as `qq.com`, `github.com`, and vendor domains are skipped to avoid generating noisy detection rules from report metadata.

## Validate Sigma Rules

```bash
python3 RuleGeneration/validate_sigma_rules.py \
  --rules-dir /home/johnson/sigma_rule_outputs_360 \
  --out-json /home/johnson/sigma_rule_outputs_360/validation_results.json
```

The validator checks:

- required Sigma top-level fields
- `logsource`
- `detection`
- `detection.condition`
- UUID-like rule ID
- ATT&CK tags

This first validator does not require external packages. If `pySigma` is available later, a compile step can be added.

## Demo Result

Demo output is stored in:

```text
RuleGeneration/results/cti_demo/
```

For the 360 Transparent Tribe report:

| Metric | Result |
| --- | ---: |
| Sigma rules generated | 2 |
| Valid rules | 2 |
| Invalid rules | 0 |

Generated rules:

| Rule Type | Output |
| --- | --- |
| IPv4 infrastructure | network connection Sigma rule |
| MD5 hashes | file hash Sigma rule |

The generated rules include ATT&CK tags from Module B, such as:

```text
attack.t1566.001
attack.t1683.001
attack.t1070.004
attack.t1083
```

## Fine-tuning Experiment

Module C also includes a fine-tuning dataset builder for Sigma rule drafting.

The dataset is built from SigmaHQ rules:

```text
/home/johnson/sigma_resources/sigma/rules
```

### Build Fine-tuning Dataset

```bash
python3 RuleGeneration/build_finetune_dataset.py \
  --sigma-rules-dir /home/johnson/sigma_resources/sigma/rules \
  --out-dir RuleGeneration/fine_tune_data_full
```

3132 YAML rules were found. 3110 valid fine-tuning records were generated. 22 were skipped due to unsupported or missing fields.

Generated files:

```text
RuleGeneration/fine_tune_data_full/
├── sigma_generation_train.jsonl
├── sigma_generation_validation.jsonl
├── sigma_generation_test.jsonl
├── dataset_summary.json
└── verification_results.json
```

Full dataset split:

| Split | Records |
| --- | ---: |
| Train | 2488 |
| Validation | 311 |
| Test | 311 |
| Total | 3110 |

### Dataset Format

Each training record uses chat-message JSONL:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You generate Sigma rule drafts from CTI-derived IoC and ATT&CK context. Output JSON only..."
    },
    {
      "role": "user",
      "content": "{... detection request JSON ...}"
    },
    {
      "role": "assistant",
      "content": "{... Sigma rule draft JSON ...}"
    }
  ]
}
```

The assistant output intentionally excludes:

```text
id
author
date
```

These fields should be added by deterministic post-processing, then checked by the Sigma validator.

### Verify Dataset

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

### Fine-tuning and Evaluation

The full dataset was used to fine-tune Qwen2.5-7B-Instruct on a remote NVIDIA L40S using LLaMA-Factory LoRA (rank 16, alpha 32, 3 epochs). Training took about 49 minutes. Train loss: 0.2066.

LLaMA-Factory configs:

```text
RuleGeneration/llamafactory_configs/
├── qwen2_5_7b_sigma_generation_smoke.yaml
└── qwen2_5_7b_sigma_generation_full.yaml
```

Evaluation results on the test split:

| Model | JSON Valid | Required Fields | Detection Condition | Logsource Exact | ATT&CK Recall | IoC Preservation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen2.5-1.5B base | 0.80 | 0.00 | 0.00 | 0.00 | 0.00 | 0.3167 |
| Qwen2.5-1.5B 50-step LoRA | 1.00 | 1.00 | 1.00 | 1.00 | 0.20 | 0.7189 |
| Qwen2.5-7B base | 1.00 | 1.00 | 1.00 | 0.40 | 0.20 | 0.8692 |
| **Qwen2.5-7B full LoRA (3 epochs)** | **0.96** | **0.96** | **0.96** | **0.96** | **0.96** | **0.8174** |

Evaluation results are stored at:

```text
RuleGeneration/results/model_eval/
├── qwen2_5_1_5b_base_test5.json
├── qwen2_5_1_5b_smoke_lora_test5.json
├── qwen2_5_1_5b_local_mini_lora_test5.json
├── qwen2_5_7b_base_test5_remote.json
└── qwen2_5_7b_full_lora_test50.json
```

The evaluation script is at:

```bash
python /root/evaluate_sigma_generation_model.py \
  --model Qwen/Qwen2.5-7B-Instruct \
  --adapter saves/Qwen2.5-7B-Instruct/lora/sigma_generation_full \
  --test-jsonl data/sigma_generation/sigma_generation_test.jsonl \
  --out-json /root/model_eval/qwen2_5_7b_full_lora_test50.json \
  --limit 50 \
  --max-new-tokens 512
```
