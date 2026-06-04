---
library_name: peft
base_model: Qwen/Qwen2.5-7B-Instruct
tags:
- peft
- lora
- llama-factory
- sigma
- cybersecurity
- cti
- detection-engineering
- mitre-attack
datasets:
- SigmaHQ/sigma
language:
- en
---

# Qwen2.5-7B Sigma Generation LoRA

This repository contains a LoRA adapter fine-tuned from `Qwen/Qwen2.5-7B-Instruct` for Sigma rule draft generation from CTI-derived IoC and MITRE ATT&CK context.

The adapter is part of an academic LLM-driven CTI-to-Detection Pipeline:

```text
CTI Report PDF/HTML
  -> IoC Extraction
  -> ATT&CK TTP Mapping
  -> Sigma Rule Generation
  -> Sigma Validation
```

## Intended Use

The model is intended to generate Sigma-style JSON rule drafts from structured CTI context, including:

- report title and description
- IoC candidates such as domains, URLs, hashes, and IP addresses
- MITRE ATT&CK technique IDs
- expected Sigma logsource

The output should be reviewed and validated before operational use.

## Base Model

```text
Qwen/Qwen2.5-7B-Instruct
```

## Adapter

```text
Finetuning method: LoRA
Training framework: LLaMA-Factory
Adapter name: sigma_generation_full
```

## Training Data

The fine-tuning dataset was built from SigmaHQ rules and converted into instruction-style records.

Dataset summary:

```text
Total records: 3110
Train: 2488
Validation: 311
Test: 311
```

## Training Results

```text
train_runtime: 2960s
train_loss: 0.2066
eval_loss: 0.1575
epochs: 3.0
total_steps: 933
```

## Evaluation

A 50-sample remote evaluation of the fine-tuned 7B LoRA adapter produced:

| Metric | Score |
| --- | ---: |
| Valid JSON rate | 0.96 |
| Required Sigma fields rate | 0.96 |
| Detection condition rate | 0.96 |
| Logsource exact match | 0.96 |
| ATT&CK tag recall | 0.96 |
| IoC preservation | 0.8174 |

## Example Prompt

```json
{
  "task": "Generate a Sigma rule draft from this CTI detection context.",
  "report_context": {
    "title": "Suspicious C2 Domain Connection",
    "description": "A malware sample connects to a suspicious command-and-control domain over HTTP."
  },
  "ioc_candidates": [
    {
      "type": "domain",
      "value": "malicious.example"
    },
    {
      "type": "url",
      "value": "http://malicious.example/update"
    }
  ],
  "attack_context": [
    {
      "technique_id": "T1071.001",
      "technique_name": "Application Layer Protocol: Web Protocols"
    },
    {
      "technique_id": "T1105",
      "technique_name": "Ingress Tool Transfer"
    }
  ],
  "expected_logsource": {
    "product": "windows",
    "category": "network_connection"
  }
}
```

## Example Output

```json
{
  "title": "Suspicious C2 Domain Connection",
  "status": "test",
  "description": "A malware sample connects to a suspicious command-and-control domain over HTTP.",
  "logsource": {
    "product": "windows",
    "category": "network_connection"
  },
  "detection": {
    "selection": {
      "DestinationHostname|contains": "malicious.example",
      "DestinationPort": 80,
      "Image|contains": "http://malicious.example/update"
    },
    "condition": "selection"
  },
  "falsepositives": [
    "Unknown"
  ],
  "level": "high",
  "tags": [
    "attack.t1071.001",
    "attack.t1105"
  ]
}
```

## Loading Example

```python
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

base_model = "Qwen/Qwen2.5-7B-Instruct"
adapter = "YOUR_HF_USERNAME/qwen2.5-7b-sigma-generation-lora"

tokenizer = AutoTokenizer.from_pretrained(base_model)
model = AutoModelForCausalLM.from_pretrained(
    base_model,
    device_map="auto",
    torch_dtype="auto",
)
model = PeftModel.from_pretrained(model, adapter)
```

## Limitations

- The model generates draft detection content and should not be deployed without validation.
- The model may produce syntactically valid but semantically weak rules.
- CTI evidence quality directly affects output quality.
- The adapter should be used together with Sigma validation and analyst review.
