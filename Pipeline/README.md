# LangGraph Pipeline

This folder contains the LangGraph orchestration layer for the LLM-driven CTI-to-Detection Pipeline.

## Graph

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

The graph is implemented in:

```text
Pipeline/langgraph_pipeline.py
```

## Node Behavior

### Node A: IoC Extraction

Uses `IOC/IOC_parser.py`.

Primary strategy:

- PDF text extraction
- defanged IoC normalization
- strict IoC extraction and filtering

Retry strategy:

- relaxed extraction
- lower confidence candidate recovery
- useful when strict extraction returns too few candidates

### Node B: TTP Mapping

Uses `TTP/map_cti_to_attack.py`.

Primary strategy:

- TF-IDF retrieval over ATT&CK KB
- optional LLM/RAG selection using Ollama or OpenAI-compatible APIs

Fallback strategy:

- if no technique is selected, infer conservative ATT&CK techniques from IoC types
- domain/url/IP indicators can fallback to command-and-control related techniques

### Node C: Rule Generation

Two providers are supported:

| Provider | Description |
| --- | --- |
| `deterministic` | Uses `RuleGeneration/generate_sigma_rules.py` |
| `hf-lora` | Uses the fine-tuned Hugging Face LoRA adapter |

Fine-tuned adapter:

```text
https://huggingface.co/jjhoada/qwen2.5-7b-sigma-generation-lora
```

If `hf-lora` fails or the generated rule does not pass validation, the graph retries with deterministic rule generation.

## Quick Demo With Existing IoC JSON

This avoids rerunning PDF parsing and starts from Module A output.

```bash
cd /home/johnson/1151_LLM-Cyber

python3 Pipeline/langgraph_pipeline.py \
  --input-ioc-json /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360 \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider prompt-only \
  --rule-provider deterministic
```

## Run With Ollama TTP Mapping

```bash
cd /home/johnson/1151_LLM-Cyber

python3 Pipeline/langgraph_pipeline.py \
  --input-ioc-json /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_ollama \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider ollama \
  --api-base http://192.168.28.151:11434 \
  --ttp-model gpt-oss:20b \
  --include-ioc-evidence \
  --max-evidence 3 \
  --rule-provider deterministic
```

Verified local output:

```text
/home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_ollama_b_real
```

Result:

```text
Node A loaded 9 IoCs.
Node B called Ollama gpt-oss:20b on 3 evidence chunks.
Ollama selected 0 techniques for this sample.
Node B fallback selected 2 heuristic techniques: T1071.001 and T1105.
Node C deterministic generation produced 2 Sigma rules.
Validation result: 2 / 2 valid, 0 invalid.
```

Evidence from `pipeline_state.json` / ATT&CK JSON:

```text
mapping_records[0].llm_provider: ollama
mapping_records[0].runtime_seconds: 34.163
mapping_records[1].llm_provider: ollama
mapping_records[1].runtime_seconds: 11.536
mapping_records[2].llm_provider: ollama
mapping_records[2].runtime_seconds: 11.783
```

Verified sample where Ollama selected techniques:

```text
/home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_ahnlab_dalbit_ollama_b_real
```

Result:

```text
Node A loaded 31 IoCs.
Node B called Ollama gpt-oss:20b on 3 evidence chunks.
Node B selected 9 ATT&CK techniques without fallback:
T1059.003, T1090, T1090.001, T1105, T1190, T1482, T1505.001, T1505.003, T1570.
Node C deterministic generation produced 4 Sigma rules.
Validation result: 4 / 4 valid, 0 invalid.
```

## Run Node C With Fine-Tuned LoRA

This requires GPU and these Python packages:

```bash
pip install transformers peft accelerate torch
```

Command:

```bash
cd /home/johnson/1151_LLM-Cyber

python3 Pipeline/langgraph_pipeline.py \
  --input-ioc-json /home/johnson/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign\(03-13-2023\).iocs.json \
  --out-dir /home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_hf_lora \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider prompt-only \
  --rule-provider hf-lora \
  --rule-model Qwen/Qwen2.5-7B-Instruct \
  --rule-adapter jjhoada/qwen2.5-7b-sigma-generation-lora
```

On this local machine, `hf-lora` may fail if model dependencies or GPU resources are unavailable. In that case, the graph automatically retries with deterministic rule generation.

## Remote L40S HF-LoRA Run

The pipeline was also executed on the remote L40S machine with the locally trained LoRA adapter:

```text
/LLaMA-Factory/saves/Qwen2.5-7B-Instruct/lora/sigma_generation_full
```

Remote command:

```bash
ssh -p 24043 root@tw-07.access.glows.ai

cd /root/1151_LLM-Cyber
source /root/miniconda3/etc/profile.d/conda.sh
conda activate workenv

python Pipeline/langgraph_pipeline.py \
  --input-ioc-json "/root/1151_LLM-Cyber-artifacts/data/aptnotes_2023_2024_ioc_json_improved/360_APT-C-56-TransparentTribe-camouflage-campaign(03-13-2023).iocs.json" \
  --out-dir /root/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_hf_lora_remote \
  --kb-jsonl TTP/data/attack_technique_kb_augmented.jsonl \
  --ttp-provider prompt-only \
  --rule-provider hf-lora \
  --rule-model Qwen/Qwen2.5-7B-Instruct \
  --rule-adapter /LLaMA-Factory/saves/Qwen2.5-7B-Instruct/lora/sigma_generation_full \
  --rule-max-new-tokens 768
```

Result:

```text
Node A loaded 9 IoCs.
Node B prompt-only mapping selected 0 techniques.
Node B fallback selected 2 heuristic ATT&CK techniques.
Node C generated 1 Sigma draft with HF LoRA.
Validation result: 1 / 1 valid, 0 invalid.
human_review_required: false
```

Local copy of the remote output:

```text
/home/johnson/1151_LLM-Cyber-artifacts/outputs/langgraph_demo_360_hf_lora_remote
```

## Output Files

Each run writes:

```text
pipeline_state.json
intermediate/*.iocs.json
intermediate/*.attack.json
rules/*.sigma.yml
validation_results.json
```

`pipeline_state.json` records:

- node events
- retry/fallback decisions
- validation summary
- generated output paths
- whether human review is required
