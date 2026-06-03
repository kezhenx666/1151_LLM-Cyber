# CTI PDF to LLM-ready CTI JSON

## Overview

This project converts CTI PDF reports into enriched, LLM-ready CTI JSON files.

The main goal is to extract Indicators of Compromise (IoCs) from CTI PDF reports, enrich them with PDF structure information, and generate a structured JSON format that can be used for downstream intrusion detection rule generation.

The enriched JSON output can be used as input for large language models to generate detection rules such as:

* Sigma rules
* Suricata rules
* Zeek detection logic
* SIEM queries
* Other intrusion detection rule formats

---

## Processing Pipeline

```text
CTI PDF Reports
      │
      ├── Step 1: IoC Extraction
      │       PATH: /IOC/IOC_parser.py
      │       └── Extract IP, domain, URL, hash, and CVE from PDF text
      │
      ├── Step 2: PDF Structure Parsing
      │       TOOL: opendataloader-pdf
      │       └── Extract headings, paragraphs, captions, and list items
      │
      ├── Step 3: JSON Enrichment / Merge
      │       PATH: /JSON handle/merge.py
      │       └── Merge IoC JSON with PDF parser JSON
      │
      └── Step 4: LLM-ready CTI JSON
              └── Use enriched JSON for detection rule generation
```

---

## Project Structure

```text
project/
├── IOC/
│   └── IOC_parser.py
│
├── JSON handle/
│   └── merge.py
│
├── yoooo/
│   ├── report_001.json
│   ├── report_002.json
│   └── report_003.json
│
├── openpdf/
│   ├── report_001.json
│   ├── report_002.json
│   └── report_003.json
│
└── merged/
    ├── report_001.json
    ├── report_002.json
    └── report_003.json
```

> Note: The folder name `JSON handle/` contains a space. When running the script from the command line, remember to wrap the path in quotes.

Example:

```bash
python "JSON handle/merge.py" --ioc-dir yoooo --parser-dir openpdf --out-dir merged
```

---

## Step 1: IoC Extraction

The IoC extraction script is located at:

```text
/IOC/IOC_parser.py
```

This script extracts common Indicators of Compromise from CTI PDF reports, including:

* IPv4 addresses
* Domains
* URLs
* MD5 hashes
* SHA1 hashes
* SHA256 hashes
* CVE identifiers

---

## Step 2: PDF Structure Parsing

This repository does not include the full `opendataloader-pdf` package due to file size and dependency considerations.

If PDF structure parsing is required, please install or set up `opendataloader-pdf` from the official GitHub repository:

```text
https://github.com/opendataloader-project/opendataloader-pdf
```

---

## Step 3: JSON Enrichment / Merge

The merge script is located at:

```text
/JSON handle/merge.py
```

This script merges two JSON outputs from the same CTI PDF report:

1. IoC extractor JSON
2. PDF parser/layout JSON

The IoC extractor JSON is treated as the primary data source.
The PDF parser JSON is used as an enrichment source.

The merge process adds:

* section context
* evidence text
* source information
* confidence adjustment
* IP and port relationship
* threat context

---

## Batch Merge Usage

### Input Arguments

```text
--ioc-dir       Folder containing IoC extractor JSON files
--parser-dir    Folder containing PDF parser/layout JSON files
--out-dir       Folder to save merged JSON files
```

### Example Command

```bash
python "JSON handle/merge.py" \
  --ioc-dir yoooo \
  --parser-dir openpdf \
  --out-dir merged
```

### Windows PowerShell

```powershell
python "JSON handle/merge.py" `
  --ioc-dir yoooo `
  --parser-dir openpdf `
  --out-dir merged
```

---

## Matching Rule

Files are matched by filename stem.

Example:

```text
yoooo/report_001.json
openpdf/report_001.json
        ↓
merged/report_001.json
```

If the IoC file uses the `.iocs.json` suffix, the script can also match it with the corresponding parser JSON.

Example:

```text
yoooo/report_001.iocs.json
openpdf/report_001.json
        ↓
merged/report_001.iocs.json
```

The output filename keeps the original IoC JSON filename.

---

## Output Format

The final output is an enriched CTI JSON file.

Main structure:

```json
{
  "schema_version": "cti-enriched-lite-v1",
  "report_id": "...",
  "report_title": "...",
  "source_type": "pdf",
  "pdf_file": "...",
  "sections": [],
  "iocs": [],
  "ioc_summary": {},
  "threat_context": {},
  "merge_notes": {}
}
```

---

## Output Fields

| Field            | Description                                        |
| ---------------- | -------------------------------------------------- |
| `schema_version` | Version of the enriched CTI JSON format            |
| `report_id`      | Report identifier                                  |
| `report_title`   | Report title                                       |
| `source_type`    | Source type, usually `pdf`                         |
| `pdf_file`       | Original PDF file path                             |
| `sections`       | Reconstructed report sections from the parser JSON |
| `iocs`           | Enriched indicators of compromise                  |
| `ioc_summary`    | Count of IoCs by type                              |
| `threat_context` | Actor, malware, behavior, and C2 context           |
| `merge_notes`    | Notes about the merge strategy                     |


## Merge Strategy

The merge process follows these principles:

1. Use the IoC extractor JSON as the base data source.
2. Use the PDF parser JSON as the enrichment source.
3. Reconstruct report sections from parser headings and text blocks.
4. Match IoCs against section text using `normalized_value`.
5. Deduplicate IoCs by `(type, normalized_value)`.
6. Add parser evidence when the IoC is found in a section.
7. Detect `IP:Port` or `IP：Port` patterns for IPv4 indicators.
8. Adjust confidence based on section matching and IoC section relevance.
9. Build `threat_context` from report sections.
10. Remove low-value PDF layout fields such as page number, bounding box, font, and text color.

---
## Recommended Folder Naming

For better compatibility, it is recommended to avoid spaces in folder names.

Current path:

```text
JSON handle/
```

Recommended path:

```text
JSON_handle/
```

or:

```text
json_handle/
```

If the folder name is not changed, always use quotes when running the script.

```bash
python "JSON handle/merge.py" --ioc-dir yoooo --parser-dir openpdf --out-dir merged
```

