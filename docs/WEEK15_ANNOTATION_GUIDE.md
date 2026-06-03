# Week 15 IoC 評估標註操作說明

## 目標

人工複核一小部分 IoC candidates，讓系統可以計算 Precision、Recall 與 F1-score，作為 Week 15 報告中的評估結果。

這個流程不需要人工重新整理所有 PDF。你只需要檢查程式已經抽出的候選項目，並在必要時補上程式漏抓的 IoC。

## 檔案說明

- `week15_evaluation/candidate_annotations.csv`：baseline pipeline 抽出的 IoC candidates，也是主要需要填寫的檔案。
- `week15_evaluation/missed_iocs.csv`：如果 PDF 裡有真正的 IoC，但程式沒有抽到，請記錄在這裡。
- `week15_evaluation/subset_manifest.json`：本次抽樣的報告清單、標題與 candidate 數量。
- `week15_evaluation/results/evaluation_metrics.json`：執行評估腳本後產生的指標結果。
- `week15_evaluation/results/ground_truth.json`：執行評估腳本後產生的人工確認標準答案。

## 標註流程

1. 開啟 `week15_evaluation/candidate_annotations.csv`。
2. 每一列代表一個 IoC candidate。閱讀 `type`、`normalized_value` 與 `context` 欄位。
3. 在 `label` 欄位填入以下其中一個值。Label 必須使用表格中的英文，否則評估腳本無法辨識。

| Label | 意義 |
| --- | --- |
| `malicious` | 報告將此值描述為可採取行動的惡意 IoC，例如 C2 IP、惡意網域或惡意檔案 hash。 |
| `benign` | 合法網站、官方網域、引用來源或聯絡資訊，例如 `cisa.gov`。 |
| `placeholder` | 範例、遮罩值、測試資料或不可直接使用的 placeholder。 |
| `false_positive` | 根本不是 IoC，例如檔名、解析錯誤或被誤認為 domain 的文字。 |
| `uncertain` | 僅靠 context 無法判斷，需要進一步查看原始 PDF。此類項目暫時不列入評分。 |

4. 如有需要，可在 `reviewer_note` 欄位補充判斷原因。
5. 如果只看 `context` 無法判斷，請開啟對應的原始 PDF。PDF 位於 `/home/johnson/aptnotes_2023_2024`。
6. 如果在 PDF 裡發現真正的 IoC，但 `candidate_annotations.csv` 沒有列出，請新增到 `week15_evaluation/missed_iocs.csv`。

## `missed_iocs.csv` 欄位說明

| 欄位 | 填寫內容 |
| --- | --- |
| `report_id` | IoC 所屬的報告 ID。可以從 `candidate_annotations.csv` 複製。 |
| `type` | IoC 類型，例如 `ipv4`、`domain`、`url`、`md5`、`sha1`、`sha256` 或 `cve`。 |
| `normalized_value` | 正規化後的 IoC 值，例如將 `evil[.]com` 寫成 `evil.com`。 |
| `evidence` | PDF 中可以支持判斷的上下文。 |
| `reviewer_note` | 可選填，說明為什麼需要手動補上。 |

## 計算評估指標

標註完成後，執行：

```bash
python3 /home/johnson/evaluate_week15_annotations.py \
  --annotations /home/johnson/week15_evaluation/candidate_annotations.csv \
  --missed-iocs /home/johnson/week15_evaluation/missed_iocs.csv \
  --out-dir /home/johnson/week15_evaluation/results
```

腳本會自動更新：

```text
/home/johnson/week15_evaluation/results/evaluation_metrics.json
/home/johnson/week15_evaluation/results/ground_truth.json
```

## 指標解讀

- **Precision**：程式抽出的 candidates 中，有多少是真正惡意的 IoC。
- **Recall**：PDF 中真正惡意的 IoC，有多少被程式成功抽出。
- **F1-score**：Precision 與 Recall 的綜合指標。

只有在檢查原始 PDF 並補上漏抓的 IoC 後，Recall 才具有完整意義。如果暫時只複核 candidates，也可以先將結果視為初步 Precision 評估。
