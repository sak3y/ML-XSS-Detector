# ML XSS Detector

Machine learning versus static analysis for spotting DOM XSS in AI-generated JavaScript. A TF-IDF + logistic regression classifier (and a random forest) is trained on 250 labelled snippets, then compared against a proximity-rule baseline and a hand-written 9-rule Semgrep configuration on a held-out 50-snippet test set.

## Results (held-out test set, vulnerable class)

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Semgrep (9 custom rules) | 0.958 | 0.920 | **0.939** |
| Logistic Regression | 1.000 | 0.840 | 0.913 |
| Random Forest | 1.000 | 0.800 | 0.889 |
| Rule-based proximity baseline | 1.000 | 0.640 | 0.780 |

Semgrep's two false negatives are a subset of LR's four, so a union of the two detectors performs no better than Semgrep alone on this test set. Bootstrap 95% CIs, McNemar's test, and a subpopulation split (prompt-generated vs real-world GitHub snippets) are computed in the notebook.

## Contents

```
.
├── xss_detector.ipynb           full pipeline notebook, 18 sections
├── xss.yml                      Semgrep rules (9 hand-written DOM XSS sinks)
├── requirements.txt             pinned Python dependencies
├── data/
│   ├── dataset_labelled.csv     250 labelled snippets, one per row
│   ├── test_snippets/           50 .js files, the 20% test split (written by the notebook)
│   └── semgrep_output.json      Semgrep findings, generated in step 2 below
└── README.md
```

## Dataset

250 JavaScript snippets across 18 task categories (URL parameter display, comment rendering, welcome messages, and so on), near-balanced at 124 vulnerable / 126 safe. Seventeen categories are prompt-generated; one ("GitHub - real world") is sourced from public repositories. Each row carries the snippet, its source and sink, the label, and a written justification.

## Pipeline

The notebook runs load → tokenise → TF-IDF → stratified 80/20 split → train LR and RF → 5-fold CV → feature importance → rule baseline → Semgrep comparison → statistical tests.

Two details worth knowing:

- **Security-aware tokenisation.** Dotted identifiers like `location.search` and `document.write` carry the signal, and a default tokeniser splits them apart. They are rewritten with underscores before vectorisation so each survives as a single token.
- **Split stratified by task category, not label.** Keeps the task mix of the test set representative instead of letting one category dominate.

All randomised operations use `random_state=42`.

## Reproduction

Python 3.12. Exact versions are pinned in `requirements.txt`.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run Semgrep against the test set **from the repository root**:

```bash
semgrep --config xss.yml data/test_snippets/ --json --quiet --metrics=off \
        --output data/semgrep_output.json
```

### Windows

Semgrep does not run natively on Windows, so use Docker for that step. Everything else runs in plain PowerShell.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```powershell
docker run --rm -v "${PWD}:/src" returntocorp/semgrep `
  semgrep --config /src/xss.yml /src/data/test_snippets/ `
  --json --quiet --metrics=off --output /src/data/semgrep_output.json
```

Then open `xss_detector.ipynb` and run the cells in order. Sections 1 to 9 can be re-run in any order once Section 4 has produced the split; Sections 10 to 18 must run in sequence, and Section 11 reads the `semgrep_output.json` produced above. Total runtime is under two minutes on a laptop.

### Verify the Semgrep run before trusting the comparison

If Semgrep cannot find `xss.yml` (wrong working directory, wrong mount path in Docker), it still exits and still writes a JSON file, just one with an empty `results` array and the failure buried in `errors`. The notebook then scores Semgrep at zero across the board, which looks like a result rather than a bug. Sanity-check the output before running Section 11:

```bash
python -c "import json; d=json.load(open('data/semgrep_output.json', encoding='utf-8-sig')); \
assert not d['errors'], d['errors']; print(len(d['results']), 'findings')"
```

A correct run against the committed test set produces findings in roughly half the files. Zero findings with a non-empty `errors` array means the scan never happened.

## Semgrep rules

`xss.yml` covers three sink families: direct HTML sinks (`innerHTML`/`outerHTML`, `document.write`, `insertAdjacentHTML`, `iframe.srcdoc`, jQuery `.html()`), dynamic code execution (`eval`, `new Function`, string-argument `setTimeout`/`setInterval`), and React's `dangerouslySetInnerHTML`. Hardcoded string assignments are excluded where the AST allows it; `javascript:` URL sinks are noted as not yet covered.
