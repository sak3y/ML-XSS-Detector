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

## Design decisions

Each choice below has an alternative that was rejected, and a reason.

**Classical ML over deep learning.** 200 training snippets is far below what a transformer or LSTM needs to generalise on code. TF-IDF with a linear model is the appropriate capacity for the data available, and its coefficients are inspectable, which matters when the output is a security claim someone has to act on.

**Logistic regression and random forest, both.** LR gives a linear, readable decision boundary over token weights. RF catches token interactions LR cannot. Running both shows whether the extra capacity buys anything here. It does not: RF scores lower on recall, which is consistent with 200 samples being too few for the ensemble to beat a linear fit.

**Underscore rewriting rather than a custom analyzer.** `location.search` split into `location` and `search` loses the source. Both halves appear in safe code; only the pair is evidence. Rewriting to `location_search` before vectorisation keeps the pair intact while still using the stock TF-IDF tokeniser, so the transformation is one visible preprocessing step instead of a bespoke regex analyzer buried in the vectoriser config.

**Stratifying by task category, not by label.** Stratifying on the label balances vulnerable and safe but lets a single task category flood the test set, which inflates scores for whatever that category happens to reward. Stratifying on category keeps the task mix representative and, because categories are near-balanced internally, keeps the label ratio close enough.

**Nine rules grouped by sink family, not by source.** Sinks are a closed, enumerable set: HTML injection points, dynamic code execution, and framework-specific escapes. Sources are open-ended. Writing rules against sinks gives bounded coverage that can be stated precisely; writing them against sources gives an endless list with no completion criterion.

**Excluding hardcoded string assignments where the AST allows it.** `el.innerHTML = "<b>hello</b>"` is a sink with no source and flagging it is noise. The exclusion is done structurally rather than by string matching so it does not misfire on concatenation that happens to start with a literal.

**`javascript:` URL sinks left out of scope, and documented.** Location assignment and anchor `href` rewrites are a distinct sink family that would need its own rules and its own labelled examples. Shipping nine rules that are tested beats eleven where two are guesses. The gap is recorded in `xss.yml` rather than left implicit.

**Prompt-generated data, with one real-world category as a control.** Coverage of 18 task categories with a known vulnerable/safe balance is not obtainable from public repositories in the time available. Generating the bulk of the set makes coverage controllable; the GitHub category exists so the subpopulation split can show whether performance holds on code that was not generated. The trade-off is that generated snippets are cleaner and more uniform than production JavaScript.

**Source, sink and a written justification stored per row.** A bare label cannot be audited. Recording which source reaches which sink, and why that makes the snippet vulnerable, makes every label checkable after the fact and forces the criterion to be applied consistently rather than by feel.

**Recall weighted over precision when reading the results.** A missed DOM XSS reaches production. A false positive costs a developer a few minutes. F1 is reported as the headline because it is comparable across detectors, but the ranking decision follows recall, which is why Semgrep at 0.920 recall is preferred over LR at 1.000 precision.

**Semgrep run from the CLI, not invoked from the notebook.** Keeps the scan reproducible outside Python and makes the JSON an inspectable artefact rather than a hidden in-process call. The cost is a manual step that can silently no-op, which is what the verification command below exists to catch.

**Statistical tests rather than a bare comparison of point estimates.** On a 50-snippet test set the difference between 0.939 and 0.913 F1 is within noise unless it is tested. Bootstrap CIs give the spread, McNemar's test compares the detectors on the same items, and the false-negative overlap is reported because it determines whether ensembling would help. It would not.

## Limitations

- **50-snippet test set.** Precision of 1.000 rests on roughly 21 predictions; one false positive moves it to 0.95. The bootstrap CIs in the notebook are the honest version of every number in the results table.
- **Single labeller.** No inter-annotator agreement was measured. A second labeller over a sample is the first thing this needs.
- **Seventeen of 18 categories are generated.** Production JavaScript is messier, longer, and mixes concerns within a file. The subpopulation split is a check on this, not a fix for it.
- **Semgrep is not trained,** so it never saw the 200 training snippets. The comparison is fair on the held-out test set, but the two approaches are not being asked for the same thing: one encodes domain knowledge up front, the other has to infer it from 200 examples.
- **Rules cover three sink families.** `javascript:` URL sinks, `srcdoc` via `setAttribute`, and DOM clobbering are out of scope.

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