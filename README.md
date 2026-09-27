# Snort ATT&CK Coverage Analysis

This project parses Snort 3 rules and produces reproducible, exploratory research outputs for rule structure, revision activity, MITRE ATT&CK coverage, mapping gaps, and optional LLM-assisted classification. It analyses either one `classtype` or a complete ruleset while preserving the original rule text in the detailed output.

## Requirements

- **Python 3.10+** (standard library only for Stages 1–3; no extra packages required for keyword/heuristic analysis).
- **PowerShell** (Windows PowerShell or PowerShell 7+) to run the provided `.ps1` workflow scripts.
- **Snort 3 Community Ruleset** as a `.rules` file or the official `.zip` archive.
- **MITRE Enterprise ATT&CK STIX data** (`data/enterprise-attack.json`) — a local copy is expected; see [Update MITRE ATT&CK Data](#update-mitre-attck-data) below to refresh it.
- An **NVIDIA API key** (`NVIDIA_API_KEY` environment variable) only if running Stage 4 or Stage 5 LLM analysis.

## Workflow

1. Load a `.rules` file or rules ZIP and parse supported Snort rule headers and options.
2. Extract metadata, references, content, PCRE, flow, service, buffer, revision, and rule-identification fields.
3. Calculate existing rule-complexity scores and categories.
4. Resolve direct ATT&CK references and transparent heuristic candidates against the local Enterprise ATT&CK STIX catalog.
5. Calculate coverage, frequency, inflation, revision, validation, and unmapped-rule findings.
6. Optionally validate already mapped rules with an LLM to test whether the model can independently reproduce existing ATT&CK mappings (Stage 4).
7. Optionally submit broader rule context to an OpenAI-compatible endpoint, compare keyword and LLM results, and create an analyst validation queue (Stage 5).
8. Write CSV, JSON, Markdown, and SVG outputs.

## Mapping and Validation Methodology

- **Direct ATT&CK mapping:** an explicit `attack.mitre.org` reference in a rule is extracted and resolved against the local STIX catalog.
- **Heuristic ATT&CK mapping:** transparent message, service, and rule-keyword selectors propose leads only; they are not confirmed mappings.
- **STIX validation:** resolved techniques are labelled active, deprecated, revoked, or unknown. Direct mapping is the strongest coverage evidence in this project.
- **Coverage analysis:** reports rule-to-technique coverage, technique frequency, category gaps, and potential coverage inflation where many rules cover few techniques.
- **Unmapped rules:** records deterministic reasons including missing ATT&CK references, unsupported heuristic indicators, and limited observable context.
- **Optional LLM classification:** returns active catalog IDs only, keeps per-rule rationale and confidence, and requires manual validation before LLM-only mappings are treated as coverage evidence.
- **Mapped-rule LLM validation:** sends only already mapped rule context to the configured LLM and compares the independent prediction with the existing ATT&CK mapping. It does not change parsing, mapping, or unmapped-rule outputs.
- **Manual validation:** `validation_dataset.csv` is an analyst queue. Its reviewer fields are intentionally blank and do not influence calculations.

## LLM Stages and Multi-LLM Validation

Stages 1–3 (parsing, ATT&CK resolution, coverage analysis) run offline over all
4,017 rules and require no API key. Stages 4 and 5 are opt-in, operate on two
disjoint cohorts, and never overwrite a keyword or heuristic mapping.

### Stage 4 — LLM validation of already mapped rules

- Cohort: the 430 rules the keyword and heuristic mapping already covered.
- The model receives only the rule context, never the existing mapping, and
  independently predicts ATT&CK techniques. Its answer is then compared with
  the existing mapping.
- Purpose: assess consistency and whether the existing mapping is
  reproducible from the rule evidence alone.
- Agreement does not establish that either mapping is correct, and
  disagreement does not by itself invalidate the existing mapping. Rules where
  the model declines to predict are recorded separately from rules where it
  proposes something different.
- Output: `mapped_rule_llm_validation.csv` and `mapped_rule_llm_validation.svg`.

### Stage 5 — LLM classification of initially unmapped rules

- Cohort: the 3,587 rules the keyword and heuristic mapping left unmapped.
- Candidate ATT&CK techniques are generated from the rule evidence, restricted
  to active IDs in the local STIX catalog.
- Output is treated as **candidate/proposed mapping requiring analyst
  validation**, not as confirmed ATT&CK coverage, and it does not replace the
  deterministic or heuristic mapping.
- Outputs: `llm_classification_results.csv`,
  `keyword_llm_classification_comparison.csv`, and the `llm_candidate` rows of
  `unmapped_rule_candidates.csv`.

Because the two cohorts are disjoint, Stage 4 and Stage 5 results are not
directly comparable and should not be aggregated into a single agreement
figure.

### Multi-LLM validation (20-rule sample)

A 20-rule sample was evaluated independently by three separate LLMs. This is a
small qualitative check on a subset, separate from the full 4,017-rule
analysis; it does not measure the accuracy of the full ruleset and does not
replace the analyst validation queue.

- `multi_llm_validation_sample_20.xlsx`: the sampled rules with their full
  Snort rule text, cohort, existing project mapping, project LLM prediction and
  confidence, and the difficulty classification and evidence basis taken from
  `difficulty_analysis_output/`.
- `manual_multi_llm_validation.xlsx`: per-SID results recording the project
  prediction, three independent model predictions with confidences, the LLM
  consensus, the manual validation verdict, and a short written reason.

The workbooks label the three systems as **Model 1**, **Model 2** and
**Model 3**. No vendor or model identifier is recorded in the project files, so
the correspondence between those labels and specific models is not documented
here.

## Run the Analysis

### Full ruleset (all categories)

```powershell
python .\snort_rule_analyzer.py `
"C:\Users\Admin\Downloads\snort3-community-rules\snort3-community-rules.zip" `
--all-categories `
--output .\all_categories_output
```

### Single category

```powershell
python .\snort_rule_analyzer.py `
"C:\Users\Admin\Downloads\snort3-community-rules\snort3-community-rules.zip" `
--category trojan-activity `
--output .\analysis_output
```

### Scripted all-category workflow (keyword/heuristic only, no LLM)

```powershell
.\run_keyword_llm_analysis.ps1 -Source "C:\path\to\rules.zip"
```

### Stage 5 — LLM classification of unmapped rules

```powershell
$env:NVIDIA_API_KEY = "nvapi-..."
.\run_keyword_llm_analysis.ps1 `
  -Source "C:\path\to\rules.zip" `
  -EnableLlm `
  -LlmTarget unmapped `
  -LlmMaxRules 100
```

The provider defaults to NVIDIA's OpenAI-compatible endpoint
(`https://integrate.api.nvidia.com/v1/chat/completions`) with
`nvidia/nemotron-3-ultra-550b-a55b`. Pass `-Model` and `-Endpoint` to use a
different one.

Start with a limited LLM cohort to assess cost, latency, and review quality. `-LlmMaxRules 0` evaluates all rules. See [LLM_WORKFLOW.md](LLM_WORKFLOW.md) for endpoint and data-handling details.

### Stage 4 — LLM validation of already mapped rules

```powershell
$env:NVIDIA_API_KEY = "nvapi-..."
.\run_keyword_llm_analysis.ps1 `
  -Source "C:\path\to\rules.zip" `
  -EnableMappedValidation `
  -MappedValidationMaxRules 100
```

### Run tests

```powershell
python -m unittest -v
```

## Generated Outputs

### Core Rule and Summary Outputs

- `report.md`: readable interpretation of scope, complexity, coverage, validation, unmapped rules, and LLM comparison when run.
- `full_summary.json`: structured all-category summary for downstream analysis.
- `all_rules.csv`: flattened parsed rule data for filtering and tabular research.
- `all_rules.json`: detailed parsed rules, including raw rule text, for reproducibility.
- `research_metrics.json`: headline research metrics and calculation metadata, including optional LLM comparison metrics.

### ATT&CK and Coverage Outputs

- `attack_mapping_dataset.csv`: rule-level direct, heuristic, and unmapped ATT&CK mapping evidence.
- `category_attack_coverage.csv`: all-category direct and heuristic coverage by technique.
- `coverage_gaps.csv`: category-level low-coverage and mapping-gap signals.
- `coverage_inflation.csv`: rules-per-technique values that identify low technique diversity.
- `technique_frequency.csv`: ATT&CK technique frequency with Top 20 and Bottom 20 labels.
- `modern_attack_comparison.csv`: selected modern attack-type comparison based on existing selectors.
- `category_statistics.csv` / `pattern_statistics.csv`: category volume, coverage, complexity, and recurring detection-pattern context.
- `frequently_updated_rules.csv`: highest-revision rules for update triage.

### Unmapped and Validation Outputs

- `unmapped_rules.csv`: unmapped rule inventory and deterministic reasons.
- `unmapped_classification_analysis.csv`: keyword and optional LLM interpretation of remaining unmapped rules.
- `unmapped_rule_candidates.csv`: validation-required improved-heuristic and optional LLM ATT&CK candidates for rules that were originally unmapped.
- `validation_findings.csv`: missing required fields, duplicate SID, unknown, and revoked ATT&CK checks.
- `extended_validation_report.csv`: adds duplicate SID+REV checks to the validation findings.
- `validation_dataset.csv`: future analyst validation queue with blank `reviewer_name`, `validation_date`, and `validation_comment` fields.

### Optional LLM Comparison Outputs

- `llm_classification_results.csv`: LLM technique proposals, confidence, rationale, processing status, and errors.
- `keyword_llm_classification_comparison.csv`: rule-level agreement, overlap, and coverage delta between deterministic and LLM approaches.
- `mapped_rule_llm_validation.csv`: existing ATT&CK mapping versus independent LLM prediction for mapped rules.
- `classification_coverage_comparison.svg`: visual comparison of keyword and LLM coverage.
- `classification_difference_breakdown.svg`: visual breakdown of agreement and disagreement states.
- `mapped_rule_llm_validation.svg`: visual summary of mapped-rule LLM agreement and disagreement states.

## Research Metrics

`coverage_score` is the fraction of rules with direct or heuristic ATT&CK evidence. `inflation_ratio` is total rules divided by unique mapped techniques. Keyword and LLM classification rates, coverage improvement, agreement, newly classified rules, remaining unmapped rules, and mean LLM confidence are reported when the relevant execution data is available. Candidate-mapping metrics separately report newly mapped candidates, remaining rules without candidates, and candidate coverage opportunity; they do not change established coverage. `mapped_rule_llm_validation` reports total tested rules, exact matches, disagreements, agreement percentage, and average LLM confidence for already mapped rules. Each metric's exact calculation is included in `research_metrics.json`.

## Interpretation Limits

- The supplied rules archive is a snapshot, not a revision history; `rev` indicates change count rather than the nature of change.
- SID cohorts are exploratory only and are not timestamps.
- Direct references are evidence, while heuristic and LLM mappings require analyst validation.
- Network signatures cannot establish coverage of host-only behaviours.
- Revoked and deprecated ATT&CK IDs require review before being used as current coverage claims.

## Update MITRE ATT&CK Data

Refresh the local STIX bundle from MITRE's official repository:

```powershell
Invoke-WebRequest `
-Uri "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" `
-OutFile ".\data\enterprise-attack.json"
```

Use an alternative local STIX bundle with `--attack-data .\data\enterprise-attack.json`.

## AI Use Declaration

AI/LLM tools were used as a supporting aid during development — for code assistance, error identification and debugging, troubleshooting, explanation of unfamiliar code, and verification of comment-only edits against the executable code (e.g. AST comparison). All project decisions, the research methodology, the implementation, the analysis, the results, and their final interpretation were made, reviewed, and controlled by the myself.

---

School of Electronics, Electrical Engineering and Computer Science
Queen's University Belfast
