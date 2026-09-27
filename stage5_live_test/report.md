# Snort Full Ruleset Coverage Analysis

## Scope

- Parsed **4017** rules across **27** Snort categories.
- Validated ATT&CK mappings against **Enterprise ATT&CK v19.1**.
- Direct coverage means the rule explicitly references `attack.mitre.org`.
- Heuristic coverage means the tool found a transparent candidate mapping that still needs analyst validation.

## Overall Findings

- Direct ATT&CK references: **161 rules**.
- Direct unique ATT&CK techniques: **29**.
- Heuristic ATT&CK candidate rules: **286**.
- Complexity mix: **1033 simple**, **1566 moderate**, **1418 complex**.
- Mean complexity score: **18.64**.
- Highest rule revision: **50**.
- Unmapped rules: **3587**.

## Interpretation

- **ATT&CK coverage:** direct references are the strongest evidence. Heuristic mappings identify research leads and should not be counted as validated coverage without review.
- **Complexity:** category complexity shows signature construction patterns, not a ranking of detection effectiveness.
- **Unmapped rules:** large unmapped populations commonly indicate limited contextual evidence or behaviour that cannot be reliably inferred from a network signature alone.
- **Coverage inflation:** categories with many rules per ATT&CK ID may represent signature depth for a small behaviour set rather than broad technique coverage.
- **Validation:** resolve missing fields, duplicate identifiers, unknown IDs, and revoked IDs before drawing final coverage conclusions.

## Largest Categories

| Category | Rules | Direct ATT&CK % | Heuristic % | Mean Complexity | Max Rev |
|---|---:|---:|---:|---:|---:|
| trojan-activity | 1118 | 7.42 | 19.68 | 22.35 | 15 |
| web-application-activity | 481 | 0.83 | 0.21 | 15.62 | 31 |
| attempted-recon | 436 | 4.36 | 0.23 | 14.36 | 27 |
| attempted-user | 427 | 0.0 | 1.87 | 17.52 | 35 |
| web-application-attack | 356 | 1.4 | 1.4 | 20.3 | 30 |
| misc-activity | 350 | 6.29 | 12.0 | 17.59 | 34 |
| attempted-admin | 278 | 1.44 | 0.72 | 18.26 | 50 |
| protocol-command-decode | 108 | 0.0 | 0.0 | 24.97 | 23 |
| misc-attack | 101 | 0.0 | 0.0 | 19.06 | 36 |
| rpc-portmap-decode | 83 | 0.0 | 0.0 | 21.06 | 31 |
| attempted-dos | 67 | 5.97 | 0.0 | 12.69 | 23 |
| policy-violation | 63 | 1.59 | 9.52 | 15.14 | 26 |

## Highest Direct ATT&CK Mapping Rates

| Category | Rules | Direct ATT&CK % | Direct Techniques | Revoked Techniques |
|---|---:|---:|---:|---:|
| default-login-attempt | 9 | 66.67 | 1 | 0 |
| suspicious-login | 16 | 31.25 | 2 | 0 |
| network-scan | 7 | 28.57 | 3 | 0 |
| unsuccessful-user | 10 | 20.0 | 1 | 0 |
| bad-unknown | 45 | 8.89 | 5 | 0 |
| trojan-activity | 1118 | 7.42 | 16 | 4 |
| misc-activity | 350 | 6.29 | 9 | 1 |
| attempted-dos | 67 | 5.97 | 1 | 0 |
| attempted-recon | 436 | 4.36 | 8 | 3 |
| policy-violation | 63 | 1.59 | 1 | 0 |

## Priority Coverage Gaps

| Category | Rules | Direct ATT&CK % | Gap Notes |
|---|---:|---:|---|
| attempted-user | 427 | 0.0 | no direct ATT&CK references |
| protocol-command-decode | 108 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| misc-attack | 101 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| rpc-portmap-decode | 83 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| shellcode-detect | 26 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| successful-admin | 10 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| suspicious-filename-detect | 6 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates; no external references |
| denial-of-service | 5 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| system-call-detect | 5 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| successful-recon-limited | 4 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| string-detect | 2 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates |
| unknown | 2 | 0.0 | no direct ATT&CK references; no heuristic ATT&CK candidates; no external references |

## Coverage Inflation Signals

| Category | Rules | Unique ATT&CK IDs | Rules per ATT&CK ID | Note |
|---|---:|---:|---:|---|
| attempted-user | 427 | 2 | 213.5 | many rules but low ATT&CK technique diversity |
| attempted-admin | 278 | 2 | 139.0 | many rules but low ATT&CK technique diversity |
| web-application-activity | 481 | 5 | 96.2 | many rules but low ATT&CK technique diversity |
| attempted-dos | 67 | 1 | 67.0 | many rules but low ATT&CK technique diversity |
| trojan-activity | 1118 | 21 | 53.24 | many rules but low ATT&CK technique diversity |
| attempted-recon | 436 | 9 | 48.44 | many rules but low ATT&CK technique diversity |
| web-application-attack | 356 | 8 | 44.5 | many rules but low ATT&CK technique diversity |
| misc-activity | 350 | 10 | 35.0 | many rules but low ATT&CK technique diversity |
| policy-violation | 63 | 2 | 31.5 | many rules but low ATT&CK technique diversity |
| unsuccessful-user | 10 | 1 | 10.0 | limited ATT&CK technique diversity |
| bad-unknown | 45 | 5 | 9.0 | no obvious inflation signal |
| default-login-attempt | 9 | 1 | 9.0 | no obvious inflation signal |

## Modern Attack Type Comparison

| Attack Type | Matched Rules | Direct | Heuristic | Keyword | Top Categories |
|---|---:|---:|---:|---:|---|
| Command and control over web | 279 | 5 | 267 | 67 | trojan-activity:213|misc-activity:42|attempted-user:8|policy-violation:6|web-application-attack:5|attempted-admin:2|web-application-activity:1|successful-user:1 |
| DNS command and control | 43 | 0 | 6 | 39 | trojan-activity:11|attempted-recon:8|web-application-attack:7|misc-activity:5|attempted-user:3|bad-unknown:2|web-application-activity:2|policy-violation:2 |
| Web shell activity | 21 | 9 | 12 | 21 | trojan-activity:20|web-application-attack:1 |
| Ingress tool transfer / malware download | 227 | 0 | 211 | 227 | trojan-activity:164|misc-activity:42|policy-violation:6|attempted-user:5|web-application-attack:5|attempted-admin:2|web-application-activity:1|successful-user:1 |
| Credential theft / input capture | 64 | 25 | 0 | 60 | trojan-activity:31|web-application-activity:5|default-login-attempt:5|attempted-recon:5|attempted-dos:4|rpc-portmap-decode:4|attempted-admin:3|attempted-user:2 |
| Exfiltration | 57 | 20 | 0 | 57 | trojan-activity:33|web-application-attack:7|web-application-activity:5|misc-activity:5|attempted-recon:4|attempted-admin:2|policy-violation:1 |
| Phishing / initial access | 20 | 16 | 0 | 19 | trojan-activity:18|misc-activity:2 |
| Ransomware-related impact | 51 | 0 | 0 | 51 | trojan-activity:50|web-application-attack:1 |

## Validation Summary

- Validation findings written: **34**.
- Review `validation_findings.csv` for missing fields, duplicate SIDs, unknown ATT&CK IDs, and revoked ATT&CK IDs.

## Generated Datasets

- `all_rules.csv`: expanded rule-level dataset for all categories.
- `category_statistics.csv`: category-wise counts, percentages, complexity, and coverage.
- `category_attack_coverage.csv`: per-category direct and heuristic ATT&CK mappings.
- `coverage_gaps.csv`: category-level mapping gap flags.
- `pattern_statistics.csv`: common rule attributes and detection patterns by category.
- `frequently_updated_rules.csv`: highest-revision rules for revision triage.
- `modern_attack_comparison.csv`: selected modern attack type comparison.
- `validation_findings.csv`: data-quality checks for generated outputs.
- `attack_mapping_dataset.csv`: rule-level direct, heuristic, and unmapped ATT&CK mapping dataset.
- `coverage_inflation.csv`: category rules-per-technique signals.
- `technique_frequency.csv`: ATT&CK technique frequency with Top 20 and Bottom 20 labels.
- `unmapped_rules.csv`: unmapped rule inventory and reasons.
- `unmapped_rule_candidates.csv`: validation-required candidate mappings for originally unmapped rules.
- `extended_validation_report.csv`: expanded required-field and duplicate SID+REV validation.
- `research_metrics.json`: aggregate metrics for research reporting.

## Evaluation Note

This remains a static rule-analysis prototype. Direct ATT&CK references are strong evidence of intended mapping, while heuristic candidates and modern attack comparisons are leads that require analyst validation against traffic semantics and current ATT&CK guidance.

## Unmapped Rule Candidate Mapping

- Originally unmapped rules: **3587**.
- Rules with one or more candidate mappings: **414**.
- Remaining without a candidate mapping: **3173**.
- Candidate coverage opportunity: **10.31 percentage points**.
- All entries in `unmapped_rule_candidates.csv` are candidate mappings requiring analyst validation and do not alter established ATT&CK coverage.

## Keyword vs LLM Classification

- LLM-classified rules: **5**; LLM errors: **0**.
- Keyword-mapped rules: **430**; LLM-mapped rules: **3**.
- Coverage change: **3 rules** and **60.0 percentage points**.
- Agreement: **0**; partial overlap: **0**; LLM-only: **3**; keyword-only: **0**.
- **Interpretation:** LLM-only and partial-overlap results are candidate evidence for review, not an automatic increase in validated ATT&CK coverage.
- Review LLM-only, keyword-only, and partial-overlap mappings in `validation_dataset.csv` before treating them as coverage evidence.
- Use `llm_classification_results.csv` for rule-level LLM output and `research_metrics.json` for the consolidated classification metrics.

## Classification Outputs

- `llm_classification_results.csv`: LLM classifications with status, confidence, and rationale.
- `keyword_llm_classification_comparison.csv`: rule-by-rule keyword and LLM comparison.
- `validation_dataset.csv`: analyst review queue for agreement and disagreement verification.
- `unmapped_classification_analysis.csv`: deterministic and LLM-specific reasons rules remain unclassified.
- `unmapped_rule_candidates.csv`: improved-heuristic and optional LLM candidates requiring analyst validation.
- `mapped_rule_llm_validation.csv`: independent LLM validation of already mapped rules.
- `research_metrics.json`: baseline and keyword-versus-LLM coverage, agreement, and confidence metrics.
- `classification_coverage_comparison.svg`, `classification_difference_breakdown.svg`, and `mapped_rule_llm_validation.svg`: coverage, difference, and mapped-validation visualisations.
