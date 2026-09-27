#!/usr/bin/env python3
from __future__ import annotations  # postponed annotation evaluation

import csv  # read the existing CSV artefacts
import json  # write the machine-readable summary
import re  # extract ATT&CK technique IDs from label text
import sys  # exit codes
from collections import Counter, defaultdict  # tallies and grouping
from pathlib import Path  # filesystem paths

csv.field_size_limit(10**9)  # rule text fields are long

SOURCE = Path("all_categories_output")  # existing outputs; READ ONLY
OUTPUT = Path("difficulty_analysis_output")  # new folder; nothing else is written

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")  # matches T1071 and T1071.001


# Read one existing CSV artefact into a list of dicts.
def read_csv(name: str) -> list[dict]:
    path = SOURCE / name  # resolve against the read-only source folder
    if not path.is_file():  # fail loudly rather than silently analysing nothing
        sys.exit(f"[difficulty] required input not found: {path}")
    with path.open(encoding="utf-8") as handle:  # open the artefact
        return list(csv.DictReader(handle))  # materialise every row


# Pull the set of ATT&CK technique IDs out of a free-text label cell.
def technique_ids(text: str) -> set[str]:
    return set(TECH_RE.findall(text or ""))  # empty text yields an empty set


# Reduce a technique ID to its parent family, so T1078.001 -> T1078.
def family(technique_id: str) -> str:
    return technique_id.split(".")[0]  # sub-technique suffix removed


# True when two ID sets name at least one common technique family.
def shares_family(left: set[str], right: set[str]) -> bool:
    return bool({family(x) for x in left} & {family(x) for x in right})


# COHORT A rule: convergence between the existing mapping and LLM validation.
def classify_cohort_a(row: dict) -> tuple[str, str, str]:
    agreement = row["Agreement"]  # match / partial_match / mismatch / no_prediction
    existing = technique_ids(row["Existing Technique"])  # keyword-derived IDs
    predicted = technique_ids(row["LLM Prediction"])  # LLM-derived IDs
    if agreement == "match":  # identical technique sets
        return "Easy", "exact_convergence", "existing mapping and LLM prediction are identical"
    if agreement == "no_prediction" or not predicted:  # model declined to answer
        return "Hard", "llm_abstained", "LLM found insufficient evidence to propose a technique"
    if agreement == "partial_match":  # overlapping but not identical sets
        return "Medium", "partial_overlap", "methods share a technique but the sets differ"
    if shares_family(existing, predicted):  # e.g. T1078 vs T1078.001
        return "Medium", "family_refinement", "same technique family at a different level of detail"
    return "Hard", "cross_family_conflict", "methods propose techniques from different families"


# COHORT B rule: strength, clarity and ambiguity of the LLM-derived evidence,
# corroborated where possible by the independent improved-heuristic candidate.
def classify_cohort_b(row: dict, heuristic: set[str]) -> tuple[str, str, str]:
    predicted = technique_ids(row["llm_attack_ids"])  # LLM-derived IDs
    if not predicted:  # abstention
        return "Hard*", "llm_abstained", "LLM found insufficient network-observable evidence"
    if len(predicted) > 1:  # several competing readings of the same rule
        return "Hard*", "competing_techniques", f"{len(predicted)} competing techniques proposed"
    if heuristic and shares_family(predicted, heuristic):  # two signals converge
        return "Easy*", "heuristic_corroborated", "improved heuristic agrees at technique-family level"
    if heuristic:  # two signals disagree
        return "Hard*", "heuristic_conflict", "improved heuristic proposes a different technique family"
    return "Medium*", "single_uncorroborated", "one plausible technique, nothing available to corroborate it"


def main() -> None:
    OUTPUT.mkdir(exist_ok=True)  # create the new folder; existing outputs untouched

    validation = read_csv("mapped_rule_llm_validation.csv")  # Stage 4, 430 rows
    classification = read_csv("llm_classification_results.csv")  # Stage 5, 4,017 rows
    candidates = read_csv("unmapped_rule_candidates.csv")  # candidate mappings
    rules = read_csv("all_rules.csv")  # for ATT&CK status flags

    rule_by_sid = {r["sid"]: r for r in rules}  # index the rule inventory

    # ---- exclusion: existing mappings that cite a revoked/deprecated ID ------
    # The prompt restricts the model to ACTIVE catalog IDs, so a revoked ID can
    # never be reproduced. Scoring these as disagreement would measure ATT&CK
    # version drift rather than classification difficulty, so they are excluded
    # from the distribution and reported separately.
    revoked_sids = set()  # SIDs excluded from cohort A
    for row in validation:  # walk the Stage 4 cohort
        rule = rule_by_sid.get(row["SID"])  # matching rule inventory record
        if not rule:  # defensive; every Stage 4 SID should be present
            continue
        statuses = f"{rule['direct_attack_statuses']}|{rule['inferred_attack_statuses']}"  # both fields
        tags = [t.strip().lower() for t in statuses.split("|") if t.strip()]  # split and clean
        if any(tag != "active" for tag in tags):  # any non-active technique
            revoked_sids.add(row["SID"])  # exclude this rule

    excluded_rows = []  # rows for the separate exclusions file
    for row in validation:  # collect the excluded cases with their evidence
        if row["SID"] in revoked_sids:
            excluded_rows.append({
                "sid": row["SID"],
                "existing_technique": row["Existing Technique"],
                "llm_prediction": row["LLM Prediction"],
                "agreement": row["Agreement"],
                "exclusion_reason": "existing mapping cites a revoked or deprecated ATT&CK ID",
            })

    # ---- heuristic candidates available for the unmapped cohort -------------
    heuristic_by_sid: dict[str, set[str]] = defaultdict(set)  # SID -> technique IDs
    heuristic_label: dict[str, str] = {}  # SID -> readable label for the audit trail
    for row in candidates:  # walk the candidate artefact
        if row["Mapping Source"] == "improved_heuristic_candidate":  # heuristic only
            heuristic_by_sid[row["SID"]] |= technique_ids(row["Candidate ATT&CK Technique"])
            heuristic_label.setdefault(row["SID"], row["Candidate ATT&CK Technique"])

    results = []  # rule-level output rows

    # ---- cohort A -----------------------------------------------------------
    for row in validation:  # 430 initially mapped rules
        if row["SID"] in revoked_sids:  # excluded, handled separately
            continue
        difficulty, basis, reason = classify_cohort_a(row)  # apply the approved rule
        results.append({
            "sid": row["SID"],
            "cohort": "A_initially_mapped",
            "difficulty": difficulty,
            "evidence_basis": basis,
            "reason": reason,
            "existing_or_heuristic_evidence": row["Existing Technique"],
            "llm_evidence": row["LLM Prediction"],
            "agreement_or_status": row["Agreement"],
        })

    # ---- cohort B -----------------------------------------------------------
    for row in classification:  # 4,017 rows, of which 3,587 were submitted
        if row["llm_status"] != "classified":  # skip the 430 not_submitted rows
            continue
        heuristic = heuristic_by_sid.get(row["sid"], set())  # corroborating signal, if any
        difficulty, basis, reason = classify_cohort_b(row, heuristic)  # apply the approved rule
        results.append({
            "sid": row["sid"],
            "cohort": "B_initially_unmapped",
            "difficulty": difficulty,
            "evidence_basis": basis,
            "reason": reason,
            "existing_or_heuristic_evidence": heuristic_label.get(row["sid"], ""),
            "llm_evidence": row["llm_attack_ids"],
            "agreement_or_status": row["llm_status"],
        })

    # ---- write the rule-level classification -------------------------------
    fields = ["sid", "cohort", "difficulty", "evidence_basis", "reason",
              "existing_or_heuristic_evidence", "llm_evidence", "agreement_or_status"]
    with (OUTPUT / "rule_difficulty_classification.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)  # fixed column order
        writer.writeheader()  # header row
        writer.writerows(results)  # every classified rule

    # ---- write the excluded cases ------------------------------------------
    with (OUTPUT / "excluded_revoked_attack_ids.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "sid", "existing_technique", "llm_prediction", "agreement", "exclusion_reason"])
        writer.writeheader()  # header row
        writer.writerows(excluded_rows)  # the excluded catalogue-versioning cases

    # ---- summary statistics, per cohort ------------------------------------
    summary_rows = []  # rows for the report-ready summary
    for cohort, order in (("A_initially_mapped", ["Easy", "Medium", "Hard"]),
                          ("B_initially_unmapped", ["Easy*", "Medium*", "Hard*"])):
        subset = [r for r in results if r["cohort"] == cohort]  # this cohort only
        counts = Counter(r["difficulty"] for r in subset)  # tally the categories
        total = len(subset)  # cohort denominator
        for label in order:  # keep a stable Easy/Medium/Hard order
            count = counts.get(label, 0)  # zero if the category is empty
            summary_rows.append({
                "cohort": cohort,
                "difficulty": label,
                "rules": count,
                "percentage": round(100 * count / total, 2) if total else 0.0,
            })
        summary_rows.append({  # explicit per-cohort total row
            "cohort": cohort, "difficulty": "Total", "rules": total,
            "percentage": round(sum(100 * counts.get(l, 0) / total for l in order), 2) if total else 0.0,
        })

    with (OUTPUT / "difficulty_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["cohort", "difficulty", "rules", "percentage"])
        writer.writeheader()  # header row
        writer.writerows(summary_rows)  # the summary table

    # ---- machine-readable summary with the integrity checks -----------------
    checks = {}  # arithmetic verification, recorded rather than asserted in prose
    for cohort in ("A_initially_mapped", "B_initially_unmapped"):
        subset = [r for r in results if r["cohort"] == cohort]  # this cohort only
        counts = Counter(r["difficulty"] for r in subset)  # tally
        checks[cohort] = {
            "counts": dict(counts),
            "sum_of_categories": sum(counts.values()),
            "cohort_total": len(subset),
            "categories_equal_total": sum(counts.values()) == len(subset),
            "percentages_sum": round(sum(100 * v / len(subset) for v in counts.values()), 4) if subset else 0.0,
        }
    checks["excluded_revoked_attack_ids"] = len(excluded_rows)  # reported separately
    checks["cohort_a_input_rows"] = len(validation)  # 430 before exclusions
    checks["cohort_b_input_rows"] = sum(1 for r in classification if r["llm_status"] == "classified")
    (OUTPUT / "difficulty_metrics.json").write_text(
        json.dumps(checks, indent=2, sort_keys=True), encoding="utf-8")  # write the checks

    print(f"[difficulty] rule-level rows written : {len(results)}")  # progress
    print(f"[difficulty] excluded (revoked IDs)  : {len(excluded_rows)}")  # exclusions
    print(f"[difficulty] outputs written to      : {OUTPUT}/")  # destination


if __name__ == "__main__":  # only run when invoked directly
    main()  # entry point
