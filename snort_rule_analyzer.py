#!/usr/bin/env python3
"""Exploratory Snort 3 community-rule analyzer for ATT&CK coverage studies."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable



RULE_RE = re.compile(r"^\s*(?P<header>.*?)\s*\((?P<options>.*)\)\s*$")
ATTACK_RE = re.compile(r"(T\d{4})(?:[./](\d{3}))?", re.IGNORECASE)
DEFAULT_ATTACK_DATA = Path(__file__).resolve().parent / "data" / "enterprise-attack.json"
ATTACK_DATA_SOURCE = (
    "https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack"
)

BUFFER_KEYWORDS = {
    "file_data",
    "http_client_body",
    "http_cookie",
    "http_header",
    "http_method",
    "http_raw_cookie",
    "http_raw_header",
    "http_raw_uri",
    "http_stat_code",
    "http_stat_msg",
    "http_uri",
    "js_data",
}
CONTENT_MODIFIERS = {
    "depth",
    "distance",
    "endswith",
    "fast_pattern",
    "nocase",
    "offset",
    "startswith",
    "within",
}
MODERN_ATTACK_TYPES = {
    "Command and control over web": {
        "techniques": {"T1071.001", "T1102", "T1105", "T1001", "T1132"},
        "keywords": {"command and control", " cnc ", "c2", "beacon"},
    },
    "DNS command and control": {
        "techniques": {"T1071.004"},
        "keywords": {"dns", "domain generation", "dga"},
    },
    "Web shell activity": {
        "techniques": {"T1505.003", "T1100"},
        "keywords": {"webshell", "web shell", "jsp.webshell", "php.webshell"},
    },
    "Ingress tool transfer / malware download": {
        "techniques": {"T1105"},
        "keywords": {"download", "payload transfer", "file transfer", "dropper"},
    },
    "Credential theft / input capture": {
        "techniques": {"T1056"},
        "keywords": {"keylog", "credential", "password", "input capture"},
    },
    "Exfiltration": {
        "techniques": {"T1020"},
        "keywords": {"exfil", "data theft", "upload"},
    },
    "Phishing / initial access": {
        "techniques": {"T1566.002", "T1192", "T1189"},
        "keywords": {"phish", "spearphishing", "drive-by", "malicious link"},
    },
    "Ransomware-related impact": {
        "techniques": {"T1486", "T1490", "T1489"},
        "keywords": {"ransomware", "encryptor", "ransom", "wiper"},
    },
}


# One parsed Snort rule; direct and heuristic ATT&CK IDs stay in separate fields.
@dataclass
class Rule:
    action: str
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str
    msg: str
    sid: int | None
    rev: int | None
    classtype: str
    priority: str
    service: str
    contents: list[str]
    pcres: list[str]
    flows: list[str]
    metadata: list[str]
    flowbits: list[str]
    references: list[str]
    attack_techniques: list[str]
    attack_details: list[dict[str, object]]
    keyword_counts: dict[str, int]
    http_keywords: list[str]
    buffer_keywords: list[str]
    content_modifier_keywords: list[str]
    option_count: int
    complexity_score: int
    complexity: str
    complexity_reasons: list[str]
    inferred_attack_candidates: list[str]
    inferred_attack_details: list[dict[str, object]]
    raw: str


# Stage 5 settings; model has no default so Stage 5 will not start unnamed.
@dataclass(frozen=True)
class LLMConfig:
    """Configuration for an OpenAI-compatible chat-completions endpoint."""

    enabled: bool = False
    endpoint: str = "https://integrate.api.nvidia.com/v1/chat/completions"
    model: str = ""
    api_key_env: str = "NVIDIA_API_KEY"
    max_rules: int = 0
    batch_size: int = 10
    timeout: int = 120
    retries: int = 4
    target: str = "all"
    cache_dir: str = ""
    debug_log: str = ""
    preflight: bool = True
    request_delay: float = -1.0  # -1 selects a delay from the model tier
    max_requests: int = 0
    reasoning_effort: str = "low"
    fallback_models: tuple[str, ...] = ()


# Stage 4 settings; separate from LLMConfig but shares one request budget.
@dataclass(frozen=True)
class MappedLLMValidationConfig:
    """Configuration for independent LLM validation of already mapped rules."""

    enabled: bool = False
    endpoint: str = "https://integrate.api.nvidia.com/v1/chat/completions"
    model: str = "nvidia/nemotron-3-ultra-550b-a55b"
    api_key_env: str = "NVIDIA_API_KEY"
    max_rules: int = 0
    batch_size: int = 10
    timeout: int = 120
    retries: int = 4
    cache_dir: str = ""
    debug_log: str = ""
    preflight: bool = True
    request_delay: float = -1.0  # -1 selects a delay from the model tier
    max_requests: int = 0
    reasoning_effort: str = "low"
    fallback_models: tuple[str, ...] = ()


# STAGE 1 - RULE PARSING: Parsing and structured feature extraction
def split_options(text: str) -> list[str]:
    """Split a Snort option block on semicolons outside quoted strings."""
    parts: list[str] = []
    current: list[str] = []
    # Quote and escape state must be tracked because a ';' inside a quoted
    # content string is rule data, not an option separator.
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == ";" and not quoted:
            item = "".join(current).strip()
            if item:
                parts.append(item)
            current = []
        else:
            current.append(char)
    item = "".join(current).strip()
    if item:
        parts.append(item)
    return parts


# Split one rule option into (keyword, value).
def option_pair(option: str) -> tuple[str, str]:
    if ":" not in option:
        return option.strip().lower(), ""
    key, value = option.split(":", 1)
    return key.strip().lower(), value.strip()


# Strip surrounding quotes from an option value.
def unquote(value: str) -> str:
    value = value.strip()
    return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value


# Bucket a rule as simple / moderate / complex, with the reasons why.
def classify_complexity(
    content_count: int, pcre_count: int, option_count: int
) -> tuple[str, list[str]]:
    # The 4 / 18 / 10 boundaries are descriptive bucket edges chosen for this
    # ruleset, not values from any published standard. They describe how much
    # detection logic a signature carries, never how effective it is, and each
    # bucket carries its reasons so a rule's label can be audited.
    reasons: list[str] = []
    if pcre_count:
        reasons.append("uses PCRE")
    if content_count >= 4:
        reasons.append("uses 4+ content matches")
    if option_count >= 18:
        reasons.append("uses 18+ options")
    if reasons:
        return "complex", reasons
    if content_count <= 1 and option_count <= 10:
        return "simple", ["one or fewer content matches and <=10 options"]
    return "moderate", ["multiple constraints without complex-rule threshold"]


# Numeric score for how much detection logic a rule carries.
def complexity_score(
    content_count: int,
    pcre_count: int,
    option_count: int,
    flowbits_count: int,
    buffer_count: int,
) -> int:
    # Relative weights, not measured costs: PCRE counts 5 because a regex
    # expresses far more constraint than one content match, which counts 2.
    # The score is only ever compared between rules in this dataset.
    return (
        option_count
        + content_count * 2
        + pcre_count * 5
        + flowbits_count * 2
        + buffer_count * 2
    )


# STAGE 3 - KEYWORD / HEURISTIC MAPPING: Heuristic candidate generation
def infer_attack_candidates(
    msg: str, service: str, keyword_counts: dict[str, int]
) -> list[str]:
    """Return transparent heuristic candidates, not confirmed ATT&CK mappings."""
    # A deliberately small, hand-auditable keyword table rather than a learned
    # model: every candidate traces to one visible term, which is what makes
    # the Stage 4 comparison against the LLM a fair test of reproducibility.
    # Protocol context disambiguates where it can - the same C2 wording maps to
    # web protocols on HTTP and to a non-application-layer technique otherwise.
    text = msg.lower()
    candidates: set[str] = set()
    is_http = service == "http" or any(k.startswith("http_") for k in keyword_counts)
    if "webshell" in text:
        candidates.add("T1505.003")
    if any(term in text for term in ("download", "payload transfer", "file transfer")):
        candidates.add("T1105")
    if any(term in text for term in ("command and control", " cnc ", "c2 ", "beacon")):
        candidates.add("T1071.001" if is_http else "T1095")
    if "powershell" in text:
        candidates.add("T1059.001")
    if service == "dns" and any(term in text for term in ("cnc", "command", "beacon")):
        candidates.add("T1071.004")
    return sorted(candidates)


# STAGE 2 - ATT&CK MAPPING: Explicit ATT&CK reference identification
def extract_attack_techniques(references: Iterable[str]) -> list[str]:
    techniques = set()
    for reference in references:
        # Only attack.mitre.org URLs count. A cve or bugtraq reference can
        # contain a T-shaped number, and accepting those would manufacture
        # coverage the rule author never declared.
        if "attack.mitre.org" not in reference.lower():
            continue
        # MITRE URLs split the sub-technique into its own path segment
        # (.../T1071/001), so the two halves are rejoined as T1071.001.
        for technique, subtechnique in ATTACK_RE.findall(reference):
            normalized = technique.upper()
            if subtechnique:
                normalized += f".{subtechnique}"
            techniques.add(normalized)
    return sorted(techniques)


# Load the local ATT&CK STIX bundle; the only source of valid technique IDs.
def load_attack_catalog(path: Path) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    """Load an official Enterprise ATT&CK STIX bundle without external packages."""
    if not path.exists():
        raise FileNotFoundError(
            f"MITRE ATT&CK data not found at {path}. See README.md for download instructions."
        )
    bundle = json.loads(path.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    collection = next(
        (
            item
            for item in objects
            if item.get("type") == "x-mitre-collection"
            and item.get("name") == "Enterprise ATT&CK"
        ),
        {},
    )
    catalog: dict[str, dict[str, object]] = {}
    for item in objects:
        if item.get("type") != "attack-pattern":
            continue
        external = next(
            (
                reference
                for reference in item.get("external_references", [])
                if reference.get("source_name") == "mitre-attack"
                and str(reference.get("external_id", "")).startswith("T")
            ),
            None,
        )
        if not external:
            continue
        # Status is recorded rather than filtered here, because the distinction
        # matters downstream: only "active" IDs are accepted from an LLM, while
        # revoked or deprecated IDs already cited in a rule's own references are
        # still reported as existing coverage.
        status = (
            "revoked"
            if item.get("revoked", False)
            else "deprecated"
            if item.get("x_mitre_deprecated", False)
            else "active"
        )
        technique_id = external["external_id"].upper()
        catalog[technique_id] = {
            "technique_id": technique_id,
            "name": item.get("name", ""),
            "status": status,
            "tactics": sorted(
                {
                    phase.get("phase_name", "")
                    for phase in item.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                }
            ),
            "url": external.get("url", ""),
            "version": item.get("x_mitre_version", ""),
            "modified": item.get("modified", ""),
        }
    info: dict[str, object] = {
        "name": collection.get("name", "Enterprise ATT&CK"),
        "version": collection.get("x_mitre_version", "unknown"),
        "modified": collection.get("modified", ""),
        "source": ATTACK_DATA_SOURCE,
        "path": str(path.resolve()),
        "total_techniques": len(catalog),
        "active_techniques": sum(
            detail["status"] == "active" for detail in catalog.values()
        ),
        "deprecated_techniques": sum(
            detail["status"] == "deprecated" for detail in catalog.values()
        ),
        "revoked_techniques": sum(
            detail["status"] == "revoked" for detail in catalog.values()
        ),
    }
    return catalog, info


# Normalise one technique ID to its canonical catalog form.
def resolve_attack_technique(
    technique_id: str, catalog: dict[str, dict[str, object]]
) -> dict[str, object]:
    return catalog.get(
        technique_id,
        {
            "technique_id": technique_id,
            "name": "(not found in current Enterprise ATT&CK)",
            "status": "unknown",
            "tactics": [],
            "url": "",
            "version": "",
            "modified": "",
        },
    ).copy()


# Attach names and tactics to each rule's IDs and drop unknown ones.
def enrich_attack_mappings(
    rules: Iterable[Rule], catalog: dict[str, dict[str, object]]
) -> None:
    for rule in rules:
        rule.attack_details = [
            resolve_attack_technique(technique_id, catalog)
            for technique_id in rule.attack_techniques
        ]
        rule.inferred_attack_details = [
            resolve_attack_technique(technique_id, catalog)
            for technique_id in rule.inferred_attack_candidates
        ]


# Parse one Snort rule line into a Rule, or None if it is not a rule.
def parse_rule(line: str) -> Rule | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = RULE_RE.match(line)
    if not match:
        return None
    header = match.group("header").split()
    # Snort 3 allows a two-token service shorthand ("alert http") as well as the
    # classic seven-token form; anything between the two is malformed.
    if len(header) not in (2,) and len(header) < 7:
        return None
    # ';' inside a quoted string is data, not a separator
    options = split_options(match.group("options"))
    pairs = [option_pair(option) for option in options]
    values: dict[str, list[str]] = {}
    for key, value in pairs:
        values.setdefault(key, []).append(value)

    def first(key: str, default: str = "") -> str:
        return unquote(values.get(key, [default])[0])

    keyword_counts = dict(Counter(key for key, _ in pairs))
    contents = [unquote(value.split(",", 1)[0]) for value in values.get("content", [])]
    pcres = [unquote(value) for value in values.get("pcre", [])]
    flows = values.get("flow", [])
    metadata = values.get("metadata", [])
    flowbits = values.get("flowbits", [])
    http_keywords = sorted(k for k in keyword_counts if k.startswith("http_"))
    buffer_keywords = sorted(k for k in keyword_counts if k in BUFFER_KEYWORDS)
    content_modifier_keywords = sorted(
        k for k in keyword_counts if k in CONTENT_MODIFIERS
    )
    references = values.get("reference", [])
    direct = extract_attack_techniques(references)  # STAGE 2: strongest evidence
    complexity, reasons = classify_complexity(len(contents), len(pcres), len(options))
    score = complexity_score(
        len(contents), len(pcres), len(options), len(flowbits), len(buffer_keywords)
    )
    msg = first("msg")
    service = first("service")
    if len(header) == 2:
        action, protocol = header
        source = source_port = direction = destination = destination_port = ""
    else:
        action, protocol, source, source_port, direction, destination, destination_port = (
            header[:7]
        )
    return Rule(
        action=action,
        protocol=protocol,
        source=source,
        source_port=source_port,
        direction=direction,
        destination=destination,
        destination_port=destination_port,
        msg=msg,
        sid=int(first("sid")) if first("sid").isdigit() else None,
        rev=int(first("rev")) if first("rev").isdigit() else None,
        classtype=first("classtype"),
        priority=first("priority"),
        service=service,
        contents=contents,
        pcres=pcres,
        flows=flows,
        metadata=metadata,
        flowbits=flowbits,
        references=references,
        attack_techniques=direct,
        attack_details=[],
        keyword_counts=keyword_counts,
        http_keywords=http_keywords,
        buffer_keywords=buffer_keywords,
        content_modifier_keywords=content_modifier_keywords,
        option_count=len(options),
        complexity_score=score,
        complexity=complexity,
        complexity_reasons=reasons,
        inferred_attack_candidates=infer_attack_candidates(msg, service, keyword_counts),
        inferred_attack_details=[],
        raw=line,
    )


# Read rule text from a .rules file or straight from the community ZIP.
def read_rule_lines(source: Path) -> list[str]:
    """Read rule lines from a plain file or ZIP, with source-specific errors.

    The returned text is intentionally unchanged so parsing and research outputs
    remain reproducible. This boundary gives users actionable file errors before
    any analysis is attempted.
    """
    if not source.exists():
        raise FileNotFoundError(f"Rules source not found: {source}")
    if source.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(source) as archive:
                names = [name for name in archive.namelist() if name.endswith(".rules")]
                if not names:
                    raise ValueError(f"No .rules file found in ZIP archive: {source}")
                return archive.read(names[0]).decode("utf-8", errors="replace").splitlines()
        except zipfile.BadZipFile as error:
            raise ValueError(f"Corrupted or invalid ZIP archive: {source}") from error
    try:
        return source.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise OSError(f"Unable to read rules source {source}: {error}") from error


# Linear-interpolated percentile over a list of integers.
def percentile(values: list[int], fraction: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = fraction * (len(ordered) - 1)
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


# Format count/total as a percentage string, guarding divide-by-zero.
def pct(count: int, total: int) -> str:
    return f"{(100 * count / total):.1f}%" if total else "0.0%"


# Print a progress line during long runs.
def progress(message: str) -> None:
    """Emit a stable, human-readable progress message for long research runs."""
    print(f"[INFO] {message}")


# Return the most common counter entries as name/count dicts.
def top(counter: Counter, limit: int = 12) -> list[dict[str, int | str]]:
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


# Stage 3 aggregation: coverage, complexity and category statistics.
def build_summary(
    rules: list[Rule],
    category: str,
    total_rules: int,
    attack_info: dict[str, object],
) -> dict:
    """Aggregate existing structural and ATT&CK evidence for research reporting.

    Inputs are parsed, enriched rules for one category or the entire ruleset.
    The returned summary feeds JSON, Markdown, and tabular outputs without
    introducing any additional mapping or complexity assumptions.
    """
    revisions = [rule.rev for rule in rules if rule.rev is not None]
    revision_counter = Counter(revisions)
    sids = [rule.sid for rule in rules if rule.sid is not None]
    keyword_counter = Counter(
        keyword for rule in rules for keyword, count in rule.keyword_counts.items() for _ in range(count)
    )
    service_counter = Counter(rule.service or "(not specified)" for rule in rules)
    protocol_counter = Counter(rule.protocol for rule in rules)
    complexity_counter = Counter(rule.complexity for rule in rules)
    complexity_scores = [rule.complexity_score for rule in rules]
    direct_counter = Counter(t for rule in rules for t in rule.attack_techniques)
    inferred_counter = Counter(t for rule in rules for t in rule.inferred_attack_candidates)
    direct_unique = {
        detail["technique_id"]: detail for rule in rules for detail in rule.attack_details
    }
    inferred_unique = {
        detail["technique_id"]: detail
        for rule in rules
        for detail in rule.inferred_attack_details
    }
    direct_statuses = Counter(detail["status"] for detail in direct_unique.values())
    inferred_statuses = Counter(detail["status"] for detail in inferred_unique.values())
    direct_tactics = Counter(
        tactic for rule in rules for detail in rule.attack_details for tactic in detail["tactics"]
    )
    reference_counter = Counter(
        ref.split(",", 1)[0].lower() for rule in rules for ref in rule.references
    )
    q1, q3 = percentile(sids, 0.25), percentile(sids, 0.75)
    low_sid = [rule for rule in rules if rule.sid is not None and rule.sid <= q1]
    high_sid = [rule for rule in rules if rule.sid is not None and rule.sid >= q3]

    def cohort(items: list[Rule]) -> dict:
        return {
            "rules": len(items),
            "pcre_usage": sum(bool(r.pcres) for r in items),
            "http_keyword_usage": sum(
                any(k.startswith("http_") for k in r.keyword_counts) for r in items
            ),
            "file_data_usage": sum("file_data" in r.keyword_counts for r in items),
            "mean_content_matches": round(
                statistics.mean(len(r.contents) for r in items), 2
            )
            if items
            else 0,
            "mean_option_count": round(statistics.mean(r.option_count for r in items), 2)
            if items
            else 0,
        }

    return {
        "category": category,
        "all_rules_in_ruleset": total_rules,
        "category_rules": len(rules),
        "category_share": round(len(rules) / total_rules, 4) if total_rules else 0,
        "attack_dataset": attack_info,
        "attack_coverage": {
            "direct_unique_techniques": len(direct_unique),
            "direct_statuses": dict(direct_statuses),
            "direct_active_coverage_ratio": round(
                direct_statuses["active"] / int(attack_info["active_techniques"]), 6
            )
            if attack_info["active_techniques"]
            else 0,
            "direct_tactics": dict(direct_tactics),
            "heuristic_unique_techniques": len(inferred_unique),
            "heuristic_statuses": dict(inferred_statuses),
        },
        "revision": {
            "distribution": dict(sorted(revision_counter.items())),
            "minimum": min(revisions, default=None),
            "maximum": max(revisions, default=None),
            "mean": round(statistics.mean(revisions), 2) if revisions else None,
            "median": round(statistics.median(revisions), 2) if revisions else None,
            "rules_with_revision": len(revisions),
            "rules_missing_revision": len(rules) - len(revisions),
            "top_revised_rules": [
                {
                    "sid": rule.sid,
                    "rev": rule.rev,
                    "msg": rule.msg,
                    "classtype": rule.classtype,
                    "direct_attack_techniques": joined(rule.attack_techniques),
                }
                for rule in sorted(
                    rules,
                    key=lambda item: (
                        item.rev if item.rev is not None else -1,
                        item.sid if item.sid is not None else -1,
                    ),
                    reverse=True,
                )[:20]
            ],
        },
        "complexity_metrics": {
            "minimum_score": min(complexity_scores, default=0),
            "maximum_score": max(complexity_scores, default=0),
            "mean_score": round(statistics.mean(complexity_scores), 2)
            if complexity_scores
            else 0,
            "median_score": round(statistics.median(complexity_scores), 2)
            if complexity_scores
            else 0,
        },
        "feature_usage": {
            "content": sum(bool(r.contents) for r in rules),
            "pcre": sum(bool(r.pcres) for r in rules),
            "flow": sum(bool(r.flows) for r in rules),
            "metadata": sum(bool(r.metadata) for r in rules),
            "references": sum(bool(r.references) for r in rules),
            "cve_reference": sum(
                any(ref.lower().startswith("cve,") for ref in r.references)
                for r in rules
            ),
            "flowbits": sum("flowbits" in r.keyword_counts for r in rules),
            "file_data": sum("file_data" in r.keyword_counts for r in rules),
            "http_keywords": sum(
                any(k.startswith("http_") for k in r.keyword_counts) for r in rules
            ),
            "service": sum(bool(r.service) for r in rules),
            "direct_attack_reference": sum(bool(r.attack_techniques) for r in rules),
            "heuristic_attack_candidate": sum(
                bool(r.inferred_attack_candidates) for r in rules
            ),
        },
        "complexity": dict(complexity_counter),
        "top_keywords": top(keyword_counter, 20),
        "top_services": top(service_counter),
        "protocols": dict(protocol_counter),
        "reference_types": dict(reference_counter),
        "direct_attack_techniques": dict(direct_counter),
        "inferred_attack_candidates": dict(inferred_counter),
        "direct_attack_catalog": [
            {**detail, "rule_count": direct_counter[technique_id]}
            for technique_id, detail in sorted(direct_unique.items())
        ],
        "inferred_attack_catalog": [
            {**detail, "rule_count": inferred_counter[technique_id]}
            for technique_id, detail in sorted(inferred_unique.items())
        ],
        "sid_proxy_comparison": {
            "warning": "SID cohorts are not dates or historical rule versions.",
            "low_sid_threshold": q1,
            "high_sid_threshold": q3,
            "low_sid_cohort": cohort(low_sid),
            "high_sid_cohort": cohort(high_sid),
        },
    }


# Render report.md for a single-category run.
def markdown_report(summary: dict, rules: list[Rule]) -> str:
    n = summary["category_rules"]
    features = summary["feature_usage"]
    complexity = summary["complexity"]
    revision = summary["revision"]
    proxy = summary["sid_proxy_comparison"]
    attack_dataset = summary["attack_dataset"]
    attack_coverage = summary["attack_coverage"]

    def feature_line(name: str, key: str) -> str:
        count = features[key]
        return f"| {name} | {count} | {pct(count, n)} |"

    def technique_table(items: list[dict[str, object]]) -> list[str]:
        rows = [
            "| Technique | Name | Status | Tactics | Rules |",
            "|---|---|---|---|---:|",
        ]
        for item in items:
            rows.append(
                f"| {item['technique_id']} | {item['name']} | {item['status']} | "
                f"{', '.join(item['tactics']) or '(none)'} | {item['rule_count']} |"
            )
        return rows

    examples = {
        level: next((r for r in rules if r.complexity == level), None)
        for level in ("simple", "moderate", "complex")
    }
    lines = [
        f"# Snort Rule Exploratory Analysis: `{summary['category']}`",
        "",
        "## Scope and Method",
        "",
        f"- Analyzed **{n}** `{summary['category']}` rules from a snapshot containing "
        f"**{summary['all_rules_in_ruleset']}** parseable rules.",
        "- The supplied archive contains one current ruleset, not historical versions. "
        "Revision counts show how often a rule has changed, but not what changed.",
        "- Low-versus-high SID cohorts are used only as a rough rule-generation proxy. "
        "SIDs are not timestamps, so this is exploratory rather than historical proof.",
        "- Direct ATT&CK coverage requires an explicit `attack.mitre.org` reference. "
        "Heuristic candidates are leads for manual validation, not confirmed mappings.",
        "",
        "## Headline Results",
        "",
        f"- Category share: **{pct(n, summary['all_rules_in_ruleset'])}** of the ruleset.",
        f"- Revision range: **{revision['minimum']} to {revision['maximum']}**, "
        f"mean **{revision['mean']}**.",
        f"- Complexity: **{complexity.get('simple', 0)} simple**, "
        f"**{complexity.get('moderate', 0)} moderate**, "
        f"**{complexity.get('complex', 0)} complex**.",
        f"- Only **{features['direct_attack_reference']} rules "
        f"({pct(features['direct_attack_reference'], n)})** have a direct ATT&CK reference.",
        f"- **{features['heuristic_attack_candidate']} rules "
        f"({pct(features['heuristic_attack_candidate'], n)})** produced at least one "
        "transparent heuristic ATT&CK candidate.",
        f"- Mappings were validated against **{attack_dataset['name']} "
        f"v{attack_dataset['version']}**, containing "
        f"**{attack_dataset['active_techniques']} active techniques/sub-techniques**.",
        "",
        "## Interpretation",
        "",
        "- **ATT&CK coverage:** direct references are the most defensible coverage evidence; heuristic candidates are a review queue rather than confirmed coverage.",
        "- **Complexity:** the simple, moderate, and complex distribution describes signature construction effort and does not by itself measure detection quality.",
        "- **Unmapped rules:** absent ATT&CK evidence often reflects generic malware labels, limited protocol context, or network-only visibility rather than absence of malicious behaviour.",
        "- **Coverage inflation:** use `coverage_inflation.csv` to distinguish broad rule volume from genuine technique diversity before making category-level coverage claims.",
        "- **Validation:** check `extended_validation_report.csv` before interpreting coverage, particularly for missing fields, duplicate identifiers, and revoked ATT&CK IDs.",
        "",
        "## Detection Characteristics",
        "",
        "| Feature | Rules | Share |",
        "|---|---:|---:|",
        feature_line("Content matching", "content"),
        feature_line("PCRE", "pcre"),
        feature_line("Flowbits", "flowbits"),
        feature_line("File-data buffer", "file_data"),
        feature_line("HTTP-specific keyword", "http_keywords"),
        feature_line("Explicit service", "service"),
        "",
        "The category is dominated by payload/content signatures. HTTP-aware rules are "
        "common, while PCRE is used selectively for variable patterns. Flowbits appear "
        "in a smaller subset where state across related traffic matters.",
        "",
        "## Revision and Rule-Style Exploration",
        "",
        f"- Revision distribution: `{json.dumps(revision['distribution'], sort_keys=True)}`",
        f"- Low-SID cohort (SID <= {proxy['low_sid_threshold']:.0f}): "
        f"{proxy['low_sid_cohort']['rules']} rules, mean "
        f"{proxy['low_sid_cohort']['mean_content_matches']} content matches, mean "
        f"{proxy['low_sid_cohort']['mean_option_count']} options.",
        f"- High-SID cohort (SID >= {proxy['high_sid_threshold']:.0f}): "
        f"{proxy['high_sid_cohort']['rules']} rules, mean "
        f"{proxy['high_sid_cohort']['mean_content_matches']} content matches, mean "
        f"{proxy['high_sid_cohort']['mean_option_count']} options.",
        f"- HTTP-keyword use changes from "
        f"{pct(proxy['low_sid_cohort']['http_keyword_usage'], proxy['low_sid_cohort']['rules'])} "
        f"to {pct(proxy['high_sid_cohort']['http_keyword_usage'], proxy['high_sid_cohort']['rules'])}; "
        f"`file_data` use changes from "
        f"{pct(proxy['low_sid_cohort']['file_data_usage'], proxy['low_sid_cohort']['rules'])} "
        f"to {pct(proxy['high_sid_cohort']['file_data_usage'], proxy['high_sid_cohort']['rules'])}.",
        "",
        "The SID cohorts show mixed indicators rather than a simple increase in "
        "complexity. Confirming evolution requires archived rulesets so the same SID "
        "can be compared across revisions.",
        "",
        "Top revised rules in this category:",
        "",
        "| SID | Rev | Message |",
        "|---:|---:|---|",
        *[
            f"| {item['sid']} | {item['rev']} | {item['msg']} |"
            for item in revision["top_revised_rules"][:10]
        ],
        "",
        "## ATT&CK Coverage Leads",
        "",
        f"- Direct references cover **{attack_coverage['direct_unique_techniques']} unique "
        f"techniques**, including **{attack_coverage['direct_statuses'].get('active', 0)} "
        f"active** and **{attack_coverage['direct_statuses'].get('revoked', 0)} revoked**.",
        f"- Direct active-technique coverage for this category is "
        f"**{100 * attack_coverage['direct_active_coverage_ratio']:.2f}%** of the active "
        "Enterprise ATT&CK catalog.",
        f"- Heuristics suggest **{attack_coverage['heuristic_unique_techniques']} unique "
        "ATT&CK candidates** for analyst review.",
        "",
        "### Directly Referenced Techniques",
        "",
        *technique_table(summary["direct_attack_catalog"]),
        "",
        "### Heuristic Technique Candidates",
        "",
        *technique_table(summary["inferred_attack_catalog"]),
        "",
        "Coverage gaps to investigate:",
        "",
        "- Most rules lack a direct ATT&CK technique reference.",
        "- Revoked ATT&CK IDs should be remapped to their current replacement techniques "
        "before claiming current coverage.",
        "- Signature detection of a malware family does not automatically prove coverage "
        "of every behavior performed by that family.",
        "- Network rules have limited visibility into host-only techniques.",
        "- Candidate mappings need analyst validation using message, service, direction, "
        "references, and matched traffic semantics.",
        "",
        "## Simple vs Complex Examples",
        "",
    ]
    for level, rule in examples.items():
        if rule:
            lines.extend(
                [
                    f"### {level.title()} rule",
                    "",
                    f"- SID `{rule.sid}`, revision `{rule.rev}`: {rule.msg}",
                    f"- Contents: `{len(rule.contents)}`; PCREs: `{len(rule.pcres)}`; "
                    f"options: `{rule.option_count}`.",
                    f"- Classification reason: {', '.join(rule.complexity_reasons)}.",
                    "",
                ]
            )
    lines.extend(
        [
            "## Recommended Next Experiment",
            "",
            "Obtain at least two dated Snort community ruleset snapshots. Join them by SID "
            "and compare each option block by revision to identify added buffers, content "
            "constraints, PCRE changes, reference changes, and ATT&CK mapping changes.",
            "",
            "## Additional Datasets",
            "",
            "- `attack_mapping_dataset.csv`: rule-level direct, heuristic, and unmapped ATT&CK mapping dataset.",
            "- `coverage_inflation.csv`: rules-per-technique signals by category.",
            "- `technique_frequency.csv`: Top 20 and Bottom 20 technique frequency labels.",
            "- `unmapped_rules.csv`: unmapped rules with reason fields.",
            "- `unmapped_rule_candidates.csv`: validation-required improved-heuristic and optional LLM ATT&CK candidates for originally unmapped rules.",
            "- `extended_validation_report.csv`: required-field, duplicate SID, duplicate SID+REV, and ATT&CK validation checks.",
            "- `research_metrics.json`: aggregate research metrics for this analysis run.",
            "",
        ]
    )
    return "\n".join(lines)


# Join values with '|', the separator used across all CSV columns.
def joined(values: Iterable[object]) -> str:
    return "|".join(str(value) for value in values)


def rule_csv_fields() -> list[str]:
    return [
        "sid",
        "rev",
        "msg",
        "classtype",
        "priority",
        "action",
        "protocol",
        "source",
        "source_port",
        "direction",
        "destination",
        "destination_port",
        "service",
        "complexity",
        "complexity_score",
        "complexity_reasons",
        "option_count",
        "content_count",
        "contents",
        "pcre_count",
        "pcres",
        "flow_count",
        "flows",
        "metadata_count",
        "metadata",
        "reference_count",
        "references",
        "flowbits_count",
        "flowbits",
        "http_keywords",
        "buffer_keywords",
        "content_modifier_keywords",
        "keyword_names",
        "direct_attack_techniques",
        "direct_attack_names",
        "direct_attack_statuses",
        "direct_attack_tactics",
        "inferred_attack_candidates",
        "inferred_attack_names",
        "inferred_attack_statuses",
        "raw",
    ]


def rule_to_csv_row(rule: Rule) -> dict[str, object]:
    return {
        "sid": rule.sid,
        "rev": rule.rev,
        "msg": rule.msg,
        "classtype": rule.classtype,
        "priority": rule.priority,
        "action": rule.action,
        "protocol": rule.protocol,
        "source": rule.source,
        "source_port": rule.source_port,
        "direction": rule.direction,
        "destination": rule.destination,
        "destination_port": rule.destination_port,
        "service": rule.service,
        "complexity": rule.complexity,
        "complexity_score": rule.complexity_score,
        "complexity_reasons": joined(rule.complexity_reasons),
        "option_count": rule.option_count,
        "content_count": len(rule.contents),
        "contents": joined(rule.contents),
        "pcre_count": len(rule.pcres),
        "pcres": joined(rule.pcres),
        "flow_count": len(rule.flows),
        "flows": joined(rule.flows),
        "metadata_count": len(rule.metadata),
        "metadata": joined(rule.metadata),
        "reference_count": len(rule.references),
        "references": joined(rule.references),
        "flowbits_count": len(rule.flowbits),
        "flowbits": joined(rule.flowbits),
        "http_keywords": joined(rule.http_keywords),
        "buffer_keywords": joined(rule.buffer_keywords),
        "content_modifier_keywords": joined(rule.content_modifier_keywords),
        "keyword_names": joined(sorted(rule.keyword_counts)),
        "direct_attack_techniques": joined(rule.attack_techniques),
        "direct_attack_names": joined(
            str(detail["name"]) for detail in rule.attack_details
        ),
        "direct_attack_statuses": joined(
            str(detail["status"]) for detail in rule.attack_details
        ),
        "direct_attack_tactics": joined(
            sorted(
                {
                    tactic
                    for detail in rule.attack_details
                    for tactic in detail["tactics"]
                }
            )
        ),
        "inferred_attack_candidates": joined(rule.inferred_attack_candidates),
        "inferred_attack_names": joined(
            str(detail["name"]) for detail in rule.inferred_attack_details
        ),
        "inferred_attack_statuses": joined(
            str(detail["status"]) for detail in rule.inferred_attack_details
        ),
        "raw": rule.raw,
    }


# Run both LLM stages and write their CSVs, metrics and charts.
def write_classification_outputs(
    output: Path,
    rules: list[Rule],
    catalog: dict[str, dict[str, object]],
    llm_config: LLMConfig,
    mapped_validation_config: MappedLLMValidationConfig | None = None,
) -> dict[str, object]:
    """Write LLM comparison artefacts while retaining deterministic outputs.

    Returns the existing comparison metrics for inclusion in the consolidated
    research metrics file. Reviewer columns are intentionally blank so human
    validation can be recorded later without affecting current calculations.
    """
    for obsolete_name in (
        "classification_metrics.json",
        "manual_validation_dataset.csv",
        "llm_classification_dataset.csv",
        "mapped_llm_validation.csv",
        "mapped_rule_gpt_validation.csv",
    ):
        (output / obsolete_name).unlink(missing_ok=True)
    mapped_validation_config = mapped_validation_config or MappedLLMValidationConfig()
    # >>> STAGE 5: LLM classification of keyword-UNMAPPED rules
    llm_rows = classify_rules_with_llm(rules, catalog, llm_config)
    # >>> STAGE 4: LLM validation of keyword-MAPPED rules (disjoint cohort)
    mapped_validation_rows = validate_mapped_rules_with_llm(
        rules, catalog, mapped_validation_config
    )
    # everything below derives from the two stages above; no further API calls
    comparison_rows = classification_comparison_rows(rules, llm_rows)
    manual_rows = manual_validation_rows(llm_rows, comparison_rows)
    reason_rows = unmapped_reason_analysis_rows(rules, llm_rows)
    # candidate mappings = improved heuristic + Stage 5 output, merged
    candidate_rows, candidate_metrics = unmapped_rule_candidate_rows(
        rules, catalog, llm_rows
    )
    metrics = classification_metrics(rules, llm_rows, comparison_rows)
    mapped_validation_metrics = mapped_rule_validation_metrics(mapped_validation_rows)
    metrics["mapped_rule_llm_validation"] = mapped_validation_metrics
    metrics["unmapped_rule_candidate_mapping"] = candidate_metrics
    metrics["newly_mapped_rules"] = candidate_metrics["newly_mapped_rules"]
    metrics["remaining_unmapped_rules_after_candidates"] = candidate_metrics[
        "remaining_unmapped_rules"
    ]
    metrics["coverage_improvement_from_candidates"] = candidate_metrics[
        "coverage_improvement"
    ]
    write_csv(output / "llm_classification_results.csv", LLM_CLASSIFICATION_FIELDS, llm_rows)
    write_csv(
        output / "keyword_llm_classification_comparison.csv",
        CLASSIFICATION_COMPARISON_FIELDS,
        comparison_rows,
    )
    write_csv(output / "validation_dataset.csv", MANUAL_VALIDATION_FIELDS, manual_rows)
    write_csv(output / "unmapped_classification_analysis.csv", UNMAPPED_REASON_FIELDS, reason_rows)
    write_csv(
        output / "unmapped_rule_candidates.csv",
        UNMAPPED_RULE_CANDIDATE_FIELDS,
        candidate_rows,
    )
    write_csv(
        output / "mapped_rule_llm_validation.csv",
        MAPPED_RULE_LLM_VALIDATION_FIELDS,
        mapped_validation_rows,
    )
    write_classification_visualizations(output, metrics)
    write_mapped_validation_visualization(output, mapped_validation_metrics)
    return metrics


def classification_report_section(metrics: dict[str, object]) -> list[str]:
    if not metrics["llm_enabled"]:
        return []
    counts = metrics["comparison_counts"]
    return [
        "## Keyword vs LLM Classification",
        "",
        f"- LLM-classified rules: **{metrics['llm_classified_rules']}**; LLM errors: **{metrics['llm_error_rules']}**.",
        f"- Keyword-mapped rules: **{metrics['keyword_mapped_rules']}**; LLM-mapped rules: **{metrics['llm_mapped_rules']}**.",
        f"- Coverage change: **{metrics['coverage_improvement_rules']} rules** and **{metrics['coverage_improvement_pct_points']} percentage points**.",
        f"- Agreement: **{counts.get('agree', 0)}**; partial overlap: **{counts.get('partial_overlap', 0)}**; LLM-only: **{counts.get('llm_only', 0)}**; keyword-only: **{counts.get('keyword_only', 0)}**.",
        "- **Interpretation:** LLM-only and partial-overlap results are candidate evidence for review, not an automatic increase in validated ATT&CK coverage.",
        "- Review LLM-only, keyword-only, and partial-overlap mappings in `validation_dataset.csv` before treating them as coverage evidence.",
        "- Use `llm_classification_results.csv` for rule-level LLM output and `research_metrics.json` for the consolidated classification metrics.",
        "",
    ]


def candidate_mapping_report_section(metrics: dict[str, object]) -> list[str]:
    """Describe validation-only unmapped-rule candidate results in Markdown."""
    candidate_metrics = metrics["unmapped_rule_candidate_mapping"]
    return [
        "## Unmapped Rule Candidate Mapping",
        "",
        f"- Originally unmapped rules: **{candidate_metrics['originally_unmapped_rules']}**.",
        f"- Rules with one or more candidate mappings: **{candidate_metrics['newly_mapped_rules']}**.",
        f"- Remaining without a candidate mapping: **{candidate_metrics['remaining_unmapped_rules']}**.",
        f"- Candidate coverage opportunity: **{candidate_metrics['coverage_improvement_percentage']} percentage points**.",
        "- All entries in `unmapped_rule_candidates.csv` are candidate mappings requiring analyst validation and do not alter established ATT&CK coverage.",
        "",
    ]


def mapped_validation_report_section(metrics: dict[str, object]) -> list[str]:
    """Describe independent LLM validation of already mapped rules."""
    validation = metrics["mapped_rule_llm_validation"]
    if not validation["enabled"]:
        return []
    return [
        "## Mapped Rule LLM Validation",
        "",
        f"- LLM-tested mapped rules: **{validation['total_tested_rules']}**.",
        f"- Exact matches: **{validation['matches']}**; partial matches: **{validation['partial_matches']}**; mismatches: **{validation['mismatches']}**; no prediction: **{validation.get('no_predictions', 0)}**.",
        f"- Exact agreement: **{validation['agreement_percentage']}%**; any technique overlap: **{validation.get('any_overlap_percentage', 0)}%**.",
        f"- Average confidence: **{validation['average_confidence']}**.",
        "- `mapped_rule_llm_validation.csv` compares existing ATT&CK mappings against independent LLM predictions for already mapped rules only.",
        "- Unmapped-rule analysis and candidate mapping outputs are unchanged by this validation pass.",
        "",
    ]


# Write every artefact for a single-category run.
def write_outputs(
    output: Path,
    rules: list[Rule],
    summary: dict,
    catalog: dict[str, dict[str, object]],
    llm_config: LLMConfig,
    mapped_validation_config: MappedLLMValidationConfig,
) -> None:
    """Write the focused-category research output suite."""
    output.mkdir(parents=True, exist_ok=True)
    category_rules = {summary["category"]: rules}
    llm_metrics = write_classification_outputs(
        output, rules, catalog, llm_config, mapped_validation_config
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    (output / "research_metrics.json").write_text(
        json.dumps(
            research_metrics(
                rules, 1, llm_metrics, llm_config, mapped_validation_config
            ),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (output / "report.md").write_text(
        markdown_report(summary, rules)
        + "\n".join(candidate_mapping_report_section(llm_metrics))
        + "\n".join(mapped_validation_report_section(llm_metrics))
        + "\n".join(classification_report_section(llm_metrics)),
        encoding="utf-8",
    )
    (output / "rules.json").write_text(
        json.dumps([asdict(rule) for rule in rules], indent=2), encoding="utf-8"
    )
    fields = rule_csv_fields()
    with (output / "rules.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule_to_csv_row(rule))
    coverage_fields = [
        "mapping_type",
        "technique_id",
        "name",
        "status",
        "tactics",
        "version",
        "modified",
        "url",
        "rule_count",
    ]
    with (output / "attack_coverage.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=coverage_fields)
        writer.writeheader()
        for mapping_type, key in (
            ("direct", "direct_attack_catalog"),
            ("heuristic", "inferred_attack_catalog"),
        ):
            for detail in summary[key]:
                writer.writerow(
                    {
                        **detail,
                        "mapping_type": mapping_type,
                        "tactics": "|".join(detail["tactics"]),
                    }
                )
    write_csv(
        output / "attack_mapping_dataset.csv",
        ATTACK_MAPPING_FIELDS,
        attack_mapping_dataset_rows(rules),
    )
    write_csv(
        output / "coverage_inflation.csv",
        COVERAGE_INFLATION_FIELDS,
        coverage_inflation_rows(category_rules),
    )
    write_csv(
        output / "technique_frequency.csv",
        TECHNIQUE_FREQUENCY_FIELDS,
        technique_frequency_rows(rules),
    )
    write_csv(
        output / "unmapped_rules.csv",
        UNMAPPED_RULE_FIELDS,
        unmapped_rule_rows(rules),
    )
    write_csv(
        output / "extended_validation_report.csv",
        VALIDATION_FIELDS,
        extended_validation_rows(rules),
    )


# one CSV writer for every table, so all outputs match
def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


ATTACK_MAPPING_FIELDS = [
    "sid",
    "rev",
    "msg",
    "classtype",
    "priority",
    "metadata",
    "references",
    "attack_id",
    "attack_name",
    "mapping_source",
]
COVERAGE_INFLATION_FIELDS = [
    "category",
    "total_rules",
    "unique_attack_ids",
    "rules_per_attack",
    "inflation_note",
]
TECHNIQUE_FREQUENCY_FIELDS = [
    "technique_id",
    "technique_name",
    "rule_count",
    "coverage_pct",
    "rank_group",
]
UNMAPPED_RULE_FIELDS = ["sid", "message", "classtype", "revision", "reason"]
VALIDATION_FIELDS = ["severity", "issue", "sid", "category", "row", "details"]
LLM_CLASSIFICATION_FIELDS = [
    "sid",
    "rev",
    "msg",
    "classtype",
    "keyword_attack_ids",
    "keyword_mapping_source",
    "llm_attack_ids",
    "llm_attack_names",
    "llm_confidence",
    "llm_reasoning",
    "llm_status",
    "llm_error",
    "llm_model",
]
CLASSIFICATION_COMPARISON_FIELDS = [
    "sid",
    "rev",
    "msg",
    "classtype",
    "keyword_attack_ids",
    "llm_attack_ids",
    "comparison",
    "shared_attack_ids",
    "llm_only_attack_ids",
    "keyword_only_attack_ids",
    "coverage_delta",
    "llm_status",
]
MANUAL_VALIDATION_FIELDS = [
    "sid",
    "rev",
    "msg",
    "classtype",
    "keyword_attack_ids",
    "llm_attack_ids",
    "llm_confidence",
    "comparison",
    "review_priority",
    "review_reason",
    "validation_status",
    "reviewer_name",
    "validation_date",
    "validation_comment",
]
UNMAPPED_REASON_FIELDS = [
    "sid",
    "rev",
    "msg",
    "classtype",
    "keyword_unmapped_reason",
    "llm_attack_ids",
    "llm_status",
    "remaining_unmapped_reason",
]
UNMAPPED_RULE_CANDIDATE_FIELDS = [
    "SID",
    "Revision",
    "Message",
    "Candidate ATT&CK Technique",
    "Mapping Source",
    "Confidence",
    "Reason",
]
MAPPED_RULE_LLM_VALIDATION_FIELDS = [
    "SID",
    "Existing Technique",
    "LLM Prediction",
    "Agreement",
    "Confidence",
    "Reason",
    # record which model answered, per rule
    "Model",
]


def category_statistics_rows(summaries: dict[str, dict]) -> list[dict[str, object]]:
    rows = []
    for category, summary in sorted(
        summaries.items(), key=lambda item: item[1]["category_rules"], reverse=True
    ):
        rules = summary["category_rules"]
        features = summary["feature_usage"]
        coverage = summary["attack_coverage"]
        rows.append(
            {
                "category": category,
                "rules": rules,
                "ruleset_share_pct": round(100 * summary["category_share"], 2),
                "direct_attack_rules": features["direct_attack_reference"],
                "direct_attack_rule_pct": round(
                    100 * features["direct_attack_reference"] / rules, 2
                )
                if rules
                else 0,
                "heuristic_attack_rules": features["heuristic_attack_candidate"],
                "heuristic_attack_rule_pct": round(
                    100 * features["heuristic_attack_candidate"] / rules, 2
                )
                if rules
                else 0,
                "direct_unique_techniques": coverage["direct_unique_techniques"],
                "direct_active_techniques": coverage["direct_statuses"].get("active", 0),
                "direct_revoked_techniques": coverage["direct_statuses"].get(
                    "revoked", 0
                ),
                "direct_active_catalog_coverage_pct": round(
                    100 * coverage["direct_active_coverage_ratio"], 3
                ),
                "simple_rules": summary["complexity"].get("simple", 0),
                "moderate_rules": summary["complexity"].get("moderate", 0),
                "complex_rules": summary["complexity"].get("complex", 0),
                "mean_complexity_score": summary["complexity_metrics"]["mean_score"],
                "max_revision": summary["revision"]["maximum"],
                "mean_revision": summary["revision"]["mean"],
                "content_rule_pct": round(100 * features["content"] / rules, 2)
                if rules
                else 0,
                "pcre_rule_pct": round(100 * features["pcre"] / rules, 2)
                if rules
                else 0,
                "flow_rule_pct": round(100 * features["flow"] / rules, 2)
                if rules
                else 0,
                "metadata_rule_pct": round(100 * features["metadata"] / rules, 2)
                if rules
                else 0,
                "reference_rule_pct": round(100 * features["references"] / rules, 2)
                if rules
                else 0,
                "http_keyword_rule_pct": round(
                    100 * features["http_keywords"] / rules, 2
                )
                if rules
                else 0,
                "file_data_rule_pct": round(100 * features["file_data"] / rules, 2)
                if rules
                else 0,
                "flowbits_rule_pct": round(100 * features["flowbits"] / rules, 2)
                if rules
                else 0,
            }
        )
    return rows


def category_attack_coverage_rows(summaries: dict[str, dict]) -> list[dict[str, object]]:
    rows = []
    for category, summary in summaries.items():
        for mapping_type, key in (
            ("direct", "direct_attack_catalog"),
            ("heuristic", "inferred_attack_catalog"),
        ):
            for detail in summary[key]:
                rows.append(
                    {
                        "category": category,
                        "mapping_type": mapping_type,
                        "technique_id": detail["technique_id"],
                        "name": detail["name"],
                        "status": detail["status"],
                        "tactics": joined(detail["tactics"]),
                        "rule_count": detail["rule_count"],
                        "url": detail["url"],
                    }
                )
    return sorted(rows, key=lambda row: (row["category"], row["mapping_type"], row["technique_id"]))


def pattern_statistics_rows(summaries: dict[str, dict]) -> list[dict[str, object]]:
    patterns = [
        ("content", "Payload/content string match"),
        ("pcre", "Regular expression match"),
        ("flow", "Flow direction/state constraint"),
        ("metadata", "Metadata annotation"),
        ("references", "External reference"),
        ("cve_reference", "CVE reference"),
        ("http_keywords", "HTTP-specific buffer/keyword"),
        ("file_data", "Decoded file data inspection"),
        ("flowbits", "Stateful flowbits usage"),
        ("service", "Explicit service selector"),
        ("direct_attack_reference", "Direct ATT&CK reference"),
        ("heuristic_attack_candidate", "Heuristic ATT&CK candidate"),
    ]
    rows = []
    for category, summary in summaries.items():
        rules = summary["category_rules"]
        for key, label in patterns:
            count = summary["feature_usage"][key]
            rows.append(
                {
                    "category": category,
                    "pattern": key,
                    "description": label,
                    "rule_count": count,
                    "rule_pct": round(100 * count / rules, 2) if rules else 0,
                }
            )
    return sorted(rows, key=lambda row: (row["category"], row["pattern"]))


# Rows for frequently_updated_rules.csv, ranked by revision.
def frequently_updated_rows(rules: list[Rule], limit: int = 250) -> list[dict[str, object]]:
    return [
        {
            "sid": rule.sid,
            "rev": rule.rev,
            "category": rule.classtype,
            "msg": rule.msg,
            "complexity": rule.complexity,
            "complexity_score": rule.complexity_score,
            "direct_attack_techniques": joined(rule.attack_techniques),
            "service": rule.service,
        }
        for rule in sorted(
            rules,
            key=lambda item: (
                item.rev if item.rev is not None else -1,
                item.complexity_score,
                item.sid if item.sid is not None else -1,
            ),
            reverse=True,
        )[:limit]
    ]


# Return ('direct_reference' | 'heuristic' | 'unmapped', details).
def mapping_candidates(rule: Rule) -> tuple[str, list[dict[str, object]]]:
    if rule.attack_details:
        return "direct_reference", rule.attack_details  # explicit attack.mitre.org reference
    if rule.inferred_attack_details:
        return "heuristic", rule.inferred_attack_details  # keyword-inferred, weaker evidence
    return "unmapped", []  # nothing found -> Stage 5 cohort


def attack_mapping_dataset_rows(rules: list[Rule]) -> list[dict[str, object]]:
    rows = []
    for rule in rules:
        source, details = mapping_candidates(rule)
        if not details:
            rows.append(
                {
                    "sid": rule.sid or "",
                    "rev": rule.rev or "",
                    "msg": rule.msg,
                    "classtype": rule.classtype,
                    "priority": rule.priority,
                    "metadata": joined(rule.metadata),
                    "references": joined(rule.references),
                    "attack_id": "",
                    "attack_name": "",
                    "mapping_source": source,
                }
            )
            continue
        for detail in details:
            rows.append(
                {
                    "sid": rule.sid or "",
                    "rev": rule.rev or "",
                    "msg": rule.msg,
                    "classtype": rule.classtype,
                    "priority": rule.priority,
                    "metadata": joined(rule.metadata),
                    "references": joined(rule.references),
                    "attack_id": detail["technique_id"],
                    "attack_name": detail["name"],
                    "mapping_source": source,
                }
            )
    return rows


# Technique IDs for a rule; empty means unmapped, which routes it to Stage 5.
def rule_mapping_ids(rule: Rule) -> set[str]:
    if rule.attack_details:  # direct attack.mitre.org reference wins outright
        return {str(detail["technique_id"]) for detail in rule.attack_details}
    # empty set => unmapped => goes to Stage 5, not Stage 4
    return {str(detail["technique_id"]) for detail in rule.inferred_attack_details}


# Why the keyword mapper left this rule unmapped.
def keyword_unmapped_reason(rule: Rule) -> str:
    """Explain the absence of deterministic ATT&CK mapping evidence."""
    reasons = []
    if not rule.references:
        reasons.append("no external references")
    elif not rule.attack_techniques:
        reasons.append("references do not contain an ATT&CK technique")
    if not rule.msg:
        reasons.append("missing message text")
    elif not rule.inferred_attack_candidates:
        reasons.append("message and service do not match supported ATT&CK heuristics")
    if not rule.service and not rule.http_keywords:
        reasons.append("limited protocol or service context")
    if not rule.contents and not rule.pcres:
        reasons.append("no content or PCRE context")
    return "; ".join(reasons) or "no deterministic mapping evidence"


# CANDIDATE MAPPING
def improved_unmapped_candidates(
    rule: Rule, catalog: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    """Return validation-only ATT&CK candidates from unmapped-rule context.

    This is intentionally separate from the established direct and heuristic
    mappers. It considers message, category, content, metadata, protocol,
    service, and PCRE evidence, but never updates a rule's existing mappings.
    """
    fields = {
        "msg": rule.msg.lower(),
        "classtype": rule.classtype.lower(),
        "content": " ".join(rule.contents).lower(),
        "metadata": " ".join(rule.metadata).lower(),
        "protocol": rule.protocol.lower(),
        "service": rule.service.lower(),
        "pcre": " ".join(rule.pcres).lower(),
    }
    combined = " ".join(fields.values())
    candidates: dict[str, tuple[float, str]] = {}

    def add(technique_id: str, confidence: float, terms: tuple[str, ...], label: str) -> None:
        if technique_id not in catalog or catalog[technique_id]["status"] != "active":
            return
        matched_fields = [
            field_name
            for field_name, value in fields.items()
            if any(term in value for term in terms)
        ]
        if not matched_fields:
            return
        reason = (
            f"{label} indicator matched in {', '.join(matched_fields)} "
            "context. Candidate mapping requiring validation."
        )
        if technique_id not in candidates or confidence > candidates[technique_id][0]:
            candidates[technique_id] = (confidence, reason)

    add("T1059.001", 0.78, ("powershell", "pwsh"), "PowerShell")
    add("T1059.003", 0.74, ("cmd.exe", "command.com", "cmd /c"), "Windows command shell")
    add("T1505.003", 0.78, ("webshell", "web shell", "php shell", "jsp shell"), "Web shell")
    add("T1056", 0.68, ("keylog", "credential", "password", "input capture"), "Credential or input capture")
    add("T1105", 0.64, ("download", "payload", "dropper", "file transfer"), "Tool transfer")
    add("T1486", 0.61, ("ransomware", "encryptor", "ransom", "wiper"), "Data encryption impact")
    add("T1041", 0.58, ("exfil", "data theft", "upload"), "Exfiltration")
    add("T1021.001", 0.65, ("rdp", "remote desktop"), "Remote Desktop Protocol")
    add("T1021.002", 0.63, ("smb", "admin$", "c$ share"), "SMB or administrative share")
    if fields["service"] == "dns" or fields["protocol"] == "dns":
        add("T1568.002", 0.72, ("dga", "domain generation", "algorithmic domain"), "Domain generation")
    if fields["service"] in {"http", "https"} or fields["protocol"] in {"http", "https"} or rule.http_keywords:
        add("T1190", 0.62, ("sql injection", "directory traversal", "remote code execution", "exploit"), "Web-facing exploit")
    return [
        {"technique_id": technique_id, "confidence": confidence, "reason": reason}
        for technique_id, (confidence, reason) in sorted(candidates.items())
    ]


# Rows for unmapped_rule_candidates.csv, merging heuristic and LLM candidates.
def unmapped_rule_candidate_rows(
    rules: list[Rule],
    catalog: dict[str, dict[str, object]],
    llm_rows: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Create candidate rows and non-authoritative coverage indicators.

    Candidate counts are kept separate from established coverage so downstream
    research can quantify review opportunities without claiming validation.
    """
    rows: list[dict[str, object]] = []
    originally_unmapped = newly_mapped = 0
    for rule, llm_row in zip(rules, llm_rows):
        if rule_mapping_ids(rule):
            continue  # candidates are only ever generated for UNMAPPED rules
        originally_unmapped += 1
        candidates = improved_unmapped_candidates(rule, catalog)  # source 1: heuristic
        source = "improved_heuristic_candidate"
        # heuristic wins when both exist, so llm_candidate counts labels
        if not candidates and llm_row["llm_status"] == "classified":
            source = "llm_candidate"  # source 2: Stage 5
            candidates = [
                {
                    "technique_id": technique_id,
                    "confidence": llm_row["llm_confidence"],
                    "reason": (
                        str(llm_row["llm_reasoning"]).strip()
                        or "LLM proposed this ATT&CK technique from the supplied rule context."
                    ) + " Candidate mapping requiring validation.",
                }
                for technique_id in sorted(llm_ids(llm_row))
                # same catalog guard as everywhere else: active IDs only
                if technique_id in catalog and catalog[technique_id]["status"] == "active"
            ]
        if candidates:
            newly_mapped += 1  # counts RULES with >=1 candidate, not candidate rows
        for candidate in candidates:
            technique_id = str(candidate["technique_id"])
            rows.append(
                {
                    "SID": rule.sid or "",
                    "Revision": rule.rev or "",
                    "Message": rule.msg,
                    "Candidate ATT&CK Technique": (
                        f"{technique_id} - {catalog[technique_id]['name']}"
                    ),
                    "Mapping Source": source,
                    "Confidence": candidate["confidence"],
                    "Reason": candidate["reason"],
                }
            )
    remaining = originally_unmapped - newly_mapped
    return rows, {
        "originally_unmapped_rules": originally_unmapped,
        "newly_mapped_rules": newly_mapped,
        "remaining_unmapped_rules": remaining,
        "coverage_improvement": round(newly_mapped / len(rules), 6) if rules else 0,
        "coverage_improvement_percentage": round(100 * newly_mapped / len(rules), 2)
        if rules
        else 0,
        "candidate_mappings_require_validation": True,
    }


# Format a technique ID as 'T1071.001 - Web Protocols'.
def technique_label(technique_id: str, catalog: dict[str, dict[str, object]]) -> str:
    detail = catalog.get(technique_id)
    if not detail:
        return technique_id
    return f"{technique_id} - {detail['name']}"


# Build the per-rule prompt object sent in Stage 5.
def _llm_rule_payload(rule: Rule, rule_index: int) -> dict[str, object]:
    # Stage 5 rules have no prior mapping to lean on, so the model is given
    # richer evidence; contents and PCREs are truncated to bound prompt size.
    return {
        "rule_index": rule_index,
        "sid": rule.sid,
        "rev": rule.rev,
        "msg": rule.msg,
        "classtype": rule.classtype,
        "service": rule.service,
        "protocol": rule.protocol,
        "direction": rule.direction,
        "metadata": rule.metadata,
        "references": rule.references,
        "contents": rule.contents[:5],
        "pcres": rule.pcres[:2],
        "keyword_attack_ids": sorted(rule_mapping_ids(rule)),
    }


# Build the per-rule prompt object sent in Stage 4.
def _mapped_validation_payload(rule: Rule, rule_index: int) -> dict[str, object]:
    """Return rule context without existing ATT&CK IDs for independent validation."""
    # Note what is absent: no attack_techniques and no keyword_attack_ids field,
    # so the model cannot copy the mapping it is being compared against.
    return {
        "rule_index": rule_index,
        "sid": rule.sid,
        "msg": rule.msg,
        "classtype": rule.classtype,
        "metadata": rule.metadata,
        "contents": rule.contents[:8],
    }



# NVIDIA LLM / API
OPENROUTER_CHAT_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_ENDPOINT = "https://openrouter.ai/api/v1/models"
OPENAI_CHAT_ENDPOINT = "https://api.openai.com/v1/chat/completions"

# NVIDIA's OpenAI-compatible endpoint - the default provider.
NVIDIA_CHAT_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODELS_ENDPOINT = "https://integrate.api.nvidia.com/v1/models"
NVIDIA_API_KEY_PREFIX = "nvapi-"

# Nemotron 3 Ultra, vendor-prefixed as NVIDIA lists it.
NEMOTRON_ULTRA_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"

# Transient codes worth retrying; other 4xx would fail identically.
RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 520, 522, 524})

# Account/model/endpoint faults: splitting the batch cannot help.
FATAL_STATUS = frozenset({401, 402, 403, 404})

# Give up on a stage after this many whole-batch failures in a row.
CONSECUTIVE_FAILURE_LIMIT = 5

# OpenRouter free-tier limits, kept for non-NVIDIA endpoints.
FREE_TIER_REQUESTS_PER_MINUTE = 20
FREE_TIER_DAILY_REQUESTS_NO_CREDIT = 50
FREE_TIER_DAILY_REQUESTS_WITH_CREDIT = 1000
FREE_TIER_MIN_INTERVAL = 60.0 / FREE_TIER_REQUESTS_PER_MINUTE + 0.2

# NVIDIA meters per key, so pacing follows the endpoint not the model.
NVIDIA_REQUESTS_PER_MINUTE = 40
NVIDIA_MIN_INTERVAL = 60.0 / NVIDIA_REQUESTS_PER_MINUTE + 0.2


# True for OpenRouter ':free' model variants.
def is_free_tier_model(model: str) -> bool:
    """True for OpenRouter zero-cost variants, which carry hard rate limits."""
    return model.strip().endswith(":free")


# True when the endpoint is NVIDIA's hosted API.
def is_nvidia_endpoint(endpoint: str) -> bool:
    """True for NVIDIA's OpenAI-compatible build/NIM endpoint."""
    return "integrate.api.nvidia.com" in (endpoint or "")


# Pick the pacing interval when --llm-request-delay is left at -1.
def auto_request_delay(model: str, endpoint: str) -> float:
    """Pick a pacing interval when --llm-request-delay is left at -1.

    Free OpenRouter variants are the tightest limit, so they win when both
    apply; otherwise an NVIDIA endpoint gets its own per-key pacing and every
    other provider is left unthrottled, exactly as before.
    """
    if is_free_tier_model(model):
        return FREE_TIER_MIN_INTERVAL
    if is_nvidia_endpoint(endpoint):
        return NVIDIA_MIN_INTERVAL
    return 0.0


# Throttles and counts real provider calls; shared by both LLM stages.
class RequestGovernor:
    """Throttles and counts real provider calls; cache hits stay free.

    A shared instance spans both LLM stages because they draw on the same
    provider quota. Counting here rather than per stage means a Stage 4 run
    followed by a Stage 5 run cannot together exceed the requested budget.
    """

    def __init__(self) -> None:
        self.min_interval = 0.0
        self.max_requests = 0
        self.count = 0
        self._last = 0.0

    def configure(self, *, min_interval: float, max_requests: int) -> None:
        # keep the strictest limit any stage asked for
        self.min_interval = max(self.min_interval, max(0.0, min_interval))
        if max_requests:
            self.max_requests = (
                min(self.max_requests, max_requests) if self.max_requests else max_requests
            )

    def reset(self) -> None:
        self.min_interval = 0.0
        self.max_requests = 0
        self.count = 0
        self._last = 0.0

    def acquire(self) -> None:
        # runs before every real request, never on a cache hit
        if self.max_requests and self.count >= self.max_requests:
            raise LLMTransportError(
                f"Request budget of {self.max_requests} calls is exhausted "
                f"(--llm-max-requests). Raise the budget or re-run to resume from cache.",
                fatal=True,
            )
        if self.min_interval:
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.monotonic()
        self.count += 1  # counts real calls only


GOVERNOR = RequestGovernor()  # one shared budget across Stage 4 and Stage 5

# Remembers which response_format each (endpoint, model) accepts.
_RESPONSE_FORMAT_MODE: dict[tuple[str, str], str] = {}

# Remembers whether the provider accepts the reasoning field.
_VENDOR_EXTRAS_SUPPORTED: dict[tuple[str, str], bool] = {}

# Logs the reasoning-channel fallback once, not every batch.
_REASONING_FALLBACK_NOTED = False


# Log the reasoning-channel fallback once per run.
def _note_reasoning_fallback(label: str) -> None:
    global _REASONING_FALLBACK_NOTED
    if not _REASONING_FALLBACK_NOTED:
        _REASONING_FALLBACK_NOTED = True
        print(
            f"[{label}] Model delivered its answer in the reasoning channel rather "
            "than the content field; parsing from there."
        )

CLASSIFICATION_JSON_SCHEMA = {
    "name": "attack_classifications",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "classifications": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rule_index": {"type": "integer"},
                        "sid": {"type": "string"},
                        "attack_ids": {"type": "array", "items": {"type": "string"}},
                        "confidence": {"type": "number"},
                        "reasoning": {"type": "string"},
                    },
                    "required": [
                        "rule_index",
                        "sid",
                        "attack_ids",
                        "confidence",
                        "reasoning",
                    ],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["classifications"],
        "additionalProperties": False,
    },
}


# One failed request, carrying flags that decide retry / split / abandon.
class LLMTransportError(RuntimeError):
    """A chat-completions request that could not be turned into classifications."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        status: int | None = None,
        retry_after: float | None = None,
        truncated: bool = False,
        unsupported_response_format: bool = False,
        fatal: bool = False,
        empty_completion: bool = False,
        unsupported_parameter: bool = False,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after
        self.truncated = truncated
        self.unsupported_response_format = unsupported_response_format
        # Provider rejected an optional field: drop it, don't retry as-is.
        self.unsupported_parameter = unsupported_parameter
        # fatal = account/model/network, not this batch's contents
        self.fatal = fatal
        # stopped cleanly with no answer: the request shape must change
        self.empty_completion = empty_completion


# Send the key to whichever provider issued it, based on its prefix.
def resolve_llm_endpoint(endpoint: str, api_key: str) -> str:
    """Send a key to the provider that issued it, whatever endpoint is set.

    A key exported without also overriding --llm-endpoint would otherwise fail
    with an opaque 401 from whichever host happened to be the default. The key
    prefix identifies the issuer unambiguously, so honour it.
    """
    endpoint = (endpoint or "").strip()
    if api_key.startswith(NVIDIA_API_KEY_PREFIX) and not is_nvidia_endpoint(endpoint):
        if "api.openai.com" in endpoint or "openrouter.ai" in endpoint:
            print(
                "[LLM] NVIDIA API key detected with a non-NVIDIA endpoint. "
                f"Using {NVIDIA_CHAT_ENDPOINT} instead."
            )
            return NVIDIA_CHAT_ENDPOINT
    if api_key.startswith("sk-or-") and "api.openai.com" in endpoint:
        print(
            "[LLM] OpenRouter API key detected with the OpenAI endpoint. "
            f"Using {OPENROUTER_CHAT_ENDPOINT} instead."
        )
        return OPENROUTER_CHAT_ENDPOINT
    return endpoint or NVIDIA_CHAT_ENDPOINT


# Add the vendor prefix the provider requires on a bare model name.
def normalise_model_id(model: str, endpoint: str) -> str:
    """Give bare model names the vendor prefix the provider requires."""
    model = (model or "").strip()
    if not model or "/" in model:
        return model  # already vendor-prefixed, e.g. nvidia/nemotron-3-ultra-...
    if is_nvidia_endpoint(endpoint):
        print(f"[LLM] NVIDIA requires vendor-prefixed model IDs. Using 'nvidia/{model}'.")
        return f"nvidia/{model}"
    if "openrouter.ai" not in endpoint:
        return model
    print(f"[LLM] OpenRouter requires vendor-prefixed model IDs. Using 'openai/{model}'.")
    return f"openai/{model}"


# Extract the readable message from a provider error body.
def _decode_error_body(raw: str) -> str:
    """Pull the human-readable message out of a provider error body."""
    if not raw:
        return ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip()[:400]
    if isinstance(data, dict):
        # Some providers wrap the fault in an "error" object, others return the
        # fields at the top level; fall back to the body itself when unwrapped.
        error = data.get("error", data)
        if isinstance(error, dict):
            message = error.get("message") or error.get("detail") or ""
            code = error.get("code")
            metadata = error.get("metadata")
            parts = [str(message)] if message else []
            if code and str(code) not in str(message):
                parts.append(f"(code {code})")
            if isinstance(metadata, dict) and metadata.get("raw"):
                parts.append(str(metadata["raw"])[:200])
            if parts:
                return " ".join(parts)[:400]
        if isinstance(error, str):
            return error[:400]
    return raw.strip()[:400]


# Remove SSE keep-alive lines and data frames before parsing JSON.
def strip_transport_noise(text: str) -> str:
    """Drop SSE comment keep-alives and byte-order marks before JSON parsing.

    OpenRouter emits lines such as ": OPENROUTER PROCESSING" while a request is
    queued, even when streaming was never requested. They are legal SSE
    comments but they are not JSON, so they must be removed first.
    """
    text = text.lstrip("﻿").strip()
    if not text or text[0] in "{[":
        return text
    kept = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(":")
    ]
    cleaned = "\n".join(kept).strip()
    # Some gateways additionally wrap the payload in SSE "data:" frames.
    if cleaned.startswith("data:"):
        frames = [
            line[len("data:"):].strip()
            for line in cleaned.splitlines()
            if line.startswith("data:") and line[len("data:"):].strip() != "[DONE]"
        ]
        if frames:
            cleaned = frames[-1]
    return cleaned


# Work out which brackets would close a truncated JSON fragment.
def _needed_closers(text: str) -> str | None:
    """Return the brackets needed to close `text`, or None if it ends mid-string."""
    stack: list[str] = []
    # String state is tracked separately: a '[' or '}' inside a JSON string
    # literal is text, not structure, and must not affect the bracket stack.
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "[":
            stack.append("]")
        elif char == "{":
            stack.append("}")
        elif char in "]}":
            if not stack:
                return None
            stack.pop()
    if in_string:
        return None
    return "".join(reversed(stack))


# Close a cut-off JSON array at the last complete object.
def repair_truncated_json(text: str, limit: int = 80):
    """Recover the complete prefix of a JSON value cut short by a token limit.

    A completion stopped at max_tokens leaves a syntactically invalid but
    semantically useful document. Rather than discard every rule in the batch,
    close the structure at the last complete object and keep what arrived.
    """
    attempts = 0
    for index in range(len(text) - 1, -1, -1):
        if text[index] != "}":
            continue
        attempts += 1
        if attempts > limit:
            break
        head = text[: index + 1].rstrip().rstrip(",")
        closers = _needed_closers(head)
        if closers is None:
            continue
        try:
            return json.loads(head + closers)
        except json.JSONDecodeError:
            continue
    return None


# Parse a provider reply, tolerating noise, fences, prose and truncation.
def loads_tolerant(text: str, *, allow_repair: bool = True):
    """Parse JSON that may be padded with keep-alives, fences, or prose."""
    cleaned = strip_transport_noise(text)
    if not cleaned:
        raise LLMTransportError("Provider returned an empty response body", retryable=True)
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json|JSON)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```\s*$", "", cleaned)
        cleaned = cleaned.strip()
    start = min(
        (position for position in (cleaned.find("{"), cleaned.find("[")) if position >= 0),
        default=-1,
    )
    if start < 0:
        raise LLMTransportError(
            f"Response contained no JSON value: {cleaned[:200]!r}", retryable=True
        )
    decoder = json.JSONDecoder()
    try:
        # raw_decode ignores trailing prose, which models add despite instructions.
        value, _ = decoder.raw_decode(cleaned[start:])
        return value
    except json.JSONDecodeError as error:
        # Last resort before the batch is lost: a reply cut off mid-array is
        # salvaged at its last complete object, keeping the classifications that
        # did arrive instead of discarding every rule in the batch.
        if allow_repair:
            repaired = repair_truncated_json(cleaned[start:])
            if repaired is not None:
                return repaired
        raise LLMTransportError(
            f"Malformed JSON from provider ({error.msg}): {cleaned[start:start + 200]!r}",
            retryable=True,
        ) from error


_UNSUPPORTED_PARAM_MARKERS = (
    "chat_template_kwargs",
    "reasoning_effort",
    "extra_fields",
    "extra inputs are not permitted",
    "unrecognized request argument",
    "unknown field",
    "additional properties are not allowed",
)


# True when an error body blames a vendor-extension field.
def _mentions_unsupported_parameter(raw: str) -> bool:
    """True when an error body blames a vendor-extension field in the request.

    Providers advertising "OpenAI-compatible" disagree about which extensions
    they tolerate. Recognising the complaint lets the request shape change once
    rather than failing a whole stage over an optional field.
    """
    if not raw:
        return False
    lowered = raw.lower()
    if "response_format" in lowered or "json_schema" in lowered:
        return False  # handled by the structured-output ladder instead
    if '"reasoning"' in lowered or "'reasoning'" in lowered:
        return True
    return any(marker in lowered for marker in _UNSUPPORTED_PARAM_MARKERS)


# Provider-specific way to request or suppress hidden reasoning.
def _reasoning_payload_fields(reasoning_effort: str, endpoint: str) -> dict[str, object]:
    """Provider-specific way to ask for (or suppress) hidden reasoning.

    Open-weight reasoning models spend completion tokens on hidden reasoning, so
    a low effort setting leaves budget for the answer. The reasoning is
    deliberately NOT excluded on any provider: some return the answer there
    instead of in `content`, and excluding it would discard the only copy.
    """
    if not reasoning_effort or reasoning_effort == "none":
        # Nemotron thinks by default, so 'off' must be stated
        if is_nvidia_endpoint(endpoint):
            return {"chat_template_kwargs": {"enable_thinking": False}}
        return {}
    if is_nvidia_endpoint(endpoint):
        # NIM controls reasoning via the chat template, not `reasoning`
        return {
            "chat_template_kwargs": {
                "enable_thinking": True,
                "reasoning_effort": reasoning_effort,
            }
        }
    return {"reasoning": {"effort": reasoning_effort}}


# The only place a provider is contacted; classifies every failure mode.
def _http_post_json(
    endpoint: str, api_key: str, payload: dict, timeout: int
) -> tuple[dict, str]:
    """POST JSON and return (parsed body, raw text), raising LLMTransportError."""
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Ask for an uncompressed body; urllib does not transparently inflate.
        "Accept-Encoding": "identity",
    }
    if "openrouter.ai" in endpoint:
        # OpenRouter attribution headers; meaningless to any other provider.
        headers["HTTP-Referer"] = "https://github.com/snort-attack-mapping"
        headers["X-Title"] = "Snort Rule ATT&CK Analyzer"
    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    # Blocks until the pacing interval has elapsed and increments the counter.
    # Placed here, after the cache miss, so cached work is never billed or paced.
    GOVERNOR.acquire()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        raw = ""
        try:
            raw = error.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - body is best-effort diagnostic only
            pass
        detail = _decode_error_body(raw) or str(error.reason)
        retry_after = None
        if error.headers is not None:
            try:
                retry_after = float(error.headers.get("Retry-After", ""))
            except (TypeError, ValueError):
                retry_after = None
        raise LLMTransportError(
            f"HTTP {error.code}: {detail}",
            retryable=error.code in RETRYABLE_STATUS,
            status=error.code,
            retry_after=retry_after,
            fatal=error.code in FATAL_STATUS,
            # NIM uses 422 where OpenRouter uses 400
            unsupported_response_format=(
                error.code in {400, 422}
                and (
                    "response_format" in raw
                    or "json_schema" in raw
                    or "guided" in raw.lower()
                    or "structured output" in raw.lower()
                )
            ),
            unsupported_parameter=(
                error.code in {400, 422}
                and _mentions_unsupported_parameter(raw)
            ),
        ) from error
    except urllib.error.URLError as error:
        raise LLMTransportError(
            f"Network error contacting {endpoint}: {error.reason}",
            retryable=True,
            fatal=True,
        ) from error
    except (TimeoutError, OSError) as error:
        raise LLMTransportError(
            f"Connection error contacting {endpoint}: {error}",
            retryable=True,
            fatal=True,
        ) from error

    data = loads_tolerant(raw, allow_repair=False)
    if not isinstance(data, dict):
        raise LLMTransportError("Provider response was not a JSON object", retryable=True)
    # OpenRouter reports some upstream failures with HTTP 200 and an error body.
    if data.get("error"):
        detail = _decode_error_body(raw)
        status = None
        if isinstance(data["error"], dict):
            code = data["error"].get("code")
            status = code if isinstance(code, int) else None
        raise LLMTransportError(
            f"Provider error: {detail}",
            retryable=status in RETRYABLE_STATUS if status else True,
            status=status,
        )
    return data, raw


# Collect the reasoning channel alongside the answer.
def _reasoning_text(message: dict) -> str:
    """Collect any reasoning the provider returned alongside the answer.

    Harmony-format models such as gpt-oss emit an "analysis" channel and a
    "final" channel. OpenRouter maps analysis to `reasoning` and final to
    `content`, but some providers put the whole answer in the analysis channel
    and leave `content` empty with finish_reason="stop". Keeping the reasoning
    means that response is recoverable instead of lost.
    """
    parts: list[str] = []
    raw = message.get("reasoning")
    if isinstance(raw, str) and raw.strip():
        parts.append(raw)
    details = message.get("reasoning_details")
    if isinstance(details, list):
        for detail in details:
            if not isinstance(detail, dict):
                continue
            text = detail.get("text") or detail.get("summary") or ""
            if isinstance(text, str) and text.strip():
                parts.append(text)
    return "\n".join(parts).strip()


# Return (content, finish_reason, reasoning) from a chat completion.
def _message_content(data: dict) -> tuple[str, str, str]:
    """Return (content, finish_reason, reasoning) from a chat-completions body."""
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMTransportError(
            f"Response contained no choices: {json.dumps(data)[:300]}", retryable=True
        )
    choice = choices[0] if isinstance(choices[0], dict) else {}
    finish_reason = str(choice.get("finish_reason") or choice.get("native_finish_reason") or "")
    message = choice.get("message")
    content = ""
    reasoning = ""
    if isinstance(message, dict):
        raw_content = message.get("content")
        if isinstance(raw_content, str):
            content = raw_content
        elif isinstance(raw_content, list):
            # Anthropic-style content parts proxied through the OpenAI schema.
            content = "".join(
                part.get("text", "")
                for part in raw_content
                if isinstance(part, dict) and part.get("type") in {None, "text", "output_text"}
            )
        reasoning = _reasoning_text(message)
    elif isinstance(choice.get("text"), str):
        content = choice["text"]
    return content.strip(), finish_reason, reasoning


# Cache filename = hash of the exact request payload.
def _cache_path(cache_dir: Path, payload: dict) -> Path:
    # sort_keys makes the digest independent of dict ordering, so the same
    # logical request always resolves to the same file. That is what lets an
    # interrupted run resume and a re-run reproduce results at zero API cost.
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return cache_dir / f"{digest}.json"


# One request end to end: cache, POST, parse, and reshape on failure.
def llm_chat_json(
    *,
    endpoint: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: int,
    retries: int,
    cache_dir: Path | None,
    debug_log: Path | None,
    label: str,
    reasoning_effort: str = "none",
    fallback_models: tuple[str, ...] = (),
) -> tuple[list[dict], str]:
    """Run one request and return (classification objects, responding model).

    Raises LLMTransportError with `truncated=True` when the model ran out of
    completion budget, which callers use as the signal to split the batch.
    """
    # Structured-output support is negotiated once per (endpoint, model) and
    # reused, so later batches do not re-pay the discovery cost.
    mode_key = (endpoint, model)
    mode = _RESPONSE_FORMAT_MODE.get(mode_key, "json_schema")
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    attempt = 0
    budget = max_tokens
    last_error: LLMTransportError | None = None
    send_extras = _VENDOR_EXTRAS_SUPPORTED.get(mode_key, True)
    while attempt <= retries:
        # temperature 0 keeps the run as close to deterministic as the provider
        # allows, which the response cache depends on for reproducibility.
        payload: dict[str, object] = {
            "model": model,
            "messages": messages,
            "max_tokens": budget,
            "temperature": 0,
        }
        if send_extras:
            payload.update(_reasoning_payload_fields(reasoning_effort, endpoint))
        if fallback_models and "openrouter.ai" in endpoint:
            # OpenRouter-only: server-side model fallback
            payload["models"] = [model, *fallback_models]
        if mode == "json_schema":
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": CLASSIFICATION_JSON_SCHEMA,
            }
        elif mode == "json_object":
            payload["response_format"] = {"type": "json_object"}

        # cache key = hash of the exact payload, so hits are exact
        cache_file = _cache_path(cache_dir, payload) if cache_dir else None
        if cache_file is not None and cache_file.is_file():
            try:
                cached = json.loads(cache_file.read_text("utf-8"))
                if isinstance(cached, dict) and "__model__" in cached:
                    return (
                        _coerce_classifications(cached["__payload__"]),
                        str(cached["__model__"]),
                    )
                return _coerce_classifications(cached), model
            except (json.JSONDecodeError, KeyError, LLMTransportError, OSError):
                cache_file.unlink(missing_ok=True)

        try:
            data, raw = _http_post_json(endpoint, api_key, payload, timeout)  # the NVIDIA call
            if debug_log is not None:
                _append_debug(debug_log, label, payload, raw)
            content, finish_reason, reasoning = _message_content(data)
            truncated = finish_reason in {"length", "max_tokens"}
            decoded = None
            parse_error: LLMTransportError | None = None
            # answer may arrive in `content` or in the reasoning channel
            for source, text in (("content", content), ("reasoning", reasoning)):
                if not text:
                    continue
                try:
                    decoded = loads_tolerant(text)
                except LLMTransportError as error:
                    parse_error = error
                    continue
                if source == "reasoning":
                    _note_reasoning_fallback(label)
                break
            if decoded is None:
                if not content:
                    raise LLMTransportError(
                        "Model returned empty content"
                        + (f" (finish_reason={finish_reason})" if finish_reason else ""),
                        retryable=True,
                        truncated=truncated,
                        # stopped cleanly with no answer: repeating would fail the same way
                        empty_completion=not truncated,
                    )
                raise parse_error or LLMTransportError(
                    "Provider returned no parseable JSON answer", retryable=True
                )
            classifications = _coerce_classifications(decoded)
            if finish_reason in {"length", "max_tokens"} and not classifications:
                raise LLMTransportError(
                    "Completion truncated before any classification was produced",
                    retryable=True,
                    truncated=True,
                )
            # which model actually answered -> per-rule provenance column
            answering_model = str(data.get("model") or model)
            if cache_file is not None:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(
                    json.dumps(
                        {"__model__": answering_model, "__payload__": decoded},
                        ensure_ascii=True,
                    ),
                    encoding="utf-8",
                )
            return classifications, answering_model
        except LLMTransportError as error:
            last_error = error
            if error.unsupported_response_format and mode != "none":
                mode = "json_object" if mode == "json_schema" else "none"
                _RESPONSE_FORMAT_MODE[mode_key] = mode
                print(f"[LLM] Provider rejected structured output; falling back to '{mode}'.")
                continue  # Re-issue immediately without consuming a retry.
            if error.unsupported_parameter and send_extras:
                # optional field refused: drop it and re-send
                send_extras = False
                _VENDOR_EXTRAS_SUPPORTED[mode_key] = False
                print(
                    f"[{label}] Provider rejected the reasoning-control parameter; "
                    "re-issuing without it."
                )
                continue  # Re-issue immediately without consuming a retry.
            if error.empty_completion and mode != "none":
                # strict JSON can suppress the answer entirely; relax it
                mode = "json_object" if mode == "json_schema" else "none"
                _RESPONSE_FORMAT_MODE[mode_key] = mode
                print(
                    f"[{label}] Model returned no answer under '{mode_key[1]}' structured "
                    f"output; retrying with response_format='{mode}'."
                )
                continue
            # ran out of completion budget mid-answer -> give it more room
            if error.truncated and budget < 32000:
                budget = min(budget * 2, 32000)
                print(f"[LLM] Completion truncated; retrying with max_tokens={budget}.")
                attempt += 1
                continue
            if not error.retryable or attempt >= retries:
                raise  # permanent (bad key/model) or out of attempts: don't loop
            # Honour the provider's own Retry-After when supplied; otherwise
            # back off exponentially, capped at 15s so a stalled provider cannot
            # stretch one batch into minutes of waiting.
            delay = error.retry_after if error.retry_after else min(2 ** attempt, 15)
            delay += random.uniform(0, 0.5)  # jitter avoids synchronised retries
            print(f"[LLM] {error} - retrying in {delay:.1f}s ({attempt + 1}/{retries}).")
            time.sleep(delay)
            attempt += 1
    raise last_error or LLMTransportError("LLM request failed", retryable=False)


# Accept the several shapes models use for a list of classifications.
def _coerce_classifications(decoded) -> list[dict]:
    """Accept the several shapes models use for a list of classifications."""
    if isinstance(decoded, dict):
        for key in ("classifications", "results", "rules", "data", "items", "output"):
            if isinstance(decoded.get(key), list):
                decoded = decoded[key]
                break
        else:
            # A single object for a single rule is a common one-shot response.
            decoded = [decoded] if "rule_index" in decoded or "sid" in decoded else []
    if not isinstance(decoded, list):
        raise LLMTransportError(
            "Response JSON was neither a classifications array nor an object containing one",
            retryable=True,
        )
    return [item for item in decoded if isinstance(item, dict)]


# Append the raw response to llm_debug.jsonl; never breaks a run.
def _append_debug(debug_log: Path, label: str, payload: dict, raw: str) -> None:
    try:
        debug_log.parent.mkdir(parents=True, exist_ok=True)
        with debug_log.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "label": label,
                        "model": payload.get("model"),
                        "response_format": payload.get("response_format"),
                        "request_messages_chars": sum(
                            len(str(message.get("content", "")))
                            for message in payload.get("messages", [])
                        ),
                        "raw_response": raw[:20000],
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
    except OSError:
        pass  # Debug logging must never break a run.


# Scale the completion budget with batch size.
def _batch_token_budget(batch_size: int) -> int:
    """Scale the completion budget with batch size, with headroom for reasoning."""
    # ~500 tokens per rule + headroom for reasoning, clamped to a sane range
    return max(2000, min(16000, 500 * batch_size + 1500))


# Batch driver shared by Stage 4 and Stage 5.
def llm_classify_batches(
    items: list,
    *,
    payload_builder,
    system: str,
    endpoint: str,
    api_key: str,
    model: str,
    batch_size: int,
    timeout: int,
    retries: int,
    cache_dir: Path | None,
    debug_log: Path | None,
    label: str,
    progress_every: int = 1,
    reasoning_effort: str = "none",
    fallback_models: tuple[str, ...] = (),
) -> tuple[dict[int, dict], dict[int, str], dict[int, str]]:
    """Classify `items` in batches, splitting on failure to salvage partial results.

    Returns (responses keyed by rule index, errors keyed by rule index). A batch
    that fails is halved and retried, down to individual rules, so one
    unparseable rule cannot erase the evidence for its nine neighbours.
    """
    responses: dict[int, dict] = {}
    errors: dict[int, str] = {}
    models: dict[int, str] = {}
    # Rules are grouped so one request covers many rules, cutting the request
    # count (and therefore the quota cost) by roughly the batch size.
    batches = [
        items[start : start + batch_size] for start in range(0, len(items), batch_size)
    ]
    total = len(batches)
    state = {"consecutive_failures": 0, "aborted": ""}
    for number, batch in enumerate(batches, start=1):
        if state["aborted"]:
            for index, _item in batch:
                errors[index] = state["aborted"]
            continue
        if progress_every and number % progress_every == 0:
            print(f"[{label}] Batch {number}/{total} ({len(batch)} rules)...", flush=True)
        answered_before = len(responses)
        _run_batch(
            batch,
            responses=responses,
            errors=errors,
            models=models,
            payload_builder=payload_builder,
            system=system,
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            timeout=timeout,
            retries=retries,
            cache_dir=cache_dir,
            debug_log=debug_log,
            label=label,
            state=state,
            reasoning_effort=reasoning_effort,
            fallback_models=fallback_models,
        )
        if len(responses) > answered_before:
            state["consecutive_failures"] = 0
        else:
            state["consecutive_failures"] += 1
            # Circuit breaker: a dead endpoint, bad key or exhausted quota fails
            # every batch identically, so stop after five in a row rather than
            # let several hundred batches each burn their own retries.
            if state["consecutive_failures"] >= CONSECUTIVE_FAILURE_LIMIT:
                state["aborted"] = (
                    f"{label} stage abandoned after {CONSECUTIVE_FAILURE_LIMIT} "
                    "consecutive batch failures; see the errors above"
                )
                print(f"[{label}] {state['aborted']}. Remaining rules are marked unavailable.")
    if models:
        used = Counter(models.values())
        if len(used) > 1:
            print(
                f"[{label}] Responses came from more than one model: "
                + ", ".join(f"{name} ({count} rules)" for name, count in used.most_common())
                + ". The per-rule model is recorded in the output CSV."
            )
    return responses, errors, models


# Send one batch and reconcile the reply; splits on failure.
def _run_batch(
    batch: list,
    *,
    responses: dict[int, dict],
    errors: dict[int, str],
    models: dict[int, str],
    payload_builder,
    system: str,
    endpoint: str,
    api_key: str,
    model: str,
    timeout: int,
    retries: int,
    cache_dir: Path | None,
    debug_log: Path | None,
    label: str,
    state: dict | None = None,
    reasoning_effort: str = "none",
    fallback_models: tuple[str, ...] = (),
) -> None:
    if not batch:
        return
    user = json.dumps(
        {"rules": [payload_builder(item, index) for index, item in batch]},
        ensure_ascii=True,
    )
    try:
        classifications, answering_model = llm_chat_json(
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            system=system,
            user=user,
            max_tokens=_batch_token_budget(len(batch)),
            timeout=timeout,
            retries=retries,
            cache_dir=cache_dir,
            debug_log=debug_log,
            label=label,
            reasoning_effort=reasoning_effort,
            fallback_models=fallback_models,
        )
    except LLMTransportError as error:
        if error.fatal:
            # every rule here and after would fail identically
            for index, _item in batch:
                errors[index] = str(error)[:500]
            return
        if len(batch) > 1:
            # Halve and retry: isolates the rule that the provider chokes on.
            print(f"[{label}] Batch of {len(batch)} failed ({error}); splitting.")
            middle = len(batch) // 2
            for half in (batch[:middle], batch[middle:]):
                _run_batch(
                    half,
                    responses=responses,
                    errors=errors,
                    models=models,
                    payload_builder=payload_builder,
                    system=system,
                    endpoint=endpoint,
                    api_key=api_key,
                    model=model,
                    timeout=timeout,
                    retries=retries,
                    cache_dir=cache_dir,
                    debug_log=debug_log,
                    label=label,
                    state=state,
                    reasoning_effort=reasoning_effort,
                    fallback_models=fallback_models,
                )
            return
        for index, _item in batch:
            errors[index] = str(error)[:500]
        return

    # match each answer back to the rule it belongs to
    by_index: dict[int, dict] = {}
    for item in classifications:
        raw_index = item.get("rule_index")
        try:
            by_index[int(str(raw_index).strip())] = item
        except (TypeError, ValueError):
            continue  # unparseable index; SID matching below may still rescue it
    # Some models renumber rule_index; fall back to matching on SID.
    by_sid = {
        str(item.get("sid", "")).strip(): item
        for item in classifications
        if str(item.get("sid", "")).strip()
    }
    for index, item in batch:
        matched = by_index.get(index)
        if matched is None:  # index missing or renumbered -> match on SID instead
            sid = str(getattr(item, "sid", "") or "").strip()
            matched = by_sid.get(sid)
        if matched is None:
            if len(batch) > 1:
                # Retry this rule alone rather than record a missing answer.
                _run_batch(
                    [(index, item)],
                    responses=responses,
                    errors=errors,
                    models=models,
                    payload_builder=payload_builder,
                    system=system,
                    endpoint=endpoint,
                    api_key=api_key,
                    model=model,
                    timeout=timeout,
                    retries=retries,
                    cache_dir=cache_dir,
                    debug_log=debug_log,
                    label=label,
                    state=state,
                    reasoning_effort=reasoning_effort,
                    fallback_models=fallback_models,
                )
            else:
                errors[index] = "Provider response omitted this rule"
            continue
        responses[index] = matched
        models[index] = answering_model  # per-rule model provenance


# List the active ATT&CK IDs the model is allowed to return.
def allowed_technique_prompt(catalog: dict[str, dict[str, object]]) -> str:
    """Render the active Enterprise ATT&CK IDs the model is allowed to return."""
    return "\n".join(
        f"{technique_id}: {detail['name']}"
        for technique_id, detail in sorted(catalog.items())
        if detail["status"] == "active"  # deprecated/revoked IDs are never offered to the model
    )


# Keep only active catalog IDs from a model answer.
def accepted_technique_ids(
    item: dict, catalog: dict[str, dict[str, object]]
) -> list[str]:
    """Keep only active catalog IDs, normalising the formats models emit."""
    raw = item.get("attack_ids", [])
    if isinstance(raw, str):
        raw = re.split(r"[,\s|]+", raw)  # some models return "T1071, T1014" as one string
    if not isinstance(raw, list):
        return []
    accepted: set[str] = set()
    for value in raw:
        technique = str(value).strip().upper()
        # Models sometimes answer "T1071.001 - Web Protocols" or "attack.t1071".
        match = re.search(r"T\d{4}(?:\.\d{3})?", technique)
        if not match:
            continue
        technique = match.group(0)
        # only IDs active in the local catalog survive - no invented coverage
        if technique in catalog and catalog[technique]["status"] == "active":
            accepted.add(technique)
    return sorted(accepted)


# Configure throttling and print the request budget before a stage.
def plan_requests(
    selected_count: int, batch_size: int, model: str, config, label: str, endpoint: str = ""
) -> None:
    """Configure throttling and report the request budget before a long run."""
    # A negative --llm-request-delay means "decide for me": derive the pacing
    # from the provider and model, then hand it to the governor that both LLM
    # stages share, so Stage 4 and Stage 5 cannot together exceed the budget.
    delay = config.request_delay
    if delay < 0:
        delay = auto_request_delay(model, endpoint)
    GOVERNOR.configure(min_interval=delay, max_requests=config.max_requests)

    planned = -(-selected_count // max(1, batch_size))  # ceiling division
    estimate = planned * delay
    print(
        f"[{label}] Planned requests: ~{planned} "
        f"({selected_count} rules / batch size {batch_size})."
    )
    if delay:
        minutes = estimate / 60
        tier = (
            f"the {NVIDIA_REQUESTS_PER_MINUTE}/min NVIDIA limit"
            if is_nvidia_endpoint(endpoint) and not is_free_tier_model(model)
            else "the free tier"
        )
        print(
            f"[{label}] Throttling to one request every {delay:.1f}s for {tier} "
            f"(~{minutes:.1f} min minimum)."
        )
    if is_free_tier_model(model) and planned > FREE_TIER_DAILY_REQUESTS_NO_CREDIT:
        print(
            f"[{label}] WARNING: {planned} requests exceeds the "
            f"{FREE_TIER_DAILY_REQUESTS_NO_CREDIT}/day free allowance for accounts with "
            f"no credit. Increase the batch size, use --llm-max-rules, or add credit to "
            f"raise the cap to {FREE_TIER_DAILY_REQUESTS_WITH_CREDIT}/day. Completed "
            "batches are cached, so an interrupted run resumes where it stopped."
        )


# One request to prove key, endpoint, model and JSON contract.
def preflight_llm(
    endpoint: str,
    api_key: str,
    model: str,
    timeout: int = 60,
    reasoning_effort: str = "none",
    retries: int = 4,
    fallback_models: tuple[str, ...] = (),
) -> bool:
    """Verify credentials, endpoint, and model before committing to a long run."""
    print(f"[Preflight] Endpoint : {endpoint}")
    print(f"[Preflight] Model    : {model}")
    print(f"[Preflight] Key      : {api_key[:8]}...{api_key[-4:]} ({len(api_key)} chars)")
    try:
        classifications, answering_model = llm_chat_json(
            endpoint=endpoint,
            api_key=api_key,
            model=model,
            system=(
                "Return JSON only, matching {\"classifications\": [...]} where each item has "
                "rule_index (integer), sid (string), attack_ids (array of strings), "
                "confidence (number), and reasoning (string)."
            ),
            user=json.dumps(
                {
                    "rules": [
                        {
                            "rule_index": 0,
                            "sid": "9999999",
                            "msg": "PROTOCOL-DNS TXT record query response with base64 payload",
                        }
                    ]
                }
            ),
            max_tokens=2000,
            timeout=timeout,
            retries=retries,
            cache_dir=None,
            debug_log=None,
            label="Preflight",
            reasoning_effort=reasoning_effort,
            fallback_models=fallback_models,
        )
    except LLMTransportError as error:
        print(f"[Preflight] FAILED: {error}")
        # Each branch names the concrete cause and its fix, so a failed preflight
        # is self-diagnosing instead of surfacing a bare HTTP status.
        if error.status in {401, 403}:
            print("[Preflight] The API key was rejected. Check the key and its credit balance.")
            if is_nvidia_endpoint(endpoint) and not api_key.startswith(NVIDIA_API_KEY_PREFIX):
                print(
                    f"[Preflight] The key does not begin with '{NVIDIA_API_KEY_PREFIX}'. "
                    "NVIDIA build keys do; check that NVIDIA_API_KEY holds the right value."
                )
        elif error.status in {400, 404, 422}:
            print("[Preflight] The model ID was rejected. Confirm it against the provider catalogue:")
            print(
                f"[Preflight]   "
                f"{NVIDIA_MODELS_ENDPOINT if is_nvidia_endpoint(endpoint) else OPENROUTER_MODELS_ENDPOINT}"
            )
            if is_nvidia_endpoint(endpoint):
                print(f"[Preflight]   Expected model ID: {NEMOTRON_ULTRA_MODEL}")
        elif error.status == 429:
            if is_nvidia_endpoint(endpoint):
                print(
                    "[Preflight] The key is rate-limited. NVIDIA meters per key, so wait a "
                    f"minute and retry, or lower the pace with --llm-request-delay "
                    f"(auto-paced at {NVIDIA_MIN_INTERVAL:.1f}s between calls)."
                )
                return False
            print(
                "[Preflight] The model is rate-limited upstream. ':free' variants are served "
                "by a single shared provider pool, so this is common at busy times."
            )
            if is_free_tier_model(model):
                paid = model.rsplit(":free", 1)[0]
                print(
                    f"[Preflight] The same model without the ':free' suffix ({paid}) is served "
                    "by around a dozen providers with automatic failover, at roughly "
                    "$0.03 per million input tokens. Stage 4 over all mapped rules costs "
                    "about two US cents at that rate."
                )
                print(f"[Preflight] To switch:  -Model \"{paid}\"")
            print(
                "[Preflight] Otherwise: wait a few minutes and retry, or pass "
                "--llm-model-fallbacks with other free model IDs."
            )
        elif error.empty_completion:
            print(
                "[Preflight] The model completed without producing an answer even after "
                "relaxing structured output. Try --llm-reasoning-effort medium, or a "
                "different model."
            )
        return False
    print(
        f"[Preflight] OK. Parsed {len(classifications)} classification object(s) "
        f"from {answering_model}."
    )
    if answering_model.split(":")[0] != model.split(":")[0]:
        print(
            f"[Preflight] Note: the request was routed to {answering_model} rather than "
            f"{model}. The responding model is recorded per rule in the output."
        )
    return True


# Resolve the cache directory and debug log for a stage.
def _llm_working_dirs(config) -> tuple[Path | None, Path | None]:
    """Resolve the cache directory and debug log for a stage configuration."""
    cache_dir = Path(config.cache_dir) if getattr(config, "cache_dir", "") else None
    debug_log = Path(config.debug_log) if getattr(config, "debug_log", "") else None  # opt-in audit log
    return cache_dir, debug_log


# Stage 4 prompt. It deliberately withholds the existing mapping and licenses an
# empty answer, so agreement is independent reproduction rather than confirmation.
MAPPED_VALIDATION_SYSTEM = (
    "You are validating Snort-to-ATT&CK mappings for a security research study.\n"
    "Predict MITRE ATT&CK techniques using ONLY the supplied Snort rule context. "
    "You are not shown the existing mapping and must not guess it.\n"
    "Judge network-observable behaviour. Do not infer a technique from malware "
    "family naming alone. Return an empty attack_ids array when the rule evidence "
    "is insufficient - an honest empty answer is more useful than a guess.\n"
    "Respond with JSON only, in the form "
    '{"classifications": [{"rule_index": <int>, "sid": "<string>", '
    '"attack_ids": ["Txxxx" or "Txxxx.yyy"], "confidence": <0..1>, '
    '"reasoning": "<one or two sentences>"}]}\n'
    "Return exactly one object per input rule, preserving each rule_index.\n"
    "Only these active Enterprise ATT&CK IDs are permitted:\n"
)


# STAGE 4 - LLM VALIDATION: Independent LLM re-prediction of mapped rules
def validate_mapped_rules_with_llm(
    rules: list[Rule],
    catalog: dict[str, dict[str, object]],
    config: MappedLLMValidationConfig,
) -> list[dict[str, object]]:
    """Ask an LLM to reproduce existing mapped-rule ATT&CK techniques independently.

    This is a reproduction test, not a correction pass: the model never sees the
    keyword mapping, and its answer never overwrites one. Agreement is therefore
    evidence about the keyword mapper, not about the model.
    """
    started = time.perf_counter()
    # STAGE 4 COHORT: keyword-MAPPED rules only (non-empty rule_mapping_ids)
    mapped = [(index, rule) for index, rule in enumerate(rules) if rule_mapping_ids(rule)]
    # cap applied after the filter, so a capped run still validates mapped rules
    selected = mapped[: config.max_rules] if config.max_rules else mapped
    rows = [
        {
            "SID": rule.sid or "",
            "Existing Technique": joined(
                technique_label(technique_id, catalog)
                for technique_id in sorted(rule_mapping_ids(rule))
            ),
            "LLM Prediction": "",
            "Agreement": "validation_not_run",
            "Confidence": "",
            "Reason": "Mapped-rule LLM validation was not enabled",
            "Model": "",
        }
        for _, rule in selected
    ]
    if not config.enabled:
        print("[Mapped LLM Validation] Disabled. Existing ATT&CK mappings are unchanged.")
        return rows

    def fail_all(message: str) -> list[dict[str, object]]:
        print(f"[Mapped LLM Validation] Cannot start: {message}")
        for row in rows:
            row["Agreement"] = "validation_error"
            row["Reason"] = message
        return rows

    if not config.model:
        return fail_all("--mapped-validation-model is required when mapped validation is enabled")
    api_key = os.environ.get(config.api_key_env, "").strip()
    if not api_key:
        return fail_all(f"API key environment variable {config.api_key_env} is not set")
    if not selected:
        print("[Mapped LLM Validation] No keyword-mapped rules to validate.")
        return rows

    endpoint = resolve_llm_endpoint(config.endpoint, api_key)
    model = normalise_model_id(config.model, endpoint)
    cache_dir, debug_log = _llm_working_dirs(config)
    print(
        f"[Mapped LLM Validation] Enabled. Submitting {len(selected)} mapped rules "
        f"to {endpoint} using {model}."
    )
    plan_requests(
        len(selected),
        max(1, config.batch_size),
        model,
        config,
        "Mapped LLM Validation",
        endpoint,
    )
    fallbacks = tuple(config.fallback_models)
    if config.preflight and not preflight_llm(
        endpoint,
        api_key,
        model,
        config.timeout,
        config.reasoning_effort,
        config.retries,
        fallbacks,
    ):
        return fail_all("Preflight check failed; see the messages above")

    system = MAPPED_VALIDATION_SYSTEM + allowed_technique_prompt(catalog)
    responses, errors, answering_models = llm_classify_batches(
        selected,
        payload_builder=_mapped_validation_payload,
        system=system,
        endpoint=endpoint,
        api_key=api_key,
        model=model,
        batch_size=max(1, config.batch_size),
        timeout=config.timeout,
        retries=config.retries,
        cache_dir=cache_dir,
        debug_log=debug_log,
        label="Mapped LLM Validation",
        reasoning_effort=config.reasoning_effort,
        fallback_models=fallbacks,
    )

    row_by_rule_index = {rule_index: row for (rule_index, _), row in zip(selected, rows)}
    for index, rule in selected:
        row = row_by_rule_index[index]
        item = responses.get(index)
        if item is None:
            row["Agreement"] = "validation_error"
            row["Reason"] = errors.get(index, "Provider response omitted this rule")[:500]
            continue
        predicted = accepted_technique_ids(item, catalog)  # LLM answer, catalog-filtered
        existing = rule_mapping_ids(rule)                  # Stage 3 keyword mapping
        predicted_set = set(predicted)
        # compare the LLM answer with the existing keyword mapping
        if predicted_set == existing:
            agreement = "match"            # same techniques
        elif predicted_set & existing:
            agreement = "partial_match"    # some overlap
        elif not predicted_set:
            agreement = "no_prediction"    # model gave nothing (not a disagreement)
        else:
            agreement = "mismatch"         # model gave something different
        row.update(
            {
                "LLM Prediction": joined(
                    technique_label(technique_id, catalog) for technique_id in predicted
                ),
                "Agreement": agreement,
                "Confidence": item.get("confidence", ""),
                "Reason": str(item.get("reasoning", "")).strip()[:1000],
                "Model": answering_models.get(index, model),
            }
        )

    counts = Counter(str(row["Agreement"]) for row in rows)
    elapsed = time.perf_counter() - started
    print(
        f"[Mapped LLM Validation] Completed {len(selected)} rules in {elapsed:.1f}s. "
        + ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    )
    print(
        f"[Mapped LLM Validation] Provider requests used so far: {GOVERNOR.count}"
        + (
            f" of the {FREE_TIER_DAILY_REQUESTS_NO_CREDIT}/day free allowance."
            if is_free_tier_model(model)
            else "."
        )
    )
    return rows


# Aggregate Stage 4 rows into the validation metrics block.
def mapped_rule_validation_metrics(rows: list[dict[str, object]]) -> dict[str, object]:
    tested = [
        row for row in rows
        if row["Agreement"] not in {"validation_not_run", "validation_error"}
    ]
    # Two agreement figures are reported deliberately: agreement_percentage
    # counts exact matches only, any_overlap_percentage also counts partials.
    # Abstentions are held separately and are folded into neither.
    matches = sum(row["Agreement"] == "match" for row in tested)
    partial_matches = sum(row["Agreement"] == "partial_match" for row in tested)
    mismatches = sum(row["Agreement"] == "mismatch" for row in tested)
    # abstention is not disagreement, so count it separately
    no_predictions = sum(row["Agreement"] == "no_prediction" for row in tested)
    disagreements = sum(row["Agreement"] != "match" for row in tested)
    confidence_scores = []
    for row in tested:
        try:
            confidence = float(row["Confidence"])
        except (TypeError, ValueError):
            continue
        if 0 <= confidence <= 1:
            confidence_scores.append(confidence)
    return {
        "enabled": bool(rows) and any(row["Agreement"] != "validation_not_run" for row in rows),
        "candidate_rules": len(rows),
        "total_tested_rules": len(tested),
        "matches": matches,
        "partial_matches": partial_matches,
        "mismatches": mismatches,
        "no_predictions": no_predictions,
        "disagreements": disagreements,
        "agreement_percentage": round(100 * matches / len(tested), 2) if tested else 0,
        "partial_match_percentage": round(100 * partial_matches / len(tested), 2)
        if tested
        else 0,
        "mismatch_percentage": round(100 * mismatches / len(tested), 2) if tested else 0,
        "no_prediction_percentage": round(100 * no_predictions / len(tested), 2)
        if tested
        else 0,
        "any_overlap_percentage": round(
            100 * (matches + partial_matches) / len(tested), 2
        )
        if tested
        else 0,
        "average_confidence": round(statistics.mean(confidence_scores), 4)
        if confidence_scores
        else None,
        "agreement_counts": dict(sorted(Counter(str(row["Agreement"]) for row in rows).items())),
    }



# Print the per-stage totals at the end of a run.
def print_llm_execution_summary(
    rules: list[Rule], rows: list[dict[str, object]], submitted: int, started: float
) -> None:
    """Print auditable LLM execution totals without altering classification results."""
    before = sum(bool(rule_mapping_ids(rule)) for rule in rules)
    after = sum(
        bool(rule_mapping_ids(rule) or llm_ids(row))
        for rule, row in zip(rules, rows)
    )
    classified = sum(row["llm_status"] == "classified" for row in rows)
    failed = sum(row["llm_status"] == "error" for row in rows)
    not_submitted = sum(row["llm_status"] == "not_submitted" for row in rows)
    total = len(rules)
    print("[LLM] Execution summary")
    print(f"[LLM] Total rules processed: {total}")
    print(f"[LLM] Rules submitted: {submitted}")
    print(f"[LLM] Successfully classified: {classified}")
    print(f"[LLM] Failed classifications: {failed}")
    print(f"[LLM] Not submitted (outside target selection): {not_submitted}")
    if submitted:
        print(f"[LLM] Submitted-rule success rate: {pct(classified, submitted)}")
    print(f"[LLM] Total runtime: {time.perf_counter() - started:.2f}s")
    print(f"[LLM] Coverage before LLM: {pct(before, total)}")
    print(f"[LLM] Coverage after LLM: {pct(after, total)}")


# Stage 5 prompt. Abstention is explicitly permitted and inference from malware
# naming is forbidden, so unsupported proposals are discouraged at the source.
CLASSIFICATION_SYSTEM = (
    "You are a careful MITRE ATT&CK analyst mapping Snort intrusion detection "
    "rules to techniques for a security research study.\n"
    "Classify only behaviour that the rule can actually observe on the network. "
    "Do not infer a technique from a malware family name alone, and do not map a "
    "rule to a technique merely because the malware is known to use it.\n"
    "Return an empty attack_ids array when the evidence is insufficient - an "
    "honest empty answer is more useful to this study than a speculative one.\n"
    "Respond with JSON only, in the form "
    '{"classifications": [{"rule_index": <int>, "sid": "<string>", '
    '"attack_ids": ["Txxxx" or "Txxxx.yyy"], "confidence": <0..1>, '
    '"reasoning": "<one or two sentences>"}]}\n'
    "Return exactly one object per input rule, preserving each rule_index.\n"
    "Only these active Enterprise ATT&CK IDs are permitted:\n"
)


# STAGE 5 - LLM CLASSIFICATION: LLM classification of initially unmapped rules
def select_llm_targets(rules: list[Rule], config: LLMConfig) -> list[tuple[int, Rule]]:
    """Choose which rules to submit, honouring --llm-target and --llm-max-rules.

    Targeting matters for Stage 5: slicing the first N rules of the full ruleset
    mostly re-sends rules the keyword mapper already handled, whereas the
    research question concerns the rules it did not.
    """
    indexed = list(enumerate(rules))  # keep original position so results map back
    target = (config.target or "all").lower()
    if target == "unmapped":
        indexed = [(index, rule) for index, rule in indexed if not rule_mapping_ids(rule)]  # Stage 5 cohort
    elif target == "mapped":
        indexed = [(index, rule) for index, rule in indexed if rule_mapping_ids(rule)]
    # slice after filtering, so the cap counts unmapped rules
    return indexed[: config.max_rules] if config.max_rules else indexed


# Stage 5: classify the keyword-unmapped rules.
def classify_rules_with_llm(
    rules: list[Rule], catalog: dict[str, dict[str, object]], config: LLMConfig
) -> list[dict[str, object]]:
    """Classify rules with an LLM, leaving keyword and heuristic mappings untouched.

    Per-rule provider failures are recorded rather than swallowed, so downstream
    analysis can separate "no LLM evidence available" from "the LLM found
    nothing", which are different claims about coverage.
    """
    started = time.perf_counter()
    base_rows = [
        {
            "sid": rule.sid or "",
            "rev": rule.rev or "",
            "msg": rule.msg,
            "classtype": rule.classtype,
            "keyword_attack_ids": joined(sorted(rule_mapping_ids(rule))),
            "keyword_mapping_source": mapping_candidates(rule)[0],
            "llm_attack_ids": "",
            "llm_attack_names": "",
            "llm_confidence": "",
            "llm_reasoning": "",
            "llm_status": "not_run",
            "llm_error": "LLM classification was not enabled",
            "llm_model": "",
        }
        for rule in rules
    ]
    if not config.enabled:
        print("[LLM] Disabled. Keyword and heuristic classification will be used only.")
        return base_rows

    def fail_all(message: str) -> list[dict[str, object]]:
        print(f"[LLM] Cannot start: {message}")
        for row in base_rows:
            row["llm_status"] = "error"
            row["llm_error"] = message
        print_llm_execution_summary(rules, base_rows, 0, started)
        return base_rows

    if not config.model:
        return fail_all("--llm-model is required when --llm-enable is used")
    api_key = os.environ.get(config.api_key_env, "").strip()
    if not api_key:
        return fail_all(f"API key environment variable {config.api_key_env} is not set")

    selected = select_llm_targets(rules, config)
    if not selected:
        print(f"[LLM] No rules matched --llm-target {config.target}.")
        print_llm_execution_summary(rules, base_rows, 0, started)
        return base_rows

    endpoint = resolve_llm_endpoint(config.endpoint, api_key)
    model = normalise_model_id(config.model, endpoint)
    cache_dir, debug_log = _llm_working_dirs(config)
    print(
        f"[LLM] Enabled. Submitting {len(selected)} of {len(rules)} rules "
        f"(target={config.target}) to {endpoint} using {model}."
    )
    plan_requests(len(selected), max(1, config.batch_size), model, config, "LLM", endpoint)
    fallbacks = tuple(config.fallback_models)
    if config.preflight and not preflight_llm(
        endpoint,
        api_key,
        model,
        config.timeout,
        config.reasoning_effort,
        config.retries,
        fallbacks,
    ):
        return fail_all("Preflight check failed; see the messages above")

    # outside the cohort: never sent, so not an error
    selected_indices = {index for index, _ in selected}
    for index, row in enumerate(base_rows):
        if index not in selected_indices:
            # never sent (Stage 4 cohort) - not a failure
            row["llm_status"] = "not_submitted"
            row["llm_error"] = f"Rule outside --llm-target {config.target} selection"

    system = CLASSIFICATION_SYSTEM + allowed_technique_prompt(catalog)
    responses, errors, answering_models = llm_classify_batches(
        selected,
        payload_builder=_llm_rule_payload,
        system=system,
        endpoint=endpoint,
        api_key=api_key,
        model=model,
        batch_size=max(1, config.batch_size),
        timeout=config.timeout,
        retries=config.retries,
        cache_dir=cache_dir,
        debug_log=debug_log,
        label="LLM",
        progress_every=5,
        reasoning_effort=config.reasoning_effort,
        fallback_models=fallbacks,
    )

    for index, _rule in selected:
        row = base_rows[index]
        item = responses.get(index)
        if item is None:
            row["llm_status"] = "error"
            row["llm_error"] = errors.get(index, "Provider response omitted this rule")[:500]
            continue
        ids = accepted_technique_ids(item, catalog)
        row.update(
            {
                "llm_attack_ids": joined(ids),
                "llm_attack_names": joined(
                    catalog[technique_id]["name"] for technique_id in ids
                ),
                "llm_confidence": item.get("confidence", ""),
                "llm_reasoning": str(item.get("reasoning", "")).strip()[:1000],
                "llm_status": "classified",
                "llm_error": "",
                "llm_model": answering_models.get(index, model),
            }
        )
    print_llm_execution_summary(rules, base_rows, len(selected), started)
    print(
        f"[LLM] Provider requests used so far: {GOVERNOR.count}"
        + (
            f" of the {FREE_TIER_DAILY_REQUESTS_NO_CREDIT}/day free allowance."
            if is_free_tier_model(model)
            else "."
        )
    )
    return base_rows


# Split an llm_attack_ids cell back into a set.
def llm_ids(row: dict[str, object]) -> set[str]:
    return {item for item in str(row["llm_attack_ids"]).split("|") if item}  # reverse of joined()


def classification_comparison_rows(
    rules: list[Rule], llm_rows: list[dict[str, object]]
) -> list[dict[str, object]]:
    results = []
    for rule, llm_row in zip(rules, llm_rows):
        keyword_ids = rule_mapping_ids(rule)
        model_ids = llm_ids(llm_row)
        if llm_row["llm_status"] != "classified":
            comparison = "llm_not_available"
        elif keyword_ids == model_ids:
            comparison = "agree" if keyword_ids else "both_unmapped"
        elif not keyword_ids:
            comparison = "llm_only"
        elif not model_ids:
            comparison = "keyword_only"
        else:
            comparison = "partial_overlap"
        results.append(
            {
                "sid": rule.sid or "",
                "rev": rule.rev or "",
                "msg": rule.msg,
                "classtype": rule.classtype,
                "keyword_attack_ids": joined(sorted(keyword_ids)),
                "llm_attack_ids": joined(sorted(model_ids)),
                "comparison": comparison,
                "shared_attack_ids": joined(sorted(keyword_ids & model_ids)),
                "llm_only_attack_ids": joined(sorted(model_ids - keyword_ids)),
                "keyword_only_attack_ids": joined(sorted(keyword_ids - model_ids)),
                "coverage_delta": len(model_ids) - len(keyword_ids),
                "llm_status": llm_row["llm_status"],
            }
        )
    return results


# Rows for validation_dataset.csv, the analyst review queue.
def manual_validation_rows(
    llm_rows: list[dict[str, object]], comparison_rows: list[dict[str, object]]
) -> list[dict[str, object]]:
    rows = []
    for llm_row, comparison in zip(llm_rows, comparison_rows):
        outcome = str(comparison["comparison"])
        confidence = llm_row["llm_confidence"]
        if outcome in {"llm_only", "partial_overlap"}:
            priority, reason = "high", "LLM adds or changes deterministic ATT&CK coverage"
        elif outcome == "keyword_only":
            priority, reason = "high", "LLM omits a deterministic ATT&CK mapping"
        elif outcome == "both_unmapped":
            priority, reason = "medium", "Both approaches lack ATT&CK evidence"
        elif outcome == "llm_not_available":
            priority, reason = "low", "LLM result unavailable for comparison"
        else:
            priority, reason = "low", "Both approaches agree"
        rows.append(
            {
                "sid": llm_row["sid"], "rev": llm_row["rev"], "msg": llm_row["msg"],
                "classtype": llm_row["classtype"],
                "keyword_attack_ids": llm_row["keyword_attack_ids"],
                "llm_attack_ids": llm_row["llm_attack_ids"],
                "llm_confidence": confidence, "comparison": outcome,
                "review_priority": priority, "review_reason": reason,
                "validation_status": "pending",
                "reviewer_name": "",
                "validation_date": "",
                "validation_comment": "",
            }
        )
    return rows


def unmapped_reason_analysis_rows(
    rules: list[Rule], llm_rows: list[dict[str, object]]
) -> list[dict[str, object]]:
    rows = []
    for rule, llm_row in zip(rules, llm_rows):
        if rule_mapping_ids(rule):
            continue
        model_ids = llm_ids(llm_row)
        if model_ids:
            # A proposal leaves the rule unmapped until an analyst confirms it;
            # an abstention is recorded as absent evidence, not as a failure.
            remaining_reason = "LLM proposed ATT&CK coverage; analyst verification required"
        elif llm_row["llm_status"] == "classified":
            remaining_reason = "LLM found insufficient network-observable behavioral evidence"
        else:
            remaining_reason = "LLM classification unavailable"
        rows.append({
            "sid": rule.sid or "", "rev": rule.rev or "", "msg": rule.msg,
            "classtype": rule.classtype,
            "keyword_unmapped_reason": keyword_unmapped_reason(rule),
            "llm_attack_ids": llm_row["llm_attack_ids"],
            "llm_status": llm_row["llm_status"],
            "remaining_unmapped_reason": remaining_reason,
        })
    return rows


# METRICS AND OUTPUTS
def classification_metrics(
    rules: list[Rule], llm_rows: list[dict[str, object]], comparison_rows: list[dict[str, object]]
) -> dict[str, object]:
    keyword_mapped = sum(bool(rule_mapping_ids(rule)) for rule in rules)
    classified = [row for row in llm_rows if row["llm_status"] == "classified"]
    # With --llm-target unmapped this is 0 by construction: the LLM cohort is
    # precisely the rules the keyword mapper did not cover. The coverage figures
    # below are therefore measured over the LLM cohort, not the whole ruleset.
    keyword_mapped_in_llm_cohort = sum(
        bool(rule_mapping_ids(rule))
        for rule, row in zip(rules, llm_rows)
        if row["llm_status"] == "classified"
    )
    llm_mapped = sum(bool(llm_ids(row)) for row in classified)
    llm_techniques = {technique for row in classified for technique in llm_ids(row)}
    comparison_counts = Counter(str(row["comparison"]) for row in comparison_rows)
    classified_comparisons = [
        row for row in comparison_rows if row["llm_status"] == "classified"
    ]
    confidence_scores = []
    for row in classified:
        try:
            confidence = float(row["llm_confidence"])
        except (TypeError, ValueError):
            continue
        if 0 <= confidence <= 1:
            confidence_scores.append(confidence)
    # Expressed over the LLM cohort. research_metrics.json separately reports a
    # whole-ruleset candidate figure; the two use different denominators and
    # must not be quoted interchangeably.
    coverage_improvement = llm_mapped - keyword_mapped_in_llm_cohort if classified else 0
    coverage_points = (
        round(
            100 * llm_mapped / len(classified)
            - 100 * keyword_mapped_in_llm_cohort / len(classified),
            2,
        )
        if classified
        else 0
    )
    return {
        "llm_enabled": any(row["llm_status"] != "not_run" for row in llm_rows),
        "llm_classified_rules": len(classified),
        "llm_error_rules": sum(row["llm_status"] == "error" for row in llm_rows),
        "keyword_mapped_rules": keyword_mapped,
        "keyword_mapped_rules_in_llm_cohort": keyword_mapped_in_llm_cohort,
        "llm_mapped_rules": llm_mapped,
        "keyword_coverage_score": round(keyword_mapped / len(rules), 6) if rules else 0,
        "keyword_cohort_coverage_score": round(
            keyword_mapped_in_llm_cohort / len(classified), 6
        ) if classified else 0,
        "llm_coverage_score": round(llm_mapped / len(classified), 6) if classified else 0,
        "coverage_improvement_rules": coverage_improvement,
        "coverage_improvement_pct_points": coverage_points,
        "llm_unique_attack_techniques": len(llm_techniques),
        "comparison_counts": dict(sorted(comparison_counts.items())),
        "keyword_classification_rate": round(keyword_mapped / len(rules), 6) if rules else 0,
        "llm_classification_rate": round(llm_mapped / len(classified), 6)
        if classified
        else 0,
        "coverage_improvement_percentage": coverage_points,
        "agreement_percentage": round(
            100
            * sum(
                row["comparison"] in {"agree", "both_unmapped"}
                for row in classified_comparisons
            )
            / len(classified_comparisons),
            2,
        )
        if classified_comparisons
        else 0,
        "newly_classified_rules": comparison_counts["llm_only"],
        "remaining_unmapped_rules": sum(
            not rule_mapping_ids(rule) and not llm_ids(row)
            for rule, row in zip(rules, llm_rows)
        ),
        "average_llm_confidence": round(statistics.mean(confidence_scores), 4)
        if confidence_scores
        else None,
    }


def write_classification_visualizations(output: Path, metrics: dict[str, object]) -> None:
    """Write dependency-free SVG charts that can be opened directly in a browser."""
    # gutter sized for the longest label so bars never overlap it
    width, height = 900, 280
    label_x, bar_x = 30, 300
    bar_max_width = 520
    # labels only; the two LLM bars measure different things
    bars = [
        ("Keyword mapped", int(metrics["keyword_mapped_rules"]), "#2563eb"),
        ("LLM classified with technique", int(metrics["llm_mapped_rules"]), "#059669"),
        ("LLM classified (responded)", int(metrics["llm_classified_rules"]), "#7c3aed"),
    ]
    max_value = max(max((count for _, count, _ in bars), default=1), 1)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="35" font-family="Arial" font-size="20" fill="#111827">Keyword Baseline vs LLM Classification Results</text>',
    ]
    for index, (label, count, color) in enumerate(bars):
        y = 70 + index * 58
        bar_width = round(bar_max_width * count / max_value)
        lines.extend([
            f'<text x="{label_x}" y="{y + 23}" font-family="Arial" font-size="14" fill="#374151">{label}</text>',
            f'<rect x="{bar_x}" y="{y}" width="{bar_width}" height="30" fill="{color}"/>',
            f'<text x="{bar_x + bar_width + 10}" y="{y + 21}" font-family="Arial" font-size="14" fill="#111827">{count}</text>',
        ])
    lines.append("</svg>")
    (output / "classification_coverage_comparison.svg").write_text("\n".join(lines), encoding="utf-8")

    counts = dict(metrics["comparison_counts"])
    labels = ["agree", "partial_overlap", "llm_only", "keyword_only", "both_unmapped"]
    bars = [(label, int(counts.get(label, 0))) for label in labels]
    max_value = max(max((count for _, count in bars), default=1), 1)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="35" font-family="Arial" font-size="20" fill="#111827">Classification Difference Breakdown</text>',
    ]
    for index, (label, count) in enumerate(bars):
        y = 60 + index * 39
        bar_width = round(500 * count / max_value)
        lines.extend([
            f'<text x="30" y="{y + 19}" font-family="Arial" font-size="14" fill="#374151">{label}</text>',
            f'<rect x="180" y="{y}" width="{bar_width}" height="24" fill="#d97706"/>',
            f'<text x="{190 + bar_width}" y="{y + 18}" font-family="Arial" font-size="14" fill="#111827">{count}</text>',
        ])
    lines.append("</svg>")
    (output / "classification_difference_breakdown.svg").write_text("\n".join(lines), encoding="utf-8")


def write_mapped_validation_visualization(
    output: Path, metrics: dict[str, object]
) -> None:
    """Write an SVG summary for LLM reproduction of existing mappings."""
    width, height = 760, 275
    counts = dict(metrics.get("agreement_counts", {}))
    bars = [
        ("match", int(counts.get("match", 0)), "#059669"),
        ("partial_match", int(counts.get("partial_match", 0)), "#2563eb"),
        ("mismatch", int(counts.get("mismatch", 0)), "#dc2626"),
        ("no_prediction", int(counts.get("no_prediction", 0)), "#d97706"),
        ("validation_error", int(counts.get("validation_error", 0)), "#6b7280"),
    ]
    max_value = max(max((count for _, count, _ in bars), default=1), 1)
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="30" y="35" font-family="Arial" font-size="20" fill="#111827">Mapped Rule LLM Validation</text>',
    ]
    for index, (label, count, color) in enumerate(bars):
        y = 60 + index * 33
        bar_width = round(500 * count / max_value)
        lines.extend(
            [
                f'<text x="30" y="{y + 18}" font-family="Arial" font-size="14" fill="#374151">{label}</text>',
                f'<rect x="180" y="{y}" width="{bar_width}" height="22" fill="{color}"/>',
                f'<text x="{190 + bar_width}" y="{y + 17}" font-family="Arial" font-size="14" fill="#111827">{count}</text>',
            ]
        )
    lines.append("</svg>")
    (output / "mapped_rule_llm_validation.svg").write_text(
        "\n".join(lines), encoding="utf-8"
    )


# Rows for coverage_inflation.csv (rules per technique).
def coverage_inflation_rows(
    category_rules: dict[str, list[Rule]]
) -> list[dict[str, object]]:
    rows = []
    for category, rules in category_rules.items():
        attack_ids = {technique for rule in rules for technique in rule_mapping_ids(rule)}
        total_rules = len(rules)
        unique_attack_ids = len(attack_ids)
        rules_per_attack = round(total_rules / unique_attack_ids, 2) if unique_attack_ids else 0
        if unique_attack_ids == 0:
            note = "no ATT&CK technique diversity"
        elif total_rules >= 20 and rules_per_attack >= 10:
            note = "many rules but low ATT&CK technique diversity"
        elif total_rules >= 10 and unique_attack_ids <= 2:
            note = "limited ATT&CK technique diversity"
        else:
            note = "no obvious inflation signal"
        rows.append(
            {
                "category": category,
                "total_rules": total_rules,
                "unique_attack_ids": unique_attack_ids,
                "rules_per_attack": rules_per_attack,
                "inflation_note": note,
            }
        )
    return sorted(
        rows,
        key=lambda row: (row["rules_per_attack"], row["total_rules"], row["category"]),
        reverse=True,
    )


def technique_frequency_rows(rules: list[Rule]) -> list[dict[str, object]]:
    mapped_rules = [rule for rule in rules if rule_mapping_ids(rule)]
    counter = Counter(technique for rule in mapped_rules for technique in rule_mapping_ids(rule))
    name_by_id = {
        str(detail["technique_id"]): str(detail["name"])
        for rule in rules
        for detail in [*rule.attack_details, *rule.inferred_attack_details]
    }
    total_mapped = len(mapped_rules)
    ordered = counter.most_common()
    ranks: dict[str, str] = {}
    for technique, _ in ordered[:20]:
        ranks[technique] = "top_20"
    for technique, _ in sorted(counter.items(), key=lambda item: (item[1], item[0]))[:20]:
        ranks.setdefault(technique, "bottom_20")
    return [
        {
            "technique_id": technique,
            "technique_name": name_by_id.get(technique, ""),
            "rule_count": count,
            "coverage_pct": round(100 * count / total_mapped, 2) if total_mapped else 0,
            "rank_group": ranks.get(technique, ""),
        }
        for technique, count in ordered
    ]


def unmapped_rule_rows(rules: list[Rule]) -> list[dict[str, object]]:
    rows = []
    for rule in rules:
        if rule_mapping_ids(rule):
            continue
        reason_parts = []
        if not rule.references:
            reason_parts.append("no references")
        else:
            reason_parts.append("no attack.mitre.org reference")
        if not rule.inferred_attack_candidates:
            reason_parts.append("no heuristic candidate")
        rows.append(
            {
                "sid": rule.sid or "",
                "message": rule.msg,
                "classtype": rule.classtype,
                "revision": rule.rev or "",
                "reason": "; ".join(reason_parts),
            }
        )
    return rows


# Per-category unmapped counts and percentages.
def unmapped_stats_by_category(rules: list[Rule]) -> dict[str, dict[str, object]]:
    stats = {}
    for category in sorted({rule.classtype for rule in rules}):
        category_rules = [rule for rule in rules if rule.classtype == category]
        unmapped = [rule for rule in category_rules if not rule_mapping_ids(rule)]
        stats[category] = {
            "total_rules": len(category_rules),
            "unmapped_rules": len(unmapped),
            "unmapped_pct": round(100 * len(unmapped) / len(category_rules), 2)
            if category_rules
            else 0,
        }
    return stats


# Rows for extended_validation_report.csv, incl. duplicate SID/REV.
def extended_validation_rows(rules: list[Rule]) -> list[dict[str, object]]:
    rows = validation_findings_rows(rules)
    if rows and rows[0]["issue"] == "no_validation_findings":
        rows = []
    sid_rev_groups: dict[tuple[int, int], list[Rule]] = {}
    for rule in rules:
        if rule.sid is not None and rule.rev is not None:
            sid_rev_groups.setdefault((rule.sid, rule.rev), []).append(rule)
    for (sid, rev), group in sorted(sid_rev_groups.items()):
        if len(group) <= 1:
            continue
        rows.append(
            {
                "severity": "high",
                "issue": "duplicate_sid_rev",
                "sid": sid,
                "category": joined(sorted({rule.classtype for rule in group})),
                "row": "",
                "details": f"{len(group)} rules share SID {sid} and REV {rev}.",
            }
        )
    if not rows:
        rows.append(
            {
                "severity": "info",
                "issue": "no_validation_findings",
                "sid": "",
                "category": "",
                "row": "",
                "details": "No missing required fields, duplicate SIDs, duplicate SID+REV pairs, or ATT&CK catalog issues were found.",
            }
        )
    return rows


# Build research_metrics.json, including per-stage provider provenance.
def research_metrics(
    rules: list[Rule],
    category_count: int,
    llm_metrics: dict[str, object] | None = None,
    llm_config: LLMConfig | None = None,
    mapped_validation_config: MappedLLMValidationConfig | None = None,
) -> dict[str, object]:
    """Return reproducible headline metrics and definitions for research reporting.

    Metric values use the established calculations. The accompanying definitions
    make results interpretable without changing the analysis methodology.
    """
    mapped_rules = [rule for rule in rules if rule_mapping_ids(rule)]
    unmapped = len(rules) - len(mapped_rules)
    unique_techniques = {technique for rule in rules for technique in rule_mapping_ids(rule)}
    avg_complexity = (
        round(statistics.mean(rule.complexity_score for rule in rules), 2) if rules else 0
    )
    coverage_score = round(len(mapped_rules) / len(rules), 6) if rules else 0
    inflation_ratio = round(len(rules) / len(unique_techniques), 4) if unique_techniques else 0
    metrics = {
        "total_rules": len(rules),
        "total_categories": category_count,
        "attack_mapped_rules": len(mapped_rules),
        "unmapped_rules": unmapped,
        "unique_attack_techniques": len(unique_techniques),
        "average_complexity": avg_complexity,
        "coverage_score": coverage_score,
        "inflation_ratio": inflation_ratio,
    }
    if llm_metrics is not None:
        metrics["llm_classification"] = llm_metrics
        metrics["mapped_rule_llm_validation"] = llm_metrics.get(
            "mapped_rule_llm_validation", {}
        )
        metrics.update(
            {
                key: llm_metrics[key]
                for key in (
                    "keyword_classification_rate",
                    "llm_classification_rate",
                    "coverage_improvement_percentage",
                    "agreement_percentage",
                    "newly_classified_rules",
                    "remaining_unmapped_rules",
                    "average_llm_confidence",
                    "newly_mapped_rules",
                    "remaining_unmapped_rules_after_candidates",
                    "coverage_improvement_from_candidates",
                )
            }
        )
    if llm_config is not None:
        metrics["llm_configuration"] = {
            "enabled": llm_config.enabled,
            "endpoint": llm_config.endpoint,
            "model": llm_config.model,
            "api_key_env": llm_config.api_key_env,
            "max_rules": llm_config.max_rules,
            "batch_size": llm_config.batch_size,
        }
    if mapped_validation_config is not None:
        metrics["mapped_rule_llm_validation_configuration"] = {
            "enabled": mapped_validation_config.enabled,
            "endpoint": mapped_validation_config.endpoint,
            "model": mapped_validation_config.model,
            "api_key_env": mapped_validation_config.api_key_env,
            "max_rules": mapped_validation_config.max_rules,
            "batch_size": mapped_validation_config.batch_size,
        }
    metrics["metric_definitions"] = {
        "coverage_score": "attack_mapped_rules divided by total_rules; a rule is mapped when it has direct or heuristic ATT&CK evidence.",
        "inflation_ratio": "total_rules divided by unique_attack_techniques; 0 when no techniques are mapped.",
        "keyword_classification_rate": "keyword_mapped_rules divided by total_rules, using direct references or existing heuristic mappings.",
        "llm_classification_rate": "llm_mapped_rules divided by llm_classified_rules in the LLM-evaluated cohort; 0 when no rules were classified.",
        "agreement_percentage": "percentage of LLM-classified rules where keyword and LLM IDs exactly agree, including rules both approaches leave unmapped.",
        "coverage_improvement_percentage": "LLM classification rate minus keyword classification rate within the same LLM-evaluated cohort, expressed in percentage points.",
        "average_llm_confidence": "arithmetic mean of valid LLM confidence values from 0 through 1; null when no valid scores are available.",
        "newly_mapped_rules": "count of originally unmapped rules with one or more improved-heuristic or eligible LLM candidate mappings; candidates require validation.",
        "remaining_unmapped_rules_after_candidates": "originally unmapped rules that have neither an improved-heuristic candidate nor an eligible LLM candidate.",
        "coverage_improvement_from_candidates": "newly_mapped_rules divided by total_rules; this is a candidate coverage opportunity, not validated ATT&CK coverage.",
        "mapped_rule_llm_validation.total_tested_rules": "already mapped rules submitted to the LLM for independent ATT&CK prediction.",
        "mapped_rule_llm_validation.matches": "mapped-rule validation rows where the LLM predicted exactly the same ATT&CK ID set as the existing mapping.",
        "mapped_rule_llm_validation.partial_matches": "mapped-rule validation rows where the LLM predicted at least one existing ATT&CK ID and at least one difference.",
        "mapped_rule_llm_validation.mismatches": "mapped-rule validation rows where the LLM predicted no overlap with the existing ATT&CK ID set.",
        "mapped_rule_llm_validation.disagreements": "mapped-rule validation rows with a partial or mismatched LLM prediction.",
        "mapped_rule_llm_validation.agreement_percentage": "matches divided by total_tested_rules, expressed as a percentage.",
        "mapped_rule_llm_validation.average_confidence": "mean LLM confidence for mapped-rule validation rows with valid confidence scores.",
    }
    return metrics


def coverage_gap_rows(summaries: dict[str, dict]) -> list[dict[str, object]]:
    rows = []
    for category, summary in summaries.items():
        rules = summary["category_rules"]
        direct_rules = summary["feature_usage"]["direct_attack_reference"]
        heuristic_rules = summary["feature_usage"]["heuristic_attack_candidate"]
        revoked = summary["attack_coverage"]["direct_statuses"].get("revoked", 0)
        notes = []
        if direct_rules == 0:
            notes.append("no direct ATT&CK references")
        elif direct_rules / rules < 0.05:
            notes.append("low direct ATT&CK reference rate")
        if heuristic_rules == 0:
            notes.append("no heuristic ATT&CK candidates")
        if revoked:
            notes.append("contains revoked ATT&CK references")
        if summary["feature_usage"]["references"] == 0:
            notes.append("no external references")
        if not notes:
            notes.append("no obvious mapping gap from aggregate metrics")
        rows.append(
            {
                "category": category,
                "rules": rules,
                "direct_attack_rules": direct_rules,
                "direct_attack_rule_pct": round(100 * direct_rules / rules, 2)
                if rules
                else 0,
                "heuristic_attack_rules": heuristic_rules,
                "heuristic_attack_rule_pct": round(100 * heuristic_rules / rules, 2)
                if rules
                else 0,
                "direct_unique_techniques": summary["attack_coverage"][
                    "direct_unique_techniques"
                ],
                "direct_revoked_techniques": revoked,
                "gap_notes": "; ".join(notes),
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["direct_attack_rule_pct"],
            -row["rules"],
            row["category"],
        ),
    )


# Rows for validation_findings.csv (missing fields, bad IDs).
def validation_findings_rows(rules: list[Rule]) -> list[dict[str, object]]:
    rows = []
    # Per-rule faults are collected in this pass while SIDs are grouped for a
    # second pass, since duplicate SIDs can only be detected once every rule
    # has been seen.
    sid_groups: dict[int, list[Rule]] = {}
    for index, rule in enumerate(rules, 1):
        if rule.sid is None:
            rows.append(
                {
                    "severity": "high",
                    "issue": "missing_sid",
                    "sid": "",
                    "category": rule.classtype,
                    "row": index,
                    "details": "Rule has no SID.",
                }
            )
        else:
            sid_groups.setdefault(rule.sid, []).append(rule)
        if rule.rev is None:
            rows.append(
                {
                    "severity": "medium",
                    "issue": "missing_revision",
                    "sid": rule.sid or "",
                    "category": rule.classtype,
                    "row": index,
                    "details": "Rule has no revision.",
                }
            )
        for field_name, value in (("msg", rule.msg), ("classtype", rule.classtype)):
            if not value:
                rows.append(
                    {
                        "severity": "high",
                        "issue": f"missing_{field_name}",
                        "sid": rule.sid or "",
                        "category": rule.classtype,
                        "row": index,
                        "details": f"Rule has no {field_name}.",
                    }
                )
        for detail in rule.attack_details:
            if detail["status"] == "unknown":
                rows.append(
                    {
                        "severity": "medium",
                        "issue": "unknown_attack_id",
                        "sid": rule.sid or "",
                        "category": rule.classtype,
                        "row": index,
                        "details": f"{detail['technique_id']} was not found in the ATT&CK catalog.",
                    }
                )
            if detail["status"] == "revoked":
                rows.append(
                    {
                        "severity": "low",
                        "issue": "revoked_attack_id",
                        "sid": rule.sid or "",
                        "category": rule.classtype,
                        "row": index,
                        "details": f"{detail['technique_id']} is revoked in current Enterprise ATT&CK.",
                    }
                )
    for sid, group in sorted(sid_groups.items()):
        if len(group) <= 1:
            continue
        categories = sorted({rule.classtype for rule in group})
        messages = sorted({rule.msg for rule in group})
        rows.append(
            {
                "severity": "high",
                "issue": "duplicate_sid",
                "sid": sid,
                "category": joined(categories),
                "row": "",
                "details": f"{len(group)} rules share SID {sid}. Distinct messages: {len(messages)}.",
            }
        )
    if not rows:
        rows.append(
            {
                "severity": "info",
                "issue": "no_validation_findings",
                "sid": "",
                "category": "",
                "row": "",
                "details": "No missing SID/revision/message/category, duplicate SID, or unknown ATT&CK IDs were found.",
            }
        )
    return rows


# Rows for modern_attack_comparison.csv; supplementary only.
def modern_attack_comparison_rows(rules: list[Rule]) -> list[dict[str, object]]:
    rows = []
    for attack_name, selectors in MODERN_ATTACK_TYPES.items():
        technique_ids = selectors["techniques"]
        keywords = selectors["keywords"]
        matched_rules = []
        direct_count = heuristic_count = keyword_count = 0
        category_counter = Counter()
        matched_techniques = Counter()
        for rule in rules:
            direct_hit = bool(technique_ids.intersection(rule.attack_techniques))
            heuristic_hit = bool(
                technique_ids.intersection(rule.inferred_attack_candidates)
            )
            keyword_hit = any(keyword in rule.msg.lower() for keyword in keywords)
            if not (direct_hit or heuristic_hit or keyword_hit):
                continue
            matched_rules.append(rule)
            direct_count += int(direct_hit)
            heuristic_count += int(heuristic_hit)
            keyword_count += int(keyword_hit)
            category_counter[rule.classtype] += 1
            for technique_id in technique_ids.intersection(
                set(rule.attack_techniques).union(rule.inferred_attack_candidates)
            ):
                matched_techniques[technique_id] += 1
        rows.append(
            {
                "attack_type": attack_name,
                "selected_techniques": joined(sorted(technique_ids)),
                "keyword_selectors": joined(sorted(keywords)),
                "matched_rules": len(matched_rules),
                "direct_rule_matches": direct_count,
                "heuristic_rule_matches": heuristic_count,
                "keyword_rule_matches": keyword_count,
                "matched_techniques": joined(
                    f"{technique}:{count}"
                    for technique, count in matched_techniques.most_common()
                ),
                "top_categories": joined(
                    f"{category}:{count}"
                    for category, count in category_counter.most_common(8)
                ),
                "coverage_note": "no evidence in current selectors"
                if not matched_rules
                else "evidence found; validate rule semantics before claiming coverage",
            }
        )
    return rows


# Render report.md for the all-category run.
def all_ruleset_report(
    global_summary: dict,
    category_summaries: dict[str, dict],
    validation_rows: list[dict[str, object]],
    modern_rows: list[dict[str, object]],
    inflation_rows: list[dict[str, object]],
    unmapped_stats: dict[str, dict[str, object]],
    llm_metrics: dict[str, object],
) -> str:
    category_rows = category_statistics_rows(category_summaries)
    gap_rows = coverage_gap_rows(category_summaries)
    top_categories = category_rows[:12]
    direct_categories = sorted(
        category_rows, key=lambda row: row["direct_attack_rule_pct"], reverse=True
    )[:10]
    lines = [
        "# Snort Full Ruleset Coverage Analysis",
        "",
        "## Scope",
        "",
        f"- Parsed **{global_summary['category_rules']}** rules across "
        f"**{len(category_summaries)}** Snort categories.",
        f"- Validated ATT&CK mappings against **{global_summary['attack_dataset']['name']} "
        f"v{global_summary['attack_dataset']['version']}**.",
        "- Direct coverage means the rule explicitly references `attack.mitre.org`.",
        "- Heuristic coverage means the tool found a transparent candidate mapping that still needs analyst validation.",
        "",
        "## Overall Findings",
        "",
        f"- Direct ATT&CK references: **{global_summary['feature_usage']['direct_attack_reference']} rules**.",
        f"- Direct unique ATT&CK techniques: **{global_summary['attack_coverage']['direct_unique_techniques']}**.",
        f"- Heuristic ATT&CK candidate rules: **{global_summary['feature_usage']['heuristic_attack_candidate']}**.",
        f"- Complexity mix: **{global_summary['complexity'].get('simple', 0)} simple**, "
        f"**{global_summary['complexity'].get('moderate', 0)} moderate**, "
        f"**{global_summary['complexity'].get('complex', 0)} complex**.",
        f"- Mean complexity score: **{global_summary['complexity_metrics']['mean_score']}**.",
        f"- Highest rule revision: **{global_summary['revision']['maximum']}**.",
        f"- Unmapped rules: **{sum(item['unmapped_rules'] for item in unmapped_stats.values())}**.",
        "",
        "## Interpretation",
        "",
        "- **ATT&CK coverage:** direct references are the strongest evidence. Heuristic mappings identify research leads and should not be counted as validated coverage without review.",
        "- **Complexity:** category complexity shows signature construction patterns, not a ranking of detection effectiveness.",
        "- **Unmapped rules:** large unmapped populations commonly indicate limited contextual evidence or behaviour that cannot be reliably inferred from a network signature alone.",
        "- **Coverage inflation:** categories with many rules per ATT&CK ID may represent signature depth for a small behaviour set rather than broad technique coverage.",
        "- **Validation:** resolve missing fields, duplicate identifiers, unknown IDs, and revoked IDs before drawing final coverage conclusions.",
        "",
        "## Largest Categories",
        "",
        "| Category | Rules | Direct ATT&CK % | Heuristic % | Mean Complexity | Max Rev |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in top_categories:
        lines.append(
            f"| {row['category']} | {row['rules']} | {row['direct_attack_rule_pct']} | "
            f"{row['heuristic_attack_rule_pct']} | {row['mean_complexity_score']} | {row['max_revision']} |"
        )
    lines.extend(
        [
            "",
            "## Highest Direct ATT&CK Mapping Rates",
            "",
            "| Category | Rules | Direct ATT&CK % | Direct Techniques | Revoked Techniques |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in direct_categories:
        lines.append(
            f"| {row['category']} | {row['rules']} | {row['direct_attack_rule_pct']} | "
            f"{row['direct_unique_techniques']} | {row['direct_revoked_techniques']} |"
        )
    lines.extend(
        [
            "",
            "## Priority Coverage Gaps",
            "",
            "| Category | Rules | Direct ATT&CK % | Gap Notes |",
            "|---|---:|---:|---|",
        ]
    )
    for row in gap_rows[:12]:
        lines.append(
            f"| {row['category']} | {row['rules']} | {row['direct_attack_rule_pct']} | {row['gap_notes']} |"
        )
    lines.extend(
        [
            "",
            "## Coverage Inflation Signals",
            "",
            "| Category | Rules | Unique ATT&CK IDs | Rules per ATT&CK ID | Note |",
            "|---|---:|---:|---:|---|",
        ]
    )
    for row in inflation_rows[:12]:
        lines.append(
            f"| {row['category']} | {row['total_rules']} | {row['unique_attack_ids']} | "
            f"{row['rules_per_attack']} | {row['inflation_note']} |"
        )
    lines.extend(
        [
            "",
            "## Modern Attack Type Comparison",
            "",
            "| Attack Type | Matched Rules | Direct | Heuristic | Keyword | Top Categories |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    for row in modern_rows:
        lines.append(
            f"| {row['attack_type']} | {row['matched_rules']} | {row['direct_rule_matches']} | "
            f"{row['heuristic_rule_matches']} | {row['keyword_rule_matches']} | {row['top_categories']} |"
        )
    lines.extend(
        [
            "",
            "## Validation Summary",
            "",
            f"- Validation findings written: **{len(validation_rows)}**.",
            "- Review `validation_findings.csv` for missing fields, duplicate SIDs, unknown ATT&CK IDs, and revoked ATT&CK IDs.",
            "",
            "## Generated Datasets",
            "",
            "- `all_rules.csv`: expanded rule-level dataset for all categories.",
            "- `category_statistics.csv`: category-wise counts, percentages, complexity, and coverage.",
            "- `category_attack_coverage.csv`: per-category direct and heuristic ATT&CK mappings.",
            "- `coverage_gaps.csv`: category-level mapping gap flags.",
            "- `pattern_statistics.csv`: common rule attributes and detection patterns by category.",
            "- `frequently_updated_rules.csv`: highest-revision rules for revision triage.",
            "- `modern_attack_comparison.csv`: selected modern attack type comparison.",
            "- `validation_findings.csv`: data-quality checks for generated outputs.",
            "- `attack_mapping_dataset.csv`: rule-level direct, heuristic, and unmapped ATT&CK mapping dataset.",
            "- `coverage_inflation.csv`: category rules-per-technique signals.",
            "- `technique_frequency.csv`: ATT&CK technique frequency with Top 20 and Bottom 20 labels.",
            "- `unmapped_rules.csv`: unmapped rule inventory and reasons.",
            "- `unmapped_rule_candidates.csv`: validation-required candidate mappings for originally unmapped rules.",
            "- `extended_validation_report.csv`: expanded required-field and duplicate SID+REV validation.",
            "- `research_metrics.json`: aggregate metrics for research reporting.",
            "",
            "## Evaluation Note",
            "",
            "This remains a static rule-analysis prototype. Direct ATT&CK references are strong evidence of intended mapping, while heuristic candidates and modern attack comparisons are leads that require analyst validation against traffic semantics and current ATT&CK guidance.",
            "",
        ]
    )
    lines.extend(candidate_mapping_report_section(llm_metrics))
    lines.extend(mapped_validation_report_section(llm_metrics))
    lines.extend(classification_report_section(llm_metrics))
    lines.extend(
        [
            "## Classification Outputs",
            "",
            "- `llm_classification_results.csv`: LLM classifications with status, confidence, and rationale.",
            "- `keyword_llm_classification_comparison.csv`: rule-by-rule keyword and LLM comparison.",
            "- `validation_dataset.csv`: analyst review queue for agreement and disagreement verification.",
            "- `unmapped_classification_analysis.csv`: deterministic and LLM-specific reasons rules remain unclassified.",
            "- `unmapped_rule_candidates.csv`: improved-heuristic and optional LLM candidates requiring analyst validation.",
            "- `mapped_rule_llm_validation.csv`: independent LLM validation of already mapped rules.",
            "- `research_metrics.json`: baseline and keyword-versus-LLM coverage, agreement, and confidence metrics.",
            "- `classification_coverage_comparison.svg`, `classification_difference_breakdown.svg`, and `mapped_rule_llm_validation.svg`: coverage, difference, and mapped-validation visualisations.",
            "",
        ]
    )
    return "\n".join(lines)


# Write every artefact; also where Stage 4 and Stage 5 are invoked.
def write_all_outputs(
    output: Path,
    rules: list[Rule],
    global_summary: dict,
    category_summaries: dict[str, dict],
    catalog: dict[str, dict[str, object]],
    llm_config: LLMConfig,
    mapped_validation_config: MappedLLMValidationConfig,
) -> None:
    """Write full-ruleset outputs using the same calculations as focused mode."""
    output.mkdir(parents=True, exist_ok=True)
    validation_rows = validation_findings_rows(rules)
    extended_validation = extended_validation_rows(rules)
    modern_rows = modern_attack_comparison_rows(rules)
    category_rules = {
        category: [rule for rule in rules if rule.classtype == category]
        for category in category_summaries
    }
    inflation_rows = coverage_inflation_rows(category_rules)
    unmapped_stats = unmapped_stats_by_category(rules)
    llm_metrics = write_classification_outputs(
        output, rules, catalog, llm_config, mapped_validation_config
    )
    (output / "full_summary.json").write_text(
        json.dumps(
            {
                "global": global_summary,
                "categories": category_summaries,
                "unmapped_by_category": unmapped_stats,
                "llm_classification": llm_metrics,
                "modern_attack_types": {
                    name: {
                        "techniques": sorted(selectors["techniques"]),
                        "keywords": sorted(selectors["keywords"]),
                    }
                    for name, selectors in MODERN_ATTACK_TYPES.items()
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (output / "research_metrics.json").write_text(
        json.dumps(
            research_metrics(
                rules,
                len(category_summaries),
                llm_metrics,
                llm_config,
                mapped_validation_config,
            ),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (output / "all_rules.json").write_text(
        json.dumps([asdict(rule) for rule in rules], indent=2), encoding="utf-8"
    )
    (output / "report.md").write_text(
        all_ruleset_report(
            global_summary,
            category_summaries,
            validation_rows,
            modern_rows,
            inflation_rows,
            unmapped_stats,
            llm_metrics,
        ),
        encoding="utf-8",
    )
    write_csv(output / "all_rules.csv", rule_csv_fields(), (rule_to_csv_row(rule) for rule in rules))
    category_fields = [
        "category",
        "rules",
        "ruleset_share_pct",
        "direct_attack_rules",
        "direct_attack_rule_pct",
        "heuristic_attack_rules",
        "heuristic_attack_rule_pct",
        "direct_unique_techniques",
        "direct_active_techniques",
        "direct_revoked_techniques",
        "direct_active_catalog_coverage_pct",
        "simple_rules",
        "moderate_rules",
        "complex_rules",
        "mean_complexity_score",
        "max_revision",
        "mean_revision",
        "content_rule_pct",
        "pcre_rule_pct",
        "flow_rule_pct",
        "metadata_rule_pct",
        "reference_rule_pct",
        "http_keyword_rule_pct",
        "file_data_rule_pct",
        "flowbits_rule_pct",
    ]
    write_csv(
        output / "category_statistics.csv",
        category_fields,
        category_statistics_rows(category_summaries),
    )
    coverage_fields = [
        "category",
        "mapping_type",
        "technique_id",
        "name",
        "status",
        "tactics",
        "rule_count",
        "url",
    ]
    write_csv(
        output / "category_attack_coverage.csv",
        coverage_fields,
        category_attack_coverage_rows(category_summaries),
    )
    write_csv(
        output / "pattern_statistics.csv",
        ["category", "pattern", "description", "rule_count", "rule_pct"],
        pattern_statistics_rows(category_summaries),
    )
    write_csv(
        output / "frequently_updated_rules.csv",
        [
            "sid",
            "rev",
            "category",
            "msg",
            "complexity",
            "complexity_score",
            "direct_attack_techniques",
            "service",
        ],
        frequently_updated_rows(rules),
    )
    write_csv(
        output / "coverage_gaps.csv",
        [
            "category",
            "rules",
            "direct_attack_rules",
            "direct_attack_rule_pct",
            "heuristic_attack_rules",
            "heuristic_attack_rule_pct",
            "direct_unique_techniques",
            "direct_revoked_techniques",
            "gap_notes",
        ],
        coverage_gap_rows(category_summaries),
    )
    write_csv(
        output / "modern_attack_comparison.csv",
        [
            "attack_type",
            "selected_techniques",
            "keyword_selectors",
            "matched_rules",
            "direct_rule_matches",
            "heuristic_rule_matches",
            "keyword_rule_matches",
            "matched_techniques",
            "top_categories",
            "coverage_note",
        ],
        modern_rows,
    )
    write_csv(
        output / "validation_findings.csv",
        VALIDATION_FIELDS,
        validation_rows,
    )
    write_csv(
        output / "attack_mapping_dataset.csv",
        ATTACK_MAPPING_FIELDS,
        attack_mapping_dataset_rows(rules),
    )
    write_csv(
        output / "coverage_inflation.csv",
        COVERAGE_INFLATION_FIELDS,
        inflation_rows,
    )
    write_csv(
        output / "technique_frequency.csv",
        TECHNIQUE_FREQUENCY_FIELDS,
        technique_frequency_rows(rules),
    )
    write_csv(
        output / "unmapped_rules.csv",
        UNMAPPED_RULE_FIELDS,
        unmapped_rule_rows(rules),
    )
    write_csv(
        output / "extended_validation_report.csv",
        VALIDATION_FIELDS,
        extended_validation,
    )


# Single-category entry point.
def analyze(
    source: Path,
    category: str,
    output: Path,
    attack_data: Path,
    llm_config: LLMConfig | None = None,
    mapped_validation_config: MappedLLMValidationConfig | None = None,
) -> dict:
    """Analyze one category while preserving the established parsing and metrics workflow."""
    progress("Loading ATT&CK STIX data...")
    attack_catalog, attack_info = load_attack_catalog(attack_data)
    progress("Loading rules...")
    lines = read_rule_lines(source)
    progress("Parsing rules and extracting metadata...")
    parsed = [rule for line in lines if (rule := parse_rule(line))]
    non_rule_lines = sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in lines) - len(parsed)
    if non_rule_lines:
        print(f"[WARN] Skipped {non_rule_lines} non-parseable rule line(s); valid rules were analyzed.")
    progress("Calculating complexity...")
    selected = [rule for rule in parsed if rule.classtype == category]
    if not selected:
        available = ", ".join(sorted({rule.classtype for rule in parsed if rule.classtype}))
        raise ValueError(f"No rules found for {category!r}. Available: {available}")
    progress("Performing ATT&CK mapping...")
    enrich_attack_mappings(selected, attack_catalog)
    progress("Generating statistics...")
    summary = build_summary(selected, category, len(parsed), attack_info)
    progress("Writing outputs...")
    write_outputs(
        output,
        selected,
        summary,
        attack_catalog,
        llm_config or LLMConfig(),
        mapped_validation_config or MappedLLMValidationConfig(),
    )
    return summary


# All-category entry point.
def analyze_all(
    source: Path,
    output: Path,
    attack_data: Path,
    llm_config: LLMConfig | None = None,
    mapped_validation_config: MappedLLMValidationConfig | None = None,
) -> dict:
    """Analyze all categories while preserving each existing output calculation."""
    progress("Loading ATT&CK STIX data...")
    attack_catalog, attack_info = load_attack_catalog(attack_data)
    progress("Loading rules...")
    lines = read_rule_lines(source)
    progress("Parsing rules and extracting metadata...")
    parsed = [rule for line in lines if (rule := parse_rule(line))]
    non_rule_lines = sum(bool(line.strip()) and not line.lstrip().startswith("#") for line in lines) - len(parsed)
    if non_rule_lines:
        print(f"[WARN] Skipped {non_rule_lines} non-parseable rule line(s); valid rules were analyzed.")
    if not parsed:
        raise ValueError("No parseable Snort rules found.")
    progress("Calculating complexity...")
    progress("Performing ATT&CK mapping...")
    enrich_attack_mappings(parsed, attack_catalog)
    categories = sorted({rule.classtype for rule in parsed if rule.classtype})
    category_summaries = {
        category: build_summary(
            [rule for rule in parsed if rule.classtype == category],
            category,
            len(parsed),
            attack_info,
        )
        for category in categories
    }
    progress("Generating statistics...")
    global_summary = build_summary(parsed, "ALL", len(parsed), attack_info)
    progress("Writing outputs...")
    write_all_outputs(
        output,
        parsed,
        global_summary,
        category_summaries,
        attack_catalog,
        llm_config or LLMConfig(),
        mapped_validation_config or MappedLLMValidationConfig(),
    )
    return {
        "global": global_summary,
        "categories": category_summaries,
    }


# MAIN EXECUTION
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Path to a .rules file or ZIP archive")
    parser.add_argument(
        "--category", default="trojan-activity", help="Exact Snort classtype to analyze"
    )
    parser.add_argument(
        "--all-categories",
        action="store_true",
        help="Analyze every Snort classtype and generate full-ruleset datasets",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("analysis_output"), help="Output directory"
    )
    parser.add_argument(
        "--attack-data",
        type=Path,
        default=DEFAULT_ATTACK_DATA,
        help="Path to the official Enterprise ATT&CK STIX JSON bundle",
    )
    parser.add_argument(
        "--llm-enable",
        action="store_true",
        help="Enable OpenAI-compatible LLM ATT&CK classification (disabled by default)",
    )
    parser.add_argument(
        "--llm-model",
        default="",
        help="Model name for the OpenAI-compatible chat-completions endpoint",
    )
    parser.add_argument(
        "--llm-endpoint",
        default=NVIDIA_CHAT_ENDPOINT,
        help="OpenAI-compatible chat-completions endpoint",
    )
    parser.add_argument(
        "--llm-api-key-env",
        default="NVIDIA_API_KEY",
        help="Environment variable containing the LLM API key",
    )
    parser.add_argument(
        "--llm-max-rules",
        type=int,
        default=0,
        help="Maximum rules sent to the LLM; 0 classifies all rules",
    )
    parser.add_argument(
        "--llm-batch-size", type=int, default=10, help="Rules per LLM request"
    )
    parser.add_argument(
        "--llm-timeout", type=int, default=120, help="LLM request timeout in seconds"
    )
    parser.add_argument(
        "--llm-retries",
        type=int,
        default=4,
        help="Retries per request for transient provider failures (429, 5xx, timeouts)",
    )
    parser.add_argument(
        "--llm-target",
        choices=("all", "mapped", "unmapped"),
        default="all",
        help=(
            "Which rules to submit. 'unmapped' targets the Stage 5 research question "
            "(rules the keyword mapper missed) instead of slicing the whole ruleset"
        ),
    )
    parser.add_argument(
        "--mapped-validation-enable",
        action="store_true",
        help="Enable LLM validation for already ATT&CK-mapped rules only",
    )
    parser.add_argument(
        "--mapped-validation-model",
        default=NEMOTRON_ULTRA_MODEL,
        help="Model name for mapped-rule LLM validation",
    )
    parser.add_argument(
        "--mapped-validation-endpoint",
        default=NVIDIA_CHAT_ENDPOINT,
        help="OpenAI-compatible chat-completions endpoint for mapped validation",
    )
    parser.add_argument(
        "--mapped-validation-api-key-env",
        default="NVIDIA_API_KEY",
        help="Environment variable containing the mapped-validation API key",
    )
    parser.add_argument(
        "--mapped-validation-max-rules",
        type=int,
        default=0,
        help="Maximum mapped rules sent to LLM validation; 0 validates all mapped rules",
    )
    parser.add_argument(
        "--mapped-validation-batch-size",
        type=int,
        default=10,
        help="Mapped rules per LLM validation request",
    )
    parser.add_argument(
        "--mapped-validation-timeout",
        type=int,
        default=120,
        help="Mapped-rule LLM validation request timeout in seconds",
    )
    parser.add_argument(
        "--mapped-validation-retries",
        type=int,
        default=4,
        help="Retries per mapped-validation request for transient provider failures",
    )
    parser.add_argument(
        "--llm-model-fallbacks",
        default="",
        help=(
            "Comma-separated model IDs to fall back to when the primary model is "
            "unavailable or rate-limited upstream. On OpenRouter these are passed as "
            "the routing chain, which matters for ':free' variants that share one "
            "pooled provider"
        ),
    )
    parser.add_argument(
        "--llm-request-delay",
        type=float,
        default=-1.0,
        help=(
            "Seconds to wait between provider requests. The default (-1) picks "
            f"{FREE_TIER_MIN_INTERVAL:.1f}s for ':free' models, which are capped at "
            f"{FREE_TIER_REQUESTS_PER_MINUTE} requests per minute, and no delay otherwise"
        ),
    )
    parser.add_argument(
        "--llm-max-requests",
        type=int,
        default=0,
        help=(
            "Hard ceiling on provider requests across both LLM stages; 0 means no "
            f"ceiling. Free accounts with no credit get {FREE_TIER_DAILY_REQUESTS_NO_CREDIT} "
            "requests per day"
        ),
    )
    parser.add_argument(
        "--llm-reasoning-effort",
        choices=("none", "low", "medium", "high"),
        default="low",
        help=(
            "Reasoning budget for open-weight reasoning models such as gpt-oss. "
            "'low' leaves completion budget for the answer; 'none' omits the parameter"
        ),
    )
    parser.add_argument(
        "--llm-no-cache",
        action="store_true",
        help=(
            "Disable the on-disk response cache. Caching is on by default so that "
            "re-running the pipeline reproduces identical results without re-billing"
        ),
    )
    parser.add_argument(
        "--llm-debug",
        action="store_true",
        help="Append every raw provider response to <output>/llm_debug.jsonl for auditing",
    )
    parser.add_argument(
        "--llm-skip-preflight",
        action="store_true",
        help="Skip the single-rule credential and model check before a long run",
    )
    parser.add_argument(
        "--llm-preflight-only",
        action="store_true",
        help="Check the endpoint, API key, and model, then exit without analysing rules",
    )
    args = parser.parse_args()

    fallback_models = tuple(
        model.strip()
        for model in args.llm_model_fallbacks.split(",")
        if model.strip()
    )
    cache_dir = "" if args.llm_no_cache else str(args.output / ".llm_cache")
    debug_log = str(args.output / "llm_debug.jsonl") if args.llm_debug else ""
    preflight = not args.llm_skip_preflight

    if args.llm_preflight_only:
        # Preflight is stage-agnostic: whichever stage's arguments were supplied
        # decides which model, endpoint and key variable are tested.
        model = args.llm_model or args.mapped_validation_model
        key_env = (
            args.llm_api_key_env if args.llm_model else args.mapped_validation_api_key_env
        )
        endpoint = args.llm_endpoint if args.llm_model else args.mapped_validation_endpoint
        api_key = os.environ.get(key_env, "").strip()
        if not api_key:
            print(f"[Preflight] FAILED: environment variable {key_env} is not set.")
            raise SystemExit(2)
        endpoint = resolve_llm_endpoint(endpoint, api_key)
        model = normalise_model_id(model, endpoint)
        GOVERNOR.configure(
            min_interval=(
                auto_request_delay(model, endpoint)
                if args.llm_request_delay < 0
                else max(0.0, args.llm_request_delay)
            ),
            max_requests=0,
        )
        raise SystemExit(
            0
            if preflight_llm(
                endpoint,
                api_key,
                model,
                args.llm_timeout,
                args.llm_reasoning_effort,
                max(args.llm_retries, 0),
                tuple(normalise_model_id(name, endpoint) for name in fallback_models),
            )
            else 1
        )
    llm_config = LLMConfig(
        enabled=args.llm_enable,
        endpoint=args.llm_endpoint,
        model=args.llm_model,
        api_key_env=args.llm_api_key_env,
        max_rules=max(args.llm_max_rules, 0),
        batch_size=max(args.llm_batch_size, 1),
        timeout=max(args.llm_timeout, 1),
        retries=max(args.llm_retries, 0),
        target=args.llm_target,
        cache_dir=cache_dir,
        debug_log=debug_log,
        preflight=preflight,
        request_delay=args.llm_request_delay,
        max_requests=max(args.llm_max_requests, 0),
        reasoning_effort=args.llm_reasoning_effort,
        fallback_models=fallback_models,
    )
    mapped_validation_config = MappedLLMValidationConfig(
        enabled=args.mapped_validation_enable,
        endpoint=args.mapped_validation_endpoint,
        model=args.mapped_validation_model,
        api_key_env=args.mapped_validation_api_key_env,
        max_rules=max(args.mapped_validation_max_rules, 0),
        batch_size=max(args.mapped_validation_batch_size, 1),
        timeout=max(args.mapped_validation_timeout, 1),
        retries=max(args.mapped_validation_retries, 0),
        cache_dir=cache_dir,
        debug_log=debug_log,
        preflight=preflight,
        request_delay=args.llm_request_delay,
        max_requests=max(args.llm_max_requests, 0),
        reasoning_effort=args.llm_reasoning_effort,
        fallback_models=fallback_models,
    )
    try:
        if args.all_categories:
            result = analyze_all(
                args.source,
                args.output,
                args.attack_data,
                llm_config,
                mapped_validation_config,
            )
            print(
                f"Analyzed {result['global']['category_rules']} rules across "
                f"{len(result['categories'])} categories. Validated mappings with "
                f"Enterprise ATT&CK v{result['global']['attack_dataset']['version']}. "
                f"Outputs written to {args.output.resolve()}"
            )
        else:
            summary = analyze(
                args.source,
                args.category,
                args.output,
                args.attack_data,
                llm_config,
                mapped_validation_config,
            )
            print(
                f"Analyzed {summary['category_rules']} {args.category} rules. "
                f"Validated mappings with Enterprise ATT&CK "
                f"v{summary['attack_dataset']['version']}. "
                f"Outputs written to {args.output.resolve()}"
            )
    except FileNotFoundError as error:
        print(f"[ERROR] Required file was not found: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    except json.JSONDecodeError as error:
        print(f"[ERROR] Invalid JSON data: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    except (PermissionError, OSError) as error:
        print(f"[ERROR] File or output-directory operation failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    except ValueError as error:
        print(f"[ERROR] Analysis could not continue: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    print("[INFO] Completed successfully.")


if __name__ == "__main__":
    main()
