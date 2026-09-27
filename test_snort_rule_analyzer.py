import json
import unittest
from pathlib import Path

from snort_rule_analyzer import (
    attack_mapping_dataset_rows,
    classification_comparison_rows,
    classification_metrics,
    classify_rules_with_llm,
    enrich_attack_mappings,
    extended_validation_rows,
    LLMConfig,
    MappedLLMValidationConfig,
    load_attack_catalog,
    manual_validation_rows,
    mapped_rule_validation_metrics,
    unmapped_rule_candidate_rows,
    parse_rule,
    split_options,
    validate_mapped_rules_with_llm,
)


class ParserTests(unittest.TestCase):
    def test_semicolon_inside_quoted_content_is_not_split(self):
        options = split_options('msg:"sample"; content:"a;b"; sid:10; rev:2;')
        self.assertEqual(options, ['msg:"sample"', 'content:"a;b"', "sid:10", "rev:2"])

    def test_parses_features_and_direct_attack_reference(self):
        rule = parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
            '(msg:"MALWARE-CNC sample beacon"; flow:to_server,established; '
            'http_uri; content:"/gate"; pcre:"/^\\\\/gate/"; service:http; '
            'reference:url,attack.mitre.org/techniques/T1071/001/; '
            'classtype:trojan-activity; sid:123; rev:4;)'
        )
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.sid, 123)
        self.assertEqual(rule.rev, 4)
        self.assertEqual(rule.attack_techniques, ["T1071.001"])
        self.assertEqual(rule.complexity, "complex")
        self.assertTrue(any("T1071.001" in item for item in rule.inferred_attack_candidates))

    def test_parses_snort3_service_rule_shorthand(self):
        rule = parse_rule(
            'alert http (msg:"service rule"; http_uri; content:"/x"; '
            'service:http; classtype:trojan-activity; sid:5; rev:1;)'
        )
        self.assertIsNotNone(rule)
        assert rule is not None
        self.assertEqual(rule.protocol, "http")
        self.assertEqual(rule.source, "")
        self.assertEqual(rule.sid, 5)

    def test_loads_and_uses_attack_stix_catalog(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "x-mitre-collection",
                    "name": "Enterprise ATT&CK",
                    "x_mitre_version": "test",
                    "modified": "2026-01-01T00:00:00Z",
                },
                {
                    "type": "attack-pattern",
                    "name": "Web Protocols",
                    "x_mitre_version": "1.0",
                    "modified": "2026-01-01T00:00:00Z",
                    "x_mitre_deprecated": False,
                    "revoked": False,
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "command-and-control",
                        }
                    ],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1071.001",
                            "url": "https://attack.mitre.org/techniques/T1071/001",
                        }
                    ],
                },
            ],
        }
        path = Path("test_attack_catalog.json")
        try:
            path.write_text(json.dumps(bundle), encoding="utf-8")
            catalog, info = load_attack_catalog(path)
        finally:
            if path.exists():
                path.unlink()
        rule = parse_rule(
            'alert http (msg:"MALWARE-CNC sample beacon"; http_uri; content:"/x"; '
            'service:http; reference:url,attack.mitre.org/techniques/T1071/001/; '
            'classtype:trojan-activity; sid:5; rev:1;)'
        )
        assert rule is not None
        enrich_attack_mappings([rule], catalog)
        self.assertEqual(info["version"], "test")
        self.assertEqual(rule.attack_details[0]["name"], "Web Protocols")
        self.assertEqual(rule.inferred_attack_details[0]["status"], "active")

    def test_mapping_dataset_and_extended_validation(self):
        catalog = {
            "T1071.001": {
                "technique_id": "T1071.001",
                "name": "Web Protocols",
                "status": "active",
                "tactics": ["command-and-control"],
                "version": "1.0",
                "modified": "2026-01-01T00:00:00Z",
                "url": "https://attack.mitre.org/techniques/T1071/001",
            }
        }
        rule_a = parse_rule(
            'alert http (msg:"MALWARE-CNC beacon"; http_uri; content:"/x"; '
            'service:http; priority:2; reference:url,attack.mitre.org/techniques/T1071/001/; '
            'classtype:trojan-activity; sid:5; rev:1;)'
        )
        rule_b = parse_rule(
            'alert http (msg:"MALWARE-CNC beacon copy"; http_uri; content:"/y"; '
            'service:http; classtype:trojan-activity; sid:5; rev:1;)'
        )
        assert rule_a is not None
        assert rule_b is not None
        enrich_attack_mappings([rule_a, rule_b], catalog)

        rows = attack_mapping_dataset_rows([rule_a, rule_b])
        self.assertEqual(rows[0]["priority"], "2")
        self.assertEqual(rows[0]["mapping_source"], "direct_reference")
        self.assertEqual(rows[1]["mapping_source"], "heuristic")

        issues = {row["issue"] for row in extended_validation_rows([rule_a, rule_b])}
        self.assertIn("duplicate_sid", issues)
        self.assertIn("duplicate_sid_rev", issues)

    def test_llm_disabled_produces_auditable_comparison_rows(self):
        rule = parse_rule(
            'alert http (msg:"generic web request"; http_uri; content:"/x"; '
            'service:http; classtype:trojan-activity; sid:9; rev:1;)'
        )
        assert rule is not None
        enrich_attack_mappings([rule], {})
        llm_rows = classify_rules_with_llm([rule], {}, LLMConfig())
        self.assertEqual(llm_rows[0]["llm_status"], "not_run")
        comparison = classification_comparison_rows([rule], llm_rows)
        self.assertEqual(comparison[0]["comparison"], "llm_not_available")

    def test_research_classification_metrics_include_requested_rates(self):
        catalog = {
            "T1071.001": {"technique_id": "T1071.001", "name": "Web Protocols", "status": "active", "tactics": []},
            "T1105": {"technique_id": "T1105", "name": "Ingress Tool Transfer", "status": "active", "tactics": []},
        }
        direct = parse_rule(
            'alert http (msg:"beacon"; service:http; reference:url,attack.mitre.org/techniques/T1071/001/; classtype:trojan-activity; sid:10; rev:1;)'
        )
        unmapped = parse_rule(
            'alert tcp (msg:"generic"; classtype:trojan-activity; sid:11; rev:1;)'
        )
        assert direct is not None and unmapped is not None
        enrich_attack_mappings([direct, unmapped], catalog)
        llm_rows = [
            {"sid": 10, "rev": 1, "llm_attack_ids": "T1071.001", "llm_confidence": 0.8, "llm_status": "classified"},
            {"sid": 11, "rev": 1, "llm_attack_ids": "T1105", "llm_confidence": 0.6, "llm_status": "classified"},
        ]
        comparison = classification_comparison_rows([direct, unmapped], llm_rows)
        metrics = classification_metrics([direct, unmapped], llm_rows, comparison)
        self.assertEqual(metrics["newly_classified_rules"], 1)
        self.assertEqual(metrics["remaining_unmapped_rules"], 0)
        self.assertEqual(metrics["agreement_percentage"], 50.0)
        self.assertEqual(metrics["average_llm_confidence"], 0.7)

    def test_manual_validation_rows_preserve_blank_reviewer_fields(self):
        llm_rows = [{
            "sid": 1, "rev": 1, "msg": "example", "classtype": "test",
            "keyword_attack_ids": "", "llm_attack_ids": "", "llm_confidence": "",
        }]
        comparisons = [{"comparison": "both_unmapped"}]
        row = manual_validation_rows(llm_rows, comparisons)[0]
        self.assertEqual(row["reviewer_name"], "")
        self.assertEqual(row["validation_date"], "")
        self.assertEqual(row["validation_comment"], "")

    def test_unmapped_candidates_are_validation_only_and_do_not_mutate_mappings(self):
        catalog = {
            "T1059.003": {
                "technique_id": "T1059.003", "name": "Windows Command Shell",
                "status": "active", "tactics": [],
            }
        }
        rule = parse_rule(
            'alert tcp (msg:"suspicious command"; content:"cmd.exe /c whoami"; '
            'classtype:misc-activity; sid:77; rev:1;)'
        )
        assert rule is not None
        enrich_attack_mappings([rule], catalog)
        rows, metrics = unmapped_rule_candidate_rows(
            [rule], catalog,
            [{"llm_status": "not_run", "llm_attack_ids": "", "llm_confidence": "", "llm_reasoning": ""}],
        )
        self.assertEqual(rule.inferred_attack_candidates, [])
        self.assertEqual(rows[0]["Mapping Source"], "improved_heuristic_candidate")
        self.assertIn("requiring validation", rows[0]["Reason"])
        self.assertEqual(metrics["newly_mapped_rules"], 1)
        self.assertEqual(metrics["remaining_unmapped_rules"], 0)

    def test_mapped_llm_validation_disabled_preserves_independent_output_contract(self):
        catalog = {
            "T1071.001": {
                "technique_id": "T1071.001",
                "name": "Web Protocols",
                "status": "active",
                "tactics": [],
            }
        }
        rule = parse_rule(
            'alert http (msg:"MALWARE-CNC beacon"; content:"/gate"; metadata:attack_target Client_Endpoint; '
            'service:http; reference:url,attack.mitre.org/techniques/T1071/001/; '
            'classtype:trojan-activity; sid:88; rev:2;)'
        )
        assert rule is not None
        enrich_attack_mappings([rule], catalog)
        rows = validate_mapped_rules_with_llm(
            [rule], catalog, MappedLLMValidationConfig()
        )
        self.assertEqual(rows[0]["SID"], 88)
        self.assertIn("T1071.001 - Web Protocols", rows[0]["Existing Technique"])
        self.assertEqual(rows[0]["LLM Prediction"], "")
        self.assertEqual(rows[0]["Agreement"], "validation_not_run")

    def test_mapped_llm_validation_metrics_count_matches_and_disagreements(self):
        rows = [
            {
                "SID": 1,
                "Existing Technique": "T1071.001 - Web Protocols",
                "LLM Prediction": "T1071.001 - Web Protocols",
                "Agreement": "match",
                "Confidence": 0.9,
                "Reason": "same behavior",
            },
            {
                "SID": 2,
                "Existing Technique": "T1105 - Ingress Tool Transfer",
                "LLM Prediction": "T1059.003 - Windows Command Shell",
                "Agreement": "mismatch",
                "Confidence": 0.7,
                "Reason": "different behavior",
            },
        ]
        metrics = mapped_rule_validation_metrics(rows)
        self.assertEqual(metrics["total_tested_rules"], 2)
        self.assertEqual(metrics["matches"], 1)
        self.assertEqual(metrics["partial_matches"], 0)
        self.assertEqual(metrics["mismatches"], 1)
        self.assertEqual(metrics["disagreements"], 1)
        self.assertEqual(metrics["agreement_percentage"], 50.0)
        self.assertEqual(metrics["average_confidence"], 0.8)


if __name__ == "__main__":
    unittest.main()
