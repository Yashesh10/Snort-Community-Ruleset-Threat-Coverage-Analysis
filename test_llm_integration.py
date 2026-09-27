#!/usr/bin/env python3
"""Integration tests for the LLM transport layer in snort_rule_analyzer.

These tests stand up a local HTTP server that reproduces the response
behaviours observed from OpenRouter and other "OpenAI-compatible" gateways,
then drive the real Stage 4 and Stage 5 code paths against it. No network
access and no API key are required, so the suite can be run as evidence that
the pipeline degrades safely rather than losing rules.

Run with:  python -m unittest test_llm_integration -v
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import snort_rule_analyzer as sra
from snort_rule_analyzer import (
    LLMConfig,
    LLMTransportError,
    MappedLLMValidationConfig,
    classify_rules_with_llm,
    loads_tolerant,
    parse_rule,
    repair_truncated_json,
    strip_transport_noise,
    validate_mapped_rules_with_llm,
)

def catalog_entry(technique_id, name, status, tactics=()):
    """Build a catalog record with the same shape load_attack_catalog produces."""
    return {
        "technique_id": technique_id,
        "name": name,
        "status": status,
        "tactics": list(tactics),
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
        "version": "1.0",
        "modified": "2026-01-01T00:00:00.000Z",
    }


# A minimal catalog stands in for the 697-technique Enterprise ATT&CK bundle.
CATALOG = {
    entry["technique_id"]: entry
    for entry in (
        catalog_entry("T1071.001", "Web Protocols", "active", ["command-and-control"]),
        catalog_entry("T1105", "Ingress Tool Transfer", "active", ["command-and-control"]),
        catalog_entry("T1014", "Rootkit", "active", ["defense-evasion"]),
        catalog_entry("T1566.002", "Spearphishing Link", "active", ["initial-access"]),
        catalog_entry("T1100", "Web Shell (superseded)", "deprecated", []),
    )
}

RULE_LINES = [
    'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"MALWARE-CNC beacon over HTTP"; '
    'flow:to_server; content:"POST"; http_method; reference:url,attack.mitre.org/techniques/T1071/001; '
    'classtype:trojan-activity; sid:1000001; rev:2;)',
    'alert tcp any any -> $HOME_NET any (msg:"MALWARE-OTHER rootkit driver load"; '
    'content:"|00 01 02|"; reference:url,attack.mitre.org/techniques/T1014; '
    'classtype:trojan-activity; sid:1000002; rev:1;)',
    'alert tcp any any -> $HOME_NET any (msg:"POLICY-OTHER unusual user agent observed"; '
    'content:"User-Agent: xyz"; classtype:policy-violation; sid:1000003; rev:1;)',
    'alert udp any any -> any 53 (msg:"PROTOCOL-DNS large TXT response"; '
    'content:"|00 10|"; classtype:misc-activity; sid:1000004; rev:3;)',
]


def build_rules() -> list:
    rules = [rule for line in RULE_LINES if (rule := parse_rule(line))]
    sra.enrich_attack_mappings(rules, CATALOG)
    return rules


def envelope(classifications, finish_reason="stop"):
    """Wrap classifications in a well-formed chat-completions body."""
    return {
        "id": "gen-test",
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"classifications": classifications}),
                },
            }
        ],
    }


class ScriptedHandler(BaseHTTPRequestHandler):
    """Replays a scripted sequence of provider responses."""

    def log_message(self, *_args):  # silence the default stderr access log
        pass

    def do_POST(self):  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", 0))
        request_body = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append(request_body)
        status, headers, body = self.server.script(request_body, self.server.requests)
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


class MockProvider:
    """Context manager exposing a scripted chat-completions endpoint."""

    def __init__(self, script):
        self.script = script

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ScriptedHandler)
        self.server.script = self.script
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.endpoint = f"http://{host}:{port}/api/v1/chat/completions"
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False

    @property
    def requests(self):
        return self.server.requests


def rule_indices(request_body):
    """Return the rule_index values a request asked about."""
    user = json.loads(request_body["messages"][1]["content"])
    return [rule["rule_index"] for rule in user["rules"]]


def mapped_config(endpoint, **overrides):
    defaults = dict(
        enabled=True,
        endpoint=endpoint,
        model="test/model",
        api_key_env="TEST_LLM_KEY",
        batch_size=10,
        timeout=15,
        retries=3,
        cache_dir="",
        debug_log="",
        preflight=False,
        request_delay=0.0,
        max_requests=0,
        reasoning_effort="none",
        fallback_models=(),
    )
    defaults.update(overrides)
    return MappedLLMValidationConfig(**defaults)


def llm_config(endpoint, **overrides):
    defaults = dict(
        enabled=True,
        endpoint=endpoint,
        model="test/model",
        api_key_env="TEST_LLM_KEY",
        batch_size=10,
        timeout=15,
        retries=3,
        target="all",
        cache_dir="",
        debug_log="",
        preflight=False,
        request_delay=0.0,
        max_requests=0,
        reasoning_effort="none",
        fallback_models=(),
    )
    defaults.update(overrides)
    return LLMConfig(**defaults)


class TransportParsingTests(unittest.TestCase):
    """Unit coverage for the parsing helpers, independent of HTTP."""

    def test_strips_openrouter_keepalive_comments(self):
        # The exact shape that produced "Invalid JSON response: Expecting value".
        raw = ": OPENROUTER PROCESSING\n\n: OPENROUTER PROCESSING\n\n{\"choices\": []}"
        self.assertEqual(strip_transport_noise(raw), '{"choices": []}')
        self.assertEqual(loads_tolerant(raw, allow_repair=False), {"choices": []})

    def test_strips_sse_data_frames(self):
        raw = 'data: {"choices": [{"message": {"content": "hi"}}]}\ndata: [DONE]'
        self.assertIn("choices", loads_tolerant(raw, allow_repair=False))

    def test_ignores_prose_and_code_fences(self):
        content = 'Here is the result:\n```json\n{"classifications": []}\n```\nHope that helps!'
        self.assertEqual(loads_tolerant(content), {"classifications": []})

    def test_repairs_truncated_json(self):
        truncated = (
            '{"classifications": [{"rule_index": 0, "sid": "1", "attack_ids": ["T1105"], '
            '"confidence": 0.9, "reasoning": "ok"}, {"rule_index": 1, "sid": "2", "attack_i'
        )
        repaired = repair_truncated_json(truncated)
        self.assertIsNotNone(repaired)
        self.assertEqual(len(repaired["classifications"]), 1)

    def test_empty_body_raises_retryable_error(self):
        with self.assertRaises(LLMTransportError) as caught:
            loads_tolerant("")
        self.assertTrue(caught.exception.retryable)

    def test_technique_ids_are_normalised_and_filtered(self):
        item = {"attack_ids": ["t1071.001", "T1105 - Ingress Tool Transfer", "T1100", "T9999"]}
        # Lowercase and label-suffixed IDs are accepted; deprecated and unknown
        # IDs are rejected so the LLM cannot invent coverage.
        self.assertEqual(sra.accepted_technique_ids(item, CATALOG), ["T1071.001", "T1105"])

    def test_technique_ids_accept_delimited_string(self):
        item = {"attack_ids": "T1105, T1014"}
        self.assertEqual(sra.accepted_technique_ids(item, CATALOG), ["T1014", "T1105"])

    def test_model_id_is_vendor_prefixed_for_openrouter(self):
        self.assertEqual(
            sra.normalise_model_id("gpt-4.1-mini", sra.OPENROUTER_CHAT_ENDPOINT),
            "openai/gpt-4.1-mini",
        )
        self.assertEqual(
            sra.normalise_model_id("google/gemini-3.5-flash-lite", sra.OPENROUTER_CHAT_ENDPOINT),
            "google/gemini-3.5-flash-lite",
        )

    def test_openrouter_key_redirects_openai_endpoint(self):
        self.assertEqual(
            sra.resolve_llm_endpoint(sra.OPENAI_CHAT_ENDPOINT, "sk-or-v1-abc"),
            sra.OPENROUTER_CHAT_ENDPOINT,
        )
        self.assertEqual(
            sra.resolve_llm_endpoint(sra.OPENAI_CHAT_ENDPOINT, "sk-proj-abc"),
            sra.OPENAI_CHAT_ENDPOINT,
        )


class NvidiaProviderTests(unittest.TestCase):
    """Provider wiring for NVIDIA's OpenAI-compatible endpoint."""

    def test_defaults_target_nemotron_ultra_on_nvidia(self):
        """Both stages must default to one NVIDIA key and one pinned model."""
        for config in (LLMConfig(), MappedLLMValidationConfig()):
            self.assertEqual(config.endpoint, sra.NVIDIA_CHAT_ENDPOINT)
            self.assertEqual(config.api_key_env, "NVIDIA_API_KEY")
        self.assertEqual(MappedLLMValidationConfig().model, sra.NEMOTRON_ULTRA_MODEL)
        self.assertEqual(sra.NEMOTRON_ULTRA_MODEL, "nvidia/nemotron-3-ultra-550b-a55b")
        self.assertEqual(
            sra.NVIDIA_CHAT_ENDPOINT,
            "https://integrate.api.nvidia.com/v1/chat/completions",
        )

    def test_nvidia_key_redirects_a_foreign_endpoint(self):
        for endpoint in (sra.OPENAI_CHAT_ENDPOINT, sra.OPENROUTER_CHAT_ENDPOINT):
            self.assertEqual(
                sra.resolve_llm_endpoint(endpoint, "nvapi-abc123"),
                sra.NVIDIA_CHAT_ENDPOINT,
            )
        # A local mock endpoint is deliberate, so it must never be redirected.
        self.assertEqual(
            sra.resolve_llm_endpoint("http://127.0.0.1:9/v1/chat/completions", "nvapi-abc"),
            "http://127.0.0.1:9/v1/chat/completions",
        )

    def test_model_id_is_vendor_prefixed_for_nvidia(self):
        self.assertEqual(
            sra.normalise_model_id("nemotron-3-ultra-550b-a55b", sra.NVIDIA_CHAT_ENDPOINT),
            sra.NEMOTRON_ULTRA_MODEL,
        )
        self.assertEqual(
            sra.normalise_model_id(sra.NEMOTRON_ULTRA_MODEL, sra.NVIDIA_CHAT_ENDPOINT),
            sra.NEMOTRON_ULTRA_MODEL,
        )

    def test_reasoning_control_is_provider_specific(self):
        """NIM gates reasoning through the chat template, not OpenRouter's field."""
        nvidia = sra._reasoning_payload_fields("low", sra.NVIDIA_CHAT_ENDPOINT)
        self.assertEqual(
            nvidia,
            {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": "low"}},
        )
        self.assertNotIn("reasoning", nvidia)
        # Nemotron's template defaults thinking on, so "none" must be explicit.
        self.assertEqual(
            sra._reasoning_payload_fields("none", sra.NVIDIA_CHAT_ENDPOINT),
            {"chat_template_kwargs": {"enable_thinking": False}},
        )
        # Every other provider keeps the behaviour it had before.
        self.assertEqual(
            sra._reasoning_payload_fields("low", sra.OPENROUTER_CHAT_ENDPOINT),
            {"reasoning": {"effort": "low"}},
        )
        self.assertEqual(
            sra._reasoning_payload_fields("none", sra.OPENROUTER_CHAT_ENDPOINT), {}
        )

    def test_nvidia_endpoint_is_paced_per_key(self):
        """NVIDIA meters per key, so pacing follows the endpoint not a ':free' tag."""
        self.assertAlmostEqual(
            sra.auto_request_delay(sra.NEMOTRON_ULTRA_MODEL, sra.NVIDIA_CHAT_ENDPOINT),
            sra.NVIDIA_MIN_INTERVAL,
        )
        self.assertEqual(
            sra.auto_request_delay("openai/gpt-oss-20b", sra.OPENAI_CHAT_ENDPOINT), 0.0
        )
        # The tighter OpenRouter free-tier limit still wins where it applies.
        self.assertAlmostEqual(
            sra.auto_request_delay("openai/gpt-oss-20b:free", sra.OPENROUTER_CHAT_ENDPOINT),
            sra.FREE_TIER_MIN_INTERVAL,
        )

    def test_validation_error_status_422_is_recognised(self):
        """NIM answers a bad field with 422 where OpenRouter uses 400."""
        self.assertTrue(sra._mentions_unsupported_parameter('{"detail": "chat_template_kwargs"}'))
        self.assertTrue(
            sra._mentions_unsupported_parameter('{"detail": "Extra inputs are not permitted"}')
        )
        # A structured-output complaint belongs to the response_format ladder.
        self.assertFalse(
            sra._mentions_unsupported_parameter('{"detail": "response_format unsupported"}')
        )


class MappedValidationTests(unittest.TestCase):
    """Stage 4: independent LLM validation of keyword-mapped rules."""

    def setUp(self):
        sra.GOVERNOR.reset()
        self.rules = build_rules()
        self.mapped = [rule for rule in self.rules if sra.rule_mapping_ids(rule)]
        self.assertEqual(len(self.mapped), 2, "fixture should have two mapped rules")

    def run_validation(self, script, **overrides):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        with MockProvider(script) as provider:
            rows = validate_mapped_rules_with_llm(
                self.rules, CATALOG, mapped_config(provider.endpoint, **overrides)
            )
            return rows, provider.requests

    def test_keepalive_prefixed_response_is_parsed(self):
        """The original failure: the run now produces real agreements."""

        def script(body, _history):
            answers = [
                {
                    "rule_index": index,
                    "sid": "x",
                    "attack_ids": ["T1071.001"] if index == 0 else ["T1014"],
                    "confidence": 0.82,
                    "reasoning": "network evidence",
                }
                for index in rule_indices(body)
            ]
            noisy = ": OPENROUTER PROCESSING\n\n" * 3 + json.dumps(envelope(answers))
            return 200, {}, noisy

        rows, _ = self.run_validation(script)
        self.assertEqual([row["Agreement"] for row in rows], ["match", "match"])
        self.assertTrue(all(row["LLM Prediction"] for row in rows))

    def test_error_returned_with_http_200_is_reported(self):
        def script(_body, _history):
            return 200, {}, json.dumps(
                {"error": {"code": 402, "message": "Insufficient credits"}}
            )

        rows, _ = self.run_validation(script, retries=0)
        self.assertTrue(all(row["Agreement"] == "validation_error" for row in rows))
        self.assertIn("Insufficient credits", rows[0]["Reason"])

    def test_http_error_body_detail_reaches_the_csv(self):
        def script(_body, _history):
            return 400, {}, json.dumps(
                {"error": {"message": "google/gemini-x is not a valid model ID", "code": 400}}
            )

        rows, _ = self.run_validation(script, retries=0)
        self.assertIn("not a valid model ID", rows[0]["Reason"])

    def test_rate_limit_is_retried_then_succeeds(self):
        def script(body, history):
            if len(history) == 1:
                return 429, {"Retry-After": "0"}, json.dumps(
                    {"error": {"message": "rate limited", "code": 429}}
                )
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": [], "confidence": 0.1, "reasoning": "none"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        rows, requests = self.run_validation(script)
        self.assertGreaterEqual(len(requests), 2)
        self.assertTrue(all(row["Agreement"] == "no_prediction" for row in rows))

    def test_empty_reasoning_content_triggers_larger_budget(self):
        """Reasoning models can spend the whole budget before answering."""

        def script(body, history):
            if len(history) == 1:
                return 200, {}, json.dumps(
                    {
                        "choices": [
                            {
                                "finish_reason": "length",
                                "message": {"role": "assistant", "content": "", "reasoning": "..."},
                            }
                        ]
                    }
                )
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.5, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        rows, requests = self.run_validation(script)
        self.assertGreater(requests[1]["max_tokens"], requests[0]["max_tokens"])
        self.assertTrue(all(row["Agreement"] in {"mismatch", "partial_match"} for row in rows))

    def test_json_schema_rejection_falls_back_to_json_object(self):
        sra._RESPONSE_FORMAT_MODE.clear()

        def script(body, _history):
            if (body.get("response_format") or {}).get("type") == "json_schema":
                return 400, {}, json.dumps(
                    {"error": {"message": "response_format json_schema is not supported", "code": 400}}
                )
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1014"], "confidence": 0.7, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        rows, requests = self.run_validation(script)
        self.assertEqual(requests[0]["response_format"]["type"], "json_schema")
        self.assertEqual(requests[1]["response_format"]["type"], "json_object")
        self.assertIn("match", [row["Agreement"] for row in rows])
        sra._RESPONSE_FORMAT_MODE.clear()

    def test_bare_array_response_is_accepted(self):
        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1071.001"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(
                {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(answers)}}]}
            )

        rows, _ = self.run_validation(script)
        self.assertNotIn("validation_error", [row["Agreement"] for row in rows])

    def test_content_as_parts_list_is_accepted(self):
        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1014"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "content": [
                                    {"type": "text", "text": '{"classifications": '},
                                    {"type": "text", "text": json.dumps(answers) + "}"},
                                ]
                            },
                        }
                    ]
                }
            )

        rows, _ = self.run_validation(script)
        self.assertNotIn("validation_error", [row["Agreement"] for row in rows])

    def test_partial_and_mismatch_are_distinguished(self):
        def script(body, _history):
            answers = []
            for index in rule_indices(body):
                # Rule 0 is keyword-mapped to T1071.001, rule 1 to T1014.
                ids = ["T1071.001", "T1105"] if index == 0 else ["T1105"]
                answers.append(
                    {"rule_index": index, "sid": "x", "attack_ids": ids, "confidence": 0.5, "reasoning": "r"}
                )
            return 200, {}, json.dumps(envelope(answers))

        rows, _ = self.run_validation(script)
        self.assertEqual([row["Agreement"] for row in rows], ["partial_match", "mismatch"])

    def test_metrics_separate_abstention_from_disagreement(self):
        rows = [
            {"Agreement": "match", "Confidence": 0.9},
            {"Agreement": "partial_match", "Confidence": 0.5},
            {"Agreement": "mismatch", "Confidence": 0.4},
            {"Agreement": "no_prediction", "Confidence": 0.1},
            {"Agreement": "validation_error", "Confidence": ""},
        ]
        metrics = sra.mapped_rule_validation_metrics(rows)
        self.assertEqual(metrics["total_tested_rules"], 4)
        self.assertEqual(metrics["no_predictions"], 1)
        self.assertEqual(metrics["mismatches"], 1)
        self.assertEqual(metrics["agreement_percentage"], 25.0)
        self.assertEqual(metrics["any_overlap_percentage"], 50.0)


class BatchRecoveryTests(unittest.TestCase):
    """A poisoned rule must not destroy the evidence for its batch."""

    def setUp(self):
        sra.GOVERNOR.reset()
        self.rules = build_rules()

    def test_batch_splits_until_only_the_bad_rule_fails(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        poisoned = 2  # rule_index 2 makes the provider fail

        def script(body, _history):
            indices = rule_indices(body)
            if poisoned in indices:
                return 500, {}, json.dumps({"error": {"message": "upstream exploded"}})
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in indices
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4, retries=1)
            )

        statuses = [row["llm_status"] for row in rows]
        self.assertEqual(statuses.count("classified"), 3)
        self.assertEqual(statuses[poisoned], "error")
        self.assertIn("upstream exploded", rows[poisoned]["llm_error"])

    def test_omitted_rule_is_retried_individually(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"

        def script(body, _history):
            indices = rule_indices(body)
            # Silently drop the last rule whenever more than one is requested.
            answered = indices[:-1] if len(indices) > 1 else indices
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in answered
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4)
            )

        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))

    def test_sid_fallback_when_provider_renumbers_rule_index(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"

        def script(body, _history):
            user = json.loads(body["messages"][1]["content"])
            answers = [
                {
                    "rule_index": 900 + position,  # deliberately wrong
                    "sid": str(rule["sid"]),
                    "attack_ids": ["T1105"],
                    "confidence": 0.6,
                    "reasoning": "r",
                }
                for position, rule in enumerate(user["rules"])
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4)
            )

        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))


class FailFastTests(unittest.TestCase):
    """An unusable endpoint must fail in seconds, not grind through every rule."""

    def setUp(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        sra.GOVERNOR.reset()
        self.rules = build_rules()

    def test_auth_failure_does_not_split_the_batch(self):
        def script(_body, _history):
            return 401, {}, json.dumps(
                {"error": {"message": "No auth credentials found", "code": 401}}
            )

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4, retries=2)
            )
            calls = len(provider.requests)

        # One batch, one call: a 401 is not retried and not split into four.
        self.assertEqual(calls, 1)
        self.assertTrue(all(row["llm_status"] == "error" for row in rows))
        self.assertIn("No auth credentials", rows[0]["llm_error"])

    def test_unreachable_endpoint_trips_the_circuit_breaker(self):
        import time

        # Port 9 (discard) refuses connections immediately on most systems.
        config = llm_config(
            "http://127.0.0.1:9/api/v1/chat/completions", batch_size=1, retries=1
        )
        many_rules = self.rules * 10  # 40 rules => 40 batches without a breaker
        started = time.perf_counter()
        rows = classify_rules_with_llm(many_rules, CATALOG, config)
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 60, "circuit breaker should abandon the stage quickly")
        self.assertTrue(all(row["llm_status"] == "error" for row in rows))
        self.assertTrue(
            any("abandoned" in str(row["llm_error"]) for row in rows),
            "later rules should be marked as abandoned rather than retried",
        )


class HarmonyModelTests(unittest.TestCase):
    """gpt-oss and other reasoning models that answer in the wrong channel."""

    def setUp(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        sra.GOVERNOR.reset()
        sra._RESPONSE_FORMAT_MODE.clear()
        sra._VENDOR_EXTRAS_SUPPORTED.clear()
        sra._REASONING_FALLBACK_NOTED = False
        self.rules = build_rules()

    def tearDown(self):
        sra.GOVERNOR.reset()
        sra._RESPONSE_FORMAT_MODE.clear()
        sra._VENDOR_EXTRAS_SUPPORTED.clear()

    def test_answer_in_reasoning_channel_is_recovered(self):
        """The observed gpt-oss failure: content empty, finish_reason=stop."""

        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "reasoning": json.dumps({"classifications": answers}),
                            },
                        }
                    ]
                }
            )

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4)
            )
            calls = len(provider.requests)

        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))
        self.assertEqual(calls, 1, "recovery should not need a second request")

    def test_answer_in_reasoning_details_is_recovered(self):
        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1014"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "reasoning_details": [
                                    {
                                        "type": "reasoning.text",
                                        "text": json.dumps({"classifications": answers}),
                                    }
                                ],
                            },
                        }
                    ]
                }
            )

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4)
            )

        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))

    def test_reasoning_is_not_excluded_from_the_request(self):
        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": [], "confidence": 0.1, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, reasoning_effort="low")
            )
            payload = provider.requests[0]

        # exclude=True would discard the only copy of an answer delivered in
        # the analysis channel, so it must not be sent.
        self.assertEqual(payload["reasoning"], {"effort": "low"})

    def test_empty_completion_relaxes_structured_output(self):
        """A clean stop with no answer must change the request, not repeat it."""

        def script(body, _history):
            fmt = (body.get("response_format") or {}).get("type")
            if fmt in {"json_schema", "json_object"}:
                # Strict decoding suppresses every token the model would emit.
                return 200, {}, json.dumps(
                    {"choices": [{"finish_reason": "stop", "message": {"content": ""}}]}
                )
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=4, retries=1)
            )
            formats = [
                (request.get("response_format") or {}).get("type")
                for request in provider.requests
            ]

        self.assertEqual(formats[:3], ["json_schema", "json_object", None])
        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))

    def test_fallback_chain_is_withheld_from_non_openrouter_endpoints(self):
        """`models` is an OpenRouter extension; OpenAI rejects unknown fields."""

        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": [], "confidence": 0.1, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            config = llm_config(provider.endpoint, fallback_models=("b/model", "c/model"))
            classify_rules_with_llm(self.rules, CATALOG, config)
            self.assertNotIn("models", provider.requests[0])

    def test_rejected_reasoning_parameter_is_dropped_not_retried(self):
        """A 422 over an optional vendor field must reshape the request, not fail.

        NVIDIA's NIM gateway validates the request body strictly and answers
        with 422. Retrying identically would reproduce it, and abandoning the
        stage would lose every rule over an optional field.
        """

        def script(body, _history):
            if "reasoning" in body or "chat_template_kwargs" in body:
                return 422, {}, json.dumps(
                    {"detail": [{"loc": ["body", "reasoning"],
                                 "msg": "Extra inputs are not permitted"}]}
                )
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"],
                 "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules,
                CATALOG,
                llm_config(provider.endpoint, batch_size=4, reasoning_effort="low", retries=1),
            )
            sent = provider.requests

        self.assertIn("reasoning", sent[0], "the first attempt should still ask for reasoning")
        self.assertNotIn("reasoning", sent[1], "the retry must drop the rejected field")
        self.assertTrue(all(row["llm_status"] == "classified" for row in rows))


class ModelProvenanceTests(unittest.TestCase):
    """A fallback chain must never make mixed-model results look homogeneous."""

    def setUp(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        sra.GOVERNOR.reset()
        sra._RESPONSE_FORMAT_MODE.clear()
        self.rules = build_rules()

    def tearDown(self):
        sra.GOVERNOR.reset()
        sra._RESPONSE_FORMAT_MODE.clear()

    def test_responding_model_is_recorded_per_rule(self):
        def script(body, history):
            # The provider reroutes to a different model on the second call.
            served = "primary/model" if len(history) == 1 else "fallback/model"
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            payload = envelope(answers)
            payload["model"] = served
            return 200, {}, json.dumps(payload)

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, batch_size=2)
            )

        recorded = [row["llm_model"] for row in rows]
        self.assertEqual(recorded[:2], ["primary/model"] * 2)
        self.assertEqual(recorded[2:], ["fallback/model"] * 2)

    def test_mapped_validation_records_the_model(self):
        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1014"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            payload = envelope(answers)
            payload["model"] = "nvidia/nemotron-nano-9b-v2:free"
            return 200, {}, json.dumps(payload)

        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        with MockProvider(script) as provider:
            rows = validate_mapped_rules_with_llm(
                self.rules, CATALOG, mapped_config(provider.endpoint)
            )

        self.assertTrue(all(row["Model"] == "nvidia/nemotron-nano-9b-v2:free" for row in rows))


class FreeTierTests(unittest.TestCase):
    """Throttling, budget ceilings, and reasoning control for :free models."""

    def setUp(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        sra.GOVERNOR.reset()
        self.rules = build_rules()

    def tearDown(self):
        sra.GOVERNOR.reset()

    def ok_script(self, body, _history):
        answers = [
            {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
            for index in rule_indices(body)
        ]
        return 200, {}, json.dumps(envelope(answers))

    def test_free_model_ids_are_recognised(self):
        self.assertTrue(sra.is_free_tier_model("openai/gpt-oss-20b:free"))
        self.assertFalse(sra.is_free_tier_model("openai/gpt-oss-20b"))

    def test_free_model_is_throttled_between_requests(self):
        import time

        with MockProvider(self.ok_script) as provider:
            # request_delay=-1 asks the model tier to decide the interval.
            config = llm_config(
                provider.endpoint,
                model="openai/gpt-oss-20b:free",
                batch_size=1,
                request_delay=-1.0,
            )
            started = time.perf_counter()
            classify_rules_with_llm(self.rules, CATALOG, config)
            elapsed = time.perf_counter() - started

        # Four rules at batch size 1 means three enforced gaps.
        self.assertGreaterEqual(elapsed, 3 * sra.FREE_TIER_MIN_INTERVAL - 0.5)
        self.assertAlmostEqual(sra.GOVERNOR.min_interval, sra.FREE_TIER_MIN_INTERVAL, places=3)

    def test_paid_model_is_not_throttled(self):
        with MockProvider(self.ok_script) as provider:
            config = llm_config(
                provider.endpoint, model="openai/gpt-oss-20b", batch_size=1, request_delay=-1.0
            )
            classify_rules_with_llm(self.rules, CATALOG, config)
        self.assertEqual(sra.GOVERNOR.min_interval, 0.0)

    def test_request_budget_stops_the_run(self):
        with MockProvider(self.ok_script) as provider:
            config = llm_config(
                provider.endpoint, batch_size=1, max_requests=2, retries=0
            )
            rows = classify_rules_with_llm(self.rules * 3, CATALOG, config)
            calls = len(provider.requests)

        self.assertEqual(calls, 2, "the ceiling must stop further provider calls")
        classified = [row for row in rows if row["llm_status"] == "classified"]
        self.assertEqual(len(classified), 2)
        self.assertTrue(
            any("budget" in str(row["llm_error"]).lower() for row in rows),
            "remaining rules should say the budget was exhausted",
        )

    def test_reasoning_effort_none_omits_the_parameter(self):
        with MockProvider(self.ok_script) as provider:
            config = llm_config(provider.endpoint, batch_size=4, reasoning_effort="none")
            classify_rules_with_llm(self.rules, CATALOG, config)
            payload = provider.requests[0]

        self.assertNotIn("reasoning", payload)


class TargetingAndCacheTests(unittest.TestCase):
    def setUp(self):
        sra.GOVERNOR.reset()
        self.rules = build_rules()

    def test_unmapped_target_submits_only_unmapped_rules(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"
        submitted = []

        def script(body, _history):
            indices = rule_indices(body)
            submitted.extend(indices)
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in indices
            ]
            return 200, {}, json.dumps(envelope(answers))

        with MockProvider(script) as provider:
            rows = classify_rules_with_llm(
                self.rules, CATALOG, llm_config(provider.endpoint, target="unmapped")
            )

        keyword_mapped = {
            index for index, rule in enumerate(self.rules) if sra.rule_mapping_ids(rule)
        }
        self.assertFalse(set(submitted) & keyword_mapped)
        self.assertEqual(len(submitted), len(self.rules) - len(keyword_mapped))
        for index in keyword_mapped:
            self.assertEqual(rows[index]["llm_status"], "not_submitted")

    def test_cache_prevents_a_second_provider_call(self):
        import os

        os.environ["TEST_LLM_KEY"] = "sk-test-key"

        def script(body, _history):
            answers = [
                {"rule_index": index, "sid": "x", "attack_ids": ["T1105"], "confidence": 0.6, "reasoning": "r"}
                for index in rule_indices(body)
            ]
            return 200, {}, json.dumps(envelope(answers))

        with TemporaryDirectory() as tmp, MockProvider(script) as provider:
            config = llm_config(provider.endpoint, cache_dir=str(Path(tmp) / "cache"))
            first = classify_rules_with_llm(self.rules, CATALOG, config)
            calls_after_first = len(provider.requests)
            second = classify_rules_with_llm(self.rules, CATALOG, config)
            self.assertEqual(len(provider.requests), calls_after_first)

        self.assertEqual(
            [row["llm_attack_ids"] for row in first],
            [row["llm_attack_ids"] for row in second],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
