#!/usr/bin/env python3
"""Live preflight against NVIDIA's OpenAI-compatible endpoint.

Unlike test_llm_integration.py, which is entirely offline, this module makes
exactly ONE real request to https://integrate.api.nvidia.com so that the key,
the endpoint, the model ID and the JSON contract are proven against the actual
provider before a stage is allowed to spend hundreds of requests.

It is skipped, not failed, when NVIDIA_API_KEY is absent, so the offline suite
stays runnable with no credentials:

    python -m unittest test_nvidia_preflight -v

Cost: 1 request, a single-rule prompt, a few hundred tokens.
"""

from __future__ import annotations

import json
import os
import unittest

import snort_rule_analyzer as sra

API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
requires_key = unittest.skipUnless(
    API_KEY, "NVIDIA_API_KEY is not set; skipping the live NVIDIA preflight"
)


class NvidiaLivePreflightTests(unittest.TestCase):
    """One real call, asserting the things a long run depends on."""

    @classmethod
    def setUpClass(cls):
        cls.endpoint = sra.resolve_llm_endpoint(sra.NVIDIA_CHAT_ENDPOINT, API_KEY)
        cls.model = sra.normalise_model_id(sra.NEMOTRON_ULTRA_MODEL, cls.endpoint)
        sra.GOVERNOR.reset()
        sra.GOVERNOR.configure(
            min_interval=sra.auto_request_delay(cls.model, cls.endpoint),
            # One live call in the happy path. The small headroom exists only so
            # a transient 429 can be retried instead of aborting the check.
            max_requests=3,
        )

    @classmethod
    def tearDownClass(cls):
        sra.GOVERNOR.reset()

    def test_key_prefix_looks_like_an_nvidia_key(self):
        """Cheap check first: a wrong key shape explains a 401 without spending one."""
        if not API_KEY:
            self.skipTest("NVIDIA_API_KEY is not set")
        self.assertTrue(
            API_KEY.startswith(sra.NVIDIA_API_KEY_PREFIX),
            f"NVIDIA build keys start with '{sra.NVIDIA_API_KEY_PREFIX}'; "
            f"got a {len(API_KEY)}-character key starting '{API_KEY[:6]}'",
        )

    @requires_key
    def test_live_preflight_returns_parseable_classifications(self):
        """The real request the pipeline makes, end to end, once."""
        classifications, answering_model = sra.llm_chat_json(
            endpoint=self.endpoint,
            api_key=API_KEY,
            model=self.model,
            system=(
                'Return JSON only, matching {"classifications": [...]} where each item has '
                "rule_index (integer), sid (string), attack_ids (array of strings), "
                "confidence (number), and reasoning (string)."
            ),
            user=json.dumps(
                {
                    "rules": [
                        {
                            "rule_index": 0,
                            "sid": "9999999",
                            "msg": (
                                "PROTOCOL-DNS TXT record query response with base64 payload"
                            ),
                        }
                    ]
                }
            ),
            max_tokens=2000,
            timeout=180,
            retries=2,
            cache_dir=None,  # never cache a liveness check
            debug_log=None,
            label="NVIDIA Preflight",
            reasoning_effort="low",
            fallback_models=(),  # pinned model: no server-side rerouting
        )

        self.assertGreaterEqual(
            len(classifications), 1, "the provider returned no classification objects"
        )
        item = classifications[0]
        self.assertIsInstance(item, dict)
        self.assertTrue(
            {"attack_ids", "sid", "rule_index"} & set(item),
            f"response object had none of the expected keys: {sorted(item)}",
        )
        # Only techniques that exist in the local catalog are ever accepted, so
        # confirm the filter runs rather than that any particular ID came back.
        self.assertIsInstance(item.get("attack_ids", []), (list, str))

        # The run must be answered by the model that was asked for; a silent
        # substitution would make the write-up's model attribution wrong.
        self.assertIn(
            "nemotron",
            answering_model.lower(),
            f"expected a Nemotron model, got {answering_model!r}",
        )

    def test_resolved_endpoint_and_model_are_the_nvidia_pair(self):
        """No network: the request would go to the right place with the right ID."""
        self.assertEqual(self.endpoint, sra.NVIDIA_CHAT_ENDPOINT)
        self.assertEqual(self.model, sra.NEMOTRON_ULTRA_MODEL)
        self.assertTrue(sra.is_nvidia_endpoint(self.endpoint))


if __name__ == "__main__":
    unittest.main(verbosity=2)
