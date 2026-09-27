# Keyword and LLM Classification Workflow

The analyzer always produces keyword-based ATT&CK mappings offline. LLM
assistance is opt-in and never overwrites a keyword mapping — it produces a
parallel, separately labelled body of evidence.

| Stage | What it does | Flag | Rules | Requests |
|-------|--------------|------|-------|----------|
| 1–3 | Keyword mapping, comparison scaffolding | *(always)* | 4,017 | 0 |
| 4 | Independent LLM validation of already-mapped rules | `-EnableMappedValidation` | 430 mapped | ~18 |
| 5 | LLM candidate mapping of unmapped rules | `-EnableLlm -LlmTarget unmapped` | 3,587 unmapped | ~144 |

## Provider and model

| Setting | Value |
|---------|-------|
| Endpoint | `https://integrate.api.nvidia.com/v1/chat/completions` |
| Model | `nvidia/nemotron-3-ultra-550b-a55b` |
| Key | read from the `NVIDIA_API_KEY` environment variable |

**Nemotron 3 Ultra** is a 550B-parameter hybrid Mamba-Transformer
mixture-of-experts reasoning model with roughly 55B parameters active per
token, served through NVIDIA's OpenAI-compatible build/NIM API. The key is
never written into any script or committed file; it is read from the
environment at run time.

### Why one pinned model

The previous OpenRouter configuration used a fallback chain, because every
`:free` variant there is served by a single shared provider pool and can be
rate-limited at any moment. That meant a single run could be answered by more
than one model, which had to be caveated in the write-up.

NVIDIA meters **per key, not per model**, so no chain is needed:
`-ModelFallbacks` now defaults to empty and server-side model routing is not
sent to NVIDIA at all. Every rule in a run is answered by Nemotron 3 Ultra.

The per-rule provenance columns are unchanged and still populated — the `Model`
column in `mapped_rule_llm_validation.csv` and `llm_model` in
`llm_classification_results.csv` — so the claim that one model answered the
whole run is evidenced in the output rather than merely asserted.

### Rate limits and pacing

NVIDIA applies a per-key request rate rather than a daily model quota, so the
planning arithmetic is about wall-clock time, not a 50/day allowance:

- Requests are auto-paced to one every **1.7s** (40/min) on NVIDIA endpoints.
  Override with `-RequestDelay`.
- The planned request count is printed **before** the run starts.
- Actual requests consumed is printed at the end of each stage.
- `--llm-max-requests` sets a hard ceiling that aborts cleanly.
- Every completed batch is cached, so an interrupted run resumes rather than
  restarting.

At batch size 25, Stage 4 is ~18 requests and Stage 5 is ~144 — roughly half a
minute and four minutes of pacing respectively, before generation time.

### Structured output

Nemotron reasoning is requested through NVIDIA's `chat_template_kwargs`
(`enable_thinking`), not OpenRouter's `reasoning` object; the pipeline picks
the right one from the endpoint. If any provider rejects either that field or
`response_format`, the request is reshaped once and re-issued rather than
retried identically or abandoned: `json_schema` → `json_object` →
unconstrained, and reasoning control dropped if refused.

## Running Stage 4 — step by step

```powershell
# 1. Open PowerShell in the project folder.
cd "C:\Users\Admin\Documents\Main Project"

# 2. Set your NVIDIA key (this session only).
$env:NVIDIA_API_KEY = "nvapi-..."

# 3. Confirm the key, endpoint and model work. Costs 1 request, takes ~10s.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip -PreflightOnly

# 4. Small real test on 5 mapped rules (1 request) before anything larger.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableMappedValidation -MappedValidationMaxRules 5 `
    -MappedValidationBatchSize 5 -Output stage4_nvidia_test

# 5. Full Stage 4 on all 430 mapped rules. ~18 requests.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableMappedValidation
```

Expected output from step 5:

```
[Mapped LLM Validation] Enabled. Submitting 430 mapped rules to
    https://integrate.api.nvidia.com/v1/chat/completions using nvidia/nemotron-3-ultra-550b-a55b.
[Mapped LLM Validation] Planned requests: ~18 (430 rules / batch size 25).
[Mapped LLM Validation] Throttling to one request every 1.7s for the 40/min NVIDIA limit.
[Preflight] OK. Parsed 1 classification object(s) from nvidia/nemotron-3-ultra-550b-a55b.
[Mapped LLM Validation] Batch 1/18 (25 rules)...
...
[Mapped LLM Validation] Completed 430 rules in ...s.
    match=..., partial_match=..., mismatch=..., no_prediction=...
[Mapped LLM Validation] Provider requests used so far: 19.
```

Results land in `all_categories_output/`:

- `mapped_rule_llm_validation.csv` — the per-rule comparison
- `mapped_rule_llm_validation.svg` — the agreement chart
- `research_metrics.json` → `mapped_rule_llm_validation` — the summary metrics
- `report.md` → "Mapped Rule GPT Validation" section

### If step 3 fails

| Message | Cause | Fix |
|---------|-------|-----|
| `HTTP 401` / `HTTP 403` | Key not set, wrong, or not an `nvapi-` key | Re-run step 2; check for stray quotes |
| `HTTP 404` / `HTTP 422: ... model` | Model ID wrong or renamed | Confirm against <https://integrate.api.nvidia.com/v1/models> |
| `HTTP 429` | Per-key rate limit hit | Wait a minute; raise `-RequestDelay` above 1.7 |
| `HTTP 422: Extra inputs are not permitted` | Provider refused an optional field | Handled automatically: the field is dropped and the request re-issued |
| `Model returned empty content (finish_reason=stop)` | Strict JSON decoding suppressed the answer, or the model replied in the reasoning channel | Handled automatically — see below |
| `Network error ... Connection refused` | No internet / proxy | Check connectivity |

### Why `finish_reason=stop` with empty content happens

Reasoning models split a reply into an *analysis* channel and a *final*
channel, exposed as `reasoning` and `content`. Two things can then go wrong:

1. The provider puts the whole answer in the analysis channel and leaves
   `content` empty. If the request set `reasoning.exclude = true`, the only
   copy of the answer is discarded.
2. Strict `json_schema` decoding suppresses every token the model would have
   emitted, so it stops cleanly having produced nothing.

Both are handled: reasoning is never excluded and is parsed as a fallback
source, and an empty completion relaxes `json_schema` → `json_object` → no
constraint rather than retrying an identical request that would fail
identically.

### If the key is rate-limited

NVIDIA meters per key. A `429` means this key is asking too fast, not that a
shared pool is saturated, so waiting or slowing down always resolves it:

```powershell
# Halve the pace; the default is 1.7s between requests.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableMappedValidation -RequestDelay 3.5
```

Completed batches are cached, so a re-run resumes rather than restarting and
costs nothing for work already done. The preflight reports the exact provider
message, so the cause is visible rather than hidden behind a generic
"Bad Request".

## Running Stage 5

```powershell
# Small real test first: 5 unmapped rules, 1 request.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableLlm -LlmTarget unmapped -LlmMaxRules 5 -LlmBatchSize 5 `
    -Output stage5_nvidia_test

# Full Stage 5 over all 3,587 unmapped rules, ~144 requests.
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableMappedValidation -EnableLlm -LlmTarget unmapped -LlmBatchSize 25
```

To stay inside a smaller budget, cap it and resume later — the cache means the
second run only pays for what the first did not finish:

```powershell
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableLlm -LlmTarget unmapped -MaxRequests 45
```

## Using a different model or provider

```powershell
.\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
    -EnableMappedValidation `
    -Model "nvidia/nemotron-3-super-120b-a12b"
```

Three guardrails prevent the most common misconfigurations:

- An NVIDIA key (`nvapi-...`) supplied with a non-NVIDIA endpoint is redirected
  to NVIDIA automatically.
- An OpenRouter key (`sk-or-...`) supplied with the OpenAI endpoint is
  redirected to OpenRouter automatically.
- A bare model ID such as `nemotron-3-ultra-550b-a55b` is rewritten to
  `nvidia/nemotron-3-ultra-550b-a55b`, because the catalogue requires a vendor
  prefix.

## Reliability behaviour

Providers that advertise an "OpenAI-compatible" API are only loosely
compatible. The transport layer absorbs the following, all observed in
practice, so that a provider quirk never silently becomes a research finding:

| Behaviour | Handling |
|-----------|----------|
| `: OPENROUTER PROCESSING` keep-alive lines before the JSON body | Stripped before parsing |
| Errors returned with HTTP 200 in an `{"error": ...}` envelope | Detected and reported |
| HTTP error bodies carrying the real diagnostic | Body text surfaced, not just "Bad Request" |
| Reasoning models returning empty content at `finish_reason=length` | Completion budget doubled and retried |
| Reasoning tokens starving the answer | `--llm-reasoning-effort low`; reasoning is never excluded, so an answer sent there is still recovered |
| Reasoning control field refused (`422 Extra inputs are not permitted`) | Dropped once and the request re-issued, not retried identically |
| Truncated JSON | Repaired at the last complete object; partial results kept |
| Markdown fences and prose around the JSON | Tolerated |
| Content returned as a list of parts | Concatenated |
| A rule missing from the response | Re-requested on its own |
| A renumbered `rule_index` | Matched back by SID |
| `response_format` unsupported | Falls back `json_schema` → `json_object` → none |
| 429 / 5xx / timeouts | Retried with `Retry-After`-aware exponential backoff |
| One rule the provider chokes on | Batch halved recursively; only that rule fails |
| Dead endpoint, bad key, unknown model, exhausted quota | Not split, not retried; stage abandoned after 5 consecutive batch failures |

Only active technique IDs from the local Enterprise ATT&CK catalog are
accepted, so the model cannot invent coverage. IDs are normalised first, so
`t1071.001` and `T1071.001 - Web Protocols` are both understood, while
deprecated and unknown IDs are discarded.

## Caching and reproducibility

Responses are cached under `<output>/.llm_cache/` keyed by the exact request
payload. Re-running reproduces identical results without spending requests —
useful when regenerating charts or the report, and essential when resuming an
interrupted run. Use `-NoCache` to force fresh calls, and
`-DebugResponses` to append every raw provider response to
`<output>/llm_debug.jsonl` for an audit trail.

## Outputs

- `mapped_rule_llm_validation.csv` — existing mapping vs. independent LLM
  prediction for each mapped rule. `Agreement` is one of `match`,
  `partial_match`, `mismatch`, `no_prediction`, `validation_error`.
- `llm_classification_results.csv` — per-rule LLM techniques, confidence,
  reasoning, and status (`classified`, `error`, `not_submitted`, `not_run`).
- `keyword_llm_classification_comparison.csv` — agreement, overlap, and
  coverage delta per rule.
- `unmapped_rule_candidates.csv` — candidate techniques for unmapped rules,
  labelled `improved_heuristic_candidate` or `llm_candidate`.
- `unmapped_classification_analysis.csv` — why each rule remains unmapped.
- `validation_dataset.csv` — prioritised analyst verification queue.
- `research_metrics.json` — all of the above as metrics.
- `classification_coverage_comparison.svg`,
  `classification_difference_breakdown.svg`,
  `mapped_rule_llm_validation.svg`.

## Interpreting the results

Four distinctions matter when writing this up:

1. **`no_prediction` is not `mismatch`.** A model that declines to propose any
   technique is abstaining; a model that proposes a different technique is
   disagreeing. Only the second is evidence against the keyword mapping.
2. **`not_submitted` is not `error`.** Rules outside the `--llm-target`
   selection were never sent. Rules with `error` were sent and failed.
3. **LLM-only proposals are candidates, not coverage.** They require analyst
   validation before being counted as ATT&CK coverage.
4. **Stage 4 is a reproduction test.** The model never sees the keyword mapping,
   so agreement is evidence about the keyword mapper's defensibility — not
   proof that either method is correct.

Note for the write-up: Nemotron 3 Ultra is an open-weight 550B/55B-active
reasoning model, so agreement figures are attributable to a single named,
openly documented model rather than to an opaque routing decision. One model
answers every rule in a run, and the per-rule `Model` / `llm_model` columns
evidence that.

## Testing the NVIDIA connection

`test_nvidia_preflight.py` makes exactly **one real request** to NVIDIA and
asserts that the key, endpoint, model ID and JSON contract all hold. It skips
rather than fails when `NVIDIA_API_KEY` is unset:

```powershell
$env:NVIDIA_API_KEY = "nvapi-..."
python -m unittest test_nvidia_preflight -v
```

## Testing without a provider

`test_llm_integration.py` stands up a local server that reproduces every
failure mode in the table above and drives the real Stage 4 and Stage 5 code
paths against it. No network access, no API key, no quota:

```powershell
python -m unittest test_llm_integration -v
```

The mock provider is embedded in the test suite itself, so no separate server
script is needed. Each test starts a scripted local endpoint, points the real
Stage 4 and Stage 5 code at it, and shuts it down again, which keeps the
offline tests self-contained and reproducible.
