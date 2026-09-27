<#
.SYNOPSIS
    Runs the Snort-to-ATT&CK analysis pipeline, optionally with LLM assistance.

.DESCRIPTION
    Stage 1-3 (keyword mapping and comparison) always run offline.
    Stage 4  (-EnableMappedValidation) asks an LLM to independently reproduce the
             ATT&CK techniques already assigned to keyword-mapped rules.
    Stage 5  (-EnableLlm -LlmTarget unmapped) asks an LLM to propose candidate
             techniques for rules the keyword mapper left unmapped.

    The provider is NVIDIA's OpenAI-compatible endpoint
    (https://integrate.api.nvidia.com/v1/chat/completions) and the model is
    nvidia/nemotron-3-ultra-550b-a55b. The key is read from the NVIDIA_API_KEY
    environment variable; it is never stored in this script.

    NVIDIA meters per key rather than per model, so the script paces itself at
    one request every 1.7s (40/min) and reports its request budget before
    starting. One pinned model means every rule in a run is answered by the
    same model, so no routing caveat is needed in the write-up.

.EXAMPLE
    # Step 1 - confirm the key, endpoint and model work (uses 1 request).
    .\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip -PreflightOnly

.EXAMPLE
    # Step 2 - small real test: Stage 4 on 5 mapped rules (1 request).
    .\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
        -EnableMappedValidation -MappedValidationMaxRules 5 `
        -MappedValidationBatchSize 5 -Output stage4_nvidia_test

.EXAMPLE
    # Step 3 - small real test: Stage 5 on 5 unmapped rules (1 request).
    .\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
        -EnableLlm -LlmTarget unmapped -LlmMaxRules 5 -LlmBatchSize 5 `
        -Output stage5_nvidia_test

.EXAMPLE
    # Full run - only after both small tests above have succeeded.
    .\run_keyword_llm_analysis.ps1 -Source .\snort3-community-rules.zip `
        -EnableMappedValidation -EnableLlm -LlmTarget unmapped -LlmBatchSize 25
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Source,

    [string]$Output = "all_categories_output",
    [string]$AttackData = "data/enterprise-attack.json",

    # Shared provider settings. NVIDIA's OpenAI-compatible endpoint with
    # Nemotron 3 Ultra. An NVIDIA key (nvapi-...) found with a non-NVIDIA
    # endpoint is redirected automatically, and a bare model ID gets the
    # required 'nvidia/' vendor prefix.
    [string]$Endpoint = "https://integrate.api.nvidia.com/v1/chat/completions",
    [string]$Model = "nvidia/nemotron-3-ultra-550b-a55b",
    [string]$ApiKeyEnvironmentVariable = "NVIDIA_API_KEY",

    # Server-side model routing is an OpenRouter extension and is not sent to
    # NVIDIA, so this stays empty: the run is pinned to exactly one model and
    # every rule is answered by it. The responding model is still recorded per
    # rule in the output as an audit trail.
    [string]$ModelFallbacks = "",

    # Stage 5: LLM classification of rules.
    [switch]$EnableLlm,
    [ValidateSet("all", "mapped", "unmapped")]
    [string]$LlmTarget = "unmapped",
    [int]$LlmMaxRules = 0,
    [int]$LlmBatchSize = 25,

    # Stage 4: independent LLM validation of already mapped rules.
    # Batch size 25 keeps all 430 mapped rules to ~18 requests.
    [switch]$EnableMappedValidation,
    [int]$MappedValidationMaxRules = 0,
    [int]$MappedValidationBatchSize = 25,

    # Free-tier pacing and cost control.
    [double]$RequestDelay = -1,        # -1 = pick automatically from the model tier
    [int]$MaxRequests = 0,             # 0 = no ceiling
    [ValidateSet("none", "low", "medium", "high")]
    [string]$ReasoningEffort = "low",

    # Diagnostics.
    [switch]$PreflightOnly,
    [switch]$SkipPreflight,
    [switch]$NoCache,
    [switch]$DebugResponses,
    [int]$Timeout = 180,
    [int]$Retries = 4
)

$ErrorActionPreference = "Stop"

function Assert-ApiKey {
    $key = [Environment]::GetEnvironmentVariable($ApiKeyEnvironmentVariable)
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw "The API key environment variable '$ApiKeyEnvironmentVariable' is not set. " +
              "Set it first, for example: `$env:$ApiKeyEnvironmentVariable = 'nvapi-...'"
    }
    return $key
}

$shared = @(
    "--llm-request-delay", $RequestDelay,
    "--llm-max-requests", $MaxRequests,
    "--llm-reasoning-effort", $ReasoningEffort
)

# PowerShell drops empty strings when splatting an array to a native command, so
# passing "" here would hand argparse a bare flag with no value. The chain is
# empty by default on NVIDIA (one pinned model), so omit the flag entirely
# rather than trying to forward an empty argument.
if (-not [string]::IsNullOrWhiteSpace($ModelFallbacks)) {
    $shared += @("--llm-model-fallbacks", $ModelFallbacks)
}

# --- Preflight only: verify credentials and model, then stop -----------------
if ($PreflightOnly) {
    Assert-ApiKey | Out-Null
    $preflightArgs = @(
        ".\snort_rule_analyzer.py", $Source,
        "--llm-preflight-only",
        "--llm-model", $Model,
        "--llm-endpoint", $Endpoint,
        "--llm-api-key-env", $ApiKeyEnvironmentVariable,
        "--llm-timeout", $Timeout
    ) + $shared
    python @preflightArgs
    exit $LASTEXITCODE
}

# --- Stages 1-3: always run, fully offline ----------------------------------
# These arguments alone produce the keyword baseline - parsing, ATT&CK mapping,
# aggregation and every non-LLM artefact. No API key is required to get here.
$arguments = @(
    ".\snort_rule_analyzer.py",
    $Source,
    "--all-categories",
    "--output", $Output,
    "--attack-data", $AttackData
) + $shared

# --- Stage 5: LLM classification of keyword-UNMAPPED rules ------------------
# Opt-in via -EnableLlm. -LlmTarget unmapped restricts the cohort to rules the
# keyword mapper did not cover; -LlmMaxRules caps the count AFTER that filter.
# Produces llm_classification_results.csv and the llm_candidate rows of
# unmapped_rule_candidates.csv.
if ($EnableLlm) {
    Assert-ApiKey | Out-Null
    $arguments += @(
        "--llm-enable",
        "--llm-model", $Model,
        "--llm-endpoint", $Endpoint,
        "--llm-api-key-env", $ApiKeyEnvironmentVariable,
        "--llm-target", $LlmTarget,
        "--llm-max-rules", $LlmMaxRules,
        "--llm-batch-size", $LlmBatchSize,
        "--llm-timeout", $Timeout,
        "--llm-retries", $Retries
    )
}

# --- Stage 4: LLM validation of rules the keyword mapper ALREADY mapped -----
# Opt-in via -EnableMappedValidation. Independent reproduction test: the model
# never sees the existing mapping and never overwrites it. Produces
# mapped_rule_llm_validation.csv/.svg. Disjoint from the Stage 5 cohort.
if ($EnableMappedValidation) {
    Assert-ApiKey | Out-Null
    $arguments += @(
        "--mapped-validation-enable",
        "--mapped-validation-model", $Model,
        "--mapped-validation-endpoint", $Endpoint,
        "--mapped-validation-api-key-env", $ApiKeyEnvironmentVariable,
        "--mapped-validation-max-rules", $MappedValidationMaxRules,
        "--mapped-validation-batch-size", $MappedValidationBatchSize,
        "--mapped-validation-timeout", $Timeout,
        "--mapped-validation-retries", $Retries
    )
}

# Diagnostics. -NoCache forces fresh provider calls (a cached run costs no
# requests and reproduces identical results); -DebugResponses appends every raw
# response to <output>\llm_debug.jsonl; -SkipPreflight omits the one-request
# liveness check before each stage.
if ($NoCache)        { $arguments += "--llm-no-cache" }
if ($DebugResponses) { $arguments += "--llm-debug" }
if ($SkipPreflight)  { $arguments += "--llm-skip-preflight" }

python @arguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Outputs are in $Output." -ForegroundColor Green
if ($EnableMappedValidation) {
    Write-Host "  Stage 4: mapped_rule_llm_validation.csv / .svg"
}
if ($EnableLlm) {
    Write-Host "  Stage 5: llm_classification_results.csv, unmapped_rule_candidates.csv"
    Write-Host "           keyword_llm_classification_comparison.csv"
}
Write-Host "  Metrics: research_metrics.json, report.md"
