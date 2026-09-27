<#
.SYNOPSIS
    Gated NVIDIA verification trail for the Snort-to-ATT&CK pipeline.

.DESCRIPTION
    Runs the checks in dependency order and STOPS at the first failure, so the
    full 430 + 3,587 run can never start on an unverified configuration:

      Gate 1  Preflight            1 request
      Gate 2  Live preflight test  1 request
      Gate 3  Stage 4, 5 rules     1 request  -> stage4_live_test\
      Gate 4  Stage 5, 5 rules     1 request  -> stage5_live_test\
      Full    Stage 4 + Stage 5    ~162 requests -> all_categories_output\

    The full run is skipped unless -Full is passed, and is refused if any gate
    failed. Gates 3 and 4 are cached per output folder, so re-running this
    script costs nothing for work already done.

    The API key is read from NVIDIA_API_KEY and is never written to disk.

.EXAMPLE
    # Gates only. Start here.
    $env:NVIDIA_API_KEY = "nvapi-..."
    .\run_nvidia_verification.ps1

.EXAMPLE
    # Gates, then the full run if all four pass.
    .\run_nvidia_verification.ps1 -Full
#>
param(
    [string]$Source = ".\snort3-community-rules.zip",
    [switch]$Full,
    [int]$Timeout = 300
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($env:NVIDIA_API_KEY)) {
    Write-Host "NVIDIA_API_KEY is not set. Run this first:" -ForegroundColor Red
    Write-Host '    $env:NVIDIA_API_KEY = "nvapi-..."' -ForegroundColor Yellow
    exit 2
}
if (-not $env:NVIDIA_API_KEY.StartsWith("nvapi-")) {
    Write-Host "Warning: NVIDIA_API_KEY does not start with 'nvapi-'." -ForegroundColor Yellow
}
if (-not (Test-Path $Source)) {
    Write-Host "Source ruleset not found: $Source" -ForegroundColor Red
    exit 2
}

$script:failed = $null

function Invoke-Gate {
    param([string]$Name, [scriptblock]$Action)

    if ($script:failed) {
        Write-Host "SKIP  $Name (blocked by: $($script:failed))" -ForegroundColor DarkGray
        return
    }
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE -ne 0) {
        $script:failed = $Name
        Write-Host "FAIL  $Name (exit $LASTEXITCODE)" -ForegroundColor Red
    }
    else {
        Write-Host "PASS  $Name" -ForegroundColor Green
    }
}

Invoke-Gate "Gate 1: preflight" {
    .\run_keyword_llm_analysis.ps1 -Source $Source -PreflightOnly -Timeout $Timeout
}

Invoke-Gate "Gate 2: live preflight test (one real request)" {
    python -m unittest test_nvidia_preflight -v
}

Invoke-Gate "Gate 3: Stage 4 on 5 mapped rules" {
    .\run_keyword_llm_analysis.ps1 -Source $Source `
        -EnableMappedValidation -MappedValidationMaxRules 5 `
        -MappedValidationBatchSize 5 -Output stage4_live_test -Timeout $Timeout
}

Invoke-Gate "Gate 4: Stage 5 on 5 unmapped rules" {
    .\run_keyword_llm_analysis.ps1 -Source $Source `
        -EnableLlm -LlmTarget unmapped -LlmMaxRules 5 -LlmBatchSize 5 `
        -Output stage5_live_test -Timeout $Timeout
}

# --- Per-gate evidence -------------------------------------------------------
Write-Host ""
Write-Host "=== Model recorded per rule ===" -ForegroundColor Cyan
foreach ($pair in @(
    @{ Folder = "stage4_live_test"; File = "mapped_rule_llm_validation.csv"; Column = "Model" },
    @{ Folder = "stage5_live_test"; File = "llm_classification_results.csv"; Column = "llm_model" }
)) {
    $path = Join-Path $pair.Folder $pair.File
    if (Test-Path $path) {
        $counts = Import-Csv $path |
            Where-Object { $_.($pair.Column) } |
            Group-Object -Property $pair.Column |
            ForEach-Object { "$($_.Name) x$($_.Count)" }
        if ($counts) { Write-Host "  $path : $($counts -join ', ')" }
        else { Write-Host "  $path : no model recorded" -ForegroundColor Yellow }
    }
    else {
        Write-Host "  $path : not produced" -ForegroundColor DarkGray
    }
}

# --- Full run ----------------------------------------------------------------
Write-Host ""
if ($script:failed) {
    Write-Host "Gates failed at '$($script:failed)'. Full run refused." -ForegroundColor Red
    Write-Host "Fix the cause above and re-run; passed gates are cached and cost nothing." -ForegroundColor Yellow
    exit 1
}

Write-Host "All four gates passed." -ForegroundColor Green

if (-not $Full) {
    Write-Host ""
    Write-Host "Full run not started (-Full was not passed). When ready:" -ForegroundColor Yellow
    Write-Host "    .\run_nvidia_verification.ps1 -Full" -ForegroundColor Yellow
    Write-Host "This overwrites all_categories_output\, which currently holds a FAILED" -ForegroundColor Yellow
    Write-Host "OpenRouter run (430 validation_error rows, Stage 5 never run)." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "==> Full run: Stage 4 (430 mapped) + Stage 5 (3,587 unmapped), ~162 requests" -ForegroundColor Cyan
Write-Host "    Overwriting all_categories_output\ ..." -ForegroundColor DarkGray
.\run_keyword_llm_analysis.ps1 -Source $Source `
    -EnableMappedValidation -EnableLlm -LlmTarget unmapped -LlmBatchSize 25 `
    -Timeout $Timeout

if ($LASTEXITCODE -ne 0) {
    Write-Host "Full run failed (exit $LASTEXITCODE). Completed batches are cached;" -ForegroundColor Red
    Write-Host "re-run to resume rather than restart." -ForegroundColor Yellow
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Full run complete. Verify the provider actually changed:" -ForegroundColor Green
$metrics = "all_categories_output\research_metrics.json"
if (Test-Path $metrics) {
    $m = Get-Content $metrics -Raw | ConvertFrom-Json
    $m.mapped_rule_llm_validation_configuration | Format-List endpoint, model, api_key_env
    Write-Host "Agreement counts:" -ForegroundColor Cyan
    $m.mapped_rule_llm_validation.agreement_counts | Format-List
}
