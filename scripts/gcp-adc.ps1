# Local development helper. Run on the machine hosting Docker.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z][a-z0-9-]{4,28}[a-z0-9]$')]
    [string]$ProjectId,
    [ValidateSet('Setup', 'Start', 'Check')]
    [string]$Action = 'Setup'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed (exit $LASTEXITCODE). Stop and resolve the error before continuing."
    }
}

if (-not $env:APPDATA) {
    throw 'This helper supports Windows. See docs/integration/GCP_ADC_SETUP_KO.md for Linux/macOS.'
}

# Respect the Cloud SDK configuration directory when explicitly configured.
$configDir = if ($env:CLOUDSDK_CONFIG) { $env:CLOUDSDK_CONFIG } else { Join-Path $env:APPDATA 'gcloud' }
$adcPath = Join-Path $configDir 'application_default_credentials.json'

if ($Action -eq 'Setup') {
    $gcloud = Get-Command gcloud -ErrorAction SilentlyContinue
    if (-not $gcloud) {
        throw 'Install Google Cloud CLI first: https://cloud.google.com/sdk/docs/install'
    }
    Invoke-Checked -Program $gcloud.Source -Arguments @('auth', 'application-default', 'login')
    Invoke-Checked -Program $gcloud.Source -Arguments @('auth', 'application-default', 'set-quota-project', $ProjectId)
}

if (-not (Test-Path -LiteralPath $adcPath -PathType Leaf)) {
    throw 'ADC file not found. Run this script with -Action Setup on the Docker host first.'
}
$env:GCP_ADC_FILE = (Resolve-Path -LiteralPath $adcPath).Path
$env:GCP_QUOTA_PROJECT = $ProjectId

if ($Action -eq 'Setup') {
    Write-Host 'ADC file configured. This does not verify project IAM permissions or deploy the worker.'
    Write-Host "Next: .\scripts\gcp-adc.ps1 -ProjectId $ProjectId -Action Start"
    return
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw 'Install and start Docker Desktop first.' }
$composeArgs = @('compose', '-f', 'docker-compose.yml', '-f', 'deploy/compose/gcp.yml')
Push-Location $repoRoot
try {
    if ($Action -eq 'Start') {
        Invoke-Checked -Program $docker.Source -Arguments ($composeArgs + @('up', '-d', '--build', 'api', 'worker', 'web'))
    } else {
        Invoke-Checked -Program $docker.Source -Arguments ($composeArgs + @(
            'exec', '-T', 'worker', 'python', '-c',
            "from cremore.gcp_auth import adc_token; adc_token()(); print('ADC authentication succeeded')"
        ))
        Write-Host 'Token acquisition succeeded. Resource-level IAM permissions still require a project access check.'
    }
} finally {
    Pop-Location
}
