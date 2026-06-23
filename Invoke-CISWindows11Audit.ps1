[CmdletBinding()]
param(
    [string]$ChecksPath = (Join-Path $PSScriptRoot 'cis_win11_v5.0.1_L1_checks.csv'),
    [string]$OutputPath = ''
)

$runner = Join-Path $PSScriptRoot 'Invoke-NessusAudit.ps1'
$params = @{ ChecksPath = $ChecksPath }
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $params.OutputPath = $OutputPath
}

& $runner @params
exit $LASTEXITCODE
