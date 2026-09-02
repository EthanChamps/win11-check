[CmdletBinding()]
param(
    [string]$ChecksPath = '',
    [string]$AuditPath = '',
    [string]$OutputPath = ''
)

$runner = Join-Path $PSScriptRoot 'Invoke-NessusAudit.ps1'
$params = @{}
if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
    $params.AuditPath = $AuditPath
} elseif (-not [string]::IsNullOrWhiteSpace($ChecksPath)) {
    $params.ChecksPath = $ChecksPath
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $params.OutputPath = $OutputPath
}

& $runner @params
exit $LASTEXITCODE
