$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-NessusAudit.ps1'
$source = Get-Content -LiteralPath $runnerPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $source,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -gt 0) {
    throw ($parseErrors.Message -join [Environment]::NewLine)
}

foreach ($functionAst in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)) {
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

function Assert-Equal {
    param(
        $Actual,
        $Expected,
        [Parameter(Mandatory)][string]$Message
    )
    if ($Actual -ne $Expected) {
        throw "$Message Expected <$Expected>, got <$Actual>."
    }
}

$orAlternatives = Split-AuditOrExpression '"Success" || "Success and Failure"'
Assert-Equal $orAlternatives.Count 2 'OR expressions must remain separate alternatives.'
Assert-Equal $orAlternatives[0].Count 1 'The first OR alternative must contain one item.'

$andAlternatives = Split-AuditOrExpression '"LOCAL SERVICE" && "NETWORK SERVICE"'
Assert-Equal $andAlternatives.Count 1 'AND expressions must remain one alternative.'
Assert-Equal $andAlternatives[0].Count 2 'An AND alternative must retain all required items.'

$legacyEncoded = 'IlN1Y2Nlc3MiIHx8ICJTdWNjZXNzIGFuZCBGYWlsdXJlIg=='
$legacyAlternatives = @(ConvertFrom-EncodedAlternatives $legacyEncoded)
Assert-Equal $legacyAlternatives.Count 2 'Legacy OR expressions must decode as separate alternatives.'

$auditFields = @{
    type = 'AUDIT_POLICY_SUBCATEGORY'
    description = "6.7 Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
    value_data = '"Success" || "Success and Failure"'
    audit_policy_subcategory = 'Authentication Policy Change'
}
$auditCheck = Convert-AuditFieldsToCheck -Fields $auditFields -Variables @{} -Index 1
$auditAlternatives = @(ConvertFrom-EncodedAlternatives $auditCheck.ExpectedData)
Assert-Equal $auditAlternatives.Count 2 'Audit policy OR values must serialize as separate alternatives.'

$rightFields = @{
    type = 'USER_RIGHTS_POLICY'
    description = "90.32 Ensure 'Replace Process Level Token' is set correctly"
    value_data = '"LOCAL SERVICE" && "NETWORK SERVICE"'
    right_type = 'SeAssignPrimaryTokenPrivilege'
}
$rightCheck = Convert-AuditFieldsToCheck -Fields $rightFields -Variables @{} -Index 2
$rightAlternatives = @(ConvertFrom-EncodedAlternatives $rightCheck.ExpectedData)
Assert-Equal $rightAlternatives.Count 1 'User-right AND values must serialize as one alternative.'
Assert-Equal $rightAlternatives[0].Items.Count 2 'User-right AND values must retain both principals.'

$servicePrincipals = ConvertTo-EncodedAlternatives (
    Split-AuditOrExpression '"LOCAL SERVICE" && "NETWORK SERVICE" && "PrintSpoolerService"'
)
$principalMatch = Test-PrincipalAlternatives `
    -ActualRaw 'NT AUTHORITY\LOCAL SERVICE,NT AUTHORITY\NETWORK SERVICE,RESTRICTED SERVICES\PrintSpoolerService' `
    -EncodedAlternatives $servicePrincipals `
    -Operator 'ExactAlternatives'
Assert-Equal $principalMatch $true 'Service principal namespaces must normalize consistently.'

$serviceFields = @{
    type = 'SERVICE_POLICY'
    description = "82.5 Ensure 'GameInput Service' is set to 'Disabled'"
    service_name = 'GameInputSvc'
    value_data = 'Disabled'
}
$serviceCheck = Convert-AuditFieldsToCheck -Fields $serviceFields -Variables @{} -Index 3
Assert-Equal $serviceCheck.Method 'Service' 'SERVICE_POLICY must produce an executable service check.'
Assert-Equal $serviceCheck.Operator 'DisabledOrNotInstalled' 'Disabled services may also be absent.'

Write-Output 'All Invoke-NessusAudit regression tests passed.'
