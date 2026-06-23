[CmdletBinding()]
param(
    [string]$ChecksPath = (Join-Path $PSScriptRoot 'cis_win11_v5.0.1_L1_checks.csv'),
    [string]$OutputPath = (Join-Path $PSScriptRoot ("cis_win11_v5.0.1_L1_results_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SecurityPolicy = $null
$script:AuditPolicy = $null

function ConvertTo-RegistryProviderPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^HKLM\\(.+)$') { return "Registry::HKEY_LOCAL_MACHINE\$($Matches[1])" }
    if ($Path -match '^HKCU\\(.+)$') { return "Registry::HKEY_CURRENT_USER\$($Matches[1])" }
    if ($Path -match '^HKU\\(.+)$') { return "Registry::HKEY_USERS\$($Matches[1])" }
    if ($Path -match '^HKEY_LOCAL_MACHINE\\(.+)$') { return "Registry::HKEY_LOCAL_MACHINE\$($Matches[1])" }
    if ($Path -match '^HKEY_CURRENT_USER\\(.+)$') { return "Registry::HKEY_CURRENT_USER\$($Matches[1])" }
    if ($Path -match '^HKEY_USERS\\(.+)$') { return "Registry::HKEY_USERS\$($Matches[1])" }
    return $Path
}

function Expand-RegistryTargetPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '^HKU\\\[USER SID\]\\(.+)$') {
        $suffix = $Matches[1]
        $hives = Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
        if ($hives.Count -eq 0) {
            throw 'No loaded HKEY_USERS user SID hives were available for HKU\[USER SID] policy checks.'
        }
        return @($hives | ForEach-Object { "HKU\$($_.PSChildName)\$suffix" })
    }
    if ($Path -match '^HKU\\(.+)$' -and $Matches[1] -notmatch '^S-\d-\d+') {
        $suffix = $Matches[1]
        $hives = Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
        if ($hives.Count -eq 0) {
            throw 'No loaded HKEY_USERS user SID hives were available for HKU user policy checks.'
        }
        return @($hives | ForEach-Object { "HKU\$($_.PSChildName)\$suffix" })
    }
    return @($Path)
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return '<not found>' }
    if ($Value -is [array]) { return (($Value | ForEach-Object { [string]$_ }) -join '; ') }
    return [string]$Value
}

function ConvertTo-Number {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    $lower = $text.ToLowerInvariant()
    switch ($lower) {
        'enabled' { return 1 }
        'enable' { return 1 }
        'yes' { return 1 }
        'on' { return 1 }
        'true' { return 1 }
        'disabled' { return 0 }
        'disable' { return 0 }
        'no' { return 0 }
        'off' { return 0 }
        'false' { return 0 }
    }
    $normalized = $text -replace ',', ''
    if ($normalized -match '^0x[0-9a-fA-F]+$') { return [Convert]::ToInt64($normalized, 16) }
    $number = 0L
    if ([Int64]::TryParse($normalized, [ref]$number)) { return $number }
    if ($normalized -match '(0x[0-9a-fA-F]+|\d+)') {
        $matchText = $Matches[1]
        if ($matchText -match '^0x') { return [Convert]::ToInt64($matchText, 16) }
        return [Convert]::ToInt64($matchText)
    }
    return $null
}

function ConvertTo-BooleanText {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim().ToLowerInvariant()
    switch ($text) {
        'enabled' { return 'true' }
        'enable' { return 'true' }
        'yes' { return 'true' }
        'on' { return 'true' }
        'true' { return 'true' }
        '1' { return 'true' }
        'disabled' { return 'false' }
        'disable' { return 'false' }
        'no' { return 'false' }
        'off' { return 'false' }
        'false' { return 'false' }
        '0' { return 'false' }
        default { return $null }
    }
}

function ConvertFrom-EncodedAlternatives {
    param([string]$Encoded)
    $alternatives = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Encoded)) { return @() }

    foreach ($altText in ($Encoded -split ';')) {
        if ([string]::IsNullOrWhiteSpace($altText)) { continue }
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($itemText in ($altText -split ',')) {
            if ($itemText -eq '~') {
                $items.Add('')
                continue
            }
            if ([string]::IsNullOrWhiteSpace($itemText)) { continue }
            $items.Add([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($itemText)))
        }
        $alternatives.Add([pscustomobject]@{ Items = [string[]]$items.ToArray() })
    }

    return @($alternatives.ToArray())
}

function Test-RangeExpression {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$Expected
    )

    $actualNumber = ConvertTo-Number $Actual
    if ($null -eq $actualNumber) { return $false }

    $range = $Expected.Trim()
    if ($range -match '^\[(MIN|\d+)\.\.(MAX|\d+)\]$') {
        $minText = $Matches[1]
        $maxText = $Matches[2]
    } elseif ($range -match '^(MIN|\d+)\.\.(MAX|\d+)$') {
        $minText = $Matches[1]
        $maxText = $Matches[2]
    } else {
        return $false
    }

    if ($minText -ne 'MIN' -and $actualNumber -lt [int64]$minText) { return $false }
    if ($maxText -ne 'MAX' -and $actualNumber -gt [int64]$maxText) { return $false }
    return $true
}

function ConvertTo-ComparableSet {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [array]) {
        return @($Value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    }
    return @(([string]$Value).Trim())
}

function Test-StringAlternatives {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$EncodedAlternatives,
        [switch]$Contains
    )

    $actualSet = @(ConvertTo-ComparableSet $Actual)
    $alternatives = ConvertFrom-EncodedAlternatives $EncodedAlternatives
    foreach ($alternative in $alternatives) {
        $expectedSet = @($alternative.Items | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
        $matched = $true
        foreach ($expected in $expectedSet) {
            if (-not ($actualSet | Where-Object { $_ -ieq $expected })) {
                $matched = $false
                break
            }
        }
        if ($matched -and (-not $Contains) -and $actualSet.Count -ne $expectedSet.Count) {
            $matched = $false
        }
        if ($matched) { return $true }
    }
    return $false
}

function Test-ScalarValue {
    param(
        $Actual,
        [Parameter(Mandatory)][string]$Operator,
        [string]$Expected,
        [string]$ExpectedData = ''
    )

    $actualNumber = ConvertTo-Number $Actual
    $expectedText = if (-not [string]::IsNullOrWhiteSpace($ExpectedData)) { $ExpectedData.Trim() } elseif ($null -eq $Expected) { '' } else { $Expected.Trim() }

    switch ($Operator) {
        'Equals' {
            $actualBool = ConvertTo-BooleanText $Actual
            $expectedBool = ConvertTo-BooleanText $expectedText
            if ($null -ne $actualBool -and $null -ne $expectedBool) {
                return ($actualBool -eq $expectedBool)
            }
            $expectedNumber = ConvertTo-Number $expectedText
            if ($null -ne $actualNumber -and $null -ne $expectedNumber -and $expectedText -match '^(0x[0-9a-fA-F]+|\d+)$') {
                return ($actualNumber -eq $expectedNumber)
            }
            return (([string]$Actual).Trim() -ieq $expectedText)
        }
        'EqualsNumber' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -eq $expectedNumber)
        }
        'Min' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -ge $expectedNumber)
        }
        'Max' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -le $expectedNumber)
        }
        'NonZeroMax' {
            $expectedNumber = ConvertTo-Number $expectedText
            return ($null -ne $actualNumber -and $null -ne $expectedNumber -and $actualNumber -ne 0 -and $actualNumber -le $expectedNumber)
        }
        'Range' {
            return Test-RangeExpression -Actual $Actual -Expected $expectedText
        }
        'In' {
            return Test-StringAlternatives -Actual $Actual -EncodedAlternatives $expectedText
        }
        'ContainsAlternatives' {
            return Test-StringAlternatives -Actual $Actual -EncodedAlternatives $expectedText -Contains
        }
        'Regex' {
            if ($null -eq $Actual) { return $false }
            return ([string]$Actual -match $expectedText)
        }
        'NotRegex' {
            if ($null -eq $Actual) { return $true }
            return -not ([string]$Actual -match $expectedText)
        }
        'NotEqual' {
            return -not (([string]$Actual).Trim() -ieq $expectedText)
        }
        'NonEmpty' {
            if ($null -eq $Actual) { return $false }
            if ($Actual -is [array]) { return $Actual.Count -gt 0 }
            return -not [string]::IsNullOrWhiteSpace([string]$Actual)
        }
        'Blank' {
            if ($null -eq $Actual) { return $true }
            if ($Actual -is [array]) { return $Actual.Count -eq 0 }
            return [string]::IsNullOrWhiteSpace([string]$Actual)
        }
        'NotExists' {
            return ($null -eq $Actual)
        }
        default {
            $actualBool = ConvertTo-BooleanText $Actual
            $expectedBool = ConvertTo-BooleanText $expectedText
            if ($null -ne $actualBool -and $null -ne $expectedBool) {
                return ($actualBool -eq $expectedBool)
            }
            return (([string]$Actual).Trim() -ieq $expectedText)
        }
    }
}

function Normalize-Principal {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $name = $Value.Trim()
    $name = $name -replace '^\*', ''

    if ($name -match '^S-\d-\d+') {
        try {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($name)
            $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $name.ToUpperInvariant()
        }
    }

    $name = $name -replace '^BUILTIN\\', ''
    $name = $name -replace '^NT AUTHORITY\\', ''
    return $name.ToUpperInvariant()
}

function Get-SecurityPolicy {
    if ($null -ne $script:SecurityPolicy) { return $script:SecurityPolicy }

    $tempFile = Join-Path $env:TEMP ("cis-secpol-{0}.inf" -f ([guid]::NewGuid()))
    try {
        $null = & secedit.exe /export /cfg $tempFile 2>$null
        $policy = @{}
        foreach ($line in Get-Content -LiteralPath $tempFile -Encoding Unicode) {
            if ($line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') {
                $policy[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $script:SecurityPolicy = $policy
        return $script:SecurityPolicy
    } finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-AuditPolicy {
    if ($null -ne $script:AuditPolicy) { return $script:AuditPolicy }
    $rows = & auditpol.exe /get /subcategory:* /r 2>$null | ConvertFrom-Csv
    $map = @{}
    foreach ($row in $rows) {
        $guid = $row.'Subcategory GUID'
        if (-not [string]::IsNullOrWhiteSpace($guid)) {
            $map[$guid.Trim('{}').ToLowerInvariant()] = $row
        }
        $subcategory = $row.Subcategory
        if (-not [string]::IsNullOrWhiteSpace($subcategory)) {
            $map[$subcategory.Trim().ToLowerInvariant()] = $row
        }
    }
    $script:AuditPolicy = $map
    return $script:AuditPolicy
}

function Test-PrincipalAlternatives {
    param(
        [string]$ActualRaw,
        [string]$EncodedAlternatives,
        [string]$Operator
    )

    $actual = @()
    if (-not [string]::IsNullOrWhiteSpace($ActualRaw)) {
        $actual = @($ActualRaw -split ',' | ForEach-Object { Normalize-Principal $_ } | Where-Object { $_ })
    }

    $alternatives = ConvertFrom-EncodedAlternatives $EncodedAlternatives
    foreach ($alternative in $alternatives) {
        $expected = @($alternative.Items | ForEach-Object { Normalize-Principal $_ } | Where-Object { $_ })
        $matched = $true
        foreach ($item in $expected) {
            if ($actual -notcontains $item) {
                $matched = $false
                break
            }
        }
        if ($matched -and $Operator -eq 'ExactAlternatives' -and $actual.Count -ne $expected.Count) {
            $matched = $false
        }
        if ($matched) {
            return $true
        }
    }
    return $false
}

function Test-RegistryCheck {
    param($Check)
    $targets = $Check.TargetsJson | ConvertFrom-Json
    $actualParts = New-Object System.Collections.Generic.List[string]
    $allPass = $true

    foreach ($target in @($targets)) {
        foreach ($expandedPath in (Expand-RegistryTargetPath $target.Path)) {
            $providerPath = ConvertTo-RegistryProviderPath $expandedPath
            $actual = $null
            $found = $true
            try {
                $actual = Get-ItemPropertyValue -LiteralPath $providerPath -Name $target.Name -ErrorAction Stop
            } catch {
                $found = $false
                $actual = $null
            }

            $actualParts.Add(("{0}:{1}={2}" -f $expandedPath, $target.Name, (Format-Value $actual)))

            if ($target.RegOption -eq 'MUST_NOT_EXIST' -or $target.Operator -eq 'NotExists') {
                if ($found) { $allPass = $false }
                continue
            }

            if (-not $found) {
                if ($target.RegOption -eq 'CAN_BE_NULL') {
                    continue
                }
                $allPass = $false
                continue
            }

            $expectedData = if ($null -ne $target.ExpectedData) { [string]$target.ExpectedData } else { '' }
            if (-not (Test-ScalarValue -Actual $actual -Operator $target.Operator -Expected $target.Expected -ExpectedData $expectedData)) {
                $allPass = $false
            }
        }
    }

    return [pscustomobject]@{
        Actual = ($actualParts -join ' | ')
        Pass = $allPass
    }
}

function Test-AccountPolicyCheck {
    param($Check)
    $policy = Get-SecurityPolicy
    $actual = if ($policy.ContainsKey($Check.Target)) { $policy[$Check.Target] } else { $null }
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = (Format-Value $actual); Pass = $pass }
}

function Test-UserRightCheck {
    param($Check)
    $policy = Get-SecurityPolicy
    $actual = if ($policy.ContainsKey($Check.Target)) { $policy[$Check.Target] } else { '' }
    $pass = Test-PrincipalAlternatives -ActualRaw $actual -EncodedAlternatives $Check.ExpectedData -Operator $Check.Operator
    $display = if ([string]::IsNullOrWhiteSpace($actual)) { 'No One' } else { (($actual -split ',' | ForEach-Object { Normalize-Principal $_ }) -join '; ') }
    return [pscustomobject]@{ Actual = $display; Pass = $pass }
}

function ConvertTo-AuditSettingTokens {
    param([string]$Value)
    $tokens = @()
    if ($Value -match 'Success') { $tokens += 'Success' }
    if ($Value -match 'Failure') { $tokens += 'Failure' }
    return @($tokens)
}

function Test-AuditPolicyCheck {
    param($Check)
    $audit = Get-AuditPolicy
    $key = $Check.Target.Trim('{}').ToLowerInvariant()
    if (-not $audit.ContainsKey($key)) {
        return [pscustomobject]@{ Actual = '<not found>'; Pass = $false }
    }
    $actual = $audit[$key].'Inclusion Setting'
    $actualTokens = @(ConvertTo-AuditSettingTokens $actual)
    $alternatives = ConvertFrom-EncodedAlternatives $Check.ExpectedData
    $pass = $false
    foreach ($alternative in $alternatives) {
        $expectedTokens = @()
        foreach ($item in $alternative.Items) {
            $expectedTokens += ConvertTo-AuditSettingTokens $item
        }
        $expectedTokens = @($expectedTokens | Select-Object -Unique)
        $matched = $true
        foreach ($token in $expectedTokens) {
            if ($actualTokens -notcontains $token) {
                $matched = $false
                break
            }
        }
        if ($matched -and $actualTokens.Count -eq $expectedTokens.Count) {
            $pass = $true
            break
        }
    }
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Test-ServiceCheck {
    param($Check)
    $name = $Check.Target
    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($name -replace "'", "''")) -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $pass = $Check.Operator -in @('DisabledOrNotInstalled', 'NotInstalled')
        return [pscustomobject]@{ Actual = 'Not Installed'; Pass = $pass }
    }
    $actual = $service.StartMode
    $pass = if ($Check.Operator -eq 'DisabledOrNotInstalled') { $actual -eq 'Disabled' } else { $actual -eq $Check.Expected }
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Test-FirewallCheck {
    param($Check)
    $parts = $Check.Target -split ':', 2
    $profileName = $parts[0]
    $propertyName = $parts[1]
    $profile = Get-NetFirewallProfile -Profile $profileName -ErrorAction Stop
    $actual = $profile.$propertyName
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected
    return [pscustomobject]@{ Actual = (Format-Value $actual); Pass = $pass }
}

function Test-LocalAccountCheck {
    param($Check)
    $suffix = if ($Check.Target -eq 'ADMINISTRATOR_ACCOUNT') { '-500' } else { '-501' }
    $account = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' |
        Where-Object { $_.SID.EndsWith($suffix) } |
        Select-Object -First 1

    if ($null -eq $account) {
        return [pscustomobject]@{ Actual = '<not found>'; Pass = $false }
    }

    if ($Check.Operator -eq 'Disabled') {
        return [pscustomobject]@{ Actual = ("{0}; Disabled={1}" -f $account.Name, $account.Disabled); Pass = [bool]$account.Disabled }
    }

    $pass = Test-ScalarValue -Actual $account.Name -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = $account.Name; Pass = $pass }
}

function Invoke-CISCheck {
    param($Check)
    switch ($Check.Method) {
        'Registry' { return Test-RegistryCheck $Check }
        'AccountPolicy' { return Test-AccountPolicyCheck $Check }
        'UserRight' { return Test-UserRightCheck $Check }
        'AuditPolicy' { return Test-AuditPolicyCheck $Check }
        'Service' { return Test-ServiceCheck $Check }
        'Firewall' { return Test-FirewallCheck $Check }
        'LocalAccount' { return Test-LocalAccountCheck $Check }
        default {
            return [pscustomobject]@{
                Actual = if ([string]::IsNullOrWhiteSpace($Check.ManualReason)) { 'Manual review required' } else { $Check.ManualReason }
                Pass = $null
            }
        }
    }
}

if (-not (Test-Path -LiteralPath $ChecksPath)) {
    throw "Checks file not found: $ChecksPath"
}

$checks = Import-Csv -LiteralPath $ChecksPath
$results = foreach ($check in $checks) {
    $checkName = "{0} {1}" -f $check.Id, $check.Title

    if ($check.Method -eq 'Manual') {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = if ([string]::IsNullOrWhiteSpace($check.ManualReason)) { 'Manual review required' } else { $check.ManualReason }
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
        continue
    }

    try {
        $result = Invoke-CISCheck $check
        $status = if ($null -eq $result.Pass) { 'Manual' } elseif ($result.Pass) { 'Pass' } else { 'Fail' }
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = $result.Actual
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = $status
        }
    } catch {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = "Error: $($_.Exception.Message)"
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
    }
}

$results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote CIS Windows 11 audit results to: $OutputPath"
