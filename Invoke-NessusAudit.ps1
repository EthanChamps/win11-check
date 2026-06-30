[CmdletBinding()]
param(
    [string]$AuditPath = '',
    [string]$ChecksPath = '',
    [string]$OutputPath = '',
    [string]$ExportChecksPath = '',
    [switch]$AllowEmbeddedScripts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SecurityPolicy = $null
$script:AuditPolicy = $null
$script:AllowEmbeddedScripts = [bool]$AllowEmbeddedScripts

function Get-ObjectPropertyValue {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AuditField {
    param(
        [hashtable]$Fields,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Fields.ContainsKey($Name)) { return [string]$Fields[$Name] }
    return ''
}

function ConvertTo-CsvSafeJson {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ($Value | ConvertTo-Json -Compress -Depth 12)
}

function Unquote-AuditValue {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $text = $Value.Trim()
    if ($text.Length -lt 2) { return $text }
    $quote = $text[0]
    if ($quote -ne '"' -and $quote -ne "'") { return $text }

    $chars = New-Object System.Collections.Generic.List[char]
    for ($i = 1; $i -lt $text.Length; $i++) {
        $ch = $text[$i]
        if ($ch -eq '\' -and ($i + 1) -lt $text.Length -and $text[$i + 1] -eq $quote) {
            $chars.Add($quote)
            $i++
            continue
        }
        if ($ch -eq $quote) {
            if ([string]::IsNullOrWhiteSpace($text.Substring($i + 1))) {
                return (-join $chars.ToArray())
            }
            return $text
        }
        $chars.Add($ch)
    }
    return $text
}

function Read-AuditVariables {
    param([string]$Text)

    $variables = @{}
    foreach ($match in [regex]::Matches($Text, '<variable>\s*(.*?)\s*</variable>', 'Singleline')) {
        $block = $match.Groups[1].Value
        $nameMatch = [regex]::Match($block, '<name>(.*?)</name>', 'Singleline')
        $defaultMatch = [regex]::Match($block, '<default>(.*?)</default>', 'Singleline')
        if ($nameMatch.Success -and $defaultMatch.Success) {
            $variables[$nameMatch.Groups[1].Value.Trim()] = $defaultMatch.Groups[1].Value.Trim()
        }
    }
    return $variables
}

function Resolve-AuditValue {
    param(
        [string]$Value,
        [hashtable]$Variables
    )

    $text = Unquote-AuditValue $Value
    if ($text -match '^@([A-Za-z0-9_]+)@$' -and $Variables.ContainsKey($Matches[1])) {
        return $Variables[$Matches[1]]
    }
    return $text
}

function ConvertTo-EncodedAlternatives {
    param([array]$Alternatives)

    $encodedAlternatives = New-Object System.Collections.Generic.List[string]
    foreach ($alternative in $Alternatives) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($item in @($alternative)) {
            if ($item -eq '') {
                $items.Add('~')
            } else {
                $items.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$item)))
            }
        }
        $encodedAlternatives.Add(($items.ToArray() -join ','))
    }
    return ($encodedAlternatives.ToArray() -join ';')
}

function Split-AuditOrExpression {
    param([string]$Expression)

    $alternatives = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Expression) { $Expression = '' }
    $value = $Expression.Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq '""' -or $value -eq "''") {
        $alternatives.Add(@(''))
        return @($alternatives.ToArray())
    }

    $outerParts = $value -split '\s+\|\|\s+'
    foreach ($outerPart in $outerParts) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($innerPart in ($outerPart -split '\s+&&\s+')) {
            $clean = (Unquote-AuditValue ($innerPart.Trim([char[]]@('(', ')', ' ')))).Trim()
            if ($clean -ne '') { $items.Add($clean) }
        }
        if ($items.Count -eq 0) { $items.Add('') }
        $alternatives.Add([string[]]$items.ToArray())
    }
    return @($alternatives.ToArray())
}

function Get-AuditDescriptionParts {
    param([string]$Description)

    $clean = Unquote-AuditValue $Description
    if ($clean -match '^([0-9]+(?:\.[0-9]+)*)\s+(?:\(L[0-9]+\)\s+)?(.*)$') {
        return [pscustomobject]@{ Id = $Matches[1]; Title = $Matches[2].Trim() }
    }
    return [pscustomobject]@{ Id = ''; Title = $clean }
}

function ConvertTo-AuditOperator {
    param(
        [string]$ValueData,
        [string]$CheckType,
        [string]$RegOption
    )

    $expected = Unquote-AuditValue $ValueData
    if ($RegOption -eq 'MUST_NOT_EXIST') {
        return [pscustomobject]@{ Operator = 'NotExists'; Expected = 'Must not exist'; ExpectedData = '' }
    }
    switch ($CheckType) {
        'CHECK_REGEX' { return [pscustomobject]@{ Operator = 'Regex'; Expected = $expected; ExpectedData = $expected } }
        'CHECK_NOT_REGEX' { return [pscustomobject]@{ Operator = 'NotRegex'; Expected = $expected; ExpectedData = $expected } }
        'CHECK_NOT_EQUAL' { return [pscustomobject]@{ Operator = 'NotEqual'; Expected = $expected; ExpectedData = $expected } }
    }
    if ($expected -match '^\[(MIN|\d+)\.\.(MAX|\d+)\]$') {
        return [pscustomobject]@{ Operator = 'Range'; Expected = $expected; ExpectedData = '' }
    }
    if ($ValueData -match '\|\|') {
        $alternatives = Split-AuditOrExpression $ValueData
        $display = (($alternatives | ForEach-Object { (@($_) -join ' AND ') }) -join ' OR ')
        return [pscustomobject]@{ Operator = 'In'; Expected = $display; ExpectedData = (ConvertTo-EncodedAlternatives $alternatives) }
    }
    return [pscustomobject]@{ Operator = 'Equals'; Expected = $expected; ExpectedData = $expected }
}

function New-AuditCheckRow {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Method,
        [string]$Target = '',
        [string]$Operator = '',
        [string]$Expected = '',
        [string]$ExpectedData = '',
        [string]$ExpectedJson = '',
        [string]$TargetsJson = '',
        [string]$ValueType = '',
        [string]$SourceType = '',
        [string]$RegOption = '',
        [string]$CheckType = '',
        [string]$ManualReason = ''
    )

    [pscustomobject]@{
        Id = $Id
        Title = $Title
        Method = $Method
        Target = $Target
        Operator = $Operator
        Expected = $Expected
        ExpectedData = $ExpectedData
        ExpectedJson = $ExpectedJson
        TargetsJson = $TargetsJson
        ValueType = $ValueType
        SourceType = $SourceType
        RegOption = $RegOption
        CheckType = $CheckType
        ManualReason = $ManualReason
    }
}

function Convert-AuditFieldsToCheck {
    param(
        [hashtable]$Fields,
        [hashtable]$Variables,
        [int]$Index
    )

    $sourceType = Get-AuditField -Fields $Fields -Name 'type'
    $description = Get-AuditField -Fields $Fields -Name 'description'
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Audit item $Index"
    }
    $parts = Get-AuditDescriptionParts $description
    $id = if ([string]::IsNullOrWhiteSpace($parts.Id)) { "audit-$('{0:d4}' -f $Index)" } else { $parts.Id }
    $title = $parts.Title
    $valueData = Resolve-AuditValue -Value (Get-AuditField -Fields $Fields -Name 'value_data') -Variables $Variables
    $checkType = Get-AuditField -Fields $Fields -Name 'check_type'
    $regOption = Get-AuditField -Fields $Fields -Name 'reg_option'
    $valueType = Get-AuditField -Fields $Fields -Name 'value_type'

    if ($sourceType -in @('REGISTRY_SETTING', 'GUID_REGISTRY_SETTING', 'BANNER_CHECK')) {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        $target = [ordered]@{
            Path = Get-AuditField -Fields $Fields -Name 'reg_key'
            Name = Get-AuditField -Fields $Fields -Name 'reg_item'
            Operator = $op.Operator
            Expected = $op.Expected
            ExpectedData = $op.ExpectedData
            RegOption = $regOption
        }
        $guidRegKey = Get-AuditField -Fields $Fields -Name 'guid_reg_key'
        if (-not [string]::IsNullOrWhiteSpace($guidRegKey)) {
            $target.GuidRegKey = $guidRegKey
        }
        $targetText = "{0}\{1}" -f $target.Path, $target.Name
        return New-AuditCheckRow -Id $id -Title $title -Method 'Registry' -Target $targetText -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -TargetsJson (ConvertTo-CsvSafeJson @($target)) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'REG_CHECK') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        $path = Unquote-AuditValue $valueData
        $target = [ordered]@{
            Path = $path
            Name = Get-AuditField -Fields $Fields -Name 'key_item'
            Operator = $op.Operator
            Expected = $op.Expected
            ExpectedData = $op.ExpectedData
            RegOption = $regOption
        }
        $targetText = "{0}\{1}" -f $target.Path, $target.Name
        return New-AuditCheckRow -Id $id -Title $title -Method 'Registry' -Target $targetText -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -TargetsJson (ConvertTo-CsvSafeJson @($target)) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -in @('PASSWORD_POLICY', 'LOCKOUT_POLICY')) {
        $policyName = (Get-AuditField -Fields $Fields -Name 'password_policy') + (Get-AuditField -Fields $Fields -Name 'lockout_policy')
        $policyTarget = switch ($policyName) {
            'ENFORCE_PASSWORD_HISTORY' { 'PasswordHistorySize' }
            'MAXIMUM_PASSWORD_AGE' { 'MaximumPasswordAge' }
            'MINIMUM_PASSWORD_AGE' { 'MinimumPasswordAge' }
            'MINIMUM_PASSWORD_LENGTH' { 'MinimumPasswordLength' }
            'COMPLEXITY_REQUIREMENTS' { 'PasswordComplexity' }
            'REVERSIBLE_ENCRYPTION' { 'ClearTextPassword' }
            'ALLOW_ADMINISTRATOR_ACCOUNT_LOCKOUT' { 'AllowAdministratorLockout' }
            'LOCKOUT_DURATION' { 'LockoutDuration' }
            'LOCKOUT_THRESHOLD' { 'LockoutBadCount' }
            'RESET_LOCKOUT_COUNTER' { 'ResetLockoutCount' }
            default { '' }
        }
        if (-not [string]::IsNullOrWhiteSpace($policyTarget)) {
            $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
            return New-AuditCheckRow -Id $id -Title $title -Method 'AccountPolicy' -Target $policyTarget -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
        }
    }

    if ($sourceType -eq 'USER_RIGHTS_POLICY') {
        $alternatives = Split-AuditOrExpression (Get-AuditField -Fields $Fields -Name 'value_data')
        $operator = if ($checkType -eq 'CHECK_SUPERSET') { 'ContainsAlternatives' } else { 'ExactAlternatives' }
        $display = (($alternatives | ForEach-Object {
            $items = @($_)
            if ($items.Count -eq 1 -and $items[0] -eq '') { 'No One' } else { $items -join ' AND ' }
        }) -join ' OR ')
        return New-AuditCheckRow -Id $id -Title $title -Method 'UserRight' -Target (Get-AuditField -Fields $Fields -Name 'right_type') -Operator $operator -Expected $display -ExpectedData (ConvertTo-EncodedAlternatives $alternatives) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'AUDIT_POLICY_SUBCATEGORY') {
        $tokens = @((Unquote-AuditValue $valueData) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $alternatives = New-Object System.Collections.Generic.List[object]
        $alternatives.Add([string[]]$tokens)
        if ($tokens.Count -eq 1 -and $title -match '\binclude\b') {
            $alternatives.Add([string[]]@('Success', 'Failure'))
        }
        $display = (($alternatives.ToArray() | ForEach-Object { (@($_) -join ' and ') }) -join ' OR ')
        return New-AuditCheckRow -Id $id -Title $title -Method 'AuditPolicy' -Target (Get-AuditField -Fields $Fields -Name 'audit_policy_subcategory') -Operator 'ExactAlternatives' -Expected $display -ExpectedData (ConvertTo-EncodedAlternatives ($alternatives.ToArray())) -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'CHECK_ACCOUNT') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        if ((Unquote-AuditValue $valueData) -eq 'Disabled') {
            $op = [pscustomobject]@{ Operator = 'Disabled'; Expected = 'Disabled'; ExpectedData = '' }
        }
        return New-AuditCheckRow -Id $id -Title $title -Method 'LocalAccount' -Target (Get-AuditField -Fields $Fields -Name 'account_type') -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    if ($sourceType -eq 'AUDIT_POWERSHELL') {
        $op = ConvertTo-AuditOperator -ValueData $valueData -CheckType $checkType -RegOption $regOption
        return New-AuditCheckRow -Id $id -Title $title -Method 'PowerShell' -Target (Get-AuditField -Fields $Fields -Name 'powershell_args') -Operator $op.Operator -Expected $op.Expected -ExpectedData $op.ExpectedData -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType
    }

    return New-AuditCheckRow -Id $id -Title $title -Method 'Manual' -Expected 'Manual review required' -ValueType $valueType -SourceType $sourceType -RegOption $regOption -CheckType $checkType -ManualReason "Unsupported Nessus audit item type for this local runner: $sourceType"
}

function Read-AuditCustomItemFields {
    # Read a <custom_item> body starting at the line after the opening tag and return
    # both the parsed field hashtable and the index of the closing </custom_item> line.
    param(
        [string[]]$Lines,
        [int]$Start
    )
    $fields = @{}
    $j = $Start
    while ($j -lt $Lines.Count -and $Lines[$j].Trim() -ne '</custom_item>') {
        if ($Lines[$j] -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s+:\s*(.*?)\s*$') {
            $key = $Matches[1]
            $value = $Matches[2]
            if ($key -eq 'value_data') {
                $fields[$key] = $value.Trim()
            } else {
                $fields[$key] = Unquote-AuditValue $value
            }
        }
        $j++
    }
    return [pscustomobject]@{ Fields = $fields; EndIndex = $j }
}

function New-CombinedConditionCheck {
    # A numbered <report> whose test logic lives in the preceding <condition> (an
    # "<if> recommendation"). Combine the condition's registry items into one check
    # titled by the report's CIS number, instead of leaving each condition item as an
    # unnamed 'audit-####' row.
    param(
        $ReportParts,
        [System.Collections.Generic.List[object]]$ConditionItems,
        [hashtable]$Variables,
        [int]$Index
    )

    $targets = New-Object System.Collections.Generic.List[object]
    $expectedParts = New-Object System.Collections.Generic.List[string]
    foreach ($fields in $ConditionItems) {
        $sub = Convert-AuditFieldsToCheck -Fields $fields -Variables $Variables -Index $Index
        if ($sub.Method -ne 'Registry') { return $null }   # caller falls back to per-item rows
        foreach ($t in @($sub.TargetsJson | ConvertFrom-Json)) {
            $targets.Add($t)
            $expectedParts.Add(('{0} {1} {2}' -f $t.Name, $t.Operator, $t.Expected).Trim())
        }
    }
    if ($targets.Count -eq 0) { return $null }

    return New-AuditCheckRow -Id $ReportParts.Id -Title $ReportParts.Title -Method 'Registry' `
        -Target $ReportParts.Title -Operator 'AllMatch' -Expected (($expectedParts.ToArray()) -join ' AND ') `
        -TargetsJson (ConvertTo-CsvSafeJson @($targets.ToArray())) -SourceType 'IF_CONDITION'
}

function ConvertFrom-NessusAuditFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Audit file not found: $Path"
    }

    $text = Get-Content -LiteralPath $Path -Raw
    $variables = Read-AuditVariables $text
    $lines = $text -split "`r?`n"
    $rows = New-Object System.Collections.Generic.List[object]
    $index = 0

    # Structure-aware walk. Nessus expresses some recommendations as
    # <if><condition>...test items...</condition><then><report>NUMBER</report></then>.
    # The condition items carry no CIS number on their own, so we must title them from
    # the report. Items that sit inside a condition with NO numbered report are pure
    # gates (OS / role detection) and are skipped. Everything else parses as before.
    $stack = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $lines.Count) {
        $t = $lines[$i].Trim()

        if ($t -eq '<if>') {
            $stack.Add([pscustomobject]@{
                ConditionItems     = (New-Object System.Collections.Generic.List[object])
                CollectingCondition = $false
                Emitted            = $false
            })
            $i++; continue
        }
        if ($t -eq '</if>') {
            if ($stack.Count -gt 0) { $stack.RemoveAt($stack.Count - 1) }
            $i++; continue
        }

        $cur = if ($stack.Count -gt 0) { $stack[$stack.Count - 1] } else { $null }

        if ($t -match '^<condition') {
            if ($cur) { $cur.CollectingCondition = $true }
            $i++; continue
        }
        if ($t -eq '</condition>') {
            if ($cur) { $cur.CollectingCondition = $false }
            $i++; continue
        }

        if ($t -match '^<report') {
            $desc = ''
            $j = $i + 1
            while ($j -lt $lines.Count -and $lines[$j].Trim() -ne '</report>') {
                if ($desc -eq '' -and $lines[$j] -match '^\s*description\s*:\s*(.*?)\s*$') {
                    $desc = $Matches[1]
                }
                $j++
            }
            if ($cur -and -not $cur.Emitted -and $desc -ne '') {
                $parts = Get-AuditDescriptionParts $desc
                if (-not [string]::IsNullOrWhiteSpace($parts.Id)) {
                    $index++
                    $combined = New-CombinedConditionCheck -ReportParts $parts -ConditionItems $cur.ConditionItems -Variables $variables -Index $index
                    if ($null -ne $combined) {
                        $rows.Add($combined)
                    } else {
                        foreach ($f in $cur.ConditionItems) {
                            $index++
                            $rows.Add((Convert-AuditFieldsToCheck -Fields $f -Variables $variables -Index $index))
                        }
                    }
                    $cur.Emitted = $true
                }
            }
            $i = $j + 1; continue
        }

        if ($t -eq '<custom_item>') {
            $parsed = Read-AuditCustomItemFields -Lines $lines -Start ($i + 1)
            $fields = $parsed.Fields
            $i = $parsed.EndIndex + 1

            if (-not $fields.ContainsKey('type') -or -not $fields.ContainsKey('description')) { continue }

            # Inside an open condition -> gating/test item; collect it for the enclosing
            # <if> rather than emitting a standalone (unnamed) row.
            if ($cur -and $cur.CollectingCondition) {
                $cur.ConditionItems.Add($fields)
                continue
            }

            if ((Get-AuditField -Fields $fields -Name 'description') -match '^(Windows \d+ is installed|Windows \d+ installation type|Target is enrolled)') {
                continue
            }
            $index++
            $rows.Add((Convert-AuditFieldsToCheck -Fields $fields -Variables $variables -Index $index))
            continue
        }

        $i++
    }

    return @($rows.ToArray())
}

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

function Get-GuidRegistryCandidatePath {
    param($Target)

    $paths = New-Object System.Collections.Generic.List[string]
    $guidRegKey = Get-ObjectPropertyValue -Object $Target -Name 'GuidRegKey'
    if (-not [string]::IsNullOrWhiteSpace([string]$guidRegKey)) {
        $paths.Add([string]$guidRegKey)
    }

    $targetPath = [string]$Target.Path
    if ($targetPath -match '^(.*\\Providers)\\\{GUID\}\\(.+)$') {
        $providersPath = ConvertTo-RegistryProviderPath $Matches[1]
        try {
            foreach ($provider in (Get-ChildItem -LiteralPath $providersPath -ErrorAction Stop)) {
                $paths.Add($targetPath.Replace('{GUID}', $provider.PSChildName))
            }
        } catch {
            if ($paths.Count -eq 0) {
                $paths.Add($targetPath)
            }
        }
    } else {
        $paths.Add($targetPath)
    }

    return @($paths.ToArray() | Select-Object -Unique)
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
            return ((Format-Value $Actual) -match $expectedText)
        }
        'NotRegex' {
            if ($null -eq $Actual) { return $true }
            return -not ((Format-Value $Actual) -match $expectedText)
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

function Invoke-NativeCommandCapture {
    # Run a native helper (auditpol.exe, secedit.exe) and capture its exit code and
    # combined stdout/stderr WITHOUT letting a non-zero exit turn into a thrown
    # exception. On PowerShell 7.4+ $PSNativeCommandUseErrorActionPreference defaults
    # to $true, which - combined with the script's $ErrorActionPreference='Stop' -
    # would otherwise surface a bare 'Error 0x........ occurred:' against every check
    # that depends on the tool. We shadow both preferences locally so the caller can
    # inspect the result and emit a clear, single diagnostic instead.
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0

    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
        $exitCode = $LASTEXITCODE
    } catch {
        # Command not found / failed to launch (e.g. tool not on PATH). Surface it as a
        # captured failure rather than letting it abort the check with a raw exception.
        $output = @([string]$_.Exception.Message)
        $exitCode = if ($LASTEXITCODE) { $LASTEXITCODE } else { -1 }
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = @($output)
    }
}

function Get-FirstNonEmptyLine {
    param([string[]]$Lines)
    $line = @($Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($line.Count -eq 0) { return '<no output>' }
    return [string]$line[0]
}

function Get-SecurityPolicy {
    if ($null -ne $script:SecurityPolicy) { return $script:SecurityPolicy }

    # [System.IO.Path]::GetTempPath() always returns a value (unlike $env:TEMP, which
    # can be null in some shells / non-Windows hosts).
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("cis-secpol-{0}.inf" -f ([guid]::NewGuid()))
    try {
        $capture = Invoke-NativeCommandCapture -FilePath 'secedit.exe' -Arguments @('/export', '/cfg', $tempFile)
        if (-not (Test-Path -LiteralPath $tempFile)) {
            throw ("Local security policy could not be exported. secedit.exe /export failed (exit code 0x{0:X8}): {1}. Run this script from an elevated PowerShell prompt on the target host." -f $capture.ExitCode, (Get-FirstNonEmptyLine $capture.Output))
        }
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

    # auditpol.exe /get /subcategory:* /r returns "Error 0x00000057 occurred:" on some
    # hosts/locales. Fall back to /category:* (which also enumerates every subcategory)
    # before giving up, and surface a clear diagnostic rather than the raw Win32 error.
    $rows = $null
    $diag = ''
    foreach ($scope in @('/subcategory:*', '/category:*')) {
        $capture = Invoke-NativeCommandCapture -FilePath 'auditpol.exe' -Arguments @('/get', $scope, '/r')
        $text = ($capture.Output -join "`n")
        $looksValid = ($capture.ExitCode -eq 0) -and ($text -match 'Subcategory') -and ($text -notmatch 'Error 0x[0-9A-Fa-f]{8} occurred')
        if ($looksValid) {
            $rows = $capture.Output | ConvertFrom-Csv
            break
        }
        $diag = "auditpol.exe /get $scope /r failed (exit code 0x{0:X8}): {1}" -f $capture.ExitCode, (Get-FirstNonEmptyLine $capture.Output)
    }

    if ($null -eq $rows) {
        throw "Advanced Audit Policy could not be read. $diag. Run 'auditpol /get /category:*' from an elevated PowerShell prompt on the target host to see the underlying error."
    }

    $map = @{}
    foreach ($row in $rows) {
        $guid = [string](Get-ObjectPropertyValue -Object $row -Name 'Subcategory GUID')
        if (-not [string]::IsNullOrWhiteSpace($guid)) {
            $map[$guid.Trim('{}').ToLowerInvariant()] = $row
        }
        $subcategory = [string](Get-ObjectPropertyValue -Object $row -Name 'Subcategory')
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

function Test-RegistryTargetValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        $Target
    )

    $providerPath = ConvertTo-RegistryProviderPath $Path
    $actual = $null
    $found = $true
    try {
        $actual = Get-ItemPropertyValue -LiteralPath $providerPath -Name $Target.Name -ErrorAction Stop
    } catch {
        $found = $false
        $actual = $null
    }

    $actualPart = "{0}:{1}={2}" -f $Path, $Target.Name, (Format-Value $actual)
    $regOption = [string](Get-ObjectPropertyValue -Object $Target -Name 'RegOption')
    $operator = [string](Get-ObjectPropertyValue -Object $Target -Name 'Operator')

    if ($regOption -eq 'MUST_NOT_EXIST' -or $operator -eq 'NotExists') {
        return [pscustomobject]@{ Actual = $actualPart; Pass = (-not $found) }
    }

    if (-not $found) {
        return [pscustomobject]@{ Actual = $actualPart; Pass = ($regOption -eq 'CAN_BE_NULL') }
    }

    $expected = [string](Get-ObjectPropertyValue -Object $Target -Name 'Expected')
    $expectedDataValue = Get-ObjectPropertyValue -Object $Target -Name 'ExpectedData'
    $expectedData = if ($null -ne $expectedDataValue) { [string]$expectedDataValue } else { '' }
    $pass = Test-ScalarValue -Actual $actual -Operator $operator -Expected $expected -ExpectedData $expectedData
    return [pscustomobject]@{ Actual = $actualPart; Pass = $pass }
}

function Test-RegistryCheck {
    param($Check)
    $targets = $Check.TargetsJson | ConvertFrom-Json
    $actualParts = New-Object System.Collections.Generic.List[string]
    $allPass = $true

    foreach ($target in @($targets)) {
        $guidRegKey = Get-ObjectPropertyValue -Object $target -Name 'GuidRegKey'
        $isGuidRegistry = (([string]$target.Path) -match '\\\{GUID\}\\') -or (-not [string]::IsNullOrWhiteSpace([string]$guidRegKey))

        if ($isGuidRegistry) {
            $candidateResults = New-Object System.Collections.Generic.List[object]
            foreach ($candidatePath in (Get-GuidRegistryCandidatePath $target)) {
                foreach ($expandedPath in (Expand-RegistryTargetPath $candidatePath)) {
                    $result = Test-RegistryTargetValue -Path $expandedPath -Target $target
                    $candidateResults.Add($result)
                    $actualParts.Add($result.Actual)
                }
            }
            if ($candidateResults.Count -eq 0 -or -not ($candidateResults | Where-Object { $_.Pass })) {
                $allPass = $false
            }
            continue
        }

        foreach ($expandedPath in (Expand-RegistryTargetPath $target.Path)) {
            $result = Test-RegistryTargetValue -Path $expandedPath -Target $target
            $actualParts.Add($result.Actual)
            if (-not $result.Pass) {
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

function Test-PowerShellCheck {
    param($Check)

    if (-not $script:AllowEmbeddedScripts) {
        return [pscustomobject]@{
            Actual = 'Embedded PowerShell was not executed. Re-run with -AllowEmbeddedScripts if this audit file is trusted.'
            Pass = $null
        }
    }

    $scriptBlock = [scriptblock]::Create($Check.Target)
    $output = & $scriptBlock 6>&1 5>&1 4>&1 3>&1 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.InformationRecord]) {
            [string]$_.MessageData
        } else {
            [string]$_
        }
    }
    $actual = (($output | Where-Object { $null -ne $_ }) -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($actual)) {
        $actual = '<no output>'
    }
    $pass = Test-ScalarValue -Actual $actual -Operator $Check.Operator -Expected $Check.Expected -ExpectedData $Check.ExpectedData
    return [pscustomobject]@{ Actual = $actual; Pass = $pass }
}

function Invoke-NessusCheck {
    param($Check)
    switch ($Check.Method) {
        'Registry' { return Test-RegistryCheck $Check }
        'AccountPolicy' { return Test-AccountPolicyCheck $Check }
        'UserRight' { return Test-UserRightCheck $Check }
        'AuditPolicy' { return Test-AuditPolicyCheck $Check }
        'Service' { return Test-ServiceCheck $Check }
        'Firewall' { return Test-FirewallCheck $Check }
        'LocalAccount' { return Test-LocalAccountCheck $Check }
        'PowerShell' { return Test-PowerShellCheck $Check }
        default {
            $manualReason = [string](Get-ObjectPropertyValue -Object $Check -Name 'ManualReason')
            return [pscustomobject]@{
                Actual = if ([string]::IsNullOrWhiteSpace($manualReason)) { 'Manual review required' } else { $manualReason }
                Pass = $null
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($AuditPath) -and [string]::IsNullOrWhiteSpace($ChecksPath)) {
    $ChecksPath = Join-Path $PSScriptRoot 'cis_win11_v5.0.1_L1_checks.csv'
}

if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
    $checks = ConvertFrom-NessusAuditFile -Path $AuditPath
    $inputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($AuditPath)
} else {
    if (-not (Test-Path -LiteralPath $ChecksPath)) {
        throw "Checks file not found: $ChecksPath"
    }
    $checks = Import-Csv -LiteralPath $ChecksPath
    $inputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ChecksPath)
}

if (-not [string]::IsNullOrWhiteSpace($ExportChecksPath)) {
    $checks | Export-Csv -LiteralPath $ExportChecksPath -NoTypeInformation -Encoding UTF8
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot ("{0}_results_{1}.csv" -f $inputBaseName, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$results = foreach ($check in $checks) {
    $checkName = "{0} {1}" -f $check.Id, $check.Title
    $manualReason = [string](Get-ObjectPropertyValue -Object $check -Name 'ManualReason')

    if ($check.Method -eq 'Manual') {
        [pscustomobject]@{
            'CHECK' = $checkName
            'Actual Value' = if ([string]::IsNullOrWhiteSpace($manualReason)) { 'Manual review required' } else { $manualReason }
            'Expected Value' = $check.Expected
            'Pass/Fail/Manual' = 'Manual'
        }
        continue
    }

    try {
        $result = Invoke-NessusCheck $check
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
Write-Host "Wrote Nessus audit results to: $OutputPath"
