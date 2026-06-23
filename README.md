# Nessus Local Audit Runner

Run locally supported Nessus `.audit` checks and write CSV output with:

```text
CHECK, Actual Value, Expected Value, Pass/Fail/Manual
```

## Windows / PowerShell

Run a Nessus audit file directly:

```powershell
.\Invoke-NessusAudit.ps1 -AuditPath .\benchmark.audit
```

Export the parsed checks as a reusable CSV catalog:

```powershell
.\Invoke-NessusAudit.ps1 -AuditPath .\benchmark.audit -ExportChecksPath .\benchmark_checks.csv
```

Run a prebuilt CSV catalog:

```powershell
.\Invoke-NessusAudit.ps1 -ChecksPath .\cis_win11_v5.0.1_L1_checks.csv
.\Invoke-NessusAudit.ps1 -ChecksPath .\cis_intune_windows11_v4.0.0_L1_checks.csv
```

Embedded PowerShell in `.audit` files is not executed by default. If the audit file is trusted:

```powershell
.\Invoke-NessusAudit.ps1 -AuditPath .\benchmark.audit -AllowEmbeddedScripts
```

The old CIS-specific entrypoint still works:

```powershell
.\Invoke-CISWindows11Audit.ps1
```

## Linux / Unix Shell

Run a Nessus audit file:

```sh
./invoke-nessus-audit.sh benchmark.audit
```

Choose the output path:

```sh
./invoke-nessus-audit.sh benchmark.audit -o results.csv
```

Embedded shell commands are not executed by default. If the audit file is trusted:

```sh
./invoke-nessus-audit.sh benchmark.audit --allow-command-exec
```

## Support Model

The tools parse any Nessus `.audit` file, but only locally runnable item types are evaluated automatically.

Supported Windows mappings include registry checks, GUID PolicyManager registry checks, password and lockout policy, user rights, audit policy subcategories, built-in account checks, banner checks, and opt-in embedded PowerShell checks.

Supported Linux/Unix mappings include common file existence/content checks, package checks, process checks, service checks, and opt-in command checks.

Unsupported audit item types are included in the result CSV as `Manual` with the source type named in `Actual Value`.
