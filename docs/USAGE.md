# ADScoutPS Usage

## Import

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Recommended operator workflow

Start with the high-signal GUI view:

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

Then manually dig deeper with CLI commands:

```powershell
Find-ADScoutSPNAccount
Find-ADScoutPrivilegedUser -Recursive
Find-ADScoutDelegationHint
Get-ADScoutOU
Get-ADScoutObjectAcl -Name "Workstations" -ObjectClass organizationalUnit
```

## Full collection

```powershell
Invoke-ADScout
```

## GUI-only style review

```powershell
Show-ADScoutFindingsGui -SkipAclSweep
```

## Findings as objects

```powershell
Get-ADScoutFinding -SkipAclSweep | Sort-Object Severity,Type
```

## Export only findings

```powershell
Get-ADScoutFinding -SkipAclSweep | Export-Csv .\findings.csv -NoTypeInformation
```

## Target a specific DC

```powershell
Invoke-ADScout -Server dc01.corp.local -Gui -SkipAclSweep
```

## Use alternate credentials

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred -Gui
```
