# ADScoutPS Usage

## Import

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Recommended Workflow

Fast, low-friction collection:

```powershell
Invoke-ADScout -SkipAclSweep
```

Findings dashboard:

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

Full review including ACL/DCSync checks:

```powershell
Invoke-ADScout -Gui
```

## Findings First

```powershell
Get-ADScoutFinding | Sort-Object Severity,Category,Title
Get-ADScoutFinding | Export-Csv .\findings.csv -NoTypeInformation
Get-ADScoutFinding | Show-ADScoutFindingsGui
```

## Focus Areas

```powershell
Find-ADScoutASREPAccount
Find-ADScoutSPNAccount
Find-ADScoutUnconstrainedDelegation
Find-ADScoutConstrainedDelegation
Find-ADScoutDCSyncRight
Find-ADScoutWeakUacFlag
Find-ADScoutAdminSDHolderOrphan
Get-ADScoutPasswordPolicy
Get-ADScoutDomainTrust
Get-ADScoutLapsStatus
```

## Target a Specific DC

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred -SearchBase "DC=corp,DC=local"
```
