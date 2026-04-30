# ADScoutPS Usage Guide

This guide is written for practical lab and authorized assessment use.

## Load the Module

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
Get-Command -Module ADScoutPS
```

## Fastest Useful Workflow

```powershell
Get-ADScoutDomainInfo
Invoke-ADScout -SkipAclSweep
Get-ADScoutFinding
```

## GUI Findings Review

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

If `Out-GridView` is unavailable, use:

```powershell
Get-ADScoutFinding |
Format-Table Severity, Category, Title, Target -AutoSize
```

## Group / Nested Membership Review

List groups:

```powershell
Get-ADScoutGroup | Select-Object Name | Sort-Object Name
```

Review one group recursively:

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive |
Format-Table RootGroup, ParentGroup, MemberSamAccountName, MemberObjectClass, Depth, Path -AutoSize
```

Clean privileged group report:

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Format-Table Group, ParentGroup, Member, MemberType, Depth -AutoSize
```

Export it:

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Export-Csv .\privileged_group_members.csv -NoTypeInformation
```

## Attack-Path Review Commands

```powershell
Find-ADScoutASREPAccount
Find-ADScoutSPNAccount
Find-ADScoutWeakUacFlag
Find-ADScoutUnconstrainedDelegation
Find-ADScoutConstrainedDelegation
Find-ADScoutDCSyncRight
Find-ADScoutAdminSDHolderOrphan
Get-ADScoutLapsStatus
Get-ADScoutPasswordPolicy
Get-ADScoutDomainTrust
```

## ACL / ACE Review

```powershell
Get-ADScoutObjectAcl -Name "Workstations" -ObjectClass organizationalUnit
Find-ADScoutInterestingAce -Name "Workstations" -ObjectClass organizationalUnit
```

Raw DN style also works:

```powershell
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

## Standalone Mode

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -SkipAclSweep
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Gui -SkipAclSweep
. .\ADScout.ps1 -LoadOnly
```

## Output

```powershell
Invoke-ADScout -OutputPath .\ADScout-Results -OutputFormat Both -SkipAclSweep
```

Output includes findings, users, groups, computers, domain controllers, privileged group members, and a summary file.
