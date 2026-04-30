# ADScoutPS Usage Guide

## Import

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Basic Sanity Check

```powershell
Get-ADScoutDomainInfo
```

If this fails, check domain connectivity, DNS, VPN, or credentials.

## Fast Lab Collection

```powershell
Invoke-ADScout -SkipAclSweep
```

## Full Collection

```powershell
Invoke-ADScout -OutputFormat Both
```

## Alternate Credentials

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred
```

## ACL Review

```powershell
Get-ADScoutOU
Find-ADScoutInterestingAce -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

## Helpful PowerShell Patterns

```powershell
Get-ADScoutUser | Select-Object SamAccountName, UserPrincipalName
Find-ADScoutSPNAccount | Export-Csv .\spns.csv -NoTypeInformation
Find-ADScoutPrivilegedUser -Recursive | Format-Table -AutoSize
```
