# ADScoutPS

PowerShell Active Directory enumeration toolkit for authorized labs, OSCP/PEN-200 preparation, and approved internal security assessments.

ADScoutPS keeps a manual CLI workflow while adding a normalized findings engine and optional findings-first GUI dashboard.

## Highlights

- Auto-discovers current domain/PDC/base DN by default
- Supports `-Server`, `-Credential`, and `-SearchBase`
- Users, groups, computers, domain controllers, trusts, GPOs, OUs
- ACL/ACE review and DCSync-right detection
- Kerberos review: SPN accounts and AS-REP roast candidates
- Delegation review: unconstrained, KCD, and RBCD indicators
- Password policy and fine-grained password policy review
- `adminCount=1` privileged-object review
- Weak UAC flag sweep with readable UAC decoding
- LAPS visibility status per computer
- Findings-first output with Critical/High/Medium/Info severity
- Optional `Invoke-ADScout -Gui` dashboard using `Out-GridView` when available
- CSV/JSON exports and `summary.md`

## Install / Import

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Fast Start

```powershell
Invoke-ADScout -SkipAclSweep
```

Open the findings-first GUI dashboard:

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

Run full collection including ACL checks:

```powershell
Invoke-ADScout -Gui
```

## Manual Commands

```powershell
Get-ADScoutDomainInfo
Get-ADScoutUser
Get-ADScoutComputer
Get-ADScoutDomainController
Get-ADScoutDomainTrust
Get-ADScoutPasswordPolicy
Get-ADScoutGPO
Get-ADScoutOU
```

## Attack-Path Findings

```powershell
Find-ADScoutASREPAccount
Find-ADScoutSPNAccount
Find-ADScoutUnconstrainedDelegation
Find-ADScoutConstrainedDelegation
Find-ADScoutDCSyncRight
Find-ADScoutAdminSDHolderOrphan
Find-ADScoutWeakUacFlag
Get-ADScoutLapsStatus
Get-ADScoutFinding
```

## ACL / ACE Review

```powershell
Find-ADScoutInterestingAce
Get-ADScoutObjectAcl -Identity "Domain Admins" -ObjectClass group
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

## Alternate Targeting

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred -SearchBase "DC=corp,DC=local"
```

## Help

```powershell
Get-Help Invoke-ADScout -Full
Get-Help Get-ADScoutFinding -Full
Get-Help Find-ADScoutASREPAccount -Full
```

## Disclaimer

Use only in authorized lab environments or approved internal assessments. ADScoutPS is read-only enumeration tooling and does not perform exploitation, credential extraction, persistence, or modification of Active Directory objects.
