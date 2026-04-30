# ADScoutPS

> PowerShell Active Directory enumeration toolkit for lab environments, OSCP preparation, and authorized internal assessments.

ADScoutPS is a lightweight AD enumeration module focused on readable CLI output, operator-friendly workflows, and a findings-first GUI dashboard for quickly reviewing what deserves attention.

## What is new in v0.6

- `Invoke-ADScout -Gui` findings-first dashboard
- `Get-ADScoutFinding` normalized findings engine
- `Show-ADScoutFindingsGui` standalone GUI launcher
- Severity sorting: Critical, High, Medium, Low, Info
- CLI/manual commands remain intact
- Auto-domain/PDC/base DN discovery by default
- `-Server` and `-Credential` support retained

## Design

ADScoutPS keeps two workflows side by side:

1. **Manual CLI mode** for controlled enumeration and learning.
2. **Findings-first GUI mode** for fast review of the most interesting results.

This is inspired by the practical split seen across mature AD tools: AD Explorer provides a GUI browser for AD inspection, BloodHound emphasizes relationship/attack-path visualization, and assessment tools such as PingCastle prioritize findings and risk summaries. ADScoutPS stays intentionally lightweight and PowerShell-native.

## Requirements

- Windows host with domain connectivity
- PowerShell 5.1+ recommended
- `Out-GridView` for GUI mode
- Authorized lab or approved assessment environment

> `Out-GridView` is Windows/UI dependent. If unavailable, ADScoutPS falls back to a console table.

## Install / Import

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Quick Start

### Findings-first GUI

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

This runs collection, writes output files, and opens a sortable/filterable findings dashboard.

### Full collection without GUI

```powershell
Invoke-ADScout
```

### Faster collection without ACL sweep

```powershell
Invoke-ADScout -SkipAclSweep
```

### Standalone findings dashboard

```powershell
Show-ADScoutFindingsGui -SkipAclSweep
```

### Return findings as objects

```powershell
Get-ADScoutFinding -SkipAclSweep | Format-Table
```

## Manual CLI Commands

```powershell
Get-ADScoutDomainInfo
Get-ADScoutUser
Get-ADScoutGroup
Get-ADScoutComputer
Get-ADScoutGPO
Get-ADScoutOU
Get-ADScoutLinkedGPO
Find-ADScoutAdminGroup
Find-ADScoutSPNAccount
Find-ADScoutDelegationHint
Find-ADScoutOldComputer
Find-ADScoutPrivilegedUser -Recursive
```

## ACL / ACE Review

Use a raw distinguished name:

```powershell
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
Find-ADScoutInterestingAce -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

Or use friendly targeting with auto-resolution:

```powershell
Get-ADScoutObjectAcl -Name "Workstations" -ObjectClass organizationalUnit
Find-ADScoutInterestingAce -Identity "Domain Admins" -ObjectClass group
```

## Output

`Invoke-ADScout` writes timestamped output:

```text
ADScout-Results/
└── ADScout-YYYYMMDD-HHMMSS/
    ├── DomainInfo.csv / .json
    ├── Users.csv / .json
    ├── Groups.csv / .json
    ├── Computers.csv / .json
    ├── GPOs.csv / .json
    ├── OUs.csv / .json
    ├── LinkedGPOs.csv / .json
    ├── SPNAccounts.csv / .json
    ├── PrivilegedUsers.csv / .json
    ├── DelegationHints.csv / .json
    ├── OldComputers.csv / .json
    ├── Findings.csv / .json
    └── summary.md
```

## Help

```powershell
Get-Help Invoke-ADScout -Full
Get-Help Get-ADScoutFinding -Full
Get-Help Show-ADScoutFindingsGui -Full
```

## Safety

ADScoutPS is read-only. It is intended for:

- Personal AD labs
- OSCP/PNPT-style preparation
- Authorized internal assessments
- Defensive AD review and learning

Do not run ADScoutPS against systems or domains without explicit authorization.

## License

MIT License
