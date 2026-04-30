# ADScoutPS

> PowerShell Active Directory Enumeration Toolkit for Lab Environments, OSCP Preparation, and Authorized Assessments

ADScoutPS is a lightweight PowerShell module for read-only Active Directory enumeration. It is built to help students and defenders understand AD structure, permissions, GPO layout, and common security-relevant indicators in authorized lab or internal assessment environments.

## Features

- Domain metadata enumeration through RootDSE
- User, group, and computer discovery
- SPN-bearing account discovery
- GPO and OU discovery
- Linked GPO review
- ACL / ACE inspection
- Interesting ACE filtering
- Recursive group membership review
- Privileged group membership review
- Delegation-related indicators
- Legacy computer hints
- One-command collection with CSV / JSON output
- Markdown summary report
- Built-in PowerShell help
- Tab completion for selected parameters

## Repository Layout

```text
ADScoutPS/
├── ADScoutPS/
│   ├── ADScoutPS.psd1
│   ├── ADScoutPS.psm1
│   └── ADScoutPS.Completion.ps1
├── examples/
│   └── quickstart.ps1
├── docs/
│   └── USAGE.md
├── CHANGELOG.md
├── LICENSE
├── README.md
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone git@github.com:jimi421/ADScoutPS.git
cd ADScoutPS
```

Import the module from PowerShell:

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

If script execution is blocked in a lab VM, use a process-scoped policy change:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

## Quick Start

Run a fast collection without ACL sweeping:

```powershell
Invoke-ADScout -SkipAclSweep
```

Run full collection and write CSV + JSON:

```powershell
Invoke-ADScout -OutputFormat Both
```

Target a specific domain controller:

```powershell
Invoke-ADScout -Server dc01.corp.local -SkipAclSweep
```

Use alternate authorized credentials:

```powershell
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred -OutputFormat Both
```

## Core Commands

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

Inspect ACLs for a specific AD object:

```powershell
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

Find potentially interesting ACEs:

```powershell
Find-ADScoutInterestingAce -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

ADScoutPS flags rights commonly reviewed during AD security assessments, such as:

```text
GenericAll
GenericWrite
WriteDacl
WriteOwner
ExtendedRight
CreateChild
DeleteChild
WriteProperty
```

## Group Membership

Direct group members:

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins"
```

Recursive group expansion:

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive
```

Privileged group review:

```powershell
Find-ADScoutPrivilegedUser -Recursive
```

## Output

`Invoke-ADScout` creates a timestamped results directory:

```text
ADScout-Results/
└── ADScout-YYYYMMDD-HHMMSS/
    ├── DomainInfo.csv/json
    ├── Users.csv/json
    ├── Groups.csv/json
    ├── Computers.csv/json
    ├── GPOs.csv/json
    ├── OUs.csv/json
    ├── LinkedGPOs.csv/json
    ├── SPNAccounts.csv/json
    ├── AdminGroups.csv/json
    ├── PrivilegedUsers.csv/json
    ├── DelegationHints.csv/json
    ├── OldComputers.csv/json
    ├── InterestingACEs.csv/json
    └── summary.md
```

## Built-In Help

ADScoutPS includes comment-based PowerShell help:

```powershell
Get-Help Invoke-ADScout -Full
Get-Help Get-ADScoutUser -Examples
Get-Help Find-ADScoutSPNAccount -Full
Get-Help Get-ADScoutObjectAcl -Full
```

List available ADScout commands:

```powershell
Get-Command -Module ADScoutPS
```

## Tab Completion

ADScoutPS supports tab completion for selected parameters:

```powershell
Invoke-ADScout -OutputFormat <TAB>
Invoke-ADScout -OutputPath <TAB>
Invoke-ADScout -Server <TAB>
Get-ADScoutObjectAcl -DistinguishedName <TAB>
Find-ADScoutInterestingAce -DistinguishedName <TAB>
Get-ADScoutGroupMember -Identity <TAB>
```

Some completions require domain connectivity because they query LDAP for live object names or distinguished names.

## Requirements

- Windows system with PowerShell 5.1+ or PowerShell 7+
- Domain connectivity for AD enumeration
- Normal domain user rights are enough for many read-only LDAP queries
- Authorized lab or assessment scope

## Intended Use

ADScoutPS is intended for:

- OSCP / PNPT / HTB / THM-style lab practice
- Internal security learning labs
- Authorized AD assessment preparation
- Understanding AD object structure, permissions, and common misconfigurations

## Safety and Scope

ADScoutPS is read-only. It does not modify Active Directory objects, request Kerberos service tickets, dump credentials, create persistence, bypass defenses, or perform exploitation.

Use only in environments where you have explicit permission.

## Roadmap

- GUID to friendly permission resolution
- Better GPO link parsing
- BloodHound-compatible relationship export
- HTML report output
- Unit tests for helper functions
- Signed release packaging

## Author

Braxton Bailey

## License

MIT License
