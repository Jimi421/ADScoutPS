# ADScoutPS

**ADScoutPS** is a PowerShell Active Directory enumeration and findings toolkit built for authorized lab environments, internal assessments, and OSCP/PEN-200-style Active Directory practice.

The goal is simple:

> Collect useful AD data, highlight what matters, and make the output easy to review.

ADScoutPS supports both:

- **Manual CLI enumeration** for step-by-step operator control
- **Findings-first GUI mode** for fast review of high-signal issues
- **Standalone one-file drop mode** for easier lab usage

---

## Intended Use

ADScoutPS is intended for:

- Authorized Active Directory labs
- OffSec / PEN-200 / OSCP practice environments
- Internal security assessments where you have permission
- Learning how AD enumeration and attack-path discovery works

Do **not** use this tool against systems you do not own or do not have permission to test.

---

## Features

### Core Enumeration

- Domain information
- Users
- Groups
- Computers
- Domain controllers
- Organizational Units
- Group Policy Objects
- Linked GPOs
- Domain trusts
- Password policy
- Fine-Grained Password Policies / PSOs

### Group / Privilege Review

- Group listing
- Group member enumeration
- Recursive nested group membership
- Privileged group review
- Clean group membership reporting

### Findings Engine

ADScoutPS attempts to highlight items worth reviewing first:

- AS-REP roasting candidates
- SPN / Kerberoast candidates
- Weak UAC flags
- Password not required
- Password never expires
- Reversible encryption
- Unconstrained delegation
- Constrained delegation indicators
- Resource-based constrained delegation indicators
- DCSync-related rights
- AdminSDHolder / `adminCount=1` objects
- LAPS visibility
- Password policy weaknesses
- Domain trust visibility
- Interesting ACL / ACE permissions

### Output

- Console objects
- CSV export
- JSON export
- Markdown summary
- Findings dashboard via `Out-GridView`
- Standalone one-file execution

---

## Repo Layout

```text
ADScoutPS/
├── ADScoutPS/
│   ├── ADScoutPS.psd1
│   ├── ADScoutPS.psm1
│   └── ADScoutPS.Completion.ps1
├── docs/
│   └── USAGE.md
├── examples/
│   └── quickstart.ps1
├── ADScout.ps1
├── README.md
├── README_STANDALONE.md
├── CHANGELOG.md
└── LICENSE
```

---

## Quick Start: Module Mode

Copy the repo folder to the Windows target or lab box.

Example location:

```powershell
C:\Users\stephanie\ADScoutPS
```

Import the module:

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

Confirm commands loaded:

```powershell
Get-Command -Module ADScoutPS
```

Run a basic domain sanity check:

```powershell
Get-ADScoutDomainInfo
```

Run low-noise collection:

```powershell
Invoke-ADScout -SkipAclSweep
```

Open findings-first GUI mode:

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

---

## Quick Start: Standalone Drop Mode

ADScoutPS also includes a standalone launcher:

```powershell
ADScout.ps1
```

Run it directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -SkipAclSweep
```

Run GUI findings mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Gui -SkipAclSweep
```

Load functions manually from standalone mode:

```powershell
. .\ADScout.ps1 -LoadOnly
```

Then run commands manually:

```powershell
Get-ADScoutDomainInfo
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
Get-ADScoutFinding
```

---

## Recommended Operator Workflow

### 1. Load ADScoutPS

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

### 2. Confirm domain discovery

```powershell
Get-ADScoutDomainInfo
```

### 3. Run fast collection first

```powershell
Invoke-ADScout -SkipAclSweep
```

### 4. Review findings

```powershell
Get-ADScoutFinding |
Sort-Object Severity, Category |
Format-Table Severity, Category, Title, Target -AutoSize
```

### 5. Open GUI dashboard

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

### 6. Review privileged groups

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Format-Table Group, ParentGroup, Member, MemberType, Depth -AutoSize
```

### 7. Save important output

```powershell
Get-ADScoutFinding |
Export-Csv .\findings.csv -NoTypeInformation

Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Export-Csv .\privileged_group_members.csv -NoTypeInformation
```

---

## Findings-First GUI

ADScoutPS can launch a sortable/filterable findings dashboard using PowerShell's grid view.

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

The GUI focuses on high-signal findings such as:

- AS-REP candidates
- SPN accounts
- Weak UAC flags
- Delegation indicators
- DCSync rights
- LAPS visibility gaps
- AdminCount objects
- Password policy concerns

This is meant to answer:

> What should I look at first?

---

## Manual Enumeration Commands

### Domain Info

```powershell
Get-ADScoutDomainInfo
```

### Users

```powershell
Get-ADScoutUser
```

Cleaner view:

```powershell
Get-ADScoutUser |
Select-Object Name, SamAccountName, Enabled, UacFlags |
Format-Table -AutoSize
```

### Groups

```powershell
Get-ADScoutGroup
```

Group names only:

```powershell
Get-ADScoutGroup |
Select-Object Name |
Sort-Object Name
```

### Group Members

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins"
```

Recursive / nested members:

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive
```

Clean report:

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Format-Table Group, ParentGroup, Member, MemberType, Depth -AutoSize
```

Export:

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Export-Csv .\privileged_group_members.csv -NoTypeInformation
```

### Computers

```powershell
Get-ADScoutComputer
```

### Domain Controllers

```powershell
Get-ADScoutDomainController
```

### Domain Trusts

```powershell
Get-ADScoutDomainTrust
```

### Password Policy

```powershell
Get-ADScoutPasswordPolicy
```

### Fine-Grained Password Policies

```powershell
Get-ADScoutFineGrainedPasswordPolicy
```

---

## Attack-Path Review Commands

### AS-REP Roasting Candidates

```powershell
Find-ADScoutASREPAccount
```

### SPN / Kerberoast Candidates

```powershell
Find-ADScoutSPNAccount
```

### Weak UAC Flags

```powershell
Find-ADScoutWeakUacFlag
```

### Delegation Review

```powershell
Find-ADScoutUnconstrainedDelegation
Find-ADScoutConstrainedDelegation
Find-ADScoutDelegationHint
```

### DCSync Rights

```powershell
Find-ADScoutDCSyncRight
```

### AdminCount Objects

```powershell
Find-ADScoutAdminSDHolderOrphan
```

### LAPS Visibility

```powershell
Get-ADScoutLapsStatus
```

### Unified Findings

```powershell
Get-ADScoutFinding
```

---

## GPO / OU / ACL Review

### GPOs

```powershell
Get-ADScoutGPO
```

### OUs

```powershell
Get-ADScoutOU
```

### Linked GPOs

```powershell
Get-ADScoutLinkedGPO
```

### Object ACL

By distinguished name:

```powershell
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
```

By friendly name:

```powershell
Get-ADScoutObjectAcl -Name "Workstations" -ObjectClass organizationalUnit
```

### Interesting ACEs

```powershell
Find-ADScoutInterestingAce -Name "Workstations" -ObjectClass organizationalUnit
```

---

## Output Folder

`Invoke-ADScout` creates a timestamped results folder.

Example:

```text
ADScout-Results/
└── Run-20260430-121654/
    ├── Findings.csv
    ├── Findings.json
    ├── Users.csv
    ├── Groups.csv
    ├── Computers.csv
    ├── DomainControllers.csv
    ├── PrivilegedGroupMembers.csv
    └── summary.md
```

Custom output path:

```powershell
Invoke-ADScout -OutputPath .\results -SkipAclSweep
```

Both CSV and JSON:

```powershell
Invoke-ADScout -OutputPath .\results -OutputFormat Both -SkipAclSweep
```

---

## Common Usage Patterns

### Fastest Useful Run

```powershell
Invoke-ADScout -SkipAclSweep
Get-ADScoutFinding
```

### GUI Findings Review

```powershell
Invoke-ADScout -Gui -SkipAclSweep
```

### Privileged Group Review

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Out-GridView -Title "ADScout Privileged Group Members"
```

### Review One Group Deeply

```powershell
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive |
Format-Table RootGroup, ParentGroup, MemberSamAccountName, MemberObjectClass, Depth, Path -AutoSize
```

### Export Findings

```powershell
Get-ADScoutFinding |
Export-Csv .\findings.csv -NoTypeInformation
```

---

## Parameters Worth Knowing

Many commands support:

```powershell
-Server
-Credential
-SearchBase
```

Example with a specific DC:

```powershell
Get-ADScoutUser -Server dc01.corp.local
```

Example with alternate credentials:

```powershell
$cred = Get-Credential
Get-ADScoutUser -Server dc01.corp.local -Credential $cred
```

Example with a search base:

```powershell
Get-ADScoutUser -SearchBase "OU=Users,DC=corp,DC=local"
```

---

## Help

ADScoutPS includes PowerShell help.

```powershell
Get-Help Invoke-ADScout -Full
Get-Help Get-ADScoutGroupMember -Full
Get-Help Get-ADScoutGroupReport -Examples
Get-Help Get-ADScoutFinding -Full
```

List all commands:

```powershell
Get-Command -Module ADScoutPS
```

---

## Tab Completion

ADScoutPS includes command completion support for selected parameters.

Examples:

```powershell
Invoke-ADScout -OutputFormat <TAB>
Get-ADScoutObjectAcl -DistinguishedName <TAB>
Find-ADScoutInterestingAce -Name <TAB>
```

---

## Troubleshooting

### Module does not import

Try:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
```

### GUI does not open

`Out-GridView` may not be available in every PowerShell environment.

Use CLI output instead:

```powershell
Get-ADScoutFinding |
Format-Table Severity, Category, Title, Target -AutoSize
```

### No domain info returned

Check whether the host is domain-joined or can reach a domain controller.

Try:

```powershell
whoami
nltest /dsgetdc:corp.com
```

Or use a specific DC:

```powershell
Get-ADScoutDomainInfo -Server dc01.corp.local
```

### Recursive group output is noisy

Use the cleaner report function:

```powershell
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
Format-Table Group, ParentGroup, Member, MemberType, Depth -AutoSize
```

### ACL sweep is slow

Use:

```powershell
Invoke-ADScout -SkipAclSweep
```

Then inspect ACLs manually only where needed:

```powershell
Find-ADScoutInterestingAce -Name "Workstations" -ObjectClass organizationalUnit
```

---

## Operator Notes

Start broad, then focus.

Recommended first questions:

```text
Who am I?
What domain am I in?
Who are the admins?
Are there nested privileged users?
Are there SPN accounts?
Are there AS-REP candidates?
Are there weak UAC flags?
Are there delegation paths?
Are there DCSync-capable principals?
Are there interesting ACEs?
```

Recommended first commands:

```powershell
Get-ADScoutDomainInfo
Invoke-ADScout -SkipAclSweep
Get-ADScoutFinding
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
```

---

## Disclaimer

ADScoutPS is a read-only enumeration and findings tool intended for authorized use only.

Use it only in environments where you have explicit permission.
