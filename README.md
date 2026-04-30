# ADScoutPS

**ADScoutPS** is a PowerShell Active Directory enumeration and findings toolkit for authorized labs, internal assessments, and OSCP/PEN-200-style AD practice.

The design goal is simple: **collect useful AD data, normalize it, highlight what matters first, and keep both manual CLI control and one-command operator workflows.**

## Quick start: single-file mode

Copy only `ADScout.ps1` to a Windows/domain-connected lab box:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Preset Quick
```

GUI findings dashboard:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Gui -View Findings -SkipAclSweep
```

Manual/load-only mode:

```powershell
. .\ADScout.ps1 -LoadOnly
Test-ADScoutEnvironment
Get-ADScoutDomainInfo
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
Get-ADScoutFinding -SkipAclSweep
```

## Module mode

```powershell
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force
Test-ADScoutEnvironment
Invoke-ADScout -Preset Standard -SkipAclSweep
Get-ADScoutFinding -SkipAclSweep | Format-Table Severity,Category,Title,Target -AutoSize
```

## Operator presets

```powershell
Invoke-ADScout -Preset Quick
Invoke-ADScout -Preset Standard -SkipAclSweep
Invoke-ADScout -Preset Deep -Report
```

- `Quick`: fast core collection and findings.
- `Standard`: adds trusts, GPOs, OUs, password policy, privileged group report.
- `Deep`: includes ACL review unless `-SkipAclSweep` is set.

## Core commands

```powershell
Get-ADScoutVersion
Test-ADScoutEnvironment
Get-ADScoutDomainInfo
Get-ADScoutUser
Get-ADScoutGroup
Get-ADScoutComputer
Get-ADScoutDomainController
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
Get-ADScoutPrivilegePath
```

## Findings commands

```powershell
Get-ADScoutFinding -SkipAclSweep
Get-ADScoutAsRepRoastCandidate
Find-ADScoutSPNAccount
Find-ADScoutWeakUacFlag
Find-ADScoutConstrainedDelegation
Find-ADScoutUnconstrainedDelegation
Find-ADScoutDCSyncRight
Find-ADScoutAdminSDHolderOrphan
Get-ADScoutLapsStatus
Get-ADScoutPasswordPolicy
Get-ADScoutDomainTrust
```

## GUI and report workflows

```powershell
Invoke-ADScout -Gui -View Findings -SkipAclSweep
Invoke-ADScout -Gui -View PrivilegedGroups
Invoke-ADScout -Report -Preset Standard -SkipAclSweep
```

`-Report` creates an offline `report.html` inside the run output folder.

## Output

`Invoke-ADScout` creates a timestamped output folder:

```text
ADScout-Results/
└── Run-YYYYMMDD-HHMMSS/
    ├── Environment.csv/json
    ├── Findings.csv/json
    ├── Users.csv/json
    ├── Groups.csv/json
    ├── Computers.csv/json
    ├── PrivilegedGroupMembers.csv/json
    ├── PrivilegePaths.csv/json
    ├── summary.md
    └── report.html   # when -Report is used
```

## Development

Static tests are included under `tests/`:

```powershell
Invoke-Pester .\tests
```

Build the standalone script from module source:

```powershell
.\tools\Build-Standalone.ps1
```

## Disclaimer

ADScoutPS is read-only enumeration tooling for authorized use only. Use it only in environments where you have explicit permission.
