# ADScoutPS

> PowerShell Active Directory enumeration and findings toolkit.  
> One file. No dependencies. No RSAT required.

---

## What it is

ADScoutPS is a single-file PowerShell script for read-only Active Directory enumeration. It collects domain data, identifies misconfigurations, and surfaces findings with context — not just raw LDAP dumps.

It works as an `Import-Module` target, a dot-sourced function library, or a standalone script you drop on a Windows box and run directly. No companion files. No installation. No internet access required.

**Authorized use only.** Use in environments where you have explicit written permission.

---

## Quick start

```powershell
# Run directly — Standard preset, export CSV + JSON
.\ADScoutPS.ps1

# Quick run, skip ACL sweep, no export
.\ADScoutPS.ps1 -Preset Quick -NoExport

# Full run with ACL sweep and HTML report
.\ADScoutPS.ps1 -Preset Deep -Report

# GUI findings dashboard
.\ADScoutPS.ps1 -Gui -View Findings -SkipAclSweep

# Restricted execution policy
powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Quick
```

---

## Loading functions

```powershell
# Import as module — all functions available, no collection runs
Import-Module .\ADScoutPS.ps1

# Dot-source
. .\ADScoutPS.ps1

# Dot-source with explicit load-only flag
. .\ADScoutPS.ps1 -LoadOnly
```

Once loaded, run anything manually:

```powershell
Test-ADScoutEnvironment
Get-ADScoutDomainInfo
Get-ADScoutUser | Format-Table SamAccountName, UacFlags -AutoSize
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
```

---

## Presets

| Preset | What runs | ACL sweep |
|---|---|---|
| `Quick` | Core objects (users, groups, computers, DCs, password policy, Kerberos, delegation, LAPS) | No |
| `Standard` | Quick + GPOs, OUs, trusts, linked GPO map, privileged group report | No |
| `Deep` | Standard + ACL sweep on domain root and high-value targets | Yes |

ACL sweep can be forced on or off regardless of preset:

```powershell
.\ADScoutPS.ps1 -Preset Standard -IncludeAclSweep   # add ACL sweep to Standard
.\ADScoutPS.ps1 -Preset Deep -SkipAclSweep           # run Deep without ACL sweep
```

---

## Findings

`Get-ADScoutFinding` is the normalized findings engine. Every finding includes:

| Field | Description |
|---|---|
| `Severity` | Critical / High / Medium / Low / Info |
| `Category` | Finding category (Authentication, Delegation, ACL Attack Path, etc.) |
| `Title` | Short finding name |
| `Target` | The specific account, group, or object |
| `Evidence` | Raw data that triggered the finding |
| `WhyItMatters` | Plain-language explanation of the risk |
| `RecommendedReview` | What to do about it |
| `SourceCommand` | The function that produced this finding |
| `DistinguishedName` | Full DN of the affected object |
| `Timestamp` | When the finding was generated |

```powershell
# All findings, skip ACL sweep
Get-ADScoutFinding -SkipAclSweep

# With ACL sweep
Get-ADScoutFinding -IncludeAclSweep

# Filter by severity
Get-ADScoutFinding -SkipAclSweep | Where-Object Severity -eq 'Critical'

# Table view
Get-ADScoutFinding -SkipAclSweep | Format-Table Severity, Category, Title, Target -AutoSize

# Pipe to summary banner
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
```

### Finding coverage

| Category | Finding | Severity |
|---|---|---|
| Credential Exposure | Password in AD description field | Critical |
| Authentication | AS-REP roast candidate (no Kerberos preauth) | Critical |
| Delegation | Unconstrained delegation on non-DC object | Critical |
| Replication Rights | DCSync-capable right held by non-privileged principal | Critical |
| ACL Attack Path | Abusable ACE on privileged group, DA account, krbtgt, or DC | Critical |
| Kerberos | SPN-bearing user account (Kerberoast candidate) | High / Medium |
| Delegation | RBCD configured | High |
| Delegation | KCD configured | Medium |
| Password Policy | Min length < 12 or lockout disabled | High |
| Account Flags | PASSWD_NOTREQD / ENCRYPTED_TEXT_PWD / USE_DES_KEY_ONLY | High / Medium |
| Privilege Hygiene | adminCount=1 object (current or historical) | Medium |
| Endpoint Hygiene | No visible LAPS metadata | Medium |
| Endpoint Hygiene | Stale computer account (>90 days) | Low |
| Trusts | Domain trust present | Info |
| Domain Controllers | DC inventory | Info |

---

## Function reference

### Environment

```powershell
Get-ADScoutVersion
Test-ADScoutEnvironment
Test-ADScoutEnvironment -Server dc01.corp.local -Credential $cred
```

`Test-ADScoutEnvironment` validates domain discovery, LDAP bind, current identity, PowerShell version, and Out-GridView availability before you run a full collection.

---

### Domain

```powershell
Get-ADScoutDomainInfo
Get-ADScoutDomainTrust
Get-ADScoutPasswordPolicy
```

`Get-ADScoutPasswordPolicy` returns both the default domain policy and any fine-grained password policies (PSOs) readable by the current user.

---

### Users

```powershell
Get-ADScoutUser
Get-ADScoutUser | Where-Object { $_.AdminCount -eq 1 }
Get-ADScoutUser | Where-Object { $_.ServicePrincipalName }
```

All users include decoded `UacFlags` — a comma-separated list of set UAC flag names (e.g. `NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD`).

```powershell
ConvertTo-ADScoutUacFlag -UserAccountControl 66048
# Returns: NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

---

### Groups

```powershell
Get-ADScoutGroup
Find-ADScoutAdminGroup

# Direct members of Domain Admins
Get-ADScoutGroupMember -Identity 'Domain Admins'

# Recursive with nesting depth and path
Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive

# Report for multiple groups
Get-ADScoutGroupReport -GroupName 'Domain Admins','Backup Operators' -Recursive

# All privileged groups
Get-ADScoutGroupReport -PrivilegedOnly -Recursive

# Who has a path to a privileged group
Get-ADScoutPrivilegePath
```

`Get-ADScoutGroupMember` resolves every member DN and returns name, samAccountName, objectClass, nesting depth, and the full membership path (e.g. `Domain Admins -> nested_group -> user`).

---

### Computers

```powershell
Get-ADScoutComputer
Get-ADScoutDomainController
Get-ADScoutLapsStatus
Find-ADScoutOldComputer           # default 90 days
Find-ADScoutOldComputer -Days 60
```

`Get-ADScoutLapsStatus` checks both legacy LAPS (`ms-Mcs-AdmPwdExpirationTime`) and Windows LAPS (`msLAPS-PasswordExpirationTime`) attributes. Visibility depends on your read rights.

---

### Kerberos

```powershell
Find-ADScoutASREPAccount           # DONT_REQUIRE_PREAUTH
Get-ADScoutAsRepRoastCandidate     # alias for above
Find-ADScoutSPNAccount             # servicePrincipalName set
```

---

### Delegation

```powershell
Find-ADScoutUnconstrainedDelegation
Find-ADScoutUnconstrainedDelegation -IncludeDomainControllers
Find-ADScoutConstrainedDelegation   # returns both KCD and RBCD
Find-ADScoutDelegationHint          # both in one call
```

---

### ACL

```powershell
# ACL on a specific object by friendly name
Get-ADScoutObjectAcl -Identity 'Domain Admins' -ObjectClass group
Get-ADScoutObjectAcl -Identity 'krbtgt'
Get-ADScoutObjectAcl -DistinguishedName 'CN=krbtgt,CN=Users,DC=corp,DC=local'

# Interesting ACEs on the domain root
Find-ADScoutInterestingAce

# Interesting ACEs on a specific object
Find-ADScoutInterestingAce -Identity 'Domain Admins'

# DCSync rights on domain root
Find-ADScoutDCSyncRight

# ACL attack paths against all high-value targets
Find-ADScoutAclAttackPath
Find-ADScoutAclAttackPath | Where-Object { $_.Rights -match 'GenericAll|WriteDacl' }
```

`Find-ADScoutAclAttackPath` sweeps ACLs against: all privileged groups, krbtgt, every Domain Admin user account, and every DC computer object. Non-privileged principals with abusable rights are returned. Well-known privileged SIDs are excluded by SID suffix (locale-safe).

`Find-ADScoutDCSyncRight` checks for `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, and `DS-Replication-Get-Changes-In-Filtered-Set`. Well-known legitimate holders (Domain Admins, Domain Controllers, Enterprise Admins, SYSTEM) are returned as `Info` severity. Everyone else is `Critical`.

---

### Credential exposure

```powershell
Find-ADScoutPasswordInDescription
```

Scans all user and computer description fields for password-related keywords. AD description fields are readable by all authenticated domain users by default.

---

### GPO / OU

```powershell
Get-ADScoutGPO
Get-ADScoutOU
Get-ADScoutLinkedGPO    # OUs with linked GPOs only
```

---

### Findings and summary

```powershell
# Collect findings
$findings = Get-ADScoutFinding -SkipAclSweep

# Summary banner
Get-ADScoutSummary
Get-ADScoutSummary -Findings $findings
$findings | Get-ADScoutSummary

# GUI dashboard (requires Windows PowerShell or pwsh with Out-GridView)
Show-ADScoutFindingsGui -View Findings
Show-ADScoutFindingsGui -View PrivilegedGroups
Show-ADScoutFindingsGui -View Delegation
Show-ADScoutFindingsGui -View Users
Show-ADScoutFindingsGui -View Computers
Show-ADScoutFindingsGui -View All
```

---

## Output

`Invoke-ADScout` creates a timestamped folder under `ADScout-Results\`:

```
ADScout-Results\
└── Run-20260430-143022\
    ├── Environment.csv / .json
    ├── DomainInfo.csv / .json
    ├── DomainControllers.csv / .json
    ├── Users.csv / .json
    ├── Groups.csv / .json
    ├── Computers.csv / .json
    ├── GPOs.csv / .json
    ├── OUs.csv / .json
    ├── LinkedGPOs.csv / .json
    ├── DomainTrusts.csv / .json
    ├── PasswordPolicies.csv / .json
    ├── PasswordInDescription.csv / .json
    ├── SPNAccounts.csv / .json
    ├── ASREPAccounts.csv / .json
    ├── Delegation.csv / .json
    ├── AclAttackPaths.csv / .json
    ├── AdminSDHolderObjects.csv / .json
    ├── PrivilegedGroupMembers.csv / .json
    ├── PrivilegePaths.csv / .json
    ├── WeakUacFlags.csv / .json
    ├── LapsStatus.csv / .json
    ├── StaleComputers.csv / .json
    ├── Findings.csv / .json
    ├── summary.md
    └── report.html          # when -Report is used
```

Control output format and location:

```powershell
.\ADScoutPS.ps1 -OutputFormat CSV                       # CSV only
.\ADScoutPS.ps1 -OutputFormat JSON                      # JSON only
.\ADScoutPS.ps1 -OutputPath C:\Temp\ADScan             # custom path
.\ADScoutPS.ps1 -NoExport                               # no files written
.\ADScoutPS.ps1 -Report                                 # include HTML report
```

---

## Alternate targets

```powershell
# Explicit domain controller
Invoke-ADScout -Server dc01.corp.local

# Alternate credentials
$cred = Get-Credential
Invoke-ADScout -Credential $cred -Server dc01.corp.local

# Specific search base (scope collection to an OU)
Invoke-ADScout -SearchBase 'OU=Workstations,DC=corp,DC=local'

# Remote domain from a non-domain-joined box
Invoke-ADScout -Server dc01.external.local -Credential $cred -SearchBase 'DC=external,DC=local'
```

---

## How it works

ADScoutPS uses `System.DirectoryServices` — the .NET namespace that wraps LDAP — with no dependency on the ActiveDirectory PowerShell module or RSAT. Every query is a standard LDAP search against port 389. Any authenticated domain user can run it. No elevated privileges required for core enumeration (some ACL reads may require higher access depending on domain hardening).

Because it runs entirely through the CLR already present on any Windows system, no binaries touch disk beyond the script itself.

---

## Caveats

**`lastLogonTimestamp` jitter** — the stale computer detection uses `lastLogonTimestamp`, which AD replicates on a 9–14 day interval by design. Results carry up to ~2 weeks of inherent fuzziness. A machine that appears stale may have authenticated within that window.

**LAPS visibility** — `Get-ADScoutLapsStatus` checks for the presence of LAPS attributes, not whether the password is readable. A computer showing `HasLegacyLaps=True` means the attribute exists; whether the current user can read the password value depends on delegation configured in the environment.

**ACL sweep noise** — `Find-ADScoutAclAttackPath` and `Find-ADScoutInterestingAce` filter well-known privileged principals by SID suffix rather than by name (locale-safe). In highly customized environments, legitimate delegations may surface as findings. Review each result in context.

**DCSync expected holders** — `Find-ADScoutDCSyncRight` always enumerates replication rights. Principals matching well-known SID suffixes (`-512`, `-516`, `-518`, `-519`, `S-1-5-18`, `S-1-5-9`) are returned as `Info`. Everything else is `Critical`.

---

## Version history

See [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*For authorized use only. Always obtain explicit written permission before running enumeration tooling against any environment.*
