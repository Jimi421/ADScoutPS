# ADScoutPS

> PowerShell Active Directory enumeration and findings toolkit.  
> One file. No RSAT. No ActiveDirectory module. No dependencies.

---

## What it is

ADScoutPS is a single-file PowerShell AD enumeration tool built for offensive operators. Drop it on any domain-connected Windows box, load it, and ask: **what is the shortest path to Domain Admin from here?**

No variables to manage. No `-RunData` to thread through commands. Collection runs automatically on load and session data is available to all analysis functions immediately.

**Authorized use only.**

---

## Quick start

```powershell
# Standard lab run
Import-Module .\ADScoutPS.ps1 -LabMode
Get-QuickWins

# OSCP/HTB lab with ACL sweep
Import-Module .\ADScoutPS.ps1 -Preset Deep -LabMode
Get-QuickWins
Get-PathHints

# Load only, collect on your own terms
Import-Module .\ADScoutPS.ps1 -LoadOnly
Collect -Preset Standard -LabMode -Server dc01.corp.local
Get-QuickWins
```

---

## The operator workflow

```powershell
# Load -- collection runs automatically
Import-Module .\ADScoutPS.ps1 -LabMode

# Shortest path to DA
Get-QuickWins

# Full findings with context
Get-Findings | Get-Summary

# Chained attack paths
Get-PathHints

# Drill into specifics
Get-Members -Identity 'Domain Admins' -Recursive
Find-ASREP
Find-SPNs | Where-Object AdminCount -eq 1
Get-ADACL -Identity 'Domain Admins'
Find-Passwords

# Export snapshot -- offline analysis, no domain needed
Export-Run -Path .\snapshot.json

# --- On another box ---
Import-Module .\ADScoutPS.ps1 -LoadOnly
Import-Run -Path .\snapshot.json
Get-QuickWins
Get-PathHints
```

---

## `Get-QuickWins`

The primary operator function. No noise. Just what's worth trying, in priority order.

```powershell
Get-QuickWins
```

| Priority | Category | What it means |
|---|---|---|
| 1 | Credential Exposure | Password or flag in a readable AD field — instant win |
| 2 | AS-REP Roast | DA members and adminCount=1 accounts surfaced first |
| 3 | Kerberoast | DA members and adminCount=1 accounts surfaced first |
| 4 | Unconstrained Delegation | Coerce a DC to authenticate here, capture the TGT |
| 5 | DCSync | Non-standard principal — if you control it, dump all hashes |
| 6 | ACL Attack Path | Abusable ACE on a privileged group, DA, krbtgt, or DC |
| 7 | Targeted Kerberoast | GenericWrite on a user — set a SPN and Kerberoast |
| 8 | Privilege Path | Nested group membership path to Domain Admins |
| 9 | GPO Abuse | Write access to a GPO linked to a privileged OU |

Each result prints `Target`, `Why`, `Evidence`, and a ready-to-run `ManualVerify` command.

---

## Aliases

Short aliases for everything you'd type mid-engagement. Full function names always work too.

| Alias | Full name |
|---|---|
| `Collect` | `Invoke-ADScoutCollection` |
| `Get-QuickWins` | `Get-ADScoutQuickWins` |
| `Get-Findings` | `Get-ADScoutFinding` |
| `Get-PathHints` | `Get-ADScoutPathHint` |
| `Get-Summary` | `Get-ADScoutSummary` |
| `Get-Users` | `Get-ADScoutUser` |
| `Get-Groups` | `Get-ADScoutGroup` |
| `Get-Computers` | `Get-ADScoutComputer` |
| `Get-DCs` | `Get-ADScoutDomainController` |
| `Get-Trusts` | `Get-ADScoutDomainTrust` |
| `Get-Policy` | `Get-ADScoutPasswordPolicy` |
| `Get-GPOs` | `Get-ADScoutGPO` |
| `Get-OUs` | `Get-ADScoutOU` |
| `Get-Members` | `Get-ADScoutGroupMember` |
| `Get-ADACL` | `Get-ADScoutObjectAcl` |
| `Find-ASREP` | `Find-ADScoutASREPAccount` |
| `Find-SPNs` | `Find-ADScoutSPNAccount` |
| `Find-Shadow` | `Find-ADScoutShadowCredential` |
| `Find-Passwords` | `Find-ADScoutPasswordInDescription` |
| `Find-Delegation` | `Find-ADScoutDelegationHint` |
| `Find-DCSync` | `Find-ADScoutDCSyncRight` |
| `Find-AclPaths` | `Find-ADScoutAclAttackPath` |
| `Find-LocalAdmin` | `Find-ADScoutLocalAdminAccess` |
| `Export-Run` | `Export-ADScoutRun` |
| `Import-Run` | `Import-ADScoutRun` |

---

## Presets

| Preset | What it collects | ACL sweep |
|---|---|---|
| `Quick` | Users, groups, computers, DCs, Kerberos, delegation, shadow creds, machine account quota, DCSync, password policy | No |
| `Standard` | Quick + GPOs, OUs, trusts, linked GPOs, privileged group report, cross-trust enumeration | No |
| `Deep` | Standard + ACL sweep: AdminSDHolder ACEs, GPO write permissions, targeted Kerberoast paths, ACL attack paths | Yes |

```powershell
# Add ACL sweep to Standard
Collect -Preset Standard -IncludeAclSweep

# Deep without ACL sweep
Collect -Preset Deep -SkipAclSweep
```

ACL sweep is slower on large domains. In OSCP/PEN-200 labs the cost is negligible.

---

## LabMode

```powershell
Import-Module .\ADScoutPS.ps1 -LabMode
```

Expands `Find-Passwords` to also match CTF flag patterns: `OS{`, `HTB{`, `FLAG{`. In normal mode only production credential keywords are checked to reduce false positives.

---

## Findings

Every finding includes:

| Field | Description |
|---|---|
| `Severity` | Critical / High / Medium / Low / Info |
| `Category` | Finding category |
| `Title` | Short finding name |
| `Target` | The specific account, group, or object |
| `Evidence` | Raw data that triggered the finding |
| `WhyItMatters` | Plain-language risk explanation |
| `RecommendedReview` | What to do about it |
| `ManualVerify` | Copy-paste command to confirm the finding |
| `DistinguishedName` | Full DN of the affected object |

```powershell
# All findings with summary banner
Get-Findings | Get-Summary

# Critical only
Get-Findings | Where-Object Severity -eq 'Critical'

# Copy-paste verify commands for every Critical finding
Get-Findings | Where-Object Severity -eq 'Critical' | Select-Object Title, Target, ManualVerify | Format-List
```

---

## Finding coverage

| Category | Finding | Severity | Needs ACL sweep |
|---|---|---|---|
| Credential Exposure | Password/flag in readable AD field | Critical | No |
| Authentication | AS-REP roast candidate | Critical | No |
| Delegation | Unconstrained delegation on non-DC | Critical | No |
| Replication Rights | Non-standard DCSync right | Critical | No |
| Persistence | Non-standard ACE on AdminSDHolder | Critical | Yes |
| ACL Attack Path | Abusable ACE on privileged object | Critical | Yes |
| GPO Abuse | GPO write linked to privileged OU | Critical | Yes |
| Domain Configuration | Machine account quota non-zero | High | No |
| Kerberos | SPN-bearing user (Kerberoast candidate) | High/Medium | No |
| Kerberos | Targeted Kerberoast path | High | Yes |
| Shadow Credentials | msDS-KeyCredentialLink present | High/Medium | No |
| Delegation | RBCD configured | High | No |
| Password Policy | Min length < 12 or lockout disabled | High | No |
| Account Flags | PASSWD_NOTREQD / USE_DES_KEY_ONLY | High/Medium | No |
| Trusts | Bidirectional trust without SID filtering | High | No |
| Delegation | KCD configured | Medium | No |
| Privilege Hygiene | adminCount=1 object | Medium | No |
| Endpoint Hygiene | No visible LAPS metadata | Medium | No |
| Endpoint Hygiene | Stale computer account (>90 days) | Low | No |

---

## Path chain engine

Walks relationships across collected data to find multi-hop paths to DA without re-querying LDAP.

```powershell
Get-PathHints
Get-PathHints -From 'helpdesk'
Get-PathHints -To 'Domain Admins'
Get-PathHints | Sort-Object ChainSeverity | Format-List
```

Chain types detected: `ACE->Kerberoast`, `ACE->DA`, `ACE->Tier0`, `SPN->Privesc`, `ASREP->Privesc`, `GPOWrite->Tier0`, `DCSync->CredDump`.

Each chain returns: `ChainSeverity`, `ChainType`, `Principal`, `Hops`, `TerminalImpact`, `NextCommand`.

---

## Drilling deeper

```powershell
# Who's in a group (recursive, shows nesting path)
Get-Members -Identity 'Domain Admins' -Recursive
Get-Members -Identity 'Backup Operators' -Recursive

# All privileged group members
Get-ADScoutGroupReport -PrivilegedOnly -Recursive

# ACL on any object -- GUIDs resolved to right names
Get-ADACL -Identity 'Domain Admins'
Get-ADACL -Identity 'krbtgt'
Get-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=corp,DC=com'

# Kerberos
Find-ASREP
Find-SPNs
Find-SPNs | Where-Object AdminCount -eq 1

# Credential exposure
Find-Passwords
Find-Passwords -LabMode

# Delegation
Find-Delegation

# Shadow credentials
Find-Shadow

# DCSync rights
Find-DCSync

# Local admin access (live host check -- touches SMB)
Find-LocalAdmin
Find-LocalAdmin -Verbose
Find-LocalAdmin -ComputerName dc01,web04,files04

# Domain info
Get-Trusts
Get-Policy
Get-DCs
```

---

## Alternate targets

```powershell
# Explicit DC
Collect -Server dc01.corp.local

# Alternate credentials
$cred = Get-Credential
Collect -Server dc01.corp.local -Credential $cred

# Scope to an OU
Collect -SearchBase 'OU=Workstations,DC=corp,DC=local'

# Non-domain-joined box
Collect -Server dc01.corp.local -Credential $cred -SearchBase 'DC=corp,DC=local'
```

---

## Snapshots

Export a full collection for offline analysis — no domain connection needed to analyze.

```powershell
# Export after collection
Export-Run -Path .\snapshot.json

# Import on any box
Import-Module .\ADScoutPS.ps1 -LoadOnly
Import-Run -Path .\snapshot.json
Get-QuickWins
Get-PathHints
Get-Findings | Get-Summary
```

---

## Direct execution with export

For a full run that writes CSV/JSON files and an HTML report:

```powershell
# Standard run -- writes to ADScout-Results\
.\ADScoutPS.ps1 -Preset Standard -LabMode

# Full run with HTML report
.\ADScoutPS.ps1 -Preset Deep -LabMode -Report

# Custom output path
.\ADScoutPS.ps1 -Preset Standard -OutputPath C:\Assessments\Corp -LabMode

# Restricted execution policy
powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Standard -LabMode
```

---

## How it works

ADScoutPS uses `System.DirectoryServices` directly — no ActiveDirectory module, no RSAT, no binaries beyond the script. Every query is standard LDAP on port 389.

`Collect` runs once and builds a `RunData` object containing all collected data plus fast lookup indexes (`GroupMembershipIndex`, `UserGroupIndex`, `TierZeroObjects`, `ObjectByDN`, `ObjectBySam`). All analysis functions consume this object without re-querying LDAP. After `Import-Run`, analysis works identically offline.

ACE `ObjectType` GUIDs are resolved via a 60+ entry static map to human-readable right names (`User-Force-Change-Password`, `DS-Replication-Get-Changes-All`, etc.). Each ACE also includes a resolved `IdentitySid` for locale-safe privileged principal filtering — works correctly on non-English AD deployments.

---

## Caveats

- **`lastLogonTimestamp` jitter** — stale computer results carry ~14 day fuzziness by AD design
- **LAPS** — checks attribute presence, not whether the password is readable to you
- **ACL sweep** — slow on large production domains; negligible in lab environments
- **Shadow credentials** — WHFB-enrolled devices have legitimate entries; review before concluding abuse
- **DCSync expected holders** — Domain Admins, DCs, Enterprise Admins returned as `Info`; everything else is `Critical`

---

## Version history

See [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*For authorized use only. Always obtain explicit written permission before running enumeration tooling against any environment.*
