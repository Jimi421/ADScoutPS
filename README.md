# ADScoutPS

> PowerShell Active Directory enumeration and findings toolkit.  
> One file. No RSAT. No ActiveDirectory module. No dependencies.

---

## What it is

ADScoutPS is a single-file PowerShell script for read-only Active Directory enumeration built for offensive operators. It collects domain data once, builds an in-memory RunData object, and runs a findings engine and path chain engine against it — no repeated LDAP queries, no re-collection, full offline analysis from a JSON snapshot.

The core question it answers: **what is the shortest path to Domain Admin from here?**

**Authorized use only.**

---

## Quick start

```powershell
# Import-Module -- loads and auto-collects
Import-Module .\ADScoutPS.ps1
Get-QuickWins

# With options
Import-Module .\ADScoutPS.ps1 -LabMode
Import-Module .\ADScoutPS.ps1 -Preset Deep -LabMode

# Load only, collect manually
Import-Module .\ADScoutPS.ps1 -LoadOnly
Collect -Preset Standard -LabMode
Get-QuickWins
```

No variables. No `-RunData`. Collection runs automatically on load and session data is stored for all analysis functions.

---

## The operator workflow

```powershell
# Import-Module auto-collects on load
Import-Module .\ADScoutPS.ps1 -LabMode

# Or collect manually after load-only
# Import-Module .\ADScoutPS.ps1 -LoadOnly
# Collect -Preset Standard -LabMode

# 1. Collection already done -- jump straight in

# 2. Shortest path to DA
Get-QuickWins

# 3. Full findings
Get-Findings | Get-Summary

# 4. Chained attack paths
Get-PathHints

# 5. Drill into anything
Get-ADACL -Identity 'Domain Admins'
Find-ASREP
Find-SPNs | Where-Object AdminCount -eq 1
Get-Members -Identity 'Domain Admins' -Recursive

# 6. Export for offline analysis
Export-Run -Path .\snapshot.json

# --- Later, no domain needed ---
Import-Run -Path .\snapshot.json
Get-QuickWins
Get-PathHints
```

Pass `-RunData` explicitly only when working with multiple RunData objects in the same session.

---

## Aliases

After dot-sourcing, short aliases are available for everything you'd type mid-engagement. Full function names always work too.

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
| `Find-ASREP` | `Find-ADScoutASREPAccount` |
| `Find-SPNs` | `Find-ADScoutSPNAccount` |
| `Find-Shadow` | `Find-ADScoutShadowCredential` |
| `Find-Passwords` | `Find-ADScoutPasswordInDescription` |
| `Find-Delegation` | `Find-ADScoutDelegationHint` |
| `Get-ADACL` | `Get-ADScoutObjectAcl` |
| `Find-DCSync` | `Find-ADScoutDCSyncRight` |
| `Find-AclPaths` | `Find-ADScoutAclAttackPath` |
| `Get-Members` | `Get-ADScoutGroupMember` |
| `Export-Run` | `Export-ADScoutRun` |
| `Import-Run` | `Import-ADScoutRun` |

---



---

## `Get-QuickWins`

The primary operator function. No noise. Just what's worth trying, in order.

```powershell
Get-QuickWins -RunData $data
```

Priority order:

| # | Category | What it means |
|---|---|---|
| 1 | Credential Exposure | Password/flag in readable AD field — instant win |
| 2 | AS-REP Roast | DA members or adminCount=1 first, then others |
| 3 | Kerberoast | DA members or adminCount=1 first, then others |
| 4 | Unconstrained Delegation | Coerce DC auth here, capture TGT |
| 5 | DCSync | Non-standard principal — if you control it, dump all hashes |
| 6 | ACL Attack Path | Abusable ACE on privileged group/DA/krbtgt/DC |
| 7 | Targeted Kerberoast | GenericWrite on user — set SPN and Kerberoast |
| 8 | Privilege Path | Nested group membership path to Domain Admins |
| 9 | GPO Abuse | Write access to GPO linked to privileged OU |

Each result includes `Target`, `Why`, `Evidence`, and a copy-paste `ManualVerify` command.

---

## Presets

| Preset | What runs | ACL sweep |
|---|---|---|
| `Quick` | Users, groups, computers, DCs, Kerberos, delegation, shadow creds, MAQ, DCSync, password policy | No |
| `Standard` | Quick + GPOs, OUs, trusts, linked GPOs, privileged group report, cross-trust enumeration | No |
| `Deep` | Standard + ACL sweep (AdminSDHolder, GPO write, targeted Kerberoast paths, ACL attack paths) | Yes |

```powershell
# Force ACL sweep on Standard
Collect -Preset Standard -IncludeAclSweep

# Deep without ACL sweep
Collect -Preset Deep -SkipAclSweep
```

---

## LabMode

Expands credential/flag detection to include CTF-style patterns (`OS{`, `HTB{`, `FLAG{`):

```powershell
$data = Collect -Preset Standard -LabMode
```

In normal mode only production credential keywords are checked.

---

## Findings

Every finding includes:

| Field | Description |
|---|---|
| `Severity` | Critical / High / Medium / Low / Info |
| `Category` | Finding category |
| `Title` | Short finding name |
| `Target` | Specific account, group, or object |
| `Evidence` | Raw data that triggered the finding |
| `WhyItMatters` | Plain-language risk explanation |
| `RecommendedReview` | What to do about it |
| `ManualVerify` | Exact copy-paste command to confirm the finding |
| `SourceCommand` | Function that produced this finding |
| `DistinguishedName` | Full DN of the affected object |

```powershell
# All findings
$data | Get-Findings | Get-Summary

# Critical only
$data | Get-Findings | Where-Object Severity -eq 'Critical'

# Show verify commands
$data | Get-Findings |
    Where-Object Severity -eq 'Critical' |
    Select-Object Title, Target, ManualVerify |
    Format-List
```

---

## Finding coverage

| Category | Finding | Severity | ACL sweep |
|---|---|---|---|
| Credential Exposure | Password/flag in readable AD field | Critical | No |
| Authentication | AS-REP roast candidate | Critical | No |
| Delegation | Unconstrained delegation on non-DC | Critical | No |
| Replication Rights | Non-standard DCSync right | Critical | No |
| Persistence | Non-standard ACE on AdminSDHolder | Critical | Yes |
| ACL Attack Path | Abusable ACE on privileged object | Critical | Yes |
| GPO Abuse | GPO write linked to privileged OU | Critical | Yes |
| Domain Configuration | Machine account quota non-zero | High | No |
| Kerberos | SPN-bearing user (Kerberoast) | High/Medium | No |
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

```powershell
Get-PathHints -RunData $data
Get-PathHints -RunData $data -From 'helpdesk'
Get-PathHints -RunData $data -To 'Domain Admins'
Get-PathHints -RunData $data | Sort-Object ChainSeverity | Format-List
```

Chain types: `ACE->Kerberoast`, `ACE->DA`, `ACE->Tier0`, `SPN->Privesc`, `ASREP->Privesc`, `GPOWrite->Tier0`, `DCSync->CredDump`.

Each chain: `ChainSeverity`, `ChainType`, `Principal`, `HopCount`, `Hops`, `TerminalImpact`, `NextCommand`.

---

## Function reference

### Collect

```powershell
Collect    -Preset Quick|Standard|Deep [-LabMode] [-SkipAclSweep] [-IncludeAclSweep]
Invoke-ADScout -Preset Quick|Standard|Deep [-LabMode] [-Report] [-Gui] [-NoExport]
```

### Analyze

```powershell
Get-QuickWins  -RunData $data    # shortest path to DA
Get-Findings   -RunData $data    # full normalized findings
Get-PathHints  -RunData $data    # chained attack paths
Get-Summary    -Findings $f      # color-coded banner
```

### Export / Import

```powershell
Export-Run -RunData $data -Path .\snapshot.json
$data = Import-Run -Path .\snapshot.json
```

### Domain

```powershell
Get-ADScoutDomainInfo
Get-Trusts                # decoded direction, type, SID filtering
Get-Policy                # default + fine-grained PSOs
Get-ADScoutMachineAccountQuota
Get-ADScoutCrossForestEnum
```

### Users / Groups / Computers

```powershell
Get-Users                 # includes HasShadowCredential, decoded UacFlags
Get-Groups
Get-Computers             # includes Description, HasShadowCredential
Get-DCs
Get-Members -Identity 'Domain Admins' -Recursive
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
Get-ADScoutPrivilegePath
```

### Kerberos / Delegation

```powershell
Find-ASREP
Find-SPNs
Find-Delegation
Find-Shadow
```

### ACL

```powershell
Get-ADACL -Identity 'Domain Admins'    # GUIDs resolved to names + IdentitySid
Find-DCSync
Find-AclPaths                         # ACL sweep
Find-ADScoutAdminSDHolderAce          # ACL sweep
Find-ADScoutGPOWritePermission        # ACL sweep
Find-ADScoutTargetedKerberoastPath    # ACL sweep
```

### Credential exposure

```powershell
Find-Passwords [-LabMode]
```

Checks: `description`, `info`, `comment`, `physicalDeliveryOfficeName`, `homeDirectory`, `scriptPath`, `profilePath`, `homePhone`, `streetAddress` on users. `description`, `info`, `comment`, `physicalDeliveryOfficeName`, `location` on computers.

### Environment

```powershell
Get-ADScoutVersion
Test-ADScoutEnvironment
```

---

## Output

`Invoke-ADScout` creates a timestamped folder with CSV/JSON per collection key, `summary.md`, `snapshot.json`, and optionally `report.html`.

```powershell
.\ADScoutPS.ps1 -OutputFormat CSV
.\ADScoutPS.ps1 -OutputFormat JSON
.\ADScoutPS.ps1 -OutputPath C:\Assessments\Corp
.\ADScoutPS.ps1 -NoExport
.\ADScoutPS.ps1 -Report
```

---

## Alternate targets

```powershell
Collect -Server dc01.corp.local
$cred = Get-Credential
Collect -Credential $cred -Server dc01.corp.local
Collect -SearchBase 'OU=Workstations,DC=corp,DC=local'
Collect -Server dc01.external.local -Credential $cred -SearchBase 'DC=external,DC=local'
```

---

## How it works

ADScoutPS uses `System.DirectoryServices` directly — no ActiveDirectory module, no RSAT. Every query is standard LDAP on port 389.

**Collection** — `Collect` (`Invoke-ADScoutCollection`) runs once and returns a `RunData` object. Indexes built once: `GroupMembershipIndex`, `UserGroupIndex`, `TierZeroObjects`, `ObjectByDN`, `ObjectBySam`.

**Analysis** — `Get-Findings` and `Get-PathHints` consume RunData without re-querying LDAP. Works fully offline after `Import-Run`.

**ACE resolution** — `ObjectType` GUIDs resolved via 60+ entry static map. `IdentitySid` resolved per ACE. Privileged exclusion uses SID suffix check first (locale-safe), display name fallback.

---

## Caveats

- `lastLogonTimestamp` carries ~14 day replication jitter — stale computer results are approximate
- LAPS checks attribute presence, not password readability
- ACL sweep is slow on large domains — gated behind `-IncludeAclSweep` / `-Preset Deep`
- Shadow credential entries may be legitimate WHFB enrollments — review before concluding abuse
- DCSync expected holders (Domain Admins, DCs, Enterprise Admins) returned as `Info`

---

## Version history

See [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT

---

*For authorized use only.*
