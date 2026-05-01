# ADScoutPS

> PowerShell Active Directory enumeration and findings toolkit.  
> One file. No RSAT. No ActiveDirectory module. No dependencies.

---

## What it is

ADScoutPS is a single-file PowerShell script for read-only Active Directory enumeration. It collects domain data, identifies misconfigurations, and surfaces findings with context — severity, abuse note, and recommended review — not just raw LDAP dumps.

Drop it on any Windows box with domain connectivity and run it. No installation. No companion files. No internet access required. Any authenticated domain user can run core collection.

**Authorized use only.** Use in environments where you have explicit written permission.

---

## Quick start

```powershell
# Standard run — exports CSV + JSON, prints summary banner
.\ADScoutPS.ps1

# Quick scan, no export
.\ADScoutPS.ps1 -Preset Quick -NoExport

# Full run with ACL sweep and HTML report
.\ADScoutPS.ps1 -Preset Deep -Report

# GUI findings dashboard
.\ADScoutPS.ps1 -Gui -View Findings -SkipAclSweep

# Restricted execution policy
powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Quick
```

---

## Loading functions interactively

The preferred method for interactive use is dot-sourcing:

```powershell
# Dot-source — loads all functions, does not run collection
. .\ADScoutPS.ps1 -LoadOnly

# Then run anything manually
Test-ADScoutEnvironment
Get-ADScoutDomainInfo
Get-ADScoutUser | Format-Table SamAccountName, UacFlags -AutoSize
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
```

> **Note on `Import-Module`:** `Import-Module .\ADScoutPS.ps1` works but will execute the
> entry point block unless you pass `-LoadOnly`. Using `. .\ADScoutPS.ps1 -LoadOnly` is the
> cleaner and more predictable path for interactive sessions.

---

## Presets

| Preset | What runs | ACL sweep |
|---|---|---|
| `Quick` | Core objects — users, groups, computers, DCs, Kerberos, delegation, LAPS, password policy, shadow credentials, machine account quota | No |
| `Standard` | Quick + GPOs, OUs, trusts (decoded), linked GPO map, privileged group report, cross-trust enumeration | No |
| `Deep` | Standard + full ACL sweep — AdminSDHolder, GPO write perms, targeted Kerberoast paths, ACL attack paths | Yes |

Force ACL sweep on or off regardless of preset:

```powershell
.\ADScoutPS.ps1 -Preset Standard -IncludeAclSweep   # add ACL sweep to Standard
.\ADScoutPS.ps1 -Preset Deep -SkipAclSweep           # Deep without ACL sweep
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
# All findings, no ACL sweep
Get-ADScoutFinding -SkipAclSweep

# With full ACL sweep
Get-ADScoutFinding -IncludeAclSweep

# Filter by severity
Get-ADScoutFinding -SkipAclSweep | Where-Object Severity -eq 'Critical'

# Pipe to summary banner
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
```

### Finding coverage

| Category | Finding | Severity | ACL sweep required |
|---|---|---|---|
| Credential Exposure | Password in AD description field | Critical | No |
| Authentication | AS-REP roast candidate (preauth disabled) | Critical | No |
| Delegation | Unconstrained delegation on non-DC | Critical | No |
| Replication Rights | DCSync right held by non-privileged principal | Critical | No |
| Persistence | Non-standard ACE on AdminSDHolder | Critical | Yes |
| ACL Attack Path | Abusable ACE on privileged group / DA / krbtgt / DC | Critical | Yes |
| GPO Abuse | GPO write access linked to privileged OU | Critical | Yes |
| Domain Configuration | Machine account quota is non-zero | High | No |
| Kerberos | SPN-bearing user account (Kerberoast candidate) | High / Medium | No |
| Kerberos | Targeted Kerberoast path (GenericAll/Write on user) | High | Yes |
| Shadow Credentials | msDS-KeyCredentialLink present | High / Medium | No |
| Delegation | RBCD configured | High | No |
| Password Policy | Min length < 12 or lockout disabled | High | No |
| Account Flags | PASSWD_NOTREQD / ENCRYPTED_TEXT_PWD / USE_DES_KEY_ONLY | High / Medium | No |
| Trusts | Bidirectional trust without SID filtering | High | No |
| Delegation | KCD configured | Medium | No |
| Privilege Hygiene | adminCount=1 object (current or historical) | Medium | No |
| Endpoint Hygiene | No visible LAPS metadata | Medium | No |
| Endpoint Hygiene | Stale computer account (>90 days) | Low | No |
| Trusts | Domain trust inventory | Info | No |
| Domain Controllers | DC inventory | Info | No |

---

## Function reference

### Environment

```powershell
Get-ADScoutVersion
Test-ADScoutEnvironment
Test-ADScoutEnvironment -Server dc01.corp.local -Credential $cred
```

`Test-ADScoutEnvironment` validates domain discovery, LDAP bind, current identity, PowerShell version, machine account quota, and Out-GridView availability before a full collection run.

---

### Domain

```powershell
Get-ADScoutDomainInfo
Get-ADScoutDomainTrust        # decoded direction, type, SID filtering, forest trust flags
Get-ADScoutPasswordPolicy     # default domain + fine-grained PSOs
Get-ADScoutMachineAccountQuota
```

`Get-ADScoutDomainTrust` decodes `TrustDirection` (Bidirectional/Inbound/Outbound/Disabled) and `TrustType` (Uplevel/Downlevel/MIT/DCE) and adds `SIDFilteringEnabled`, `IsTransitive`, and `IsForestTrust` as explicit boolean fields.

`Get-ADScoutMachineAccountQuota` reads `ms-DS-MachineAccountQuota`. Non-zero means any authenticated user can join machines to the domain — a prerequisite for RBCD and shadow credential attacks.

---

### Cross-trust enumeration

```powershell
Get-ADScoutCrossForestEnum
Get-ADScoutCrossForestEnum -Credential $cred
```

Follows trust relationships and attempts collection from each reachable trusted domain — DC count, user count, computer count. Skips outbound-only trusts. Returns `Status`, `SIDFilteringEnabled`, and `IsForestTrust` per domain.

---

### Users

```powershell
Get-ADScoutUser
Get-ADScoutUser | Where-Object { $_.AdminCount -eq 1 }
Get-ADScoutUser | Where-Object { $_.HasShadowCredential }
Get-ADScoutUser | Where-Object { $_.ServicePrincipalName }
```

All users include:
- `UacFlags` — decoded UAC flag names (e.g. `NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD`)
- `HasShadowCredential` — `$true` if `msDS-KeyCredentialLink` is set
- `AdminCount` — `1` if SDProp has applied

```powershell
ConvertTo-ADScoutUacFlag -UserAccountControl 66048
# Returns: NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

---

### Groups

```powershell
Get-ADScoutGroup
Find-ADScoutAdminGroup         # groups matching admin/operator/backup name patterns

Get-ADScoutGroupMember -Identity 'Domain Admins'
Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive

Get-ADScoutGroupReport -GroupName 'Domain Admins','Backup Operators' -Recursive
Get-ADScoutGroupReport -PrivilegedOnly -Recursive

Get-ADScoutPrivilegePath       # users with a path to a privileged group
```

`Get-ADScoutGroupMember` resolves every member DN and returns `MemberObjectClass`, nesting depth, and the full membership path string (e.g. `Domain Admins -> nested_group -> user`).

---

### Computers

```powershell
Get-ADScoutComputer            # includes Description and HasShadowCredential
Get-ADScoutDomainController
Get-ADScoutLapsStatus
Find-ADScoutOldComputer        # default 90 days
Find-ADScoutOldComputer -Days 60
```

`Get-ADScoutComputer` includes `Description` — needed for `Find-ADScoutPasswordInDescription` to check computer accounts. `HasShadowCredential` is `$true` if `msDS-KeyCredentialLink` is set.

`Get-ADScoutLapsStatus` checks both legacy LAPS (`ms-Mcs-AdmPwdExpirationTime`) and Windows LAPS (`msLAPS-PasswordExpirationTime`). Actual password readability depends on your delegation rights.

---

### Kerberos

```powershell
Find-ADScoutASREPAccount       # DONT_REQUIRE_PREAUTH set
Get-ADScoutAsRepRoastCandidate # alias
Find-ADScoutSPNAccount         # servicePrincipalName set (Kerberoast candidates)
```

---

### Delegation

```powershell
Find-ADScoutUnconstrainedDelegation
Find-ADScoutUnconstrainedDelegation -IncludeDomainControllers
Find-ADScoutConstrainedDelegation   # returns KCD and RBCD
Find-ADScoutDelegationHint          # both in one call
```

---

### Shadow credentials

```powershell
Find-ADScoutShadowCredential
```

Finds accounts with `msDS-KeyCredentialLink` set. Legitimate entries exist for Windows Hello for Business enrolled devices. Unexpected entries allow TGT retrieval without knowing the account password.

---

### ACL

```powershell
# ACL on any object — GUIDs resolved to human-readable right names
Get-ADScoutObjectAcl -Identity 'Domain Admins' -ObjectClass group
Get-ADScoutObjectAcl -Identity 'krbtgt'
Get-ADScoutObjectAcl -DistinguishedName 'CN=krbtgt,CN=Users,DC=corp,DC=local'

# Interesting ACEs on the domain root
Find-ADScoutInterestingAce

# Specific object
Find-ADScoutInterestingAce -Identity 'Domain Admins'

# DCSync rights — non-privileged holders Critical, expected holders Info
Find-ADScoutDCSyncRight

# ACL attack paths on all high-value targets (ACL sweep)
Find-ADScoutAclAttackPath
Find-ADScoutAclAttackPath | Where-Object { $_.Rights -match 'GenericAll|WriteDacl' }

# AdminSDHolder non-standard ACEs (ACL sweep)
Find-ADScoutAdminSDHolderAce

# GPO write permissions (ACL sweep)
Find-ADScoutGPOWritePermission
Find-ADScoutGPOWritePermission | Where-Object AppliesToPrivOu

# Targeted Kerberoast paths (ACL sweep)
Find-ADScoutTargetedKerberoastPath
```

**ACE output fields:**

| Field | Description |
|---|---|
| `IdentityReference` | Display name of the principal (e.g. `CORP\helpdesk`) |
| `IdentitySid` | Resolved SID string — locale-safe privileged identity filtering |
| `ActiveDirectoryRights` | Raw AD rights flags |
| `ObjectType` | Human-readable extended right / attribute name (GUID resolved) |
| `ObjectTypeGuid` | Raw GUID (preserved for programmatic use) |
| `InheritedObjectType` | Resolved inherited scope name |
| `InheritedObjectTypeGuid` | Raw inherited GUID |
| `IsInherited` | Whether the ACE is inherited |

**`Find-ADScoutAclAttackPath`** sweeps ACLs on all privileged groups, `krbtgt`, every DA member account, and every DC. Non-privileged principals with abusable rights returned. Exclusions use `Test-ADScoutPrivilegedIdentity` — SID-suffix check first (locale-safe), display name second (English fallback).

**`Find-ADScoutAdminSDHolderAce`** sweeps `CN=AdminSDHolder,CN=System,...`. Non-standard ACEs here propagate to all `adminCount=1` objects every 60 minutes via SDProp.

**`Find-ADScoutGPOWritePermission`** maps GPO ACLs to linked OUs. Write access to a GPO linked to a privileged OU is Critical — modify the GPO, get SYSTEM on every machine in scope.

**`Find-ADScoutTargetedKerberoastPath`** finds `GenericAll`/`GenericWrite` on user objects — enough to set a SPN and Kerberoast the TGS even with no pre-existing SPN.

---

### Credential exposure

```powershell
Find-ADScoutPasswordInDescription
```

Scans all user and computer `description` fields for password-related keywords. Description is readable by all authenticated domain users by default.

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
$findings = Get-ADScoutFinding -SkipAclSweep

Get-ADScoutSummary
Get-ADScoutSummary -Findings $findings
$findings | Get-ADScoutSummary

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
└── Run-20260501-143022\
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
    ├── MachineAccountQuota.csv / .json
    ├── PasswordInDescription.csv / .json
    ├── SPNAccounts.csv / .json
    ├── ASREPAccounts.csv / .json
    ├── ShadowCredentials.csv / .json
    ├── Delegation.csv / .json
    ├── AclAttackPaths.csv / .json
    ├── AdminSDHolderAces.csv / .json
    ├── GPOWritePermissions.csv / .json
    ├── TargetedKerberoastPaths.csv / .json
    ├── CrossForest.csv / .json
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

```powershell
.\ADScoutPS.ps1 -OutputFormat CSV
.\ADScoutPS.ps1 -OutputFormat JSON
.\ADScoutPS.ps1 -OutputPath C:\Temp\ADScan
.\ADScoutPS.ps1 -NoExport
.\ADScoutPS.ps1 -Report
```

---

## Alternate targets

```powershell
Invoke-ADScout -Server dc01.corp.local
$cred = Get-Credential
Invoke-ADScout -Credential $cred -Server dc01.corp.local
Invoke-ADScout -SearchBase 'OU=Workstations,DC=corp,DC=local'
Invoke-ADScout -Server dc01.external.local -Credential $cred -SearchBase 'DC=external,DC=local'
```

---

## How it works

ADScoutPS uses `System.DirectoryServices` — the .NET namespace that wraps LDAP — directly. No ActiveDirectory module, no RSAT, no binaries beyond the script itself. Every query is a standard LDAP search against port 389. The CLR already present on any Windows system is the only runtime requirement.

ACL reads use `DirectoryEntry.ObjectSecurity.Access` to retrieve the DACL. `ObjectType` and `InheritedObjectType` GUIDs are resolved against a built-in static map of 60+ AD schema and extended rights GUIDs. `IdentitySid` is resolved per ACE using `NTAccount.Translate(SecurityIdentifier)` with a graceful `$null` fallback. Privileged identity exclusion in all ACL sweep functions uses `Test-ADScoutPrivilegedIdentity`, which checks resolved SID suffix first (locale-safe) and falls back to display name matching — making the tool correct on non-English Active Directory deployments.

---

## Caveats

**`lastLogonTimestamp` jitter** — stale computer detection uses `lastLogonTimestamp`, which AD replicates on a 9–14 day interval by design. Results carry up to ~2 weeks of inherent fuzziness.

**LAPS visibility** — `Get-ADScoutLapsStatus` checks for attribute presence, not password readability. Whether the current user can read the password value depends on delegation in the environment.

**ACL sweep performance** — `Find-ADScoutAclAttackPath` and `Find-ADScoutTargetedKerberoastPath` perform per-object ACL reads. On large production domains this will be slow. Both are gated behind `-IncludeAclSweep` / `-Preset Deep`. In OSCP/PEN-200 lab environments the cost is negligible.

**ACL sweep noise** — in highly customized environments, legitimate delegations may surface as findings. Review each result in context.

**DCSync expected holders** — `Find-ADScoutDCSyncRight` always enumerates all replication rights holders. Principals matching well-known SID suffixes (`-512`, `-516`, `-518`, `-519`, `S-1-5-18`, `S-1-5-9`) are returned as `Info`. Everything else is `Critical`.

**Shadow credentials** — `Find-ADScoutShadowCredential` flags all accounts with `msDS-KeyCredentialLink` set. Legitimate entries exist for Windows Hello for Business enrolled devices. Review each entry before concluding abuse.

---

## Version history

See [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*For authorized use only. Always obtain explicit written permission before running enumeration tooling against any environment.*
