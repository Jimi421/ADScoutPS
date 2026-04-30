# Changelog

## v1.2.0 - WorldClassFoundation

- Added `Test-ADScoutEnvironment` preflight validation.
- Added `Get-ADScoutVersion`.
- Added normalized findings with identity/timestamp fields.
- Added `Invoke-ADScout -Preset Quick|Standard|Deep`.
- Added `Invoke-ADScout -Report` with offline HTML report output.
- Added GUI view selection with `-View Findings|PrivilegedGroups|Delegation|Users|Computers|All`.
- Added `Get-ADScoutPrivilegePath`.
- Added static Pester tests and standalone build tooling.
- Preserved CLI/manual mode and single-file standalone `ADScout.ps1`.

## v1.1.0

- Bugfixes for missing properties and ACL parameter binding.
