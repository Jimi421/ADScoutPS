# Changelog

## v1.0.0 - OperatorReady

- Preserves v0.9 CleanOps functionality.
- Adds a more operator-focused README with practical workflows.
- Expands usage documentation for module mode, standalone mode, GUI findings review, group review, and troubleshooting.
- Keeps manual CLI functionality, findings-first GUI, exports, and standalone runner intact.

## v0.9.0 - CleanOps

- Preserves v0.7 attack-path findings and v0.6 GUI behavior.
- Adds clean recursive group/member output.
- Adds `Get-ADScoutGroupReport`.
- Adds privileged group member export during `Invoke-ADScout`.
- Fixes noisy StrictMode/property errors when user objects do not have computer-only properties such as `PrimaryGroupId`.
- Hardens password policy parsing.
- Reduces duplicate raw ACL collection in `Invoke-ADScout`.
- Keeps CLI/manual workflow intact.

## v0.7.0

- Added AS-REP candidates, delegation review, DCSync detection, trusts, DCs, password policy, adminCount review, weak UAC flag sweep, LAPS status, and normalized findings.

## v0.6.0

- Added findings-first GUI dashboard with `Out-GridView`.
