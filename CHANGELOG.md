# Changelog

## v0.7.0

- Added normalized attack-path findings engine.
- Added AS-REP roast candidate detection via `DONT_REQUIRE_PREAUTH`.
- Added unconstrained delegation detection with non-DC filtering by default.
- Added constrained delegation review for KCD and RBCD indicators.
- Added DCSync-right detection for domain-root replication GUIDs.
- Added domain trust enumeration.
- Added domain controller enumeration.
- Added default and fine-grained password policy review.
- Added `adminCount=1` privileged-object review.
- Added weak UAC flag sweep and `ConvertTo-ADScoutUacFlag` helper.
- Added LAPS visibility review per computer.
- Preserved manual CLI commands and `Invoke-ADScout -Gui` findings dashboard.
- Rebuilt module core for consistent `-Server`, `-Credential`, and `-SearchBase` support.

## v0.6.0

- Added findings-first GUI mode.
- Added normalized basic findings output.

## v0.5.0

- Added auto domain/PDC/base DN discovery.
