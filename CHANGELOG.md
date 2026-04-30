# Changelog

## v0.4.0

- Added comment-based help to exported functions.
- Added tab completion support through `ADScoutPS.Completion.ps1`.
- Added completion for `Invoke-ADScout -OutputFormat`.
- Added completion for `Invoke-ADScout -OutputPath`.
- Added live LDAP-backed completion for `-DistinguishedName` where supported.
- Added live LDAP-backed completion for `Get-ADScoutGroupMember -Identity`.
- Improved README and usage documentation.

## v0.3.0

- Added `Invoke-ADScout` easy-mode collection.
- Added CSV / JSON export support.
- Added Markdown summary output.
- Added `-Server` and `-Credential` support.
- Added recursive group membership and privileged membership review.

## v0.2.0

- Added GPO discovery.
- Added OU discovery.
- Added linked GPO review.
- Added ACL / ACE inspection.
- Added interesting ACE filtering.

## v0.1.0

- Initial ADScoutPS module.
- Added domain, user, group, computer, admin group, and SPN account enumeration.
