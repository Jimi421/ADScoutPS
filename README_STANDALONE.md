# ADScoutPS Standalone

`ADScout.ps1` is the single-file operator drop. You do not need the module folder on the Windows lab box for standalone use.

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Preset Quick
. .\ADScout.ps1 -LoadOnly
Test-ADScoutEnvironment
Get-ADScoutFinding -SkipAclSweep
```
