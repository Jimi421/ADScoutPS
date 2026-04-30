# ADScoutPS Standalone Runner

`ADScout.ps1` is a one-file launcher that embeds the ADScoutPS module logic so it can be dropped onto an authorized Windows lab box and run quickly.

## Run Collection

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -SkipAclSweep
```

## Run Findings GUI

```powershell
powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Gui -SkipAclSweep
```

## Load Functions for Manual Use

```powershell
. .\ADScout.ps1 -LoadOnly
```

Then run manual commands:

```powershell
Get-ADScoutDomainInfo
Get-ADScoutFinding
Get-ADScoutGroupReport -PrivilegedOnly -Recursive
Find-ADScoutSPNAccount
Find-ADScoutASREPAccount
Find-ADScoutWeakUacFlag
```

## Notes

- Use `-SkipAclSweep` first for a faster, lower-noise run.
- Use CLI output as the source of truth if GUI mode is unavailable.
- Keep the generated `ADScout-Results` folder for notes and screenshots.
