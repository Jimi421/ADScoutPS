# ADScoutPS Quickstart
# Run from the repository root on an authorized Windows/domain-connected lab machine.

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force

Get-ADScoutDomainInfo
Get-ADScoutUser | Select-Object -First 10
Get-ADScoutGroup | Select-Object -First 10
Get-ADScoutComputer | Select-Object -First 10
Find-ADScoutSPNAccount
Find-ADScoutPrivilegedUser -Recursive

# Fast one-command collection:
Invoke-ADScout -SkipAclSweep
