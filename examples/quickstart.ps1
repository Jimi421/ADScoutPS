Import-Module "$PSScriptRoot\..\ADScoutPS\ADScoutPS.psd1" -Force

# Fast findings-first GUI review
Invoke-ADScout -Gui -SkipAclSweep

# Manual follow-up examples
Get-ADScoutDomainInfo
Find-ADScoutSPNAccount
Find-ADScoutPrivilegedUser -Recursive
Find-ADScoutDelegationHint
