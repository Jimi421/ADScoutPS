Import-Module .\ADScoutPS\ADScoutPS.psd1 -Force

Get-ADScoutDomainInfo
Invoke-ADScout -SkipAclSweep
Get-ADScoutFinding -SkipAclSweep

# Clean nested group review
Get-ADScoutGroupReport -PrivilegedOnly -Recursive |
    Format-Table Group,ParentGroup,Member,MemberType,Depth -AutoSize
