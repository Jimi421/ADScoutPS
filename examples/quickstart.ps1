Import-Module "$PSScriptRoot\..\ADScoutPS\ADScoutPS.psd1" -Force

# Fast first pass
Invoke-ADScout -SkipAclSweep

# Findings dashboard where Out-GridView is available
Invoke-ADScout -Gui -SkipAclSweep

# Manual finding review
Get-ADScoutFinding | Sort-Object Severity,Category,Title
