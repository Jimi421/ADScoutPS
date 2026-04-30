@{
    RootModule        = 'ADScoutPS.psm1'
    ModuleVersion     = '0.4.0'
    GUID              = 'b88ad47a-cc7e-4d7b-9735-8f50e1af6a44'
    Author            = 'Braxton Bailey'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Braxton Bailey. All rights reserved.'
    Description       = 'PowerShell Active Directory enumeration toolkit for authorized labs, OSCP preparation, and approved internal assessments.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Get-ADScoutDomainInfo',
        'Get-ADScoutUser',
        'Get-ADScoutGroup',
        'Get-ADScoutComputer',
        'Find-ADScoutAdminGroup',
        'Find-ADScoutSPNAccount',
        'Get-ADScoutGPO',
        'Get-ADScoutOU',
        'Get-ADScoutLinkedGPO',
        'Get-ADScoutObjectAcl',
        'Find-ADScoutInterestingAce',
        'Get-ADScoutGroupMember',
        'Find-ADScoutPrivilegedUser',
        'Find-ADScoutDelegationHint',
        'Find-ADScoutOldComputer',
        'Invoke-ADScout'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory','LDAP','PowerShell','OSCP','Security','Enumeration')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/jimi421/ADScoutPS'
            ReleaseNotes = 'v0.4.0 adds comment-based help and tab completion support.'
        }
    }
}
