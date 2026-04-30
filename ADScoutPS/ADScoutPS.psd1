@{
    RootModule        = 'ADScoutPS.psm1'
    ModuleVersion     = '0.7.0'
    GUID              = 'b88ad47a-cc7e-4d7b-9735-8f50e1af6a44'
    Author            = 'Braxton Bailey'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026 Braxton Bailey. All rights reserved.'
    Description       = 'PowerShell Active Directory enumeration toolkit for authorized labs, OSCP preparation, and approved internal assessments.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'ConvertTo-ADScoutUacFlag',
        'Get-ADScoutDomainInfo',
        'Get-ADScoutUser',
        'Get-ADScoutGroup',
        'Get-ADScoutComputer',
        'Get-ADScoutDomainController',
        'Get-ADScoutDomainTrust',
        'Get-ADScoutPasswordPolicy',
        'Get-ADScoutLapsStatus',
        'Find-ADScoutAdminGroup',
        'Find-ADScoutSPNAccount',
        'Find-ADScoutASREPAccount',
        'Find-ADScoutUnconstrainedDelegation',
        'Find-ADScoutConstrainedDelegation',
        'Find-ADScoutAdminSDHolderOrphan',
        'Find-ADScoutWeakUacFlag',
        'Find-ADScoutDCSyncRight',
        'Get-ADScoutGPO',
        'Get-ADScoutOU',
        'Get-ADScoutLinkedGPO',
        'Get-ADScoutObjectAcl',
        'Find-ADScoutInterestingAce',
        'Get-ADScoutGroupMember',
        'Find-ADScoutPrivilegedUser',
        'Find-ADScoutDelegationHint',
        'Find-ADScoutOldComputer',
        'Get-ADScoutFinding',
        'Show-ADScoutFindingsGui',
        'Invoke-ADScout'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    PrivateData = @{
        PSData = @{
            Tags = @('ActiveDirectory','LDAP','PowerShell','OSCP','Security','Enumeration','ACL','GPO','Kerberos')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/jimi421/ADScoutPS'
            ReleaseNotes = 'v0.7.0 adds attack-path findings: AS-REP candidates, delegation review, DCSync-right detection, trusts, DCs, password policy, adminCount review, UAC flag sweep, LAPS status, and improved findings output.'
        }
    }
}
