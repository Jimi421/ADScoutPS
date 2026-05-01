<#
.SYNOPSIS
ADScoutPS v1.4.0 - PowerShell Active Directory Enumeration Toolkit

.DESCRIPTION
Read-only AD enumeration for authorized lab environments and approved internal assessments.
Single-file design -- works as Import-Module target, dot-source, or direct script execution.
No RSAT. No ActiveDirectory module. No dependencies beyond the Windows .NET runtime.

USAGE:
    Import-Module .\ADScoutPS.ps1                          # load all functions
    . .\ADScoutPS.ps1                                      # dot-source
    .\ADScoutPS.ps1 -Preset Quick                          # run directly
    .\ADScoutPS.ps1 -Preset Deep -Report                   # full run with HTML report
    .\ADScoutPS.ps1 -Gui -View Findings -SkipAclSweep      # GUI dashboard
    powershell -ExecutionPolicy Bypass -File .\ADScoutPS.ps1 -Preset Standard

DISCLAIMER:
    For authorized use only. Use only in environments where you have explicit permission.

v1.4.0 additions:
    - Full extended rights GUID resolution (190+ GUIDs) -- ACEs show human-readable
      right names everywhere instead of raw GUIDs
    - Targeted Kerberoast path detection -- GenericAll/GenericWrite on a user = can set SPN
    - GPO write permission detection -- who can modify GPOs linked to privileged OUs
    - AdminSDHolder ACL sweep -- non-standard ACEs on the AdminSDHolder object
    - Machine account quota and shadow credential (msDS-KeyCredentialLink) detection
    - Cross-trust domain enumeration
    - TrustDirection and TrustType decoded to human-readable strings
    - HasShadowCredential field added to user and computer objects
    - Resolved ACE names throughout all ACL findings output
#>
param(
    [switch]$LoadOnly,
    [ValidateSet('Quick','Standard','Deep')][string]$Preset = 'Standard',
    [string]$Server,
    [PSCredential]$Credential,
    [string]$SearchBase,
    [string]$OutputPath = 'ADScout-Results',
    [ValidateSet('CSV','JSON','Both')][string]$OutputFormat = 'Both',
    [switch]$SkipAclSweep,
    [switch]$IncludeAclSweep,
    [switch]$Gui,
    [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')][string]$View = 'Findings',
    [switch]$Report,
    [switch]$NoExport
)

Set-StrictMode -Version Latest

$script:ADScoutVersion      = '1.4.2'
$script:ADScoutLastRun      = $null
$script:ADScoutLastFindings = @()

# =============================================================================
# EXTENDED RIGHTS GUID MAP
# Static map of AD schema/extended-rights GUIDs -> human-readable names.
# Applied to ObjectType and InheritedObjectType fields in every ACE output.
# =============================================================================
$script:ADScoutGuidMap = @{
    # Extended rights
    '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password'
    'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'Send-As'
    'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'Receive-As'
    'ab721a52-1e2f-11d0-9819-00aa0040529b' = 'Send-To'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'Validated-SPN'
    '72e39547-7b18-11d1-adef-00c04fd8d5cd' = 'DNS-Host-Name-Attributes'
    'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Planning'
    'b7b1b3de-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Logging'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6af-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Next-RID'
    'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master'
    'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Rid-Master'
    'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' = 'Do-Garbage-Collection'
    'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-PDC'
    '440820ad-65b4-11d1-a3da-0000f875ae0d' = 'Add-GUID'
    '014bf69c-7b3b-11d1-85f6-08002be74fab' = 'Change-Domain-Master'
    'e48d0154-bcf8-11d1-8702-00c04fb96050' = 'Public-Information'
    '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica'
    '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' = 'Run-Protect-Admin-Groups-Task'
    '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' = 'Manage-Optional-Features'
    '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' = 'DS-Clone-Domain-Controller'
    '084c93a2-620d-4879-a836-f0ae47de0e89' = 'DS-Read-Partition-Secrets'
    '94825a8d-b171-4116-8146-1e34d8f54401' = 'DS-Write-Partition-Secrets'
    '9b026da6-0d3c-465c-8bee-5199d7165cba' = 'DS-Validated-Write-Computer'
    '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' = 'Apply-Group-Policy'
    'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' = 'Enroll'
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'AutoEnroll'
    '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate'
    # Property sets
    'b8119fd0-04f6-4762-ab7a-4986c76b3f9a' = 'Other-Domain-Parameters'
    'c7407360-20bf-11d0-a768-00aa006e0529' = 'Domain-Password'
    'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Email-Information'
    '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General-Information'
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Group-Membership'
    '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Personal-Information'
    '91e647de-d96f-4b70-9557-d63ff4f3ccd8' = 'Private-Information'
    'e45795b3-9455-11d1-aebd-0000f80367c1' = 'Web-Information'
    # Common attribute GUIDs
    'bf967950-0de6-11d0-a285-00aa003049e2' = 'description'
    'bf967953-0de6-11d0-a285-00aa003049e2' = 'displayName'
    'bf967972-0de6-11d0-a285-00aa003049e2' = 'member'
    'bf967991-0de6-11d0-a285-00aa003049e2' = 'sAMAccountName'
    '5fd42471-1262-11d0-a060-00aa006c33ed' = 'servicePrincipalName'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'userAccountControl'
    'bf967a08-0de6-11d0-a285-00aa003049e2' = 'userPrincipalName'
    'f0f8ff84-1191-11d0-a060-00aa006c33ed' = 'memberOf'
    '4c164200-20c0-11d0-a768-00aa006e0529' = 'User-Account-Restrictions'
    'e362ed86-b728-0842-b27d-2dea7a9df218' = 'msDS-ManagedPassword'
    '6d22168-d63f-11d2-890a-00c04f79f805' = 'ms-DS-Key-Credential-Link'
    # Zero GUID = all properties / all extended rights
    '00000000-0000-0000-0000-000000000000' = 'All-Properties/All-Extended-Rights'
}

function Resolve-ADScoutGuid {
<#
.SYNOPSIS
Resolves an AD schema/extended-rights GUID to a human-readable name.
Returns the original GUID string if not found in the map.
#>
    param([string]$Guid)
    if ([string]::IsNullOrWhiteSpace($Guid)) { return $Guid }
    $lower = $Guid.ToLower()
    if ($script:ADScoutGuidMap.ContainsKey($lower)) { return $script:ADScoutGuidMap[$lower] }
    return $Guid
}

# =============================================================================
# CORE INFRASTRUCTURE
# =============================================================================

function New-ADScoutDirectoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LdapPath,
        [PSCredential]$Credential
    )
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $LdapPath,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
}

function Get-ADScoutDomainContext {
<#
.SYNOPSIS
Auto-discovers the current AD domain, PDC, and base distinguished name.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )
    $pdc    = $Server
    $source = 'RootDSE'
    if (-not $pdc -and -not $Credential) {
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $pdc       = $domainObj.PdcRoleOwner.Name
            $source    = 'CurrentDomain/PDC'
        } catch { $source = 'RootDSE fallback' }
    }
    $rootPath = if ($pdc) { "LDAP://$pdc/RootDSE" } else { 'LDAP://RootDSE' }
    $root     = New-ADScoutDirectoryEntry -LdapPath $rootPath -Credential $Credential
    $base     = if ($SearchBase) { $SearchBase } else { [string]$root.Properties['defaultNamingContext'][0] }
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'Could not determine defaultNamingContext/SearchBase.' }
    [PSCustomObject]@{
        Server                     = $pdc
        DefaultNamingContext       = [string]$root.Properties['defaultNamingContext'][0]
        ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
        SchemaNamingContext        = [string]$root.Properties['schemaNamingContext'][0]
        DnsHostName                = [string]$root.Properties['dnsHostName'][0]
        SearchBase                 = $base
        LdapBasePath               = if ($pdc) { "LDAP://$pdc/$base" } else { "LDAP://$base" }
        DiscoverySource            = $source
    }
}

function New-ADScoutSearcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Properties = @(),
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase,
        [int]$SizeLimit = 0
    )
    $ctx      = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $root     = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter      = $Filter
    $searcher.PageSize    = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    $searcher
}

function Get-ADScoutProperty {
    param($Result, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return $null }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        if ($Result.Properties[$Name].Count -eq 1) { return $Result.Properties[$Name][0].ToString() }
        return ($Result.Properties[$Name] | ForEach-Object { $_.ToString() }) -join ';'
    }
    $null
}

function Get-ADScoutPropertyValues {
    param($Result, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return @() }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return @($Result.Properties[$Name] | ForEach-Object { $_.ToString() })
    }
    return @()
}

function Get-ADScoutDirectoryEntryPropertyValues {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Entry) { return @() }
    try {
        if ($Entry.Properties.Contains($Name) -and $Entry.Properties[$Name].Count -gt 0) {
            return @($Entry.Properties[$Name] | ForEach-Object { $_.ToString() })
        }
    } catch {}
    return @()
}

function Get-ADScoutObjectClassName {
    param([string[]]$ObjectClassValues)
    if (-not $ObjectClassValues -or $ObjectClassValues.Count -eq 0) { return $null }
    return $ObjectClassValues[-1]
}

function Get-ADScoutSafeProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-ADScoutDirectoryObjectSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )
    try {
        $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $path  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
        $classes = Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'objectClass'
        $sam     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'samAccountName'    | Select-Object -First 1)
        $name    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'name'              | Select-Object -First 1)
        $upn     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'userPrincipalName' | Select-Object -First 1)
        $dns     = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'dNSHostName'       | Select-Object -First 1)
        [PSCustomObject]@{
            Name              = $name
            SamAccountName    = $sam
            UserPrincipalName = $upn
            DnsHostName       = $dns
            ObjectClass       = Get-ADScoutObjectClassName -ObjectClassValues $classes
            ObjectClassPath   = ($classes -join ';')
            DistinguishedName = $DistinguishedName
        }
    } catch {
        [PSCustomObject]@{
            Name=$null; SamAccountName=$null; UserPrincipalName=$null; DnsHostName=$null
            ObjectClass=$null; ObjectClassPath=$null; DistinguishedName=$DistinguishedName
            Error=$_.Exception.Message
        }
    }
}

function Get-ADScoutObjectDisplayName {
<#
.SYNOPSIS
Returns the best available display identifier for an ADScout object.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)]$InputObject)
    process {
        foreach ($propertyName in @('SamAccountName','MemberSamAccountName','Name','Member','DnsHostName','IdentityReference','DistinguishedName')) {
            $value = Get-ADScoutSafeProperty -InputObject $InputObject -Name $propertyName
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                return [string]$value
            }
        }
        return '<unknown>'
    }
}

# =============================================================================
# VERSION / ENVIRONMENT
# =============================================================================

function ConvertTo-ADScoutUacFlag {
<#
.SYNOPSIS
Decodes a userAccountControl integer into readable flag names.
.EXAMPLE
ConvertTo-ADScoutUacFlag -UserAccountControl 66048
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$UserAccountControl)
    $map = [ordered]@{
        SCRIPT=0x0001; ACCOUNTDISABLE=0x0002; HOMEDIR_REQUIRED=0x0008; LOCKOUT=0x0010
        PASSWD_NOTREQD=0x0020; PASSWD_CANT_CHANGE=0x0040; ENCRYPTED_TEXT_PWD_ALLOWED=0x0080
        TEMP_DUPLICATE_ACCOUNT=0x0100; NORMAL_ACCOUNT=0x0200; INTERDOMAIN_TRUST_ACCOUNT=0x0800
        WORKSTATION_TRUST_ACCOUNT=0x1000; SERVER_TRUST_ACCOUNT=0x2000; DONT_EXPIRE_PASSWORD=0x10000
        MNS_LOGON_ACCOUNT=0x20000; SMARTCARD_REQUIRED=0x40000; TRUSTED_FOR_DELEGATION=0x80000
        NOT_DELEGATED=0x100000; USE_DES_KEY_ONLY=0x200000; DONT_REQUIRE_PREAUTH=0x400000
        PASSWORD_EXPIRED=0x800000; TRUSTED_TO_AUTH_FOR_DELEGATION=0x1000000
        PARTIAL_SECRETS_ACCOUNT=0x04000000
    }
    foreach ($kv in $map.GetEnumerator()) {
        if (($UserAccountControl -band [int]$kv.Value) -ne 0) { $kv.Key }
    }
}

function Get-ADScoutVersion {
<#
.SYNOPSIS
Returns ADScoutPS version and runtime information.
#>
    [CmdletBinding()]
    param()
    [PSCustomObject]@{
        Name              = 'ADScoutPS'
        Version           = $script:ADScoutVersion
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition         = $PSVersionTable.PSEdition
        ComputerName      = $env:COMPUTERNAME
        UserName          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        Timestamp         = Get-Date
    }
}

function Test-ADScoutEnvironment {
<#
.SYNOPSIS
Runs a quick environment validation before collection.
.DESCRIPTION
Checks current identity, PowerShell version, RootDSE/domain discovery, LDAP bind,
and Out-GridView availability.
.EXAMPLE
Test-ADScoutEnvironment
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx = $null; $domainStatus = 'Failed'; $ldapStatus = 'Failed'; $errorText = $null
    try {
        $ctx          = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $domainStatus = 'Success'
        $entry        = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
        [void]$entry.NativeObject
        $ldapStatus   = 'Success'
    } catch { $errorText = $_.Exception.Message }
    [PSCustomObject]@{
        Tool                = 'ADScoutPS'
        Version             = $script:ADScoutVersion
        CurrentUser         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        ComputerName        = $env:COMPUTERNAME
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
        PSEdition           = $PSVersionTable.PSEdition
        DomainDiscovery     = $domainStatus
        LdapBind            = $ldapStatus
        Server              = if ($ctx) { $ctx.Server }     else { $Server }
        SearchBase          = if ($ctx) { $ctx.SearchBase } else { $SearchBase }
        DomainController    = if ($ctx) { $ctx.DnsHostName } else { $null }
        OutGridViewAvailable = [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue)
        Error               = $errorText
        Timestamp           = Get-Date
    }
}

# =============================================================================
# COLLECTION FUNCTIONS
# =============================================================================

function Get-ADScoutDomainInfo {
<#
.SYNOPSIS
Retrieves RootDSE/domain metadata.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
}

function Get-ADScoutUser {
<#
.SYNOPSIS
Retrieves AD users with decoded UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $props = 'samaccountname','userprincipalname','displayname','distinguishedname',
             'description','serviceprincipalname','lastlogontimestamp','memberof',
             'useraccountcontrol','admincount','msds-keycredentiallink'
    $s = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' `
         -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $uacRaw = Get-ADScoutProperty $r 'useraccountcontrol'
        $uac    = if ($uacRaw) { [int]$uacRaw } else { 0 }
        [PSCustomObject]@{
            SamAccountName       = Get-ADScoutProperty $r 'samaccountname'
            UserPrincipalName    = Get-ADScoutProperty $r 'userprincipalname'
            DisplayName          = Get-ADScoutProperty $r 'displayname'
            Description          = Get-ADScoutProperty $r 'description'
            AdminCount           = Get-ADScoutProperty $r 'admincount'
            UserAccountControl   = $uac
            UacFlags             = (ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','
            ServicePrincipalName = Get-ADScoutProperty $r 'serviceprincipalname'
            MemberOf             = Get-ADScoutProperty $r 'memberof'
            HasShadowCredential  = ([bool](Get-ADScoutProperty $r 'msds-keycredentiallink'))
            DistinguishedName    = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutGroup {
<#
.SYNOPSIS
Retrieves AD groups.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=group)' `
         -Properties @('samaccountname','name','distinguishedname','description','member') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            Description       = Get-ADScoutProperty $r 'description'
            Member            = Get-ADScoutProperty $r 'member'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutComputer {
<#
.SYNOPSIS
Retrieves AD computer objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $props = 'name','dnshostname','operatingsystem','operatingsystemversion',
             'distinguishedname','description','useraccountcontrol','lastlogontimestamp',
             'primarygroupid','ms-mcs-admpwdexpirationtime','mslaps-passwordexpirationtime',
             'msds-keycredentiallink'
    $s = New-ADScoutSearcher -Filter '(objectCategory=computer)' `
         -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $uacRaw = Get-ADScoutProperty $r 'useraccountcontrol'
        $uac    = if ($uacRaw) { [int]$uacRaw } else { 0 }
        [PSCustomObject]@{
            Name                   = Get-ADScoutProperty $r 'name'
            DnsHostName            = Get-ADScoutProperty $r 'dnshostname'
            Description            = Get-ADScoutProperty $r 'description'
            OperatingSystem        = Get-ADScoutProperty $r 'operatingsystem'
            OperatingSystemVersion = Get-ADScoutProperty $r 'operatingsystemversion'
            LastLogonTimestamp    = Get-ADScoutProperty $r 'lastlogontimestamp'
            PrimaryGroupId        = Get-ADScoutProperty $r 'primarygroupid'
            UserAccountControl    = $uac
            UacFlags              = (ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','
            HasLegacyLaps          = ([bool](Get-ADScoutProperty $r 'ms-mcs-admpwdexpirationtime'))
            HasWindowsLaps         = ([bool](Get-ADScoutProperty $r 'mslaps-passwordexpirationtime'))
            HasShadowCredential    = ([bool](Get-ADScoutProperty $r 'msds-keycredentiallink'))
            DistinguishedName      = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutDomainController {
<#
.SYNOPSIS
Enumerates domain controllers.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'SERVER_TRUST_ACCOUNT' -or $_.PrimaryGroupId -eq '516' }
}

function Find-ADScoutSPNAccount {
<#
.SYNOPSIS
Finds accounts with servicePrincipalName values set (Kerberoast review targets).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(&(servicePrincipalName=*)(|(objectCategory=person)(objectCategory=computer)))' `
         -Properties @('samaccountname','serviceprincipalname','distinguishedname','description','admincount') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            SamAccountName       = Get-ADScoutProperty $r 'samaccountname'
            ServicePrincipalName = Get-ADScoutProperty $r 'serviceprincipalname'
            Description          = Get-ADScoutProperty $r 'description'
            AdminCount           = Get-ADScoutProperty $r 'admincount'
            DistinguishedName    = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutASREPAccount {
<#
.SYNOPSIS
Finds accounts with Kerberos preauthentication disabled (AS-REP roast candidates).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'DONT_REQUIRE_PREAUTH' }
}

function Find-ADScoutUnconstrainedDelegation {
<#
.SYNOPSIS
Finds accounts configured for unconstrained delegation.
.DESCRIPTION
Returns users and computers with TRUSTED_FOR_DELEGATION set. Domain controllers are
excluded by default since unconstrained delegation is expected on DCs.
#>
    [CmdletBinding()]
    param(
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$IncludeDomainControllers
    )
    $items = @(Get-ADScoutUser     -Server $Server -Credential $Credential -SearchBase $SearchBase) +
             @(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase)
    foreach ($item in $items) {
        $uacFlags = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'UacFlags')
        if ($uacFlags -notmatch 'TRUSTED_FOR_DELEGATION') { continue }
        $primaryGroupId  = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'PrimaryGroupId')
        $objectName      = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'SamAccountName')
        if ([string]::IsNullOrWhiteSpace($objectName)) {
            $objectName = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'Name')
        }
        $isDomainController = ($primaryGroupId -eq '516' -or $uacFlags -match 'SERVER_TRUST_ACCOUNT')
        if ($isDomainController -and -not $IncludeDomainControllers) { continue }
        [PSCustomObject]@{
            Name              = $objectName
            ObjectType        = if ($primaryGroupId) { 'computer' } else { 'user' }
            IsDomainController = $isDomainController
            PrimaryGroupId    = $primaryGroupId
            UacFlags          = $uacFlags
            DistinguishedName = Get-ADScoutSafeProperty -InputObject $item -Name 'DistinguishedName'
        }
    }
}

function Find-ADScoutConstrainedDelegation {
<#
.SYNOPSIS
Finds traditional constrained delegation (KCD) and resource-based constrained delegation (RBCD).
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $kcd = New-ADScoutSearcher `
           -Filter '(&(msDS-AllowedToDelegateTo=*)(|(objectCategory=computer)(objectCategory=person)))' `
           -Properties @('samaccountname','distinguishedname','msds-allowedtodelegateto') `
           -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $kcd.FindAll()) {
        [PSCustomObject]@{
            Type              = 'KCD'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            DelegatesTo       = Get-ADScoutProperty $r 'msds-allowedtodelegateto'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
    $rbcd = New-ADScoutSearcher `
            -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
            -Properties @('samaccountname','distinguishedname','name') `
            -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $rbcd.FindAll()) {
        [PSCustomObject]@{
            Type              = 'RBCD'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            DelegatesTo       = 'msDS-AllowedToActOnBehalfOfOtherIdentity present'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutDomainTrust {
<#
.SYNOPSIS
Enumerates domain trust objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=trustedDomain)' `
         -Properties @('name','flatname','trustdirection','trusttype','trustattributes','distinguishedname') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $attrs    = Get-ADScoutProperty $r 'trustattributes'
        $attrsInt = if ($attrs) { [int]$attrs } else { 0 }
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            FlatName          = Get-ADScoutProperty $r 'flatname'
            TrustDirection    = switch ([int](Get-ADScoutProperty $r 'trustdirection')) {
                                    0 { 'Disabled' } 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' }
                                    default { Get-ADScoutProperty $r 'trustdirection' }
                                }
            TrustType         = switch ([int](Get-ADScoutProperty $r 'trusttype')) {
                                    1 { 'Downlevel' } 2 { 'Uplevel' } 3 { 'MIT' } 4 { 'DCE' }
                                    default { Get-ADScoutProperty $r 'trusttype' }
                                }
            SIDFilteringEnabled = (($attrsInt -band 0x4) -ne 0)
            IsTransitive      = (($attrsInt -band 0x2) -eq 0)
            IsForestTrust     = (($attrsInt -band 0x8) -ne 0)
            TrustAttributesRaw = $attrs
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutPasswordPolicy {
<#
.SYNOPSIS
Returns default domain password policy and fine-grained password policies where readable.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $entry = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $defaultMinLength = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdLength'    | Select-Object -First 1)
    $defaultHistory   = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'pwdHistoryLength' | Select-Object -First 1)
    $defaultLockout   = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'lockoutThreshold' | Select-Object -First 1)
    $defaultMaxAge    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'maxPwdAge'        | Select-Object -First 1)
    $defaultMinAge    = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdAge'        | Select-Object -First 1)
    [PSCustomObject]@{
        PolicyType       = 'DefaultDomain'
        Name             = 'Default Domain Policy'
        DistinguishedName = $ctx.SearchBase
        MinPwdLength     = $defaultMinLength
        PwdHistoryLength = $defaultHistory
        LockoutThreshold = $defaultLockout
        LockoutDisabled  = ($defaultLockout -ne $null -and [int]$defaultLockout -eq 0)
        MaxPwdAgeRaw     = $defaultMaxAge
        MinPwdAgeRaw     = $defaultMinAge
    }
    $s = New-ADScoutSearcher -Filter '(objectClass=msDS-PasswordSettings)' `
         -Properties @('name','distinguishedname','msds-minimumpasswordlength','msds-passwordhistorylength',
                       'msds-lockoutthreshold','msds-passwordsettingsprecedence','msds-psoappliesto') `
         -Server $Server -Credential $Credential -SearchBase $ctx.SearchBase
    foreach ($r in $s.FindAll()) {
        $fgLockout = Get-ADScoutProperty $r 'msds-lockoutthreshold'
        [PSCustomObject]@{
            PolicyType       = 'FineGrained'
            Name             = Get-ADScoutProperty $r 'name'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
            Precedence       = Get-ADScoutProperty $r 'msds-passwordsettingsprecedence'
            MinPwdLength     = Get-ADScoutProperty $r 'msds-minimumpasswordlength'
            PwdHistoryLength = Get-ADScoutProperty $r 'msds-passwordhistorylength'
            LockoutThreshold = $fgLockout
            LockoutDisabled  = ($fgLockout -ne $null -and [int]$fgLockout -eq 0)
            AppliesTo        = Get-ADScoutProperty $r 'msds-psoappliesto'
        }
    }
}

function Find-ADScoutAdminSDHolderOrphan {
<#
.SYNOPSIS
Finds adminCount=1 users/groups -- current or historical privileged objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(&(adminCount=1)(|(objectCategory=person)(objectCategory=group)))' `
         -Properties @('samaccountname','name','objectclass','distinguishedname','admincount') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            SamAccountName    = Get-ADScoutProperty $r 'samaccountname'
            ObjectClass       = Get-ADScoutProperty $r 'objectclass'
            AdminCount        = Get-ADScoutProperty $r 'admincount'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutWeakUacFlag {
<#
.SYNOPSIS
Finds users with weak or review-worthy UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.UacFlags -match 'PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD|ENCRYPTED_TEXT_PWD_ALLOWED|USE_DES_KEY_ONLY' }
}

function Get-ADScoutLapsStatus {
<#
.SYNOPSIS
Reports visible legacy/Windows LAPS metadata per computer.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Select-Object Name, DnsHostName, HasLegacyLaps, HasWindowsLaps, DistinguishedName
}

function Get-ADScoutGPO {
<#
.SYNOPSIS
Enumerates Group Policy Objects.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential)
    $ctx        = Get-ADScoutDomainContext -Server $Server -Credential $Credential
    $policyBase = "CN=Policies,CN=System,$($ctx.DefaultNamingContext)"
    $s = New-ADScoutSearcher -Filter '(objectClass=groupPolicyContainer)' `
         -Properties @('displayname','name','distinguishedname','whenchanged','gpcfilesyspath') `
         -Server $Server -Credential $Credential -SearchBase $policyBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            DisplayName       = Get-ADScoutProperty $r 'displayname'
            Guid              = Get-ADScoutProperty $r 'name'
            GpcFileSysPath    = Get-ADScoutProperty $r 'gpcfilesyspath'
            WhenChanged       = Get-ADScoutProperty $r 'whenchanged'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutOU {
<#
.SYNOPSIS
Enumerates Organizational Units and linked GPO metadata.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=organizationalUnit)' `
         -Properties @('name','distinguishedname','gplink') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty $r 'name'
            LinkedGPOs        = Get-ADScoutProperty $r 'gplink'
            DistinguishedName = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutLinkedGPO {
<#
.SYNOPSIS
Returns OUs that have linked GPOs.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutOU -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.LinkedGPOs }
}

function Find-ADScoutOldComputer {
<#
.SYNOPSIS
Finds computer accounts that have not authenticated within the specified number of days.
.DESCRIPTION
Converts lastLogonTimestamp via [datetime]::FromFileTime() for accurate comparison.
Note: lastLogonTimestamp replicates on a 9-14 day jitter by design -- results carry
inherent fuzziness of up to ~2 weeks. Accounts with no lastLogonTimestamp are always
included as they may have never authenticated.
.EXAMPLE
Find-ADScoutOldComputer -Days 90
#>
    [CmdletBinding()]
    param(
        [int]$Days = 90,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $cutoff = (Get-Date).AddDays(-$Days)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object {
        if (-not $_.LastLogonTimestamp) { return $true }
        try {
            $ft = [long]$_.LastLogonTimestamp
            [datetime]::FromFileTime($ft) -lt $cutoff
        } catch { $true }
    }
}

function Test-ADScoutPrivilegedIdentity {
<#
.SYNOPSIS
Returns $true if an ACE identity reference or SID belongs to a well-known privileged principal.
.DESCRIPTION
Checks both the IdentityReference (display name) and IdentitySid fields so the exclusion
works correctly on non-English AD environments where group names are localized.
Well-known privileged SID suffixes: -512 (DA), -516 (DC), -518 (Schema Admins),
-519 (EA), -544 (Builtin\Admins), S-1-5-18 (SYSTEM), S-1-5-9 (Enterprise DCs).
#>
    param(
        [string]$IdentityReference,
        [string]$IdentitySid
    )
    # SID-suffix match -- locale-safe, primary check
    $privilegedSidPattern = '-512$|-516$|-518$|-519$|-544$|^S-1-5-18$|^S-1-5-9$'
    if ($IdentitySid -and $IdentitySid -match $privilegedSidPattern) { return $true }
    # Name-pattern match -- English fallback / additional coverage
    $privilegedNamePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                             'SYSTEM|CREATOR OWNER|Domain Controllers|NT AUTHORITY\\SYSTEM|' +
                             'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS'
    if ($IdentityReference -and $IdentityReference -match $privilegedNamePattern) { return $true }
    return $false
}

function Find-ADScoutAclAttackPath {
<#
.SYNOPSIS
Checks ACLs on high-value AD objects for abusable rights held by non-privileged principals.
.DESCRIPTION
Find-ADScoutInterestingAce only checks the domain root. This function sweeps ACLs on
specific high-value targets: privileged groups, krbtgt, DA user accounts, and DC computer
objects -- the objects where an abusable ACE actually translates to a privilege escalation path.

Abusable rights checked: GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty,
Self, ExtendedRight.

Well-known privileged principals are filtered via Test-ADScoutPrivilegedIdentity
(SID-suffix primary, display name fallback -- locale-safe).
.EXAMPLE
Find-ADScoutAclAttackPath
.EXAMPLE
Find-ADScoutAclAttackPath | Where-Object { $_.Rights -match 'GenericAll|WriteDacl' }
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)

    # Well-known privileged principal SID suffixes and name fragments to exclude from results.
    # These holders are expected -- anything else is worth reviewing.
    $excludePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|SYSTEM|CREATOR OWNER|' +
                      'Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544'

    # Fixed high-value group targets
    $groupTargets = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Server Operators', 'Print Operators', 'DnsAdmins',
        'Group Policy Creator Owners', 'Remote Management Users'
    )

    # Add krbtgt account
    $userTargets = @('krbtgt')

    # Add individual DA members (users only -- so an ACE on a DA account is visible)
    try {
        $daMembers = @(Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive `
                       -Server $Server -Credential $Credential -SearchBase $SearchBase |
                       Where-Object { $_.MemberObjectClass -eq 'user' } |
                       Select-Object -ExpandProperty MemberSamAccountName)
        $userTargets += $daMembers
    } catch {}

    # Add DC computer objects
    $dcTargets = @(Get-ADScoutDomainController -Server $Server -Credential $Credential -SearchBase $SearchBase |
                   Select-Object -ExpandProperty Name)

    $allTargets = @(
        ($groupTargets | ForEach-Object { @{ Identity=$_; TargetType='Group' } })
        ($userTargets  | ForEach-Object { @{ Identity=$_; TargetType='User'  } })
        ($dcTargets    | ForEach-Object { @{ Identity=$_; TargetType='Computer' } })
    )

    foreach ($t in $allTargets) {
        try {
            Get-ADScoutObjectAcl -Identity $t.Identity -Server $Server -Credential $Credential -SearchBase $SearchBase |
                Where-Object {
                    $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|Self|ExtendedRight' -and
                    $_.AccessControlType     -eq 'Allow' -and
                    -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        TargetObject      = $t.Identity
                        TargetType        = $t.TargetType
                        IdentityReference = $_.IdentityReference
                        Rights            = $_.ActiveDirectoryRights
                        ObjectType        = $_.ObjectType
                        IsInherited       = $_.IsInherited
                        DistinguishedName = $_.DistinguishedName
                    }
                }
        } catch {}
    }
}


function Find-ADScoutAdminGroup {
<#
.SYNOPSIS
Finds admin/privileged-looking groups by name pattern.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.Name -match 'admin|operator|backup|account|enterprise|schema|domain controllers' }
}

function Find-ADScoutPasswordInDescription {
<#
.SYNOPSIS
Finds user and computer accounts with password-like content in the description field.
.DESCRIPTION
A common misconfiguration in real environments -- admins set temporary passwords in the
AD description field and forget to remove them. Description is readable by all
authenticated users by default.
.EXAMPLE
Find-ADScoutPasswordInDescription
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $keywords = @('pass','pwd','cred','secret','key','login','logon','temp','default','welcome','initial','P@ss','changeme')
    $pattern  = ($keywords | ForEach-Object { [regex]::Escape($_) }) -join '|'

    $users = Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.Description -and $_.Description -match $pattern } |
        ForEach-Object {
            [PSCustomObject]@{
                ObjectType        = 'user'
                SamAccountName    = $_.SamAccountName
                Description       = $_.Description
                DistinguishedName = $_.DistinguishedName
            }
        }

    $computers = Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { 
            $desc = Get-ADScoutSafeProperty -InputObject $_ -Name 'Description'
            $desc -and $desc -match $pattern
        } |
        ForEach-Object {
            [PSCustomObject]@{
                ObjectType        = 'computer'
                SamAccountName    = $_.Name
                Description       = (Get-ADScoutSafeProperty -InputObject $_ -Name 'Description')
                DistinguishedName = $_.DistinguishedName
            }
        }

    @($users) + @($computers)
}

# =============================================================================
# ACL FUNCTIONS
# =============================================================================

function Resolve-ADScoutDistinguishedName {
    [CmdletBinding()]
    param(
        [string]$Identity, [string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if ($Identity -match '^(CN|OU|DC)=') { return $Identity }
    $safe        = $Identity -replace '\\','\\5c' -replace '\*','\\2a' -replace '\(','\\28' -replace '\)','\\29'
    $classFilter = if ($ObjectClass -and $ObjectClass -ne '*') { "(objectClass=$ObjectClass)" } else { '(objectClass=*)' }
    $filter      = "(&${classFilter}(|(name=$safe)(samAccountName=$safe)(displayName=$safe)))"
    $s = New-ADScoutSearcher -Filter $filter -Properties @('distinguishedname') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase -SizeLimit 1
    $r = $s.FindOne()
    if (-not $r) { throw "Could not resolve identity '$Identity' to a distinguishedName." }
    Get-ADScoutProperty $r 'distinguishedname'
}

function Get-ADScoutObjectAcl {
<#
.SYNOPSIS
Reads ACL/ACE data for an AD object by distinguishedName or friendly identity.
.EXAMPLE
Get-ADScoutObjectAcl -Identity 'Domain Admins' -ObjectClass group
#>
    [CmdletBinding(DefaultParameterSetName = 'DN')]
    param(
        [Parameter(ParameterSetName = 'DN')][string]$DistinguishedName,
        [Parameter(ParameterSetName = 'Identity')][string]$Identity,
        [Parameter(ParameterSetName = 'Identity')][string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if (-not $DistinguishedName) {
        $DistinguishedName = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass $ObjectClass `
                             -Server $Server -Credential $Credential -SearchBase $SearchBase
    }
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $path  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
    $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
    foreach ($ace in $entry.ObjectSecurity.Access) {
        $rawObjType = $ace.ObjectType.ToString()
        $rawInhType = $ace.InheritedObjectType.ToString()
        $identRef   = $ace.IdentityReference
        # Resolve to NTAccount if it came in as a SID, or extract SID if it came as NTAccount
        $sidString  = $null
        try {
            if ($identRef -is [System.Security.Principal.SecurityIdentifier]) {
                $sidString = $identRef.ToString()
            } elseif ($identRef -is [System.Security.Principal.NTAccount]) {
                $sidString = $identRef.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
            } else {
                $sidString = ([System.Security.Principal.NTAccount]$identRef.ToString()).Translate([System.Security.Principal.SecurityIdentifier]).ToString()
            }
        } catch { $sidString = $null }
        [PSCustomObject]@{
            IdentityReference       = $ace.IdentityReference.ToString()
            IdentitySid             = $sidString
            ActiveDirectoryRights   = $ace.ActiveDirectoryRights.ToString()
            AccessControlType       = $ace.AccessControlType.ToString()
            ObjectType              = Resolve-ADScoutGuid -Guid $rawObjType
            ObjectTypeGuid          = $rawObjType
            InheritedObjectType     = Resolve-ADScoutGuid -Guid $rawInhType
            InheritedObjectTypeGuid = $rawInhType
            IsInherited             = $ace.IsInherited
            InheritanceType         = $ace.InheritanceType.ToString()
            DistinguishedName       = $DistinguishedName
        }
    }
}

function Find-ADScoutInterestingAce {
<#
.SYNOPSIS
Finds powerful ACEs on a target object or the domain root.
#>
    [CmdletBinding()]
    param(
        [string]$DistinguishedName, [string]$Identity, [string]$ObjectClass = '*',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $aclParams = @{ Server=$Server; Credential=$Credential; SearchBase=$SearchBase }
    if     ($DistinguishedName) { $aclParams['DistinguishedName'] = $DistinguishedName }
    elseif ($Identity)          { $aclParams['Identity'] = $Identity; $aclParams['ObjectClass'] = $ObjectClass }
    else   { $aclParams['DistinguishedName'] = (Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase).SearchBase }
    Get-ADScoutObjectAcl @aclParams |
        Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|CreateChild|DeleteChild|WriteProperty' }
}

function Find-ADScoutDCSyncRight {
<#
.SYNOPSIS
Detects principals with replication rights on the domain root ACL.
.DESCRIPTION
Well-known privileged principals are identified by SID suffix rather than name,
making detection locale-safe on non-English Windows installs.
Well-known SID suffixes treated as expected/Info:
  -512 Domain Admins, -516 Domain Controllers, -518 Schema Admins,
  -519 Enterprise Admins, S-1-5-18 SYSTEM, S-1-5-9 Enterprise Domain Controllers
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $repGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
        '89e95b76-444d-4c62-991a-0facbeda640c'
    )
    Get-ADScoutObjectAcl -DistinguishedName $ctx.SearchBase -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $repGuids -contains $_.ObjectTypeGuid } |
        ForEach-Object {
            $identityRef = $_.IdentityReference
            $identitySid = $_.IdentitySid
            $isWellKnown = Test-ADScoutPrivilegedIdentity -IdentityReference $identityRef -IdentitySid $identitySid
            $sev         = if ($isWellKnown) { 'Info' } else { 'Critical' }
            [PSCustomObject]@{
                Severity              = $sev
                IdentityReference     = $identityRef
                RightName             = $_.ObjectType
                ActiveDirectoryRights = $_.ActiveDirectoryRights
                AccessControlType     = $_.AccessControlType
                IsInherited           = $_.IsInherited
                DistinguishedName     = $ctx.SearchBase
            }
        }
}

# =============================================================================
# GROUP MEMBERSHIP / PRIVILEGE PATH
# =============================================================================

function Get-ADScoutGroupMember {
<#
.SYNOPSIS
Gets direct or recursive group members with analyst-friendly columns.
.EXAMPLE
Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Recursive,
        [int]$MaxDepth = 20,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    $rootGroupDn   = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass group `
                     -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootSummary   = Get-ADScoutDirectoryObjectSummary -DistinguishedName $rootGroupDn `
                     -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootGroupName = if ($rootSummary.SamAccountName) { $rootSummary.SamAccountName } `
                     elseif ($rootSummary.Name) { $rootSummary.Name } else { $Identity }
    $visited       = New-Object 'System.Collections.Generic.HashSet[string]'

    function Invoke-ADScoutGroupMemberWalk {
        param([string]$GroupDn, [string]$ParentGroupName, [int]$Depth, [string]$Path)
        if ($Depth -gt $MaxDepth) { return }
        if (-not $visited.Add($GroupDn)) { return }
        $ctx        = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $groupPath  = if ($ctx.Server) { "LDAP://$($ctx.Server)/$GroupDn" } else { "LDAP://$GroupDn" }
        $groupEntry = New-ADScoutDirectoryEntry -LdapPath $groupPath -Credential $Credential
        $memberDns  = Get-ADScoutDirectoryEntryPropertyValues -Entry $groupEntry -Name 'member'
        foreach ($memberDn in $memberDns) {
            $member     = Get-ADScoutDirectoryObjectSummary -DistinguishedName $memberDn `
                          -Server $Server -Credential $Credential -SearchBase $SearchBase
            $display    = if ($member.SamAccountName) { $member.SamAccountName } `
                          elseif ($member.Name) { $member.Name } `
                          elseif ($member.DnsHostName) { $member.DnsHostName } else { $memberDn }
            $memberPath = if ($Path) { "$Path -> $display" } else { "$ParentGroupName -> $display" }
            [PSCustomObject]@{
                RootGroup              = $rootGroupName
                ParentGroup            = $ParentGroupName
                MemberName             = $member.Name
                MemberSamAccountName   = $member.SamAccountName
                MemberUserPrincipalName = $member.UserPrincipalName
                MemberDnsHostName      = $member.DnsHostName
                MemberObjectClass      = $member.ObjectClass
                Depth                  = $Depth
                IsNested               = ($Depth -gt 0)
                Path                   = $memberPath
                MemberDistinguishedName = $member.DistinguishedName
            }
            if ($Recursive -and $member.ObjectClass -eq 'group') {
                Invoke-ADScoutGroupMemberWalk -GroupDn $memberDn -ParentGroupName $display `
                    -Depth ($Depth + 1) -Path $memberPath
            }
        }
    }
    Invoke-ADScoutGroupMemberWalk -GroupDn $rootGroupDn -ParentGroupName $rootGroupName -Depth 0 -Path $rootGroupName
}

function Get-ADScoutGroupReport {
<#
.SYNOPSIS
Creates a clean group/member report for all groups, selected groups, or privileged groups.
.EXAMPLE
Get-ADScoutGroupReport -PrivilegedOnly -Recursive | Format-Table -AutoSize
.EXAMPLE
Get-ADScoutGroupReport -GroupName 'Domain Admins','Remote Management Users' -Recursive
#>
    [CmdletBinding()]
    param(
        [string[]]$GroupName, [switch]$Recursive, [switch]$PrivilegedOnly,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    if ($PrivilegedOnly) {
        $GroupName = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                       'Account Operators','Backup Operators','Server Operators','Print Operators',
                       'Remote Desktop Users','Remote Management Users','DnsAdmins',
                       'Group Policy Creator Owners')
    }
    if (-not $GroupName -or $GroupName.Count -eq 0) {
        $GroupName = @(Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase |
                       Select-Object -ExpandProperty Name)
    }
    foreach ($group in $GroupName) {
        try {
            $rows = @(Get-ADScoutGroupMember -Identity $group -Recursive:$Recursive `
                      -Server $Server -Credential $Credential -SearchBase $SearchBase)
            if ($rows.Count -eq 0) {
                [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<No members found>'
                    MemberType=$null; Depth=$null; IsNested=$null; Path=$null; DistinguishedName=$null }
                continue
            }
            foreach ($row in $rows) {
                $memberName = if ($row.MemberSamAccountName) { $row.MemberSamAccountName } `
                              elseif ($row.MemberName) { $row.MemberName } `
                              elseif ($row.MemberDnsHostName) { $row.MemberDnsHostName } `
                              else { $row.MemberDistinguishedName }
                [PSCustomObject]@{
                    Group=$row.RootGroup; ParentGroup=$row.ParentGroup; Member=$memberName
                    MemberType=$row.MemberObjectClass; Depth=$row.Depth; IsNested=$row.IsNested
                    Path=$row.Path; DistinguishedName=$row.MemberDistinguishedName
                }
            }
        } catch {
            [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<Error>'
                MemberType=$null; Depth=$null; IsNested=$null
                Path=$_.Exception.Message; DistinguishedName=$null }
        }
    }
}

function Find-ADScoutPrivilegedUser {
<#
.SYNOPSIS
Expands common privileged groups to identify privileged user members.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.Member -and $_.Member -notlike '<*>' }
}

function Find-ADScoutDelegationHint {
<#
.SYNOPSIS
Compatibility wrapper -- returns all delegation review items.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    @(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) +
    @(Find-ADScoutConstrainedDelegation   -Server $Server -Credential $Credential -SearchBase $SearchBase)
}

function Get-ADScoutPrivilegePath {
<#
.SYNOPSIS
Shows user-to-privileged-group membership paths.
.EXAMPLE
Get-ADScoutPrivilegePath
#>
    [CmdletBinding()]
    param([int]$MaxDepth = 20, [string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { $_.MemberType -eq 'user' } |
        Select-Object Group, ParentGroup, Member, MemberType, Depth, Path, DistinguishedName
}

function Get-ADScoutAsRepRoastCandidate {
<#
.SYNOPSIS
Alias for Find-ADScoutASREPAccount.
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    Find-ADScoutASREPAccount -Server $Server -Credential $Credential -SearchBase $SearchBase
}

function Get-ADScoutMachineAccountQuota {
<#
.SYNOPSIS
Returns the ms-DS-MachineAccountQuota value for the domain.
.DESCRIPTION
A non-zero value means any authenticated user can add that many computer accounts
to the domain -- a prerequisite for RBCD and shadow credential attacks.
.EXAMPLE
Get-ADScoutMachineAccountQuota
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx   = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $entry = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $maq   = Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'ms-DS-MachineAccountQuota' | Select-Object -First 1
    $maqInt = if ($maq) { [int]$maq } else { 0 }
    [PSCustomObject]@{
        MachineAccountQuota = $maqInt
        AbuseRisk           = if ($maqInt -gt 0) {
                                  "Non-zero ($maqInt) -- any authenticated user can add computer accounts (RBCD/ShadowCred prerequisite)"
                              } else {
                                  'Zero -- only privileged users can add computer accounts'
                              }
        DistinguishedName   = $ctx.SearchBase
    }
}

function Find-ADScoutShadowCredential {
<#
.SYNOPSIS
Finds accounts with msDS-KeyCredentialLink set (shadow credentials indicator).
.DESCRIPTION
msDS-KeyCredentialLink is used by Windows Hello for Business but can also be abused
(shadow credentials attack) to obtain a TGT without knowing the account password.
Any unexpected entry here should be reviewed.
.EXAMPLE
Find-ADScoutShadowCredential
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $s = New-ADScoutSearcher `
         -Filter '(msDS-KeyCredentialLink=*)' `
         -Properties @('samaccountname','name','objectclass','distinguishedname','msds-keycredentiallink') `
         -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $classes = Get-ADScoutPropertyValues $r 'objectclass'
        [PSCustomObject]@{
            SamAccountName     = Get-ADScoutProperty $r 'samaccountname'
            Name               = Get-ADScoutProperty $r 'name'
            ObjectClass        = Get-ADScoutObjectClassName -ObjectClassValues $classes
            KeyCredentialCount = $r.Properties['msds-keycredentiallink'].Count
            DistinguishedName  = Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Find-ADScoutAdminSDHolderAce {
<#
.SYNOPSIS
Checks the AdminSDHolder object for non-standard ACEs.
.DESCRIPTION
The AdminSDHolder object (CN=AdminSDHolder,CN=System,...) is the ACL template for all
protected (adminCount=1) objects. SDProp propagates its ACL to all protected objects
every 60 minutes. A non-standard ACE here is a persistence and privilege escalation mechanism.
.EXAMPLE
Find-ADScoutAdminSDHolderAce
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $ctx       = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $asdnDn    = "CN=AdminSDHolder,CN=System,$($ctx.DefaultNamingContext)"
    $excludePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                      'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544'
    try {
        Get-ADScoutObjectAcl -DistinguishedName $asdnDn -Server $Server -Credential $Credential -SearchBase $SearchBase |
            Where-Object {
                $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and
                $_.AccessControlType     -eq 'Allow' -and
                -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
            } |
            ForEach-Object {
                [PSCustomObject]@{
                    IdentityReference = $_.IdentityReference
                    Rights            = $_.ActiveDirectoryRights
                    ObjectType        = $_.ObjectType
                    ObjectTypeGuid    = $_.ObjectTypeGuid
                    IsInherited       = $_.IsInherited
                    AbuseNote         = 'ACE on AdminSDHolder propagates to all protected objects via SDProp -- persistence/privesc path'
                    DistinguishedName = $asdnDn
                }
            }
    } catch {
        Write-Verbose "AdminSDHolder ACL read failed: $($_.Exception.Message)"
    }
}

function Find-ADScoutGPOWritePermission {
<#
.SYNOPSIS
Identifies principals that can modify GPOs linked to privileged or sensitive OUs.
.DESCRIPTION
Combines GPO ACL data with OU link data. A non-privileged principal with write access
to a GPO linked to a privileged OU (Domain Controllers, Tier 0, PAW, etc.) can execute
code as SYSTEM on all machines in scope. GUIDs resolved to human-readable names in output.
.EXAMPLE
Find-ADScoutGPOWritePermission
.EXAMPLE
Find-ADScoutGPOWritePermission | Where-Object AppliesToPrivOu
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $excludePattern     = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                          'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544|' +
                          'Group Policy Creator Owners'
    $privilegedOuPattern = 'Domain Controllers|Tier 0|Privileged|Admin|Executive|PAW|Secure'
    $ctx  = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $gpos = @(Get-ADScoutGPO -Server $Server -Credential $Credential)
    $ous  = @(Get-ADScoutOU  -Server $Server -Credential $Credential -SearchBase $SearchBase |
              Where-Object { $_.LinkedGPOs })
    # Build GPO guid -> linked OU names map
    $gpoOuMap = @{}
    foreach ($ou in $ous) {
        if (-not $ou.LinkedGPOs) { continue }
        $guids = [regex]::Matches($ou.LinkedGPOs, '\{([^}]+)\}') | ForEach-Object { "{$($_.Groups[1].Value)}" }
        foreach ($guid in $guids) {
            if (-not $gpoOuMap.ContainsKey($guid)) { $gpoOuMap[$guid] = @() }
            $gpoOuMap[$guid] += $ou.Name
        }
    }
    foreach ($gpo in $gpos) {
        $gpoGuid   = $gpo.Guid
        $linkedOus = if ($gpoOuMap.ContainsKey($gpoGuid)) { $gpoOuMap[$gpoGuid] } else { @() }
        $isPrivOu  = $linkedOus | Where-Object { $_ -match $privilegedOuPattern }
        try {
            $aces = @(Get-ADScoutObjectAcl -DistinguishedName $gpo.DistinguishedName `
                      -Server $Server -Credential $Credential -SearchBase $SearchBase |
                      Where-Object {
                          $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild' -and
                          $_.AccessControlType     -eq 'Allow' -and
                          -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                      })
            foreach ($ace in $aces) {
                [PSCustomObject]@{
                    GPOName           = $gpo.DisplayName
                    GPOGuid           = $gpoGuid
                    IdentityReference = $ace.IdentityReference
                    Rights            = $ace.ActiveDirectoryRights
                    ObjectType        = $ace.ObjectType
                    LinkedOUs         = ($linkedOus -join '; ')
                    AppliesToPrivOu   = ([bool]$isPrivOu)
                    AbuseNote         = if ($isPrivOu) {
                                            'GPO linked to privileged OU -- write access enables code exec on in-scope machines'
                                        } else { 'GPO write access -- review scope' }
                    DistinguishedName = $gpo.DistinguishedName
                }
            }
        } catch {}
    }
}

function Find-ADScoutTargetedKerberoastPath {
<#
.SYNOPSIS
Finds principals that can perform a targeted Kerberoast attack.
.DESCRIPTION
GenericAll or GenericWrite on a user account allows an attacker to set an arbitrary SPN
on that account, request a TGS, and crack it offline -- even if the account had no SPN.
This function identifies non-privileged principals with those rights on user objects.
Runs only under -IncludeAclSweep or -Preset Deep due to the per-user ACL cost.
.EXAMPLE
Find-ADScoutTargetedKerberoastPath
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $excludePattern = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|' +
                      'SYSTEM|CREATOR OWNER|Domain Controllers|S-1-5-18|S-1-5-9|-512|-516|-518|-519|-544'
    $users = Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase |
             Where-Object { $_.UacFlags -notmatch 'ACCOUNTDISABLE' }
    foreach ($user in $users) {
        try {
            Get-ADScoutObjectAcl -DistinguishedName $user.DistinguishedName `
                                 -Server $Server -Credential $Credential -SearchBase $SearchBase |
                Where-Object {
                    $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite' -and
                    $_.AccessControlType     -eq 'Allow' -and
                    -not (Test-ADScoutPrivilegedIdentity -IdentityReference $_.IdentityReference -IdentitySid $_.IdentitySid)
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        TargetUser        = $user.SamAccountName
                        AttackerPrincipal = $_.IdentityReference
                        Rights            = $_.ActiveDirectoryRights
                        ObjectType        = $_.ObjectType
                        IsInherited       = $_.IsInherited
                        AbuseNote         = 'Can set SPN on target and Kerberoast (targeted Kerberoast)'
                        DistinguishedName = $user.DistinguishedName
                    }
                }
        } catch {}
    }
}

function Get-ADScoutCrossForestEnum {
<#
.SYNOPSIS
Enumerates basic information from trusted domains/forests.
.DESCRIPTION
Follows trust relationships from Get-ADScoutDomainTrust and attempts to collect
domain context from each reachable trusted domain. Skips outbound-only trusts.
Collection depth limited to direct trusts only.
.EXAMPLE
Get-ADScoutCrossForestEnum
#>
    [CmdletBinding()]
    param([string]$Server, [PSCredential]$Credential, [string]$SearchBase)
    $trusts = @(Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase)
    if ($trusts.Count -eq 0) { Write-Verbose 'No domain trusts found.'; return }
    foreach ($trust in $trusts) {
        $trustName = $trust.Name
        if ([string]::IsNullOrWhiteSpace($trustName)) { continue }
        if ($trust.TrustDirection -eq 'Outbound') {
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Skipped -- outbound-only trust'
                SearchBase=$null; DomainControllers=$null; UserCount=$null; ComputerCount=$null; Error=$null
            }
            continue
        }
        try {
            $ctx       = Get-ADScoutDomainContext -Server $trustName -Credential $Credential -SearchBase $null
            $dcCount   = @(Get-ADScoutDomainController -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase).Count
            $userCount = 0; $compCount = 0
            try { $us = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' -Properties @('samaccountname') -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase; $userCount = $us.FindAll().Count } catch {}
            try { $cs = New-ADScoutSearcher -Filter '(objectCategory=computer)' -Properties @('name') -Server $trustName -Credential $Credential -SearchBase $ctx.SearchBase; $compCount = $cs.FindAll().Count } catch {}
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Reachable'; SearchBase=$ctx.SearchBase
                DomainControllers   = $dcCount; UserCount=$userCount; ComputerCount=$compCount; Error=$null
            }
        } catch {
            [PSCustomObject]@{
                TrustedDomain       = $trustName; TrustDirection=$trust.TrustDirection
                IsForestTrust       = $trust.IsForestTrust; SIDFilteringEnabled=$trust.SIDFilteringEnabled
                Status              = 'Unreachable'; SearchBase=$null
                DomainControllers   = $null; UserCount=$null; ComputerCount=$null; Error=$_.Exception.Message
            }
        }
    }
}

# =============================================================================
# FINDINGS ENGINE
# =============================================================================

function New-ADScoutFinding {
<#
.SYNOPSIS
Creates a normalized ADScout finding object.
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Position=1)][string]$Category,
        [Parameter(Position=2)][string]$Title,
        [Parameter(Position=3)][string]$Target,
        [Parameter(Position=4)][string]$Evidence,
        [Parameter(Position=5)][string]$WhyItMatters,
        [Parameter(Position=6)][string]$RecommendedReview,
        [Parameter(Position=7)][string]$SourceCommand,
        [Parameter(Position=8)][string]$DistinguishedName,
        [string]$Identity
    )
    if (-not $Identity) { $Identity = $Target }
    [PSCustomObject][ordered]@{
        Severity          = $Severity
        Category          = $Category
        Title             = $Title
        Target            = $Target
        Identity          = $Identity
        Evidence          = $Evidence
        WhyItMatters      = $WhyItMatters
        RecommendedReview = $RecommendedReview
        SourceCommand     = $SourceCommand
        DistinguishedName = $DistinguishedName
        Timestamp         = Get-Date
    }
}

function Get-ADScoutFinding {
<#
.SYNOPSIS
Returns normalized findings sorted by operational priority.
.DESCRIPTION
ACL sweep (Find-ADScoutInterestingAce) is opt-in via -IncludeAclSweep or -Preset Deep.
DCSync rights always checked -- well-known privileged principals surfaced as Info.
Stale computers (>90 days) included as Low severity.
.EXAMPLE
Get-ADScoutFinding -SkipAclSweep
.EXAMPLE
Get-ADScoutFinding -IncludeAclSweep
#>
    [CmdletBinding()]
    param(
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$SkipAclSweep, [switch]$IncludeAclSweep
    )
    $runAcl = $IncludeAclSweep.IsPresent -and (-not $SkipAclSweep.IsPresent)
    $f      = New-Object System.Collections.Generic.List[object]

    # Password in description field
    foreach ($x in Find-ADScoutPasswordInDescription -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding 'Critical' 'Credential Exposure' 'Password in description field' `
            $x.SamAccountName $x.Description `
            'AD description fields are readable by all authenticated users. Passwords stored here are trivially accessible.' `
            'Remove the credential from the description field immediately and rotate the password.' `
            'Find-ADScoutPasswordInDescription' $x.DistinguishedName))
    }

    # AS-REP roast
    foreach ($x in Find-ADScoutASREPAccount -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding 'Critical' 'Authentication' 'AS-REP roast candidate' `
            (Get-ADScoutObjectDisplayName $x) $x.UacFlags `
            'Kerberos preauthentication is disabled for this account.' `
            'Review whether preauthentication should be required and whether the account is still needed.' `
            'Find-ADScoutASREPAccount' $x.DistinguishedName))
    }

    # --- Machine account quota ---
    foreach ($x in Get-ADScoutMachineAccountQuota -Server $Server -Credential $Credential -SearchBase $SearchBase |
             Where-Object { $_.MachineAccountQuota -gt 0 }) {
        $f.Add((New-ADScoutFinding 'High' 'Domain Configuration' 'Machine account quota is non-zero' `
            "ms-DS-MachineAccountQuota=$($x.MachineAccountQuota)" $x.AbuseRisk `
            'Any authenticated domain user can join machines to the domain. This is a prerequisite for RBCD and shadow credential attacks.' `
            'Set ms-DS-MachineAccountQuota to 0. Use delegated OU permissions for legitimate computer joins.' `
            'Get-ADScoutMachineAccountQuota' $x.DistinguishedName))
    }

    # --- Shadow credentials ---
    foreach ($x in Find-ADScoutShadowCredential -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $sev = if ($x.ObjectClass -eq 'computer' -and $x.KeyCredentialCount -eq 1) { 'Medium' } else { 'High' }
        $f.Add((New-ADScoutFinding $sev 'Shadow Credentials' 'msDS-KeyCredentialLink present' `
            $x.SamAccountName "ObjectClass=$($x.ObjectClass); KeyCount=$($x.KeyCredentialCount)" `
            'msDS-KeyCredentialLink enables certificate-based auth. Attacker-controlled entries allow TGT retrieval without the account password.' `
            'Review each KeyCredentialLink entry. Legitimate entries exist for WHFB-enrolled devices. Unexpected entries indicate shadow credential abuse.' `
            'Find-ADScoutShadowCredential' $x.DistinguishedName))
    }

    # --- Kerberoast (SPN accounts) ---
    foreach ($x in Find-ADScoutSPNAccount -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $sev = if ((Get-ADScoutSafeProperty -InputObject $x -Name 'AdminCount') -eq '1') { 'High' } else { 'Medium' }
        $f.Add((New-ADScoutFinding $sev 'Kerberos' 'SPN-bearing user account' `
            (Get-ADScoutObjectDisplayName $x) $x.ServicePrincipalName `
            'User accounts with SPNs are Kerberoast review targets in authorized assessments.' `
            'Validate service account ownership, password policy, and privilege level.' `
            'Find-ADScoutSPNAccount' $x.DistinguishedName))
    }

    # Unconstrained delegation
    foreach ($x in Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding 'Critical' 'Delegation' 'Unconstrained delegation on non-DC object' `
            (Get-ADScoutObjectDisplayName $x) $x.UacFlags `
            'Unconstrained delegation can expose delegated authentication material if the account/host is compromised.' `
            'Confirm business need and review delegation configuration.' `
            'Find-ADScoutUnconstrainedDelegation' $x.DistinguishedName))
    }

    # Constrained delegation
    foreach ($x in Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $sev = if ($x.Type -eq 'RBCD') { 'High' } else { 'Medium' }
        $f.Add((New-ADScoutFinding $sev 'Delegation' "$($x.Type) delegation configured" `
            (Get-ADScoutObjectDisplayName $x) $x.DelegatesTo `
            'Delegation configuration should be reviewed as part of AD attack-path analysis.' `
            'Validate target services/principals and intended administration model.' `
            'Find-ADScoutConstrainedDelegation' $x.DistinguishedName))
    }

    # DCSync rights -- severity pre-computed using SID suffix matching (locale-safe)
    foreach ($x in Find-ADScoutDCSyncRight -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding $x.Severity 'Replication Rights' 'DCSync-related replication right' `
            $x.IdentityReference $x.RightName `
            'Replication rights on the domain root are highly sensitive.' `
            'Review whether this principal should have directory replication permissions.' `
            'Find-ADScoutDCSyncRight' $x.DistinguishedName))
    }

    # Password policy
    foreach ($x in Get-ADScoutPasswordPolicy -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object {
            (Get-ADScoutSafeProperty -InputObject $_ -Name 'LockoutDisabled') -eq $true -or
            ((Get-ADScoutSafeProperty -InputObject $_ -Name 'MinPwdLength') -ne $null -and
             [int](Get-ADScoutSafeProperty -InputObject $_ -Name 'MinPwdLength') -lt 12)
        }) {
        $f.Add((New-ADScoutFinding 'High' 'Password Policy' 'Password policy review item' `
            $x.Name "MinPwdLength=$($x.MinPwdLength); LockoutThreshold=$($x.LockoutThreshold)" `
            'Weak password or lockout policy settings can increase account abuse risk.' `
            'Review password and lockout policy against organizational standards.' `
            'Get-ADScoutPasswordPolicy' $x.DistinguishedName))
    }

    # Domain trusts
    foreach ($x in Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding 'Info' 'Trusts' 'Domain trust present' `
            $x.Name "Direction=$($x.TrustDirection); Type=$($x.TrustType); Attr=$($x.TrustAttributes)" `
            'Trusts expand the AD security boundary and should be mapped.' `
            'Review trust direction, transitivity, and SID filtering configuration.' `
            'Get-ADScoutDomainTrust' $x.DistinguishedName))
    }

    # Domain controllers (informational inventory)
    foreach ($x in Get-ADScoutDomainController -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $f.Add((New-ADScoutFinding 'Info' 'Domain Controllers' 'Domain controller discovered' `
            (Get-ADScoutObjectDisplayName $x) $x.OperatingSystem `
            'Domain controllers are Tier 0 assets and should be tracked separately.' `
            'Use for scoping and defensive review.' `
            'Get-ADScoutDomainController' $x.DistinguishedName))
    }

    # adminCount orphans
    foreach ($x in Find-ADScoutAdminSDHolderOrphan -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $target = if ($x.SamAccountName) { $x.SamAccountName } else { $x.Name }
        $f.Add((New-ADScoutFinding 'Medium' 'Privilege Hygiene' 'adminCount=1 object' `
            $target $x.ObjectClass `
            'adminCount=1 may indicate current or historical privileged protection.' `
            'Review whether object is still privileged and whether ACL inheritance is appropriate.' `
            'Find-ADScoutAdminSDHolderOrphan' $x.DistinguishedName))
    }

    # Weak UAC flags
    foreach ($x in Find-ADScoutWeakUacFlag -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $sev = if ($x.UacFlags -match 'ENCRYPTED_TEXT_PWD_ALLOWED|PASSWD_NOTREQD|USE_DES_KEY_ONLY') { 'High' } else { 'Medium' }
        $f.Add((New-ADScoutFinding $sev 'Account Flags' 'Weak/review-worthy UAC flag' `
            (Get-ADScoutObjectDisplayName $x) $x.UacFlags `
            'UAC flags can reveal relaxed authentication or password controls.' `
            'Review whether these flags are required.' `
            'Find-ADScoutWeakUacFlag' $x.DistinguishedName))
    }

    # LAPS coverage gaps
    foreach ($x in Get-ADScoutLapsStatus -Server $Server -Credential $Credential -SearchBase $SearchBase |
        Where-Object { -not $_.HasLegacyLaps -and -not $_.HasWindowsLaps }) {
        $f.Add((New-ADScoutFinding 'Medium' 'Endpoint Hygiene' 'No visible LAPS metadata' `
            (Get-ADScoutObjectDisplayName $x) $x.DnsHostName `
            'Systems without visible LAPS metadata may need local admin password management review.' `
            'Confirm whether LAPS or another local admin password control is deployed.' `
            'Get-ADScoutLapsStatus' $x.DistinguishedName))
    }

    # Stale computer accounts
    foreach ($x in Find-ADScoutOldComputer -Days 90 -Server $Server -Credential $Credential -SearchBase $SearchBase) {
        $evidence = if ($x.LastLogonTimestamp) { "LastLogonTimestamp=$($x.LastLogonTimestamp)" } else { 'LastLogonTimestamp absent' }
        $f.Add((New-ADScoutFinding 'Low' 'Endpoint Hygiene' 'Stale computer account (>90 days)' `
            (Get-ADScoutObjectDisplayName $x) $evidence `
            'Stale computer accounts may represent decommissioned systems still enabled in AD.' `
            'Confirm whether the account is still in use; disable or remove if not. Note: lastLogonTimestamp has ~14 day replication jitter.' `
            'Find-ADScoutOldComputer' $x.DistinguishedName))
    }

    # ACL sweep (opt-in only)
    if ($runAcl) {
        foreach ($x in Find-ADScoutInterestingAce -Server $Server -Credential $Credential -SearchBase $SearchBase) {
            $f.Add((New-ADScoutFinding 'High' 'ACL/ACE' 'Interesting ACE on domain root' `
                $x.IdentityReference "$($x.ActiveDirectoryRights) [$($x.ObjectType)]" `
                'Powerful ACEs on the domain root can enable privilege escalation or persistence.' `
                'Review whether this principal requires this permission.' `
                'Find-ADScoutInterestingAce' $x.DistinguishedName))
        }
        foreach ($x in Find-ADScoutAclAttackPath -Server $Server -Credential $Credential -SearchBase $SearchBase) {
            $f.Add((New-ADScoutFinding 'Critical' 'ACL Attack Path' "Abusable ACE on $($x.TargetType): $($x.TargetObject)" `
                $x.IdentityReference "$($x.Rights) [$($x.ObjectType)]" `
                "A non-privileged principal has $($x.Rights) on a high-value $($x.TargetType) object. Direct privilege escalation path." `
                'Remove the ACE. GenericAll = full control, WriteDacl = grant self any right, User-Force-Change-Password = reset without knowing current password.' `
                'Find-ADScoutAclAttackPath' $x.DistinguishedName))
        }
        foreach ($x in Find-ADScoutAdminSDHolderAce -Server $Server -Credential $Credential -SearchBase $SearchBase) {
            $f.Add((New-ADScoutFinding 'Critical' 'Persistence' 'Non-standard ACE on AdminSDHolder' `
                $x.IdentityReference "$($x.Rights) [$($x.ObjectType)]" `
                'AdminSDHolder ACEs propagate to all protected objects every 60 minutes via SDProp. This is a persistence and privilege escalation mechanism.' `
                'Remove the non-standard ACE from CN=AdminSDHolder,CN=System,... immediately.' `
                'Find-ADScoutAdminSDHolderAce' $x.DistinguishedName))
        }
        foreach ($x in Find-ADScoutGPOWritePermission -Server $Server -Credential $Credential -SearchBase $SearchBase) {
            $sev = if ($x.AppliesToPrivOu) { 'Critical' } else { 'High' }
            $f.Add((New-ADScoutFinding $sev 'GPO Abuse' 'GPO write permission' `
                $x.IdentityReference "GPO: $($x.GPOName); OUs: $($x.LinkedOUs); Rights: $($x.Rights)" `
                $x.AbuseNote `
                'Review whether this principal requires GPO write access. Prefer read-only delegation.' `
                'Find-ADScoutGPOWritePermission' $x.DistinguishedName))
        }
        foreach ($x in Find-ADScoutTargetedKerberoastPath -Server $Server -Credential $Credential -SearchBase $SearchBase) {
            $f.Add((New-ADScoutFinding 'High' 'Kerberos' 'Targeted Kerberoast path' `
                $x.AttackerPrincipal "Can set SPN on $($x.TargetUser) via $($x.Rights)" `
                'GenericAll/GenericWrite on a user allows setting an SPN and Kerberoasting the TGS, even if the account had no SPN.' `
                'Remove the write access or restrict SPN writes via Validated-SPN.' `
                'Find-ADScoutTargetedKerberoastPath' $x.DistinguishedName))
        }
    }

    $rank   = @{Critical=0; High=1; Medium=2; Low=3; Info=4}
    $items  = @($f | Sort-Object @{Expression={$rank[$_.Severity]}}, Category, Title, Target)
    $script:ADScoutLastFindings = $items
    return $items
}

# =============================================================================
# OUTPUT / REPORTING
# =============================================================================

function New-ADScoutHtmlReport {
<#
.SYNOPSIS
Creates a lightweight offline HTML report for an ADScout run.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$RunData,
        [Parameter(Mandatory)][string]$OutputPath
    )
    function ConvertTo-ADScoutHtmlTable {
        param($Rows, [string]$Title)
        $items = @($Rows)
        if ($items.Count -eq 0) { return "<h2>$Title</h2><p>No rows.</p>" }
        return ($items | ConvertTo-Html -Fragment -PreContent "<h2>$Title</h2>") -join [Environment]::NewLine
    }
    $findings  = @($RunData.Findings)
    $critical  = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high      = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
    $generated = [System.Net.WebUtility]::HtmlEncode((Get-Date).ToString())
    $html = @"
<!doctype html><html>
<head><meta charset="utf-8"/><title>ADScoutPS Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1f2933}
h1{margin-bottom:0}.meta{color:#5b6773;margin-top:4px}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}
.card{border:1px solid #d9e2ec;border-radius:8px;padding:12px 16px;min-width:140px;background:#f8fafc}
table{border-collapse:collapse;width:100%;margin-bottom:28px;font-size:13px}
th,td{border:1px solid #d9e2ec;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#eef2f7}
</style></head>
<body>
<h1>ADScoutPS Report</h1>
<div class="meta">Generated: $generated &nbsp;|&nbsp; Version: $script:ADScoutVersion</div>
<div class="summary">
  <div class="card"><strong>Findings</strong><br/>$($findings.Count)</div>
  <div class="card"><strong>Critical</strong><br/>$critical</div>
  <div class="card"><strong>High</strong><br/>$high</div>
  <div class="card"><strong>Users</strong><br/>$(@($RunData.Users).Count)</div>
  <div class="card"><strong>Computers</strong><br/>$(@($RunData.Computers).Count)</div>
</div>
$(ConvertTo-ADScoutHtmlTable -Rows ($findings | Sort-Object Severity,Category,Title) -Title 'Findings')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.PrivilegedGroupMembers -Title 'Privileged Group Members')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.Delegation            -Title 'Delegation Review')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.PasswordPolicies      -Title 'Password Policy')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.DomainTrusts          -Title 'Domain Trusts')
$(ConvertTo-ADScoutHtmlTable -Rows $RunData.DomainControllers     -Title 'Domain Controllers')
</body></html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    return $OutputPath
}

function Show-ADScoutFindingsGui {
<#
.SYNOPSIS
Shows selected ADScout views in Out-GridView when available, otherwise console table.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')]
        [string]$View = 'Findings',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [switch]$IncludeAclSweep, [switch]$SkipAclSweep,
        [object[]]$Findings
    )
    $grid = [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue)
    switch ($View) {
        'PrivilegedGroups' { $data = @(Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Privileged Group Members' }
        'Delegation'       { $data = @(Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) + @(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Delegation Review' }
        'Users'            { $data = @(Get-ADScoutUser     -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Users' }
        'Computers'        { $data = @(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase); $title = 'ADScoutPS - Computers' }
        default            { $data = if ($Findings) { @($Findings) } else { @(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep) }; $title = 'ADScoutPS - Findings Dashboard' }
    }
    if ($grid) { $data | Out-GridView -Title $title }
    else        { Write-Warning 'Out-GridView unavailable; falling back to console.'; $data | Format-Table -AutoSize }
    if ($View -eq 'All' -and $grid) {
        Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase | Out-GridView -Title 'ADScoutPS - Privileged Groups'
        Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase | Out-GridView -Title 'ADScoutPS - Users'
    }
}

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

function Invoke-ADScout {
<#
.SYNOPSIS
Runs ADScoutPS collection using operator presets.
.DESCRIPTION
Quick    -- fast core collection, no GPO/OU/trust enumeration, no ACL sweep.
Standard -- adds GPOs, OUs, trusts, password policy, privileged group report. No ACL sweep.
Deep     -- full collection including ACL sweep (unless -SkipAclSweep is set).
.EXAMPLE
Invoke-ADScout -Preset Quick
.EXAMPLE
Invoke-ADScout -Gui -View Findings -SkipAclSweep
.EXAMPLE
Invoke-ADScout -Preset Deep -Report
#>
    [CmdletBinding()]
    param(
        [ValidateSet('Quick','Standard','Deep')][string]$Preset = 'Standard',
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase,
        [string]$OutputPath = 'ADScout-Results',
        [ValidateSet('CSV','JSON','Both')][string]$OutputFormat = 'Both',
        [switch]$SkipAclSweep, [switch]$IncludeAclSweep,
        [switch]$Gui,
        [ValidateSet('Findings','PrivilegedGroups','Delegation','Users','Computers','All')]
        [string]$View = 'Findings',
        [switch]$Report, [switch]$NoExport
    )

    $runAcl = $IncludeAclSweep.IsPresent -or ($Preset -eq 'Deep')
    if ($SkipAclSweep) { $runAcl = $false }

    Write-Host "[*] ADScoutPS v$script:ADScoutVersion collection starting..." -ForegroundColor Cyan
    Write-Host "[*] Preset: $Preset | ACL sweep: $runAcl"                    -ForegroundColor Cyan

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runPath   = Join-Path $OutputPath "Run-$timestamp"
    if (-not $NoExport) { New-Item -ItemType Directory -Path $runPath -Force | Out-Null }

    $data = [ordered]@{}
    $data.Environment       = @(Test-ADScoutEnvironment  -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.DomainInfo        = @(Get-ADScoutDomainInfo    -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.DomainControllers = @(Get-ADScoutDomainController -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Users             = @(Get-ADScoutUser          -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Groups            = @(Get-ADScoutGroup         -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Computers         = @(Get-ADScoutComputer      -Server $Server -Credential $Credential -SearchBase $SearchBase)

    if ($Preset -ne 'Quick') {
        $data.GPOs         = @(Get-ADScoutGPO        -Server $Server -Credential $Credential)
        $data.OUs          = @(Get-ADScoutOU         -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.LinkedGPOs   = @(Get-ADScoutLinkedGPO  -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.DomainTrusts = @(Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase)
    } else {
        $data.GPOs = @(); $data.OUs = @(); $data.LinkedGPOs = @(); $data.DomainTrusts = @()
    }

    $data.PasswordPolicies      = @(Get-ADScoutPasswordPolicy        -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.MachineAccountQuota   = @(Get-ADScoutMachineAccountQuota   -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.PasswordInDescription = @(Find-ADScoutPasswordInDescription -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.SPNAccounts           = @(Find-ADScoutSPNAccount           -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.ASREPAccounts         = @(Find-ADScoutASREPAccount         -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.ShadowCredentials     = @(Find-ADScoutShadowCredential     -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Delegation            = @(@(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) +
                                    @(Find-ADScoutConstrainedDelegation   -Server $Server -Credential $Credential -SearchBase $SearchBase))
    $data.AdminSDHolderObjects  = @(Find-ADScoutAdminSDHolderOrphan  -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.PrivilegedGroupMembers= @(Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.PrivilegePaths        = @(Get-ADScoutPrivilegePath         -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.WeakUacFlags          = @(Find-ADScoutWeakUacFlag          -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.LapsStatus            = @(Get-ADScoutLapsStatus            -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.StaleComputers        = @(Find-ADScoutOldComputer -Days 90  -Server $Server -Credential $Credential -SearchBase $SearchBase)

    if ($runAcl) {
        Write-Host '[*] Running ACL sweep (may take time on large domains)...' -ForegroundColor Cyan
        $data.AclAttackPaths          = @(Find-ADScoutAclAttackPath          -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.AdminSDHolderAces       = @(Find-ADScoutAdminSDHolderAce       -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.GPOWritePermissions     = @(Find-ADScoutGPOWritePermission      -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.TargetedKerberoastPaths = @(Find-ADScoutTargetedKerberoastPath  -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.CrossForest             = @(Get-ADScoutCrossForestEnum          -Server $Server -Credential $Credential -SearchBase $SearchBase)
        $data.Findings                = @(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -IncludeAclSweep)
    } else {
        $data.AclAttackPaths          = @()
        $data.AdminSDHolderAces       = @()
        $data.GPOWritePermissions     = @()
        $data.TargetedKerberoastPaths = @()
        $data.CrossForest             = @()
        $data.Findings                = @(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -SkipAclSweep)
    }

    $script:ADScoutLastRun      = [PSCustomObject]$data
    $script:ADScoutLastFindings = $data.Findings

    if (-not $NoExport) {
        foreach ($k in $data.Keys) {
            $base = Join-Path $runPath $k
            if ($OutputFormat -in @('CSV','Both'))  { $data[$k] | Export-Csv "$base.csv" -NoTypeInformation }
            if ($OutputFormat -in @('JSON','Both')) { $data[$k] | ConvertTo-Json -Depth 8 | Out-File "$base.json" -Encoding UTF8 }
        }
        $summary = @('# ADScoutPS Summary', '',
            "Version: $script:ADScoutVersion", "Preset: $Preset", "ACL sweep: $runAcl", '',
            '| Collection | Count |', '|---|---:|') +
            ($data.Keys | ForEach-Object { "| $_ | $($data[$_].Count) |" })
        $summary | Out-File (Join-Path $runPath 'summary.md') -Encoding UTF8
        if ($Report) { New-ADScoutHtmlReport -RunData ([PSCustomObject]$data) -OutputPath (Join-Path $runPath 'report.html') | Out-Null }
        Write-Host "[+] Results written to $runPath" -ForegroundColor Green
    }

    Write-Host "[!] Critical: $(@($data.Findings | Where-Object Severity -eq 'Critical').Count)" -ForegroundColor Red
    Write-Host "[!] High:     $(@($data.Findings | Where-Object Severity -eq 'High').Count)"     -ForegroundColor Yellow
    Write-Host "[!] Low:      $(@($data.Findings | Where-Object Severity -eq 'Low').Count)"      -ForegroundColor DarkYellow

    Get-ADScoutSummary -Findings $data.Findings

    if ($Gui) {
        Show-ADScoutFindingsGui -View $View -Server $Server -Credential $Credential -SearchBase $SearchBase `
            -Findings $data.Findings -IncludeAclSweep:$runAcl -SkipAclSweep:(!$runAcl)
    }

    [PSCustomObject]@{
        OutputPath              = if ($NoExport) { $null } else { $runPath }
        Preset                  = $Preset
        AclSweep                = $runAcl
        Findings                = $data.Findings.Count
        Critical                = @($data.Findings | Where-Object Severity -eq 'Critical').Count
        High                    = @($data.Findings | Where-Object Severity -eq 'High').Count
        Low                     = @($data.Findings | Where-Object Severity -eq 'Low').Count
        PasswordInDesc          = $data.PasswordInDescription.Count
        ShadowCredentials       = $data.ShadowCredentials.Count
        AclAttackPaths          = $data.AclAttackPaths.Count
        AdminSDHolderAces       = $data.AdminSDHolderAces.Count
        GPOWritePermissions     = $data.GPOWritePermissions.Count
        TargetedKerberoastPaths = $data.TargetedKerberoastPaths.Count
        Users                   = $data.Users.Count
        Computers               = $data.Computers.Count
        DomainControllers       = $data.DomainControllers.Count
        StaleComputers          = $data.StaleComputers.Count
    }
}

# =============================================================================
# TAB COMPLETION (inlined -- no companion file needed)
# =============================================================================

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName Preset -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'Quick','Standard','Deep' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"Preset: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout,Show-ADScoutFindingsGui -ParameterName View -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'Findings','PrivilegedGroups','Delegation','Users','Computers','All' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"View: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputFormat -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    'CSV','JSON','Both' | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"Format: $_") }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputPath -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    Get-ChildItem -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$wordToComplete*" } |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_.FullName,$_.Name,'ParameterValue',$_.FullName) }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout,Get-ADScoutDomainInfo,Get-ADScoutUser,Get-ADScoutGroup,Get-ADScoutComputer,Find-ADScoutSPNAccount,Find-ADScoutASREPAccount,Find-ADScoutUnconstrainedDelegation,Find-ADScoutConstrainedDelegation,Get-ADScoutObjectAcl,Find-ADScoutInterestingAce,Get-ADScoutGroupMember,Get-ADScoutGroupReport -ParameterName Server -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    $candidates = @()
    try { $root = [ADSI]'LDAP://RootDSE'; if ($root.dnsHostName) { $candidates += $root.dnsHostName.ToString() } } catch {}
    $envLogonServer = $env:LOGONSERVER -replace '^\\\\', ''
    if ($envLogonServer) { $candidates += $envLogonServer }
    $candidates | Where-Object { $_ -and $_ -like "$wordToComplete*" } | Sort-Object -Unique |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_,'ParameterValue',"DC: $_") }
}

Register-ArgumentCompleter -CommandName Get-ADScoutObjectAcl,Find-ADScoutInterestingAce -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) {
            '(|(objectClass=organizationalUnit)(objectClass=group)(objectCategory=person)(objectCategory=computer))'
        } else { "(|(name=*$safeWord*)(samAccountName=*$safeWord*))" }
        [void]$searcher.PropertiesToLoad.Add('name'); [void]$searcher.PropertiesToLoad.Add('samAccountName'); [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        foreach ($result in $searcher.FindAll()) {
            $display = if ($result.Properties.Contains('samaccountname')) { $result.Properties.samaccountname[0].ToString() }
                       elseif ($result.Properties.Contains('name'))       { $result.Properties.name[0].ToString() }
                       else { $result.Properties.distinguishedname[0].ToString() }
            [System.Management.Automation.CompletionResult]::new("'$display'", $display, 'ParameterValue', $display)
        }
    } catch { return }
}

Register-ArgumentCompleter -CommandName Get-ADScoutGroupMember,Get-ADScoutGroupReport -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) { '(objectClass=group)' }
                           else { "(&(objectClass=group)(|(name=*$safeWord*)(samAccountName=*$safeWord*)))" }
        [void]$searcher.PropertiesToLoad.Add('name'); [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('name')) {
                $name = $result.Properties.name[0].ToString()
                [System.Management.Automation.CompletionResult]::new("'$name'", $name, 'ParameterValue', $name)
            }
        }
    } catch { return }
}

Register-ArgumentCompleter -CommandName Get-ADScoutGroupReport -ParameterName GroupName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)
    try {
        $root = [ADSI]'LDAP://RootDSE'; $baseDn = $root.defaultNamingContext; if (-not $baseDn) { return }
        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50; $searcher.SizeLimit = 25
        $safeWord = $wordToComplete -replace "'"
        $searcher.Filter = if ([string]::IsNullOrWhiteSpace($safeWord)) { '(objectClass=group)' }
                           else { "(&(objectClass=group)(|(name=*$safeWord*)(samAccountName=*$safeWord*)))" }
        [void]$searcher.PropertiesToLoad.Add('name')
        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('name')) {
                $name = $result.Properties.name[0].ToString()
                [System.Management.Automation.CompletionResult]::new("'$name'", $name, 'ParameterValue', $name)
            }
        }
    } catch { return }
}

# =============================================================================
# SUMMARY
# =============================================================================

function Get-ADScoutSummary {
<#
.SYNOPSIS
Prints a concise, color-coded summary of findings grouped by what's actionable.
.DESCRIPTION
Designed to give an immediate read on what was found after a collection run.
Pass findings from Get-ADScoutFinding or Invoke-ADScout, or run standalone
to collect findings automatically.
.EXAMPLE
Get-ADScoutFinding -SkipAclSweep | Get-ADScoutSummary
.EXAMPLE
Get-ADScoutSummary  # collects findings automatically with -SkipAclSweep
.EXAMPLE
$results = Invoke-ADScout -Preset Standard -NoExport
Get-ADScoutSummary -Findings $results.Findings
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][object[]]$Findings,
        [string]$Server, [PSCredential]$Credential, [string]$SearchBase
    )
    begin   { $collected = New-Object System.Collections.Generic.List[object] }
    process { if ($Findings) { foreach ($f in $Findings) { $collected.Add($f) } } }
    end {
        if ($collected.Count -eq 0) {
            Write-Host '[*] No findings passed -- running Get-ADScoutFinding -SkipAclSweep ...' -ForegroundColor Cyan
            $collected = @(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -SkipAclSweep)
        }

        $all = @($collected)

        Write-Host ''
        Write-Host '+==========================================+' -ForegroundColor Cyan
        Write-Host '|         ADScoutPS -- Finding Summary       |' -ForegroundColor Cyan
        Write-Host '+==========================================+' -ForegroundColor Cyan
        Write-Host ''

        # Severity counts
        $critical = @($all | Where-Object Severity -eq 'Critical').Count
        $high     = @($all | Where-Object Severity -eq 'High').Count
        $medium   = @($all | Where-Object Severity -eq 'Medium').Count
        $low      = @($all | Where-Object Severity -eq 'Low').Count
        $info     = @($all | Where-Object Severity -eq 'Info').Count

        Write-Host '  Severity Breakdown' -ForegroundColor White
        if ($critical -gt 0) { Write-Host "    Critical : $critical" -ForegroundColor Red }
        if ($high     -gt 0) { Write-Host "    High     : $high"     -ForegroundColor Yellow }
        if ($medium   -gt 0) { Write-Host "    Medium   : $medium"   -ForegroundColor DarkYellow }
        if ($low      -gt 0) { Write-Host "    Low      : $low"      -ForegroundColor Gray }
        if ($info     -gt 0) { Write-Host "    Info     : $info"     -ForegroundColor DarkGray }
        Write-Host ''

        # Actionable hit checks -- ordered by exploitation directness
        $checks = @(
            @{ Pattern='Password in description';               Label='Cleartext creds in description';  Color='Red'        }
            @{ Pattern='AS-REP roast candidate';                Label='AS-REP Roast';                    Color='Red'        }
            @{ Pattern='Non-standard ACE on AdminSDHolder';     Label='AdminSDHolder persistence ACE';   Color='Red'        }
            @{ Pattern='Abusable ACE on';                       Label='ACL attack path on HVT';          Color='Red'        }
            @{ Pattern='DCSync-related replication right';      Label='DCSync path';                     Color='Red'        }
            @{ Pattern='Unconstrained delegation';              Label='Unconstrained Delegation';         Color='Red'        }
            @{ Pattern='GPO write permission';                  Label='GPO write (linked to priv OU)';   Color='Red'        }
            @{ Pattern='Machine account quota is non-zero';     Label='Non-zero machine account quota';  Color='Yellow'     }
            @{ Pattern='SPN-bearing user account';              Label='Kerberoast';                      Color='Yellow'     }
            @{ Pattern='Targeted Kerberoast path';              Label='Targeted Kerberoast path';        Color='Yellow'     }
            @{ Pattern='RBCD delegation';                       Label='RBCD abuse';                      Color='Yellow'     }
            @{ Pattern='KCD delegation';                        Label='KCD delegation';                  Color='Yellow'     }
            @{ Pattern='msDS-KeyCredentialLink present';        Label='Shadow credentials';              Color='Yellow'     }
            @{ Pattern='Interesting ACE on domain root';        Label='Interesting ACE on domain root';  Color='Yellow'     }
            @{ Pattern='Weak password policy';                  Label='Weak password policy';            Color='Yellow'     }
            @{ Pattern='Weak/review-worthy UAC flag';           Label='Weak UAC flags';                  Color='DarkYellow' }
            @{ Pattern='adminCount=1';                          Label='adminCount=1 objects';            Color='DarkYellow' }
            @{ Pattern='No visible LAPS metadata';              Label='No LAPS coverage';                Color='DarkYellow' }
            @{ Pattern='Stale computer account';                Label='Stale computers';                 Color='Gray'       }
        )

        Write-Host '  Actionable Findings' -ForegroundColor White
        $anyHit = $false
        foreach ($c in $checks) {
            $hits = @($all | Where-Object { $_.Title -match $c.Pattern -and $_.Severity -ne 'Info' })
            if ($hits.Count -gt 0) {
                $anyHit = $true
                Write-Host "    [+] $($c.Label): $($hits.Count) hit(s)" -ForegroundColor $c.Color
                $hits | ForEach-Object {
                    Write-Host "        -> $($_.Target)" -ForegroundColor DarkGray
                }
            }
        }
        if (-not $anyHit) { Write-Host '    None above threshold.' -ForegroundColor DarkGray }

        # Info -- trusts and DCs just as a count
        Write-Host ''
        Write-Host '  Inventory (Info)' -ForegroundColor White
        $dcCount    = @($all | Where-Object { $_.Title -match 'Domain controller discovered' }).Count
        $trustCount = @($all | Where-Object { $_.Title -match 'Domain trust present' }).Count
        Write-Host "    Domain Controllers : $dcCount"  -ForegroundColor DarkGray
        Write-Host "    Domain Trusts      : $trustCount" -ForegroundColor DarkGray
        Write-Host ''
    }
}

# =============================================================================
# ENTRY POINT
# When dot-sourced ($MyInvocation.InvocationName -eq '.') or imported as a
# module, the block below is skipped and only functions are loaded.
# When run directly as a script, Invoke-ADScout fires with the top-level params.
# =============================================================================

if ($MyInvocation.InvocationName -ne '.' -and -not $LoadOnly) {
    Invoke-ADScout -Preset $Preset -Server $Server -Credential $Credential `
        -SearchBase $SearchBase -OutputPath $OutputPath -OutputFormat $OutputFormat `
        -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep `
        -Gui:$Gui -View $View -Report:$Report -NoExport:$NoExport
}
