<#
ADScoutPS Standalone Runner
Read-only Active Directory enumeration for authorized labs and approved assessments only.

Examples:
  powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -SkipAclSweep
  powershell -ExecutionPolicy Bypass -File .\ADScout.ps1 -Gui -SkipAclSweep
  . .\ADScout.ps1 -LoadOnly
  Get-ADScoutGroupReport -PrivilegedOnly -Recursive
#>

param(
    [switch]$LoadOnly,
    [switch]$Gui,
    [switch]$SkipAclSweep,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$SearchBase,
    [string]$OutputPath = 'ADScout-Results',
    [ValidateSet('CSV','JSON','Both')]
    [string]$OutputFormat = 'Both'
)

<#
ADScoutPS v1.1.0 - PowerShell Active Directory Enumeration Toolkit
Read-only enumeration for authorized lab environments and approved internal assessments only.
#>

Set-StrictMode -Version Latest

function New-ADScoutDirectoryEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LdapPath,[PSCredential]$Credential)
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry($LdapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
}

function Get-ADScoutDomainContext {
<#
.SYNOPSIS
Auto-discovers the current AD domain, PDC, and base distinguished name.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $pdc = $Server
    $source = 'RootDSE'
    if (-not $pdc -and -not $Credential) {
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $pdc = $domainObj.PdcRoleOwner.Name
            $source = 'CurrentDomain/PDC'
        } catch { $source = 'RootDSE fallback' }
    }
    $rootPath = if ($pdc) { "LDAP://$pdc/RootDSE" } else { 'LDAP://RootDSE' }
    $root = New-ADScoutDirectoryEntry -LdapPath $rootPath -Credential $Credential
    $base = if ($SearchBase) { $SearchBase } else { [string]$root.Properties['defaultNamingContext'][0] }
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'Could not determine defaultNamingContext/SearchBase.' }
    [PSCustomObject]@{
        Server = $pdc
        DefaultNamingContext = [string]$root.Properties['defaultNamingContext'][0]
        ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
        SchemaNamingContext = [string]$root.Properties['schemaNamingContext'][0]
        DnsHostName = [string]$root.Properties['dnsHostName'][0]
        SearchBase = $base
        LdapBasePath = if ($pdc) { "LDAP://$pdc/$base" } else { "LDAP://$base" }
        DiscoverySource = $source
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
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $root = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    if ($SizeLimit -gt 0) { $searcher.SizeLimit = $SizeLimit }
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    $searcher
}

function Get-ADScoutProperty {
    param($Result,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return $null }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        if ($Result.Properties[$Name].Count -eq 1) { return $Result.Properties[$Name][0].ToString() }
        return ($Result.Properties[$Name] | ForEach-Object { $_.ToString() }) -join ';'
    }
    $null
}



function Get-ADScoutPropertyValues {
    param($Result,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Result) { return @() }
    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return @($Result.Properties[$Name] | ForEach-Object { $_.ToString() })
    }
    return @()
}

function Get-ADScoutDirectoryEntryPropertyValues {
    param($Entry,[Parameter(Mandatory)][string]$Name)
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
    param([Parameter(Mandatory)]$InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-ADScoutDirectoryObjectSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DistinguishedName,[string]$Server,[PSCredential]$Credential,[string]$SearchBase)

    try {
        $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $path = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
        $classes = Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'objectClass'
        $sam = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'samAccountName' | Select-Object -First 1)
        $name = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'name' | Select-Object -First 1)
        $upn = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'userPrincipalName' | Select-Object -First 1)
        $dns = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'dNSHostName' | Select-Object -First 1)
        [PSCustomObject]@{
            Name = $name
            SamAccountName = $sam
            UserPrincipalName = $upn
            DnsHostName = $dns
            ObjectClass = Get-ADScoutObjectClassName -ObjectClassValues $classes
            ObjectClassPath = ($classes -join ';')
            DistinguishedName = $DistinguishedName
        }
    }
    catch {
        [PSCustomObject]@{
            Name = $null
            SamAccountName = $null
            UserPrincipalName = $null
            DnsHostName = $null
            ObjectClass = $null
            ObjectClassPath = $null
            DistinguishedName = $DistinguishedName
            Error = $_.Exception.Message
        }
    }
}

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
        PASSWORD_EXPIRED=0x800000; TRUSTED_TO_AUTH_FOR_DELEGATION=0x1000000; PARTIAL_SECRETS_ACCOUNT=0x04000000
    }
    foreach ($kv in $map.GetEnumerator()) { if (($UserAccountControl -band [int]$kv.Value) -ne 0) { $kv.Key } }
}

function Get-ADScoutDomainInfo {
<#
.SYNOPSIS
Retrieves RootDSE/domain metadata.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
}

function Get-ADScoutUser {
<#
.SYNOPSIS
Retrieves AD users with decoded UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $props='samaccountname','userprincipalname','displayname','distinguishedname','description','serviceprincipalname','lastlogontimestamp','memberof','useraccountcontrol','admincount'
    $s = New-ADScoutSearcher -Filter '(&(objectCategory=person)(objectClass=user))' -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) {
        $uacRaw = Get-ADScoutProperty $r 'useraccountcontrol'; $uac = if ($uacRaw) { [int]$uacRaw } else { 0 }
        [PSCustomObject]@{
            SamAccountName=Get-ADScoutProperty $r 'samaccountname'; UserPrincipalName=Get-ADScoutProperty $r 'userprincipalname'; DisplayName=Get-ADScoutProperty $r 'displayname'; Description=Get-ADScoutProperty $r 'description'; AdminCount=Get-ADScoutProperty $r 'admincount'; UserAccountControl=$uac; UacFlags=(ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','; ServicePrincipalName=Get-ADScoutProperty $r 'serviceprincipalname'; MemberOf=Get-ADScoutProperty $r 'memberof'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname'
        }
    }
}

function Get-ADScoutGroup {
<#
.SYNOPSIS
Retrieves AD groups.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=group)' -Properties @('samaccountname','name','distinguishedname','description','member') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ Name=Get-ADScoutProperty $r 'name'; SamAccountName=Get-ADScoutProperty $r 'samaccountname'; Description=Get-ADScoutProperty $r 'description'; Member=Get-ADScoutProperty $r 'member'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutComputer {
<#
.SYNOPSIS
Retrieves AD computer objects.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $props='name','dnshostname','operatingsystem','operatingsystemversion','distinguishedname','useraccountcontrol','lastlogontimestamp','primarygroupid','ms-mcs-admpwdexpirationtime','mslaps-passwordexpirationtime'
    $s = New-ADScoutSearcher -Filter '(objectCategory=computer)' -Properties $props -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { $uacRaw=Get-ADScoutProperty $r 'useraccountcontrol'; $uac=if($uacRaw){[int]$uacRaw}else{0}; [PSCustomObject]@{ Name=Get-ADScoutProperty $r 'name'; DnsHostName=Get-ADScoutProperty $r 'dnshostname'; OperatingSystem=Get-ADScoutProperty $r 'operatingsystem'; OperatingSystemVersion=Get-ADScoutProperty $r 'operatingsystemversion'; LastLogonTimestamp=Get-ADScoutProperty $r 'lastlogontimestamp'; PrimaryGroupId=Get-ADScoutProperty $r 'primarygroupid'; UserAccountControl=$uac; UacFlags=(ConvertTo-ADScoutUacFlag -UserAccountControl $uac) -join ','; HasLegacyLaps=([bool](Get-ADScoutProperty $r 'ms-mcs-admpwdexpirationtime')); HasWindowsLaps=([bool](Get-ADScoutProperty $r 'mslaps-passwordexpirationtime')); DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutDomainController {
<#
.SYNOPSIS
Enumerates domain controllers.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.UacFlags -match 'SERVER_TRUST_ACCOUNT' -or $_.PrimaryGroupId -eq '516' }
}

function Find-ADScoutSPNAccount {
<#
.SYNOPSIS
Finds accounts with servicePrincipalName values.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(&(servicePrincipalName=*)(|(objectCategory=person)(objectCategory=computer)))' -Properties @('samaccountname','serviceprincipalname','distinguishedname','description') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ SamAccountName=Get-ADScoutProperty $r 'samaccountname'; ServicePrincipalName=Get-ADScoutProperty $r 'serviceprincipalname'; Description=Get-ADScoutProperty $r 'description'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Find-ADScoutASREPAccount {
<#
.SYNOPSIS
Finds accounts with Kerberos preauthentication disabled.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.UacFlags -match 'DONT_REQUIRE_PREAUTH' }
}

function Find-ADScoutUnconstrainedDelegation {
<#
.SYNOPSIS
Finds accounts configured for unconstrained delegation.
.DESCRIPTION
Returns users and computers with TRUSTED_FOR_DELEGATION. By default, domain controllers are excluded from the result set to keep the output focused on unusual delegation exposure.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase,[switch]$IncludeDomainControllers)

    $items = @(Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase) + @(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase)

    foreach ($item in $items) {
        $uacFlags = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'UacFlags')
        if ($uacFlags -notmatch 'TRUSTED_FOR_DELEGATION') { continue }

        $primaryGroupId = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'PrimaryGroupId')
        $objectName = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'SamAccountName')
        if ([string]::IsNullOrWhiteSpace($objectName)) { $objectName = [string](Get-ADScoutSafeProperty -InputObject $item -Name 'Name') }

        $isDomainController = ($primaryGroupId -eq '516' -or $uacFlags -match 'SERVER_TRUST_ACCOUNT')
        if ($isDomainController -and -not $IncludeDomainControllers) { continue }

        [PSCustomObject]@{
            Name = $objectName
            ObjectType = if ($primaryGroupId) { 'computer' } else { 'user' }
            IsDomainController = $isDomainController
            PrimaryGroupId = $primaryGroupId
            UacFlags = $uacFlags
            DistinguishedName = Get-ADScoutSafeProperty -InputObject $item -Name 'DistinguishedName'
        }
    }
}

function Find-ADScoutConstrainedDelegation {
<#
.SYNOPSIS
Finds traditional constrained delegation and resource-based constrained delegation indicators.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $kcd = New-ADScoutSearcher -Filter '(&(msDS-AllowedToDelegateTo=*)(|(objectCategory=computer)(objectCategory=person)))' -Properties @('samaccountname','distinguishedname','msds-allowedtodelegateto') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $kcd.FindAll()) { [PSCustomObject]@{ Type='KCD'; SamAccountName=Get-ADScoutProperty $r 'samaccountname'; DelegatesTo=Get-ADScoutProperty $r 'msds-allowedtodelegateto'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
    $rbcd = New-ADScoutSearcher -Filter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties @('samaccountname','distinguishedname','name') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $rbcd.FindAll()) { [PSCustomObject]@{ Type='RBCD'; SamAccountName=Get-ADScoutProperty $r 'samaccountname'; DelegatesTo='msDS-AllowedToActOnBehalfOfOtherIdentity present'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutDomainTrust {
<#
.SYNOPSIS
Enumerates domain trust objects.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=trustedDomain)' -Properties @('name','flatname','trustdirection','trusttype','trustattributes','distinguishedname') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ Name=Get-ADScoutProperty $r 'name'; FlatName=Get-ADScoutProperty $r 'flatname'; TrustDirection=Get-ADScoutProperty $r 'trustdirection'; TrustType=Get-ADScoutProperty $r 'trusttype'; TrustAttributes=Get-ADScoutProperty $r 'trustattributes'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutPasswordPolicy {
<#
.SYNOPSIS
Returns default domain password policy and fine-grained password policies where readable.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $entry = New-ADScoutDirectoryEntry -LdapPath $ctx.LdapBasePath -Credential $Credential

    $defaultMinLength = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdLength' | Select-Object -First 1)
    $defaultHistory = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'pwdHistoryLength' | Select-Object -First 1)
    $defaultLockout = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'lockoutThreshold' | Select-Object -First 1)
    $defaultMaxAge = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'maxPwdAge' | Select-Object -First 1)
    $defaultMinAge = (Get-ADScoutDirectoryEntryPropertyValues -Entry $entry -Name 'minPwdAge' | Select-Object -First 1)

    [PSCustomObject]@{
        PolicyType='DefaultDomain'
        Name='Default Domain Policy'
        DistinguishedName=$ctx.SearchBase
        MinPwdLength=$defaultMinLength
        PwdHistoryLength=$defaultHistory
        LockoutThreshold=$defaultLockout
        LockoutDisabled=($defaultLockout -ne $null -and [int]$defaultLockout -eq 0)
        MaxPwdAgeRaw=$defaultMaxAge
        MinPwdAgeRaw=$defaultMinAge
    }

    $s = New-ADScoutSearcher -Filter '(objectClass=msDS-PasswordSettings)' -Properties @('name','distinguishedname','msds-minimumpasswordlength','msds-passwordhistorylength','msds-lockoutthreshold','msds-passwordsettingsprecedence','msds-psoappliesto') -Server $Server -Credential $Credential -SearchBase $ctx.SearchBase
    foreach ($r in $s.FindAll()) {
        $fgLockout = Get-ADScoutProperty $r 'msds-lockoutthreshold'
        [PSCustomObject]@{
            PolicyType='FineGrained'
            Name=Get-ADScoutProperty $r 'name'
            DistinguishedName=Get-ADScoutProperty $r 'distinguishedname'
            Precedence=Get-ADScoutProperty $r 'msds-passwordsettingsprecedence'
            MinPwdLength=Get-ADScoutProperty $r 'msds-minimumpasswordlength'
            PwdHistoryLength=Get-ADScoutProperty $r 'msds-passwordhistorylength'
            LockoutThreshold=$fgLockout
            LockoutDisabled=($fgLockout -ne $null -and [int]$fgLockout -eq 0)
            AppliesTo=Get-ADScoutProperty $r 'msds-psoappliesto'
        }
    }
}

function Find-ADScoutAdminSDHolderOrphan {
<#
.SYNOPSIS
Finds adminCount=1 users/groups for privileged object review.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(&(adminCount=1)(|(objectCategory=person)(objectCategory=group)))' -Properties @('samaccountname','name','objectclass','distinguishedname','admincount') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ Name=Get-ADScoutProperty $r 'name'; SamAccountName=Get-ADScoutProperty $r 'samaccountname'; ObjectClass=Get-ADScoutProperty $r 'objectclass'; AdminCount=Get-ADScoutProperty $r 'admincount'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Find-ADScoutWeakUacFlag {
<#
.SYNOPSIS
Finds users with weak or review-worthy UAC flags.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.UacFlags -match 'PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD|ENCRYPTED_TEXT_PWD_ALLOWED|USE_DES_KEY_ONLY' }
}

function Get-ADScoutLapsStatus {
<#
.SYNOPSIS
Reports visible legacy/new Windows LAPS metadata per computer.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase | Select-Object Name,DnsHostName,HasLegacyLaps,HasWindowsLaps,DistinguishedName
}

function Get-ADScoutGPO {
<#
.SYNOPSIS
Enumerates Group Policy Objects.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential)
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential
    $policyBase = "CN=Policies,CN=System,$($ctx.DefaultNamingContext)"
    $s = New-ADScoutSearcher -Filter '(objectClass=groupPolicyContainer)' -Properties @('displayname','name','distinguishedname','whenchanged','gpcfilesyspath') -Server $Server -Credential $Credential -SearchBase $policyBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ DisplayName=Get-ADScoutProperty $r 'displayname'; Guid=Get-ADScoutProperty $r 'name'; GpcFileSysPath=Get-ADScoutProperty $r 'gpcfilesyspath'; WhenChanged=Get-ADScoutProperty $r 'whenchanged'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutOU {
<#
.SYNOPSIS
Enumerates Organizational Units and linked GPO metadata.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $s = New-ADScoutSearcher -Filter '(objectClass=organizationalUnit)' -Properties @('name','distinguishedname','gplink') -Server $Server -Credential $Credential -SearchBase $SearchBase
    foreach ($r in $s.FindAll()) { [PSCustomObject]@{ Name=Get-ADScoutProperty $r 'name'; LinkedGPOs=Get-ADScoutProperty $r 'gplink'; DistinguishedName=Get-ADScoutProperty $r 'distinguishedname' } }
}

function Get-ADScoutLinkedGPO {
<#
.SYNOPSIS
Returns OUs that have linked GPOs.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutOU -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.LinkedGPOs }
}

function Resolve-ADScoutDistinguishedName {
    [CmdletBinding()]
    param([string]$Identity,[string]$ObjectClass='*',[string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    if ($Identity -match '^(CN|OU|DC)=') { return $Identity }
    $safe = $Identity -replace '\\','\\5c' -replace '\*','\\2a' -replace '\(','\\28' -replace '\)','\\29'
    $classFilter = if ($ObjectClass -and $ObjectClass -ne '*') { "(objectClass=$ObjectClass)" } else { '(objectClass=*)' }
    $filter = "(&${classFilter}(|(name=$safe)(samAccountName=$safe)(displayName=$safe)))"
    $s = New-ADScoutSearcher -Filter $filter -Properties @('distinguishedname') -Server $Server -Credential $Credential -SearchBase $SearchBase -SizeLimit 1
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
    [CmdletBinding(DefaultParameterSetName='DN')]
    param([Parameter(ParameterSetName='DN')][string]$DistinguishedName,[Parameter(ParameterSetName='Identity')][string]$Identity,[Parameter(ParameterSetName='Identity')][string]$ObjectClass='*',[string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    if (-not $DistinguishedName) { $DistinguishedName = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass $ObjectClass -Server $Server -Credential $Credential -SearchBase $SearchBase }
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $path = if ($ctx.Server) { "LDAP://$($ctx.Server)/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
    $entry = New-ADScoutDirectoryEntry -LdapPath $path -Credential $Credential
    foreach ($ace in $entry.ObjectSecurity.Access) { [PSCustomObject]@{ IdentityReference=$ace.IdentityReference.ToString(); ActiveDirectoryRights=$ace.ActiveDirectoryRights.ToString(); AccessControlType=$ace.AccessControlType.ToString(); ObjectType=$ace.ObjectType.ToString(); InheritedObjectType=$ace.InheritedObjectType.ToString(); IsInherited=$ace.IsInherited; InheritanceType=$ace.InheritanceType.ToString(); DistinguishedName=$DistinguishedName } }
}

function Find-ADScoutInterestingAce {
<#
.SYNOPSIS
Finds powerful ACEs on a target object or domain root.
#>
    [CmdletBinding()]
    param([string]$DistinguishedName,[string]$Identity,[string]$ObjectClass='*',[string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $aclParams = @{ Server=$Server; Credential=$Credential; SearchBase=$SearchBase }
    if ($DistinguishedName) {
        $aclParams['DistinguishedName'] = $DistinguishedName
    } elseif ($Identity) {
        $aclParams['Identity'] = $Identity
        $aclParams['ObjectClass'] = $ObjectClass
    } else {
        $aclParams['DistinguishedName'] = (Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase).SearchBase
    }
    Get-ADScoutObjectAcl @aclParams | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|CreateChild|DeleteChild|WriteProperty' }
}

function Find-ADScoutDCSyncRight {
<#
.SYNOPSIS
Detects principals with replication rights on the domain root ACL.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rep = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='DS-Replication-Get-Changes'; '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='DS-Replication-Get-Changes-All'; '89e95b76-444d-4c62-991a-0facbeda640c'='DS-Replication-Get-Changes-In-Filtered-Set' }
    Get-ADScoutObjectAcl -DistinguishedName $ctx.SearchBase -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $rep.ContainsKey($_.ObjectType) } | ForEach-Object { [PSCustomObject]@{ IdentityReference=$_.IdentityReference; RightName=$rep[$_.ObjectType]; ActiveDirectoryRights=$_.ActiveDirectoryRights; AccessControlType=$_.AccessControlType; IsInherited=$_.IsInherited; DistinguishedName=$ctx.SearchBase } }
}

function Find-ADScoutAdminGroup {
<#
.SYNOPSIS
Finds admin/privileged-looking groups by name.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.Name -match 'admin|operator|backup|account|enterprise|schema|domain controllers' }
}

function Get-ADScoutGroupMember {
<#
.SYNOPSIS
Gets direct or recursive group members with analyst-friendly columns.
.DESCRIPTION
Resolves each member DN into name, samAccountName, objectClass, and nesting depth. This keeps output readable during lab/engagement work.
.EXAMPLE
Get-ADScoutGroupMember -Identity 'Domain Admins' -Recursive
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [switch]$Recursive,
        [int]$MaxDepth = 20,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )

    $rootGroupDn = Resolve-ADScoutDistinguishedName -Identity $Identity -ObjectClass group -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootSummary = Get-ADScoutDirectoryObjectSummary -DistinguishedName $rootGroupDn -Server $Server -Credential $Credential -SearchBase $SearchBase
    $rootGroupName = if ($rootSummary.SamAccountName) { $rootSummary.SamAccountName } elseif ($rootSummary.Name) { $rootSummary.Name } else { $Identity }
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'

    function Invoke-ADScoutGroupMemberWalk {
        param(
            [string]$GroupDn,
            [string]$ParentGroupName,
            [int]$Depth,
            [string]$Path
        )

        if ($Depth -gt $MaxDepth) { return }
        if (-not $visited.Add($GroupDn)) { return }

        $ctx = Get-ADScoutDomainContext -Server $Server -Credential $Credential -SearchBase $SearchBase
        $groupPath = if ($ctx.Server) { "LDAP://$($ctx.Server)/$GroupDn" } else { "LDAP://$GroupDn" }
        $groupEntry = New-ADScoutDirectoryEntry -LdapPath $groupPath -Credential $Credential
        $memberDns = Get-ADScoutDirectoryEntryPropertyValues -Entry $groupEntry -Name 'member'

        foreach ($memberDn in $memberDns) {
            $member = Get-ADScoutDirectoryObjectSummary -DistinguishedName $memberDn -Server $Server -Credential $Credential -SearchBase $SearchBase
            $display = if ($member.SamAccountName) { $member.SamAccountName } elseif ($member.Name) { $member.Name } elseif ($member.DnsHostName) { $member.DnsHostName } else { $memberDn }
            $memberPath = if ($Path) { "$Path -> $display" } else { "$ParentGroupName -> $display" }

            [PSCustomObject]@{
                RootGroup = $rootGroupName
                ParentGroup = $ParentGroupName
                MemberName = $member.Name
                MemberSamAccountName = $member.SamAccountName
                MemberUserPrincipalName = $member.UserPrincipalName
                MemberDnsHostName = $member.DnsHostName
                MemberObjectClass = $member.ObjectClass
                Depth = $Depth
                IsNested = ($Depth -gt 0)
                Path = $memberPath
                MemberDistinguishedName = $member.DistinguishedName
            }

            if ($Recursive -and $member.ObjectClass -eq 'group') {
                Invoke-ADScoutGroupMemberWalk -GroupDn $memberDn -ParentGroupName $display -Depth ($Depth + 1) -Path $memberPath
            }
        }
    }

    Invoke-ADScoutGroupMemberWalk -GroupDn $rootGroupDn -ParentGroupName $rootGroupName -Depth 0 -Path $rootGroupName
}

function Get-ADScoutGroupReport {
<#
.SYNOPSIS
Creates a clean group/member report for all groups, selected groups, or common privileged groups.
.EXAMPLE
Get-ADScoutGroupReport -PrivilegedOnly -Recursive | Format-Table -AutoSize
.EXAMPLE
Get-ADScoutGroupReport -GroupName 'Domain Admins','Remote Management Users' -Recursive
#>
    [CmdletBinding()]
    param(
        [string[]]$GroupName,
        [switch]$Recursive,
        [switch]$PrivilegedOnly,
        [string]$Server,
        [PSCredential]$Credential,
        [string]$SearchBase
    )

    if ($PrivilegedOnly) {
        $GroupName = @(
            'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','Remote Desktop Users','Remote Management Users','DnsAdmins','Group Policy Creator Owners'
        )
    }

    if (-not $GroupName -or $GroupName.Count -eq 0) {
        $GroupName = @(Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase | Select-Object -ExpandProperty Name)
    }

    foreach ($group in $GroupName) {
        try {
            $rows = @(Get-ADScoutGroupMember -Identity $group -Recursive:$Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase)
            if ($rows.Count -eq 0) {
                [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<No members found>'; MemberType=$null; Depth=$null; IsNested=$null; Path=$null; DistinguishedName=$null }
                continue
            }
            foreach ($row in $rows) {
                $memberName = if ($row.MemberSamAccountName) { $row.MemberSamAccountName } elseif ($row.MemberName) { $row.MemberName } elseif ($row.MemberDnsHostName) { $row.MemberDnsHostName } else { $row.MemberDistinguishedName }
                [PSCustomObject]@{ Group=$row.RootGroup; ParentGroup=$row.ParentGroup; Member=$memberName; MemberType=$row.MemberObjectClass; Depth=$row.Depth; IsNested=$row.IsNested; Path=$row.Path; DistinguishedName=$row.MemberDistinguishedName }
            }
        }
        catch {
            [PSCustomObject]@{ Group=$group; ParentGroup=$group; Member='<Error>'; MemberType=$null; Depth=$null; IsNested=$null; Path=$_.Exception.Message; DistinguishedName=$null }
        }
    }
}

function Find-ADScoutPrivilegedUser {
<#
.SYNOPSIS
Expands common privileged groups to identify privileged members.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { $_.Member -and $_.Member -notlike '<*>' }
}

function Find-ADScoutOldComputer {
<#
.SYNOPSIS
Finds computer accounts with old or missing lastLogonTimestamp.
#>
    [CmdletBinding()]
    param([int]$Days=90,[string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { -not $_.LastLogonTimestamp }
}

function Find-ADScoutDelegationHint {
<#
.SYNOPSIS
Compatibility wrapper for delegation-related review items.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase)
    @(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) + @(Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase)
}

function New-ADScoutFinding {
    param([string]$Severity,[string]$Category,[string]$Title,[string]$Target,[string]$Evidence,[string]$WhyItMatters,[string]$RecommendedReview,[string]$SourceCommand,[string]$DistinguishedName)
    [PSCustomObject]@{ Severity=$Severity; Category=$Category; Title=$Title; Target=$Target; Evidence=$Evidence; WhyItMatters=$WhyItMatters; RecommendedReview=$RecommendedReview; SourceCommand=$SourceCommand; DistinguishedName=$DistinguishedName }
}

function Get-ADScoutObjectDisplayName {
<#
.SYNOPSIS
Returns the best available display identifier for an ADScout object.
.DESCRIPTION
Used by the findings engine to avoid strict-mode property errors when different object types expose different property names.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory,ValueFromPipeline)]$InputObject)
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

function Get-ADScoutFinding {
<#
.SYNOPSIS
Returns normalized findings sorted by operational priority.
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase,[switch]$SkipAclSweep)
    $f = New-Object System.Collections.Generic.List[object]
    foreach ($x in Find-ADScoutASREPAccount -Server $Server -Credential $Credential -SearchBase $SearchBase) { $target = Get-ADScoutObjectDisplayName -InputObject $x; $f.Add((New-ADScoutFinding 'Critical' 'Kerberos' 'AS-REP roast candidate' $target $x.UacFlags 'Kerberos preauthentication is disabled for this account.' 'Review whether preauthentication should be required and whether the account is still needed.' 'Find-ADScoutASREPAccount' $x.DistinguishedName)) }
    foreach ($x in Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) { $target = Get-ADScoutObjectDisplayName -InputObject $x; $f.Add((New-ADScoutFinding 'Critical' 'Delegation' 'Unconstrained delegation account' $target $x.UacFlags 'Unconstrained delegation can expose delegated authentication material if the account/host is compromised.' 'Confirm business need and review delegation configuration.' 'Find-ADScoutUnconstrainedDelegation' $x.DistinguishedName)) }
    foreach ($x in Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase) { $target = Get-ADScoutObjectDisplayName -InputObject $x; $sev=if($x.Type -eq 'RBCD'){'High'}else{'Medium'}; $f.Add((New-ADScoutFinding $sev 'Delegation' "$($x.Type) delegation configured" $target $x.DelegatesTo 'Delegation configuration should be reviewed as part of AD attack-path analysis.' 'Validate target services/principals and intended administration model.' 'Find-ADScoutConstrainedDelegation' $x.DistinguishedName)) }
    if (-not $SkipAclSweep) { foreach ($x in Find-ADScoutDCSyncRight -Server $Server -Credential $Credential -SearchBase $SearchBase) { $f.Add((New-ADScoutFinding 'Critical' 'ACL' 'DCSync-capable replication right' $x.IdentityReference $x.RightName 'Replication rights on the domain root are highly sensitive.' 'Review whether this principal should have directory replication permissions.' 'Find-ADScoutDCSyncRight' $x.DistinguishedName)) } }
    foreach ($x in Get-ADScoutPasswordPolicy -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { (Get-ADScoutSafeProperty -InputObject $_ -Name 'LockoutDisabled') -eq $true -or ((Get-ADScoutSafeProperty -InputObject $_ -Name 'MinPwdLength') -ne $null -and [int](Get-ADScoutSafeProperty -InputObject $_ -Name 'MinPwdLength') -lt 12) }) { $f.Add((New-ADScoutFinding 'High' 'Policy' 'Password policy review item' $x.Name "MinPwdLength=$($x.MinPwdLength); LockoutThreshold=$($x.LockoutThreshold)" 'Weak password or lockout policy settings can increase account abuse risk.' 'Review password and lockout policy against organizational standards.' 'Get-ADScoutPasswordPolicy' $x.DistinguishedName)) }
    foreach ($x in Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase) { $f.Add((New-ADScoutFinding 'Info' 'Trust' 'Domain trust present' $x.Name "Direction=$($x.TrustDirection); Type=$($x.TrustType); Attr=$($x.TrustAttributes)" 'Trusts expand the AD security boundary and should be mapped.' 'Review trust direction, transitivity, and SID filtering configuration.' 'Get-ADScoutDomainTrust' $x.DistinguishedName)) }
    foreach ($x in Find-ADScoutAdminSDHolderOrphan -Server $Server -Credential $Credential -SearchBase $SearchBase) { $target=if($x.SamAccountName){$x.SamAccountName}else{$x.Name}; $f.Add((New-ADScoutFinding 'Medium' 'Privilege' 'adminCount=1 object' $target $x.ObjectClass 'adminCount=1 may indicate current or historical privileged protection.' 'Review whether object is still privileged and whether ACL inheritance is appropriate.' 'Find-ADScoutAdminSDHolderOrphan' $x.DistinguishedName)) }
    foreach ($x in Find-ADScoutWeakUacFlag -Server $Server -Credential $Credential -SearchBase $SearchBase) { $target = Get-ADScoutObjectDisplayName -InputObject $x; $sev=if($x.UacFlags -match 'ENCRYPTED_TEXT_PWD_ALLOWED|PASSWD_NOTREQD'){'High'}else{'Medium'}; $f.Add((New-ADScoutFinding $sev 'AccountControl' 'Weak/review-worthy UAC flag' $target $x.UacFlags 'UAC flags can reveal relaxed authentication or password controls.' 'Review whether these flags are required.' 'Find-ADScoutWeakUacFlag' $x.DistinguishedName)) }
    foreach ($x in Get-ADScoutLapsStatus -Server $Server -Credential $Credential -SearchBase $SearchBase | Where-Object { -not $_.HasLegacyLaps -and -not $_.HasWindowsLaps }) { $target = Get-ADScoutObjectDisplayName -InputObject $x; $f.Add((New-ADScoutFinding 'Medium' 'Endpoint' 'No visible LAPS metadata' $target $x.DnsHostName 'Systems without visible LAPS metadata may need local admin password management review.' 'Confirm whether LAPS or another local admin password control is deployed.' 'Get-ADScoutLapsStatus' $x.DistinguishedName)) }
    if (-not $SkipAclSweep) { foreach ($x in Find-ADScoutInterestingAce -Server $Server -Credential $Credential -SearchBase $SearchBase) { $f.Add((New-ADScoutFinding 'High' 'ACL' 'Interesting ACE' $x.IdentityReference $x.ActiveDirectoryRights 'Powerful ACEs can indicate delegated control paths.' 'Review whether the delegated permission is expected and least-privilege.' 'Find-ADScoutInterestingAce' $x.DistinguishedName)) } }
    $rank=@{Critical=0;High=1;Medium=2;Low=3;Info=4}; $f | Sort-Object @{Expression={$rank[$_.Severity]}},Category,Title,Target
}

function Test-ADScoutGridViewAvailable { [CmdletBinding()] param(); [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue) }

function Show-ADScoutFindingsGui {
<#
.SYNOPSIS
Shows findings in Out-GridView when available, otherwise console table.
#>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][object[]]$Findings)
    process { if (-not (Get-Variable -Name ADScoutGuiBuffer -Scope Script -ErrorAction SilentlyContinue)) { $script:ADScoutGuiBuffer = @() }; $script:ADScoutGuiBuffer += $Findings }
    end {
        $items=@($script:ADScoutGuiBuffer); $script:ADScoutGuiBuffer=$null
        if (Test-ADScoutGridViewAvailable) { $items | Select-Object Severity,Category,Title,Target,Evidence,WhyItMatters,RecommendedReview,SourceCommand,DistinguishedName | Out-GridView -Title 'ADScoutPS Findings Dashboard' }
        else { $items | Select-Object Severity,Category,Title,Target,Evidence | Format-Table -AutoSize }
    }
}

function Invoke-ADScout {
<#
.SYNOPSIS
Runs ADScoutPS collection and optional findings-first GUI dashboard.
.EXAMPLE
Invoke-ADScout -SkipAclSweep
.EXAMPLE
Invoke-ADScout -Gui -OutputFormat Both
#>
    [CmdletBinding()]
    param([string]$Server,[PSCredential]$Credential,[string]$SearchBase,[string]$OutputPath='ADScout-Results',[ValidateSet('CSV','JSON','Both')][string]$OutputFormat='Both',[switch]$SkipAclSweep,[switch]$Gui)
    $timestamp=Get-Date -Format 'yyyyMMdd-HHmmss'; $runPath=Join-Path $OutputPath "Run-$timestamp"; New-Item -ItemType Directory -Path $runPath -Force | Out-Null
    Write-Host '[*] ADScoutPS v1.1 collection starting...' -ForegroundColor Cyan
    $data=[ordered]@{}
    $data.DomainInfo=@(Get-ADScoutDomainInfo -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.DomainControllers=@(Get-ADScoutDomainController -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Users=@(Get-ADScoutUser -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Groups=@(Get-ADScoutGroup -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Computers=@(Get-ADScoutComputer -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.GPOs=@(Get-ADScoutGPO -Server $Server -Credential $Credential)
    $data.OUs=@(Get-ADScoutOU -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.SPNAccounts=@(Find-ADScoutSPNAccount -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.ASREPAccounts=@(Find-ADScoutASREPAccount -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.UnconstrainedDelegation=@(Find-ADScoutUnconstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.ConstrainedDelegation=@(Find-ADScoutConstrainedDelegation -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.DomainTrusts=@(Get-ADScoutDomainTrust -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.PasswordPolicies=@(Get-ADScoutPasswordPolicy -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.AdminSDHolderObjects=@(Find-ADScoutAdminSDHolderOrphan -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.PrivilegedGroupMembers=@(Get-ADScoutGroupReport -PrivilegedOnly -Recursive -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.WeakUacFlags=@(Find-ADScoutWeakUacFlag -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.LapsStatus=@(Get-ADScoutLapsStatus -Server $Server -Credential $Credential -SearchBase $SearchBase)
    $data.Findings=@(Get-ADScoutFinding -Server $Server -Credential $Credential -SearchBase $SearchBase -SkipAclSweep:$SkipAclSweep)
    foreach ($k in $data.Keys) { $base=Join-Path $runPath $k; if($OutputFormat -in @('CSV','Both')){ $data[$k] | Export-Csv "$base.csv" -NoTypeInformation }; if($OutputFormat -in @('JSON','Both')){ $data[$k] | ConvertTo-Json -Depth 8 | Out-File "$base.json" -Encoding UTF8 } }
    $summary=@('# ADScoutPS Summary','',"Run: $timestamp",'', '| Collection | Count |','|---|---:|') + ($data.Keys | ForEach-Object { "| $_ | $($data[$_].Count) |" })
    $summary | Out-File (Join-Path $runPath 'summary.md') -Encoding UTF8
    Write-Host "[+] Results written to $runPath" -ForegroundColor Green
    Write-Host "[!] Critical findings: $(@($data.Findings | Where-Object Severity -eq 'Critical').Count)" -ForegroundColor Red
    Write-Host "[!] High findings:     $(@($data.Findings | Where-Object Severity -eq 'High').Count)" -ForegroundColor Yellow
    if ($Gui) { $data.Findings | Show-ADScoutFindingsGui }
    [PSCustomObject]@{ OutputPath=$runPath; Findings=$data.Findings.Count; Critical=@($data.Findings | Where-Object Severity -eq 'Critical').Count; High=@($data.Findings | Where-Object Severity -eq 'High').Count; Users=$data.Users.Count; Computers=$data.Computers.Count; DomainControllers=$data.DomainControllers.Count }
}



$calledViaImportModule = $false
try {
    $calledViaImportModule = ($MyInvocation.Line -match '^\s*Import-Module\b') -or ($MyInvocation.InvocationName -eq 'Import-Module')
} catch {
    $calledViaImportModule = $false
}

if ($calledViaImportModule) {
    $LoadOnly = $true
}

if (-not $LoadOnly) {
    Invoke-ADScout -Server $Server -Credential $Credential -SearchBase $SearchBase -OutputPath $OutputPath -OutputFormat $OutputFormat -SkipAclSweep:$SkipAclSweep -Gui:$Gui
}
