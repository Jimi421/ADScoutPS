<#
ADScoutPS - PowerShell Active Directory Enumeration Toolkit
For authorized lab environments and approved security assessments only.
#>

Set-StrictMode -Version Latest

function New-ADScoutDirectoryEntry {
<#
.SYNOPSIS
Creates an ADSI DirectoryEntry object.
.DESCRIPTION
Internal helper used by ADScoutPS functions to create LDAP DirectoryEntry objects with optional server and credentials.
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Server,
        [PSCredential]$Credential
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($Server) { $Path = "LDAP://$Server/RootDSE" }
        else { $Path = "LDAP://RootDSE" }
    }
    elseif ($Server -and $Path -notmatch '^LDAP://[^/]+/') {
        $Path = $Path -replace '^LDAP://', "LDAP://$Server/"
    }

    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }

    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function Get-ADScoutDomainContext {
<#
.SYNOPSIS
Resolves the current Active Directory context.
.DESCRIPTION
Internal helper that follows the ADScoutPS auto-discovery pattern: use the current domain/PDC when available, then fall back to RootDSE. It returns the PDC/server, default naming context, and LDAP base path used by search functions.
.PARAMETER Server
Optional domain controller or LDAP server. When supplied, ADScoutPS builds LDAP paths against this server.
.PARAMETER Credential
Optional alternate domain credential for LDAP bind operations.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $pdc = $Server
    $defaultNamingContext = $null
    $source = 'RootDSE'

    if (-not $Server -and -not $Credential) {
        try {
            $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $pdc = $domainObj.PdcRoleOwner.Name
            $source = 'CurrentDomain/PDC'
        }
        catch {
            $pdc = $null
            $source = 'RootDSE fallback'
        }
    }

    try {
        $rootDsePath = if ($pdc) { "LDAP://$pdc/RootDSE" } else { "LDAP://RootDSE" }
        $rootDse = New-ADScoutDirectoryEntry -Path $rootDsePath -Credential $Credential
        $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]
    }
    catch {
        throw "Could not resolve AD domain context. $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        throw "Could not resolve defaultNamingContext from Active Directory."
    }

    $ldapBasePath = if ($pdc) { "LDAP://$pdc/$defaultNamingContext" } else { "LDAP://$defaultNamingContext" }

    [PSCustomObject]@{
        Server               = $pdc
        DefaultNamingContext = $defaultNamingContext
        LdapBasePath         = $ldapBasePath
        Source               = $source
    }
}

function Get-ADScoutRootDSE {
<#
.SYNOPSIS
Gets the Active Directory RootDSE object.
.DESCRIPTION
Internal helper that binds to LDAP RootDSE and returns metadata used by other ADScoutPS functions.
.PARAMETER Server
Specifies a domain controller or LDAP server.
.PARAMETER Credential
Specifies alternate domain credentials.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    New-ADScoutDirectoryEntry -Path $null -Server $Server -Credential $Credential
}

function Get-ADScoutSearchRoot {
<#
.SYNOPSIS
Gets the default LDAP search root.
.DESCRIPTION
Internal helper that auto-resolves the current domain/PDC/defaultNamingContext and returns a DirectoryEntry for the domain naming context.
.PARAMETER Server
Specifies a domain controller or LDAP server.
.PARAMETER Credential
Specifies alternate domain credentials.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $context = Get-ADScoutDomainContext -Server $Server -Credential $Credential
    New-ADScoutDirectoryEntry -Path $context.LdapBasePath -Credential $Credential
}

function New-ADScoutSearcher {
<#
.SYNOPSIS
Creates a DirectorySearcher object.
.DESCRIPTION
Internal helper for LDAP searches with a consistent page size and optional properties to load.
.PARAMETER SearchRoot
LDAP search root DirectoryEntry.
.PARAMETER Filter
LDAP search filter.
.PARAMETER Properties
Properties to load.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry]$SearchRoot,

        [Parameter(Mandatory)]
        [string]$Filter,

        [string[]]$Properties = @()
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($SearchRoot)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree

    foreach ($property in $Properties) {
        [void]$searcher.PropertiesToLoad.Add($property)
    }

    return $searcher
}

function Get-ADScoutProperty {
<#
.SYNOPSIS
Reads a property from a DirectorySearcher result.
.DESCRIPTION
Internal helper that safely reads LDAP result properties and returns a joined value for multi-valued properties.
.PARAMETER Result
DirectorySearcher SearchResult.
.PARAMETER Name
Property name to read.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Result,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
        return ($Result.Properties[$Name] | ForEach-Object { $_.ToString() }) -join ';'
    }

    return $null
}

function Get-ADScoutDomainInfo {
<#
.SYNOPSIS
Retrieves Active Directory domain metadata.
.DESCRIPTION
Queries LDAP RootDSE and returns core domain metadata such as defaultNamingContext, configurationNamingContext, schemaNamingContext, DNS host name, and functionality levels.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutDomainInfo
.EXAMPLE
$cred = Get-Credential
Get-ADScoutDomainInfo -Server dc01.corp.local -Credential $cred
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    try {
        $context = Get-ADScoutDomainContext -Server $Server -Credential $Credential
        $rootPath = if ($context.Server) { "LDAP://$($context.Server)/RootDSE" } else { "LDAP://RootDSE" }
        $root = New-ADScoutDirectoryEntry -Path $rootPath -Credential $Credential

        [PSCustomObject]@{
            DefaultNamingContext       = [string]$root.Properties['defaultNamingContext'][0]
            ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
            SchemaNamingContext        = [string]$root.Properties['schemaNamingContext'][0]
            DnsHostName                = [string]$root.Properties['dnsHostName'][0]
            DomainFunctionality        = [string]$root.Properties['domainFunctionality'][0]
            ForestFunctionality        = [string]$root.Properties['forestFunctionality'][0]
            Server                     = if ($context.Server) { $context.Server } else { 'Default logon server' }
            LdapBasePath               = $context.LdapBasePath
            DiscoverySource            = $context.Source
        }
    }
    catch {
        Write-Error "Failed to query RootDSE. $($_.Exception.Message)"
    }
}

function Get-ADScoutUser {
<#
.SYNOPSIS
Retrieves Active Directory user objects.
.DESCRIPTION
Queries LDAP for user objects and returns common attributes useful for AD enumeration, including samAccountName, userPrincipalName, distinguishedName, description, lastLogonTimestamp, and servicePrincipalName.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutUser
.EXAMPLE
Get-ADScoutUser | Select-Object -First 10 SamAccountName, DistinguishedName
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'samaccountname','userprincipalname','displayname','distinguishedname','description','serviceprincipalname','lastlogontimestamp','memberof'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(&(objectCategory=person)(objectClass=user))' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            SamAccountName     = Get-ADScoutProperty -Result $result -Name 'samaccountname'
            UserPrincipalName  = Get-ADScoutProperty -Result $result -Name 'userprincipalname'
            DisplayName        = Get-ADScoutProperty -Result $result -Name 'displayname'
            DistinguishedName  = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            Description        = Get-ADScoutProperty -Result $result -Name 'description'
            ServicePrincipalName = Get-ADScoutProperty -Result $result -Name 'serviceprincipalname'
            MemberOf           = Get-ADScoutProperty -Result $result -Name 'memberof'
            LastLogonTimestamp = Get-ADScoutProperty -Result $result -Name 'lastlogontimestamp'
        }
    }
}

function Get-ADScoutGroup {
<#
.SYNOPSIS
Retrieves Active Directory group objects.
.DESCRIPTION
Queries LDAP for group objects and returns common group attributes including samAccountName, distinguishedName, description, and members.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutGroup
.EXAMPLE
Get-ADScoutGroup | Where-Object Name -match 'Admin'
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'name','samaccountname','distinguishedname','description','member'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(objectClass=group)' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty -Result $result -Name 'name'
            SamAccountName    = Get-ADScoutProperty -Result $result -Name 'samaccountname'
            DistinguishedName = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            Description       = Get-ADScoutProperty -Result $result -Name 'description'
            Members           = Get-ADScoutProperty -Result $result -Name 'member'
        }
    }
}

function Get-ADScoutComputer {
<#
.SYNOPSIS
Retrieves Active Directory computer objects.
.DESCRIPTION
Queries LDAP for computer objects and returns common attributes including operating system, DNS host name, distinguished name, delegation flags, and last logon timestamp.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutComputer
.EXAMPLE
Get-ADScoutComputer | Where-Object OperatingSystem -match 'Server'
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'name','dnshostname','distinguishedname','operatingsystem','operatingsystemversion','lastlogontimestamp','useraccountcontrol','serviceprincipalname'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(objectCategory=computer)' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            Name                   = Get-ADScoutProperty -Result $result -Name 'name'
            DnsHostName            = Get-ADScoutProperty -Result $result -Name 'dnshostname'
            DistinguishedName      = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            OperatingSystem        = Get-ADScoutProperty -Result $result -Name 'operatingsystem'
            OperatingSystemVersion = Get-ADScoutProperty -Result $result -Name 'operatingsystemversion'
            UserAccountControl     = Get-ADScoutProperty -Result $result -Name 'useraccountcontrol'
            ServicePrincipalName   = Get-ADScoutProperty -Result $result -Name 'serviceprincipalname'
            LastLogonTimestamp     = Get-ADScoutProperty -Result $result -Name 'lastlogontimestamp'
        }
    }
}

function Find-ADScoutAdminGroup {
<#
.SYNOPSIS
Finds admin-related Active Directory groups.
.DESCRIPTION
Searches group names and descriptions for common privileged keywords such as admin, operator, backup, remote, helpdesk, and domain.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutAdminGroup
.NOTES
This is a heuristic discovery function, not a proof of privilege.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    Get-ADScoutGroup -Server $Server -Credential $Credential | Where-Object {
        $_.Name -match 'admin|operator|backup|remote|helpdesk|domain|enterprise|server|account'
    }
}

function Find-ADScoutSPNAccount {
<#
.SYNOPSIS
Finds user accounts with Service Principal Names.
.DESCRIPTION
Queries LDAP for user accounts with servicePrincipalName values. SPN-bearing user accounts are important to identify during authorized AD security reviews and OSCP-style lab enumeration.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutSPNAccount
.EXAMPLE
Find-ADScoutSPNAccount | Export-Csv .\spn_accounts.csv -NoTypeInformation
.NOTES
This function only enumerates SPN-bearing accounts. It does not request tickets or perform roasting.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'samaccountname','userprincipalname','distinguishedname','serviceprincipalname','description'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            SamAccountName       = Get-ADScoutProperty -Result $result -Name 'samaccountname'
            UserPrincipalName    = Get-ADScoutProperty -Result $result -Name 'userprincipalname'
            DistinguishedName    = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            ServicePrincipalName = Get-ADScoutProperty -Result $result -Name 'serviceprincipalname'
            Description          = Get-ADScoutProperty -Result $result -Name 'description'
        }
    }
}

function Get-ADScoutGPO {
<#
.SYNOPSIS
Retrieves Group Policy Objects.
.DESCRIPTION
Searches CN=Policies,CN=System under the domain naming context for groupPolicyContainer objects and returns policy names, GUIDs, paths, and modification metadata.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutGPO
.NOTES
Requires normal read access to Group Policy container objects.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $rootDse = Get-ADScoutRootDSE -Server $Server -Credential $Credential
    $baseDn = [string]$rootDse.Properties['defaultNamingContext'][0]
    $policyPath = if ($Server) { "LDAP://$Server/CN=Policies,CN=System,$baseDn" } else { "LDAP://CN=Policies,CN=System,$baseDn" }
    $searchRoot = New-ADScoutDirectoryEntry -Path $policyPath -Credential $Credential
    $props = 'displayname','name','distinguishedname','gpcfilesyspath','whenchanged','whencreated'
    $searcher = New-ADScoutSearcher -SearchRoot $searchRoot -Filter '(objectClass=groupPolicyContainer)' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            DisplayName       = Get-ADScoutProperty -Result $result -Name 'displayname'
            Guid              = Get-ADScoutProperty -Result $result -Name 'name'
            DistinguishedName = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            GpcFileSysPath    = Get-ADScoutProperty -Result $result -Name 'gpcfilesyspath'
            WhenCreated       = Get-ADScoutProperty -Result $result -Name 'whencreated'
            WhenChanged       = Get-ADScoutProperty -Result $result -Name 'whenchanged'
        }
    }
}

function Get-ADScoutOU {
<#
.SYNOPSIS
Retrieves Organizational Units.
.DESCRIPTION
Queries LDAP for organizationalUnit objects and returns names, distinguished names, descriptions, and linked GPO values.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutOU
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'name','distinguishedname','description','gplink','gpoptions'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(objectClass=organizationalUnit)' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        [PSCustomObject]@{
            Name              = Get-ADScoutProperty -Result $result -Name 'name'
            DistinguishedName = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
            Description       = Get-ADScoutProperty -Result $result -Name 'description'
            GpLink            = Get-ADScoutProperty -Result $result -Name 'gplink'
            GpOptions         = Get-ADScoutProperty -Result $result -Name 'gpoptions'
        }
    }
}

function Get-ADScoutLinkedGPO {
<#
.SYNOPSIS
Finds OUs with linked Group Policy Objects.
.DESCRIPTION
Returns Organizational Units where the gpLink attribute is populated. This helps identify where policies are applied in the directory structure.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutLinkedGPO
.NOTES
This function reports gpLink strings and does not modify policy links.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    Get-ADScoutOU -Server $Server -Credential $Credential | Where-Object { $_.GpLink }
}

function ConvertTo-ADScoutLdapEscapedFilterValue {
<#
.SYNOPSIS
Escapes an LDAP filter value.
.DESCRIPTION
Internal helper for safe LDAP filter construction.
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) { return $null }

    return $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}

function Resolve-ADScoutDistinguishedName {
<#
.SYNOPSIS
Resolves a friendly object name or raw DN to a Distinguished Name.
.DESCRIPTION
Internal helper that lets ADScoutPS commands accept either a full DistinguishedName or easy input such as an OU, group, user, or computer name.
.PARAMETER DistinguishedName
Raw Distinguished Name. Returned as-is when supplied.
.PARAMETER Identity
Friendly name, sAMAccountName, CN, OU name, DNS host name, or partial distinguishedName.
.PARAMETER ObjectClass
Optional LDAP object class hint such as organizationalUnit, group, user, or computer.
.PARAMETER Server
Optional domain controller or LDAP server.
.PARAMETER Credential
Optional alternate domain credential.
#>
    [CmdletBinding()]
    param(
        [string]$DistinguishedName,
        [string]$Identity,
        [string]$ObjectClass,
        [string]$Server,
        [PSCredential]$Credential
    )

    if (-not [string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return $DistinguishedName
    }

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        throw "Provide either -DistinguishedName or -Identity/-Name."
    }

    $escaped = ConvertTo-ADScoutLdapEscapedFilterValue -Value $Identity
    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential

    $identityFilter = "(|(distinguishedName=$escaped)(name=$escaped)(cn=$escaped)(ou=$escaped)(samAccountName=$escaped)(dNSHostName=$escaped))"
    if ($ObjectClass) {
        $classFilter = if ($ObjectClass -eq 'user') { '(&(objectCategory=person)(objectClass=user))' } else { "(objectClass=$ObjectClass)" }
        $filter = "(&$classFilter$identityFilter)"
    }
    else {
        $filter = $identityFilter
    }

    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter $filter -Properties @('distinguishedName','name','samAccountName','objectClass')
    $searcher.SizeLimit = 5
    $results = @($searcher.FindAll())

    if ($results.Count -eq 0) {
        throw "Could not resolve '$Identity' to a DistinguishedName. Try Get-ADScoutOU/Get-ADScoutGroup/Get-ADScoutUser first, or provide -DistinguishedName."
    }

    if ($results.Count -gt 1) {
        $matches = $results | ForEach-Object { $_.Properties['distinguishedname'][0] }
        Write-Warning "Multiple objects matched '$Identity'. Using first match. Matches: $($matches -join '; ')"
    }

    return [string]$results[0].Properties['distinguishedname'][0]
}

function Get-ADScoutObjectAcl {
<#
.SYNOPSIS
Gets ACL entries for an Active Directory object.
.DESCRIPTION
Binds to an AD object by DistinguishedName or resolves a friendly -Identity/-Name automatically, then returns Access Control Entries showing identity references, Active Directory rights, access type, inheritance, and object GUID values.
.PARAMETER DistinguishedName
Distinguished Name of the AD object to inspect.
.PARAMETER Identity
Friendly object name to resolve automatically, such as Workstations, Domain Admins, a username, or a computer name.
.PARAMETER ObjectClass
Optional object class hint: organizationalUnit, group, user, or computer.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutObjectAcl -Name "Workstations" -ObjectClass organizationalUnit
.EXAMPLE
Get-ADScoutObjectAcl -Identity "Domain Admins" -ObjectClass group | Format-Table
.EXAMPLE
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
.NOTES
This function is read-only and does not modify permissions.
#>
    [CmdletBinding(DefaultParameterSetName='ByDistinguishedName')]
    param(
        [Parameter(ParameterSetName='ByDistinguishedName', ValueFromPipelineByPropertyName)]
        [Alias('DN')]
        [string]$DistinguishedName,

        [Parameter(ParameterSetName='ByIdentity')]
        [Alias('Name')]
        [string]$Identity,

        [Parameter(ParameterSetName='ByIdentity')]
        [ValidateSet('organizationalUnit','group','user','computer')]
        [string]$ObjectClass,

        [string]$Server,
        [PSCredential]$Credential
    )

    process {
        try {
            $resolvedDn = Resolve-ADScoutDistinguishedName -DistinguishedName $DistinguishedName -Identity $Identity -ObjectClass $ObjectClass -Server $Server -Credential $Credential
            $context = Get-ADScoutDomainContext -Server $Server -Credential $Credential
            $path = if ($context.Server) { "LDAP://$($context.Server)/$resolvedDn" } else { "LDAP://$resolvedDn" }
            $entry = New-ADScoutDirectoryEntry -Path $path -Credential $Credential
            $acl = $entry.ObjectSecurity

            foreach ($ace in $acl.Access) {
                [PSCustomObject]@{
                    TargetDistinguishedName = $resolvedDn
                    IdentityReference       = $ace.IdentityReference.ToString()
                    ActiveDirectoryRights   = $ace.ActiveDirectoryRights.ToString()
                    AccessControlType       = $ace.AccessControlType.ToString()
                    ObjectType              = $ace.ObjectType.ToString()
                    InheritedObjectType     = $ace.InheritedObjectType.ToString()
                    IsInherited             = $ace.IsInherited
                    InheritanceType         = $ace.InheritanceType.ToString()
                }
            }
        }
        catch {
            Write-Warning "Failed to read ACL. $($_.Exception.Message)"
        }
    }
}

function Find-ADScoutInterestingAce {
<#
.SYNOPSIS
Finds potentially interesting ACEs on an AD object.
.DESCRIPTION
Filters ACL entries for rights commonly reviewed during AD security assessments, including GenericAll, GenericWrite, WriteDacl, WriteOwner, ExtendedRight, CreateChild, DeleteChild, and WriteProperty. Accepts either a raw DistinguishedName or an easy -Identity/-Name value.
.PARAMETER DistinguishedName
Distinguished Name of the AD object to inspect.
.PARAMETER Identity
Friendly object name to resolve automatically, such as Workstations, Domain Admins, a username, or a computer name.
.PARAMETER ObjectClass
Optional object class hint: organizationalUnit, group, user, or computer.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutInterestingAce -Name "Workstations" -ObjectClass organizationalUnit
.EXAMPLE
Find-ADScoutInterestingAce -Identity "Domain Admins" -ObjectClass group
.NOTES
This function is read-only and intended for authorized review.
#>
    [CmdletBinding(DefaultParameterSetName='ByDistinguishedName')]
    param(
        [Parameter(ParameterSetName='ByDistinguishedName', ValueFromPipelineByPropertyName)]
        [Alias('DN')]
        [string]$DistinguishedName,

        [Parameter(ParameterSetName='ByIdentity')]
        [Alias('Name')]
        [string]$Identity,

        [Parameter(ParameterSetName='ByIdentity')]
        [ValidateSet('organizationalUnit','group','user','computer')]
        [string]$ObjectClass,

        [string]$Server,
        [PSCredential]$Credential
    )

    process {
        Get-ADScoutObjectAcl -DistinguishedName $DistinguishedName -Identity $Identity -ObjectClass $ObjectClass -Server $Server -Credential $Credential |
            Where-Object {
                $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight|CreateChild|DeleteChild|WriteProperty'
            }
    }
}

function Get-ADScoutGroupMember {
<#
.SYNOPSIS
Retrieves members of an Active Directory group.
.DESCRIPTION
Finds a group by name, samAccountName, or distinguishedName and returns direct members. With -Recursive, expands nested group membership where readable.
.PARAMETER Identity
Group name, samAccountName, or distinguishedName.
.PARAMETER Recursive
Recursively expands nested group membership.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutGroupMember -Identity "Domain Admins"
.EXAMPLE
Get-ADScoutGroupMember -Identity "Domain Admins" -Recursive
.NOTES
Recursive expansion depends on readable group/member attributes.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [switch]$Recursive,
        [string]$Server,
        [PSCredential]$Credential
    )

    $visited = New-Object 'System.Collections.Generic.HashSet[string]'

    function Resolve-GroupDn {
        param([string]$GroupIdentity)
        if ($GroupIdentity -match '^CN=|^OU=|^DC=') { return $GroupIdentity }
        $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
        $safe = $GroupIdentity.Replace('\\','\\5c').Replace('*','\\2a').Replace('(','\\28').Replace(')','\\29')
        $searcher = New-ADScoutSearcher -SearchRoot $root -Filter "(&(objectClass=group)(|(name=$safe)(samAccountName=$safe)))" -Properties @('distinguishedname')
        $result = $searcher.FindOne()
        if ($result) { return Get-ADScoutProperty -Result $result -Name 'distinguishedname' }
        throw "Could not find group: $GroupIdentity"
    }

    function Get-MembersByDn {
        param([string]$GroupDn)
        if ($visited.Contains($GroupDn)) { return }
        [void]$visited.Add($GroupDn)

        $path = if ($Server) { "LDAP://$Server/$GroupDn" } else { "LDAP://$GroupDn" }
        $entry = New-ADScoutDirectoryEntry -Path $path -Credential $Credential

        foreach ($member in $entry.Properties['member']) {
            $memberDn = $member.ToString()
            [PSCustomObject]@{
                ParentGroup = $GroupDn
                MemberDistinguishedName = $memberDn
            }

            if ($Recursive -and $memberDn -match '^CN=') {
                try {
                    $memberEntry = New-ADScoutDirectoryEntry -Path $(if ($Server) { "LDAP://$Server/$memberDn" } else { "LDAP://$memberDn" }) -Credential $Credential
                    $objectClass = ($memberEntry.Properties['objectClass'] | ForEach-Object { $_.ToString() }) -join ';'
                    if ($objectClass -match 'group') {
                        Get-MembersByDn -GroupDn $memberDn
                    }
                }
                catch { }
            }
        }
    }

    $groupDn = Resolve-GroupDn -GroupIdentity $Identity
    Get-MembersByDn -GroupDn $groupDn
}

function Find-ADScoutPrivilegedUser {
<#
.SYNOPSIS
Reviews members of common privileged groups.
.DESCRIPTION
Enumerates members of common high-value groups such as Domain Admins, Enterprise Admins, Administrators, Account Operators, Server Operators, Backup Operators, and Remote Desktop Users.
.PARAMETER Recursive
Recursively expands nested group membership.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutPrivilegedUser -Recursive
.NOTES
This is a heuristic review based on common group names.
#>
    [CmdletBinding()]
    param(
        [switch]$Recursive,
        [string]$Server,
        [PSCredential]$Credential
    )

    $groups = @(
        'Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins',
        'Account Operators', 'Server Operators', 'Backup Operators', 'Remote Desktop Users',
        'DnsAdmins', 'Group Policy Creator Owners'
    )

    foreach ($group in $groups) {
        try {
            Get-ADScoutGroupMember -Identity $group -Recursive:$Recursive -Server $Server -Credential $Credential |
                ForEach-Object {
                    [PSCustomObject]@{
                        Group = $group
                        MemberDistinguishedName = $_.MemberDistinguishedName
                        ParentGroup = $_.ParentGroup
                    }
                }
        }
        catch { }
    }
}

function Find-ADScoutDelegationHint {
<#
.SYNOPSIS
Finds basic delegation-related AD indicators.
.DESCRIPTION
Reviews users and computers for userAccountControl flags and SPN presence that may be relevant during authorized AD assessments.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutDelegationHint
.NOTES
This is a lightweight hinting function and does not perform exploitation.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    $root = Get-ADScoutSearchRoot -Server $Server -Credential $Credential
    $props = 'samaccountname','name','distinguishedname','useraccountcontrol','serviceprincipalname'
    $searcher = New-ADScoutSearcher -SearchRoot $root -Filter '(|(objectCategory=computer)(&(objectCategory=person)(objectClass=user)))' -Properties $props

    foreach ($result in $searcher.FindAll()) {
        $uacRaw = Get-ADScoutProperty -Result $result -Name 'useraccountcontrol'
        $uac = 0
        [void][int]::TryParse($uacRaw, [ref]$uac)
        $spn = Get-ADScoutProperty -Result $result -Name 'serviceprincipalname'

        if (($uac -band 0x80000) -or ($uac -band 0x1000000) -or $spn) {
            [PSCustomObject]@{
                Name = Get-ADScoutProperty -Result $result -Name 'name'
                SamAccountName = Get-ADScoutProperty -Result $result -Name 'samaccountname'
                DistinguishedName = Get-ADScoutProperty -Result $result -Name 'distinguishedname'
                UserAccountControl = $uac
                HasSPN = [bool]$spn
                TrustedForDelegation = [bool]($uac -band 0x80000)
                TrustedToAuthForDelegation = [bool]($uac -band 0x1000000)
                ServicePrincipalName = $spn
            }
        }
    }
}

function Find-ADScoutOldComputer {
<#
.SYNOPSIS
Finds older computer operating systems by LDAP attributes.
.DESCRIPTION
Returns computer objects whose operatingSystem field appears to reference legacy Windows systems.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutOldComputer
.NOTES
This is a simple heuristic based on operatingSystem strings.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential
    )

    Get-ADScoutComputer -Server $Server -Credential $Credential | Where-Object {
        $_.OperatingSystem -match '2000|2003|2008|2012|XP|Vista|Windows 7|Windows 8'
    }
}

function Test-ADScoutGridViewAvailable {
<#
.SYNOPSIS
Tests whether Out-GridView is available in the current PowerShell session.
#>
    [CmdletBinding()]
    param()
    return [bool](Get-Command Out-GridView -ErrorAction SilentlyContinue)
}

function New-ADScoutFinding {
<#
.SYNOPSIS
Creates a normalized ADScout finding object.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Title,
        [string]$Identity,
        [string]$ObjectClass,
        [string]$Reason,
        [string]$Evidence,
        [string]$DistinguishedName,
        [object]$Source
    )
    [PSCustomObject]@{
        Severity          = $Severity
        Type              = $Type
        Title             = $Title
        Identity          = $Identity
        ObjectClass       = $ObjectClass
        Reason            = $Reason
        Evidence          = $Evidence
        DistinguishedName = $DistinguishedName
        Source            = $Source
    }
}

function Get-ADScoutFinding {
<#
.SYNOPSIS
Builds normalized ADScout findings.
.DESCRIPTION
Runs the findings-focused review layer and returns normalized objects designed for sorting, filtering, export, and GUI review. This keeps manual CLI commands available while adding a higher-signal analysis layer on top.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.PARAMETER SkipAclSweep
Skips OU ACL/ACE review for faster findings collection.
.EXAMPLE
Get-ADScoutFinding -SkipAclSweep
.EXAMPLE
Get-ADScoutFinding | Sort-Object Severity,Type | Format-Table
.NOTES
This function is read-only and intended for authorized labs and approved assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$SkipAclSweep
    )

    $findings = New-Object System.Collections.Generic.List[object]

    try {
        foreach ($spn in @(Find-ADScoutSPNAccount -Server $Server -Credential $Credential)) {
            $findings.Add((New-ADScoutFinding -Severity 'Medium' -Type 'SPN' -Title 'SPN-bearing account found' -Identity $spn.SamAccountName -ObjectClass 'user/service' -Reason 'Accounts with SPNs are useful to review during Kerberoast-aware AD assessment workflows.' -Evidence $spn.ServicePrincipalName -DistinguishedName $spn.DistinguishedName -Source $spn))
        }
    } catch { Write-Warning "SPN findings failed. $($_.Exception.Message)" }

    try {
        foreach ($member in @(Find-ADScoutPrivilegedUser -Recursive -Server $Server -Credential $Credential)) {
            $findings.Add((New-ADScoutFinding -Severity 'High' -Type 'PrivilegedMembership' -Title 'Privileged group membership found' -Identity $member.MemberDistinguishedName -ObjectClass 'member' -Reason "Member is listed under high-value group '$($member.Group)'." -Evidence "Group=$($member.Group); ParentGroup=$($member.ParentGroup)" -DistinguishedName $member.MemberDistinguishedName -Source $member))
        }
    } catch { Write-Warning "Privileged membership findings failed. $($_.Exception.Message)" }

    try {
        foreach ($item in @(Find-ADScoutDelegationHint -Server $Server -Credential $Credential)) {
            $severity = if ($item.TrustedForDelegation -or $item.TrustedToAuthForDelegation) { 'High' } else { 'Medium' }
            $title = if ($item.TrustedForDelegation -or $item.TrustedToAuthForDelegation) { 'Delegation-related flag found' } else { 'SPN/delegation-adjacent account found' }
            $evidence = "UAC=$($item.UserAccountControl); TrustedForDelegation=$($item.TrustedForDelegation); TrustedToAuthForDelegation=$($item.TrustedToAuthForDelegation); HasSPN=$($item.HasSPN)"
            $findings.Add((New-ADScoutFinding -Severity $severity -Type 'Delegation' -Title $title -Identity $item.SamAccountName -ObjectClass 'user/computer' -Reason 'Delegation-related configuration deserves focused review during AD assessment.' -Evidence $evidence -DistinguishedName $item.DistinguishedName -Source $item))
        }
    } catch { Write-Warning "Delegation findings failed. $($_.Exception.Message)" }

    try {
        foreach ($computer in @(Find-ADScoutOldComputer -Server $Server -Credential $Credential)) {
            $findings.Add((New-ADScoutFinding -Severity 'Medium' -Type 'LegacyComputer' -Title 'Legacy operating system indicator' -Identity $computer.Name -ObjectClass 'computer' -Reason 'Older operating systems may indicate increased exposure or weaker baseline controls.' -Evidence $computer.OperatingSystem -DistinguishedName $computer.DistinguishedName -Source $computer))
        }
    } catch { Write-Warning "Legacy computer findings failed. $($_.Exception.Message)" }

    if (-not $SkipAclSweep) {
        try {
            foreach ($ou in @(Get-ADScoutOU -Server $Server -Credential $Credential)) {
                if ($ou.DistinguishedName) {
                    foreach ($ace in @(Find-ADScoutInterestingAce -DistinguishedName $ou.DistinguishedName -Server $Server -Credential $Credential)) {
                        $severity = if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner') { 'Critical' } else { 'High' }
                        $findings.Add((New-ADScoutFinding -Severity $severity -Type 'InterestingACE' -Title 'Interesting AD permission found' -Identity $ace.IdentityReference -ObjectClass 'acl/ace' -Reason 'ACE contains powerful rights commonly reviewed during AD permission analysis.' -Evidence $ace.ActiveDirectoryRights -DistinguishedName $ace.TargetDistinguishedName -Source $ace))
                    }
                }
            }
        } catch { Write-Warning "ACL/ACE findings failed. $($_.Exception.Message)" }
    }

    $rank = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Info = 5 }
    $findings | Sort-Object @{ Expression = { $rank[$_.Severity] } }, Type, Identity
}

function Show-ADScoutFindingsGui {
<#
.SYNOPSIS
Opens the ADScout findings-first GUI dashboard.
.DESCRIPTION
Collects normalized ADScout findings and displays only the high-signal results in Out-GridView. If Out-GridView is unavailable, it falls back to a sorted console table.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.PARAMETER SkipAclSweep
Skips OU ACL/ACE review for faster findings collection.
.PARAMETER PassThru
Returns the findings after displaying them.
.EXAMPLE
Show-ADScoutFindingsGui -SkipAclSweep
.EXAMPLE
Invoke-ADScout -Gui -SkipAclSweep
.NOTES
Out-GridView is Windows/UI dependent. Server Core or non-GUI sessions will use console fallback.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$SkipAclSweep,
        [switch]$PassThru
    )

    Write-Host "[*] Building ADScout findings dashboard..." -ForegroundColor Cyan
    $findings = @(Get-ADScoutFinding -Server $Server -Credential $Credential -SkipAclSweep:$SkipAclSweep)

    $critical = @($findings | Where-Object Severity -eq 'Critical').Count
    $high     = @($findings | Where-Object Severity -eq 'High').Count
    $medium   = @($findings | Where-Object Severity -eq 'Medium').Count

    Write-Host "[!] Critical: $critical" -ForegroundColor Red
    Write-Host "[!] High:     $high" -ForegroundColor Yellow
    Write-Host "[!] Medium:   $medium" -ForegroundColor DarkYellow
    Write-Host "[*] Total findings: $($findings.Count)" -ForegroundColor Cyan

    if ($findings.Count -eq 0) {
        Write-Host '[+] No findings produced by the current checks.' -ForegroundColor Green
        return
    }

    if (Test-ADScoutGridViewAvailable) {
        $findings | Select-Object Severity,Type,Title,Identity,ObjectClass,Reason,Evidence,DistinguishedName | Out-GridView -Title 'ADScoutPS Findings Dashboard - Critical/High/Medium Review'
    } else {
        Write-Warning 'Out-GridView is not available in this session. Showing console table instead.'
        $findings | Select-Object Severity,Type,Title,Identity,Evidence | Format-Table -AutoSize
    }

    if ($PassThru) { return $findings }
}

function Invoke-ADScout {
<#
.SYNOPSIS
Runs an Active Directory enumeration collection.
.DESCRIPTION
Invoke-ADScout performs domain, user, group, computer, GPO, OU, SPN, delegation, privileged membership, and optional ACL/ACE enumeration using LDAP queries. Results are written to a timestamped output directory as CSV and/or JSON, with a Markdown summary report.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.PARAMETER OutputPath
Directory where results are written.
.PARAMETER OutputFormat
Specifies output format. Valid values: CSV, JSON, Both.
.PARAMETER SkipAclSweep
Skips ACL/ACE enumeration for faster collection.
.PARAMETER Gui
Opens the findings-first GUI dashboard after collection. The CLI/manual functions remain unchanged.
.EXAMPLE
Invoke-ADScout -Gui -SkipAclSweep
.EXAMPLE
Invoke-ADScout -SkipAclSweep
.EXAMPLE
$cred = Get-Credential
Invoke-ADScout -Server dc01.corp.local -Credential $cred -OutputFormat Both
.EXAMPLE
Invoke-ADScout -OutputPath .\results -OutputFormat CSV
.NOTES
For authorized lab environments and approved security assessments only.
#>
    [CmdletBinding()]
    param(
        [string]$Server,
        [PSCredential]$Credential,
        [string]$OutputPath = ".\ADScout-Results",
        [ValidateSet('CSV','JSON','Both')]
        [string]$OutputFormat = 'Both',
        [switch]$SkipAclSweep,
        [switch]$Gui
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runPath = Join-Path $OutputPath "ADScout-$timestamp"
    New-Item -ItemType Directory -Path $runPath -Force | Out-Null

    Write-Host "[*] ADScoutPS collection started" -ForegroundColor Cyan
    Write-Host "[*] Output: $runPath" -ForegroundColor Cyan

    $collections = [ordered]@{}
    $collections.DomainInfo = @(Get-ADScoutDomainInfo -Server $Server -Credential $Credential)
    $collections.Users = @(Get-ADScoutUser -Server $Server -Credential $Credential)
    $collections.Groups = @(Get-ADScoutGroup -Server $Server -Credential $Credential)
    $collections.Computers = @(Get-ADScoutComputer -Server $Server -Credential $Credential)
    $collections.GPOs = @(Get-ADScoutGPO -Server $Server -Credential $Credential)
    $collections.OUs = @(Get-ADScoutOU -Server $Server -Credential $Credential)
    $collections.LinkedGPOs = @(Get-ADScoutLinkedGPO -Server $Server -Credential $Credential)
    $collections.SPNAccounts = @(Find-ADScoutSPNAccount -Server $Server -Credential $Credential)
    $collections.AdminGroups = @(Find-ADScoutAdminGroup -Server $Server -Credential $Credential)
    $collections.PrivilegedUsers = @(Find-ADScoutPrivilegedUser -Recursive -Server $Server -Credential $Credential)
    $collections.DelegationHints = @(Find-ADScoutDelegationHint -Server $Server -Credential $Credential)
    $collections.OldComputers = @(Find-ADScoutOldComputer -Server $Server -Credential $Credential)
    $collections.Findings = @(Get-ADScoutFinding -Server $Server -Credential $Credential -SkipAclSweep:$SkipAclSweep)

    if (-not $SkipAclSweep) {
        $aceResults = @()
        foreach ($ou in $collections.OUs) {
            if ($ou.DistinguishedName) {
                $aceResults += @(Find-ADScoutInterestingAce -DistinguishedName $ou.DistinguishedName -Server $Server -Credential $Credential)
            }
        }
        $collections.InterestingACEs = @($aceResults)
    }

    foreach ($name in $collections.Keys) {
        $data = $collections[$name]
        if ($OutputFormat -in @('CSV','Both')) {
            $data | Export-Csv -Path (Join-Path $runPath "$name.csv") -NoTypeInformation
        }
        if ($OutputFormat -in @('JSON','Both')) {
            $data | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $runPath "$name.json") -Encoding UTF8
        }
    }

    $domain = $collections.DomainInfo | Select-Object -First 1
    $summary = @()
    $summary += "# ADScoutPS Summary"
    $summary += ""
    $summary += "Generated: $(Get-Date)"
    $summary += "Server: $($domain.Server)"
    $summary += "DefaultNamingContext: $($domain.DefaultNamingContext)"
    $summary += ""
    $summary += "## Counts"
    foreach ($name in $collections.Keys) {
        $summary += "- $name: $(@($collections[$name]).Count)"
    }
    $summary += ""
    $summary += "## Suggested Next Review"
    $summary += "- Review SPNAccounts for service account exposure awareness."
    $summary += "- Review PrivilegedUsers for nested privileged membership."
    $summary += "- Review DelegationHints for delegation-related configuration."
    $summary += "- Review InterestingACEs if ACL sweep was enabled."
    $summary += ""
    $summary += "## Safety"
    $summary += "This collection is read-only and intended for authorized labs or approved assessments."

    $summary | Out-File -FilePath (Join-Path $runPath 'summary.md') -Encoding UTF8

    Write-Host "[+] Collection complete: $runPath" -ForegroundColor Green

    if ($Gui) {
        $dashboardData = @($collections.Findings)
        if ($dashboardData.Count -gt 0) {
            Write-Host "[*] Opening findings-first GUI dashboard..." -ForegroundColor Cyan
            if (Test-ADScoutGridViewAvailable) {
                $dashboardData | Select-Object Severity,Type,Title,Identity,ObjectClass,Reason,Evidence,DistinguishedName | Out-GridView -Title 'ADScoutPS Findings Dashboard - Critical/High/Medium Review'
            }
            else {
                Write-Warning 'Out-GridView is not available in this session. Showing console table instead.'
                $dashboardData | Select-Object Severity,Type,Title,Identity,Evidence | Format-Table -AutoSize
            }
        }
        else {
            Write-Host '[+] No GUI findings produced by the current checks.' -ForegroundColor Green
        }
    }

    [PSCustomObject]@{
        OutputPath = $runPath
        DomainInfo = $collections.DomainInfo.Count
        Users = $collections.Users.Count
        Groups = $collections.Groups.Count
        Computers = $collections.Computers.Count
        GPOs = $collections.GPOs.Count
        OUs = $collections.OUs.Count
        SPNAccounts = $collections.SPNAccounts.Count
        AdminGroups = $collections.AdminGroups.Count
        PrivilegedUsers = $collections.PrivilegedUsers.Count
        DelegationHints = $collections.DelegationHints.Count
        OldComputers = $collections.OldComputers.Count
        Findings = $collections.Findings.Count
        InterestingACEs = if ($collections.Contains('InterestingACEs')) { $collections.InterestingACEs.Count } else { 0 }
    }

}

# Load tab-completion support
$completionPath = Join-Path $PSScriptRoot 'ADScoutPS.Completion.ps1'
if (Test-Path $completionPath) {
    . $completionPath
}

Export-ModuleMember -Function @(
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
    'Get-ADScoutFinding',
    'Show-ADScoutFindingsGui',
    'Invoke-ADScout'
)
