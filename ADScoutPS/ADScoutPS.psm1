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
Internal helper that resolves defaultNamingContext from RootDSE and returns a DirectoryEntry for that domain naming context.
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

    $rootDse = Get-ADScoutRootDSE -Server $Server -Credential $Credential
    $baseDn = [string]$rootDse.Properties['defaultNamingContext'][0]

    if ([string]::IsNullOrWhiteSpace($baseDn)) {
        throw "Could not resolve defaultNamingContext from RootDSE."
    }

    if ($Server) { $path = "LDAP://$Server/$baseDn" }
    else { $path = "LDAP://$baseDn" }

    New-ADScoutDirectoryEntry -Path $path -Credential $Credential
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
        $root = Get-ADScoutRootDSE -Server $Server -Credential $Credential

        [PSCustomObject]@{
            DefaultNamingContext       = [string]$root.Properties['defaultNamingContext'][0]
            ConfigurationNamingContext = [string]$root.Properties['configurationNamingContext'][0]
            SchemaNamingContext        = [string]$root.Properties['schemaNamingContext'][0]
            DnsHostName                = [string]$root.Properties['dnsHostName'][0]
            DomainFunctionality        = [string]$root.Properties['domainFunctionality'][0]
            ForestFunctionality        = [string]$root.Properties['forestFunctionality'][0]
            Server                     = if ($Server) { $Server } else { 'Default logon server' }
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

function Get-ADScoutObjectAcl {
<#
.SYNOPSIS
Gets ACL entries for an Active Directory object.
.DESCRIPTION
Binds to an AD object by distinguishedName and returns Access Control Entries showing identity references, Active Directory rights, access type, inheritance, and object GUID values.
.PARAMETER DistinguishedName
Distinguished Name of the AD object to inspect.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Get-ADScoutObjectAcl -DistinguishedName "OU=Workstations,DC=corp,DC=local"
.EXAMPLE
Get-ADScoutObjectAcl -DistinguishedName "CN=Domain Admins,CN=Users,DC=corp,DC=local" | Format-Table
.NOTES
This function is read-only and does not modify permissions.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,

        [string]$Server,
        [PSCredential]$Credential
    )

    process {
        try {
            $path = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
            $entry = New-ADScoutDirectoryEntry -Path $path -Credential $Credential
            $acl = $entry.ObjectSecurity

            foreach ($ace in $acl.Access) {
                [PSCustomObject]@{
                    TargetDistinguishedName = $DistinguishedName
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
            Write-Warning "Failed to read ACL for $DistinguishedName. $($_.Exception.Message)"
        }
    }
}

function Find-ADScoutInterestingAce {
<#
.SYNOPSIS
Finds potentially interesting ACEs on an AD object.
.DESCRIPTION
Filters ACL entries for rights commonly reviewed during AD security assessments, including GenericAll, GenericWrite, WriteDacl, WriteOwner, ExtendedRight, CreateChild, DeleteChild, and WriteProperty.
.PARAMETER DistinguishedName
Distinguished Name of the AD object to inspect.
.PARAMETER Server
Specifies a domain controller or LDAP server to query.
.PARAMETER Credential
Specifies alternate domain credentials.
.EXAMPLE
Find-ADScoutInterestingAce -DistinguishedName "OU=Workstations,DC=corp,DC=local"
.NOTES
This function is read-only and intended for authorized review.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$DistinguishedName,

        [string]$Server,
        [PSCredential]$Credential
    )

    process {
        Get-ADScoutObjectAcl -DistinguishedName $DistinguishedName -Server $Server -Credential $Credential |
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
        [switch]$SkipAclSweep
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
    'Invoke-ADScout'
)
