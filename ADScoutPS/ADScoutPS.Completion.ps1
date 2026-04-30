# ADScoutPS tab completion support
# Loaded automatically by ADScoutPS.psm1

$adScoutCommands = @(
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

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputFormat -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)

    'CSV', 'JSON', 'Both' |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_,
                $_,
                'ParameterValue',
                "Output format: $_"
            )
        }
}

Register-ArgumentCompleter -CommandName Invoke-ADScout -ParameterName OutputPath -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)

    Get-ChildItem -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$wordToComplete*" -or $_.FullName -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_.FullName,
                $_.Name,
                'ParameterValue',
                $_.FullName
            )
        }
}

Register-ArgumentCompleter -CommandName $adScoutCommands -ParameterName Server -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)

    $candidates = @()

    try {
        $root = [ADSI]'LDAP://RootDSE'
        if ($root.dnsHostName) { $candidates += $root.dnsHostName.ToString() }
    }
    catch { }

    $envLogonServer = $env:LOGONSERVER -replace '^\\\\', ''
    if ($envLogonServer) { $candidates += $envLogonServer }

    $candidates |
        Where-Object { $_ -and $_ -like "$wordToComplete*" } |
        Sort-Object -Unique |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new(
                $_,
                $_,
                'ParameterValue',
                "Domain controller/server: $_"
            )
        }
}

Register-ArgumentCompleter -CommandName Get-ADScoutObjectAcl,Find-ADScoutInterestingAce -ParameterName DistinguishedName -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)

    try {
        $root = [ADSI]'LDAP://RootDSE'
        $baseDn = $root.defaultNamingContext
        if (-not $baseDn) { return }

        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50
        $searcher.SizeLimit = 25

        $safeWord = $wordToComplete.Replace('\\','\\5c').Replace('*','\\2a').Replace('(','\\28').Replace(')','\\29').Replace("'", '')
        if ([string]::IsNullOrWhiteSpace($safeWord)) {
            $searcher.Filter = '(|(objectClass=organizationalUnit)(objectClass=group)(objectClass=computer))'
        }
        else {
            $searcher.Filter = "(|(distinguishedName=*$safeWord*)(name=*$safeWord*))"
        }

        [void]$searcher.PropertiesToLoad.Add('distinguishedName')
        [void]$searcher.PropertiesToLoad.Add('name')

        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('distinguishedname')) {
                $dn = $result.Properties.distinguishedname[0].ToString()
                [System.Management.Automation.CompletionResult]::new(
                    "'$dn'",
                    $dn,
                    'ParameterValue',
                    $dn
                )
            }
        }
    }
    catch {
        return
    }
}

Register-ArgumentCompleter -CommandName Get-ADScoutGroupMember -ParameterName Identity -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete)

    try {
        $root = [ADSI]'LDAP://RootDSE'
        $baseDn = $root.defaultNamingContext
        if (-not $baseDn) { return }

        $searchRoot = [ADSI]"LDAP://$baseDn"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PageSize = 50
        $searcher.SizeLimit = 25

        $safeWord = $wordToComplete.Replace('\\','\\5c').Replace('*','\\2a').Replace('(','\\28').Replace(')','\\29').Replace("'", '')
        if ([string]::IsNullOrWhiteSpace($safeWord)) {
            $searcher.Filter = '(objectClass=group)'
        }
        else {
            $searcher.Filter = "(&(objectClass=group)(|(name=*$safeWord*)(samAccountName=*$safeWord*)))"
        }

        [void]$searcher.PropertiesToLoad.Add('name')
        [void]$searcher.PropertiesToLoad.Add('distinguishedName')

        foreach ($result in $searcher.FindAll()) {
            if ($result.Properties.Contains('name')) {
                $name = $result.Properties.name[0].ToString()
                $dn = if ($result.Properties.Contains('distinguishedname')) { $result.Properties.distinguishedname[0].ToString() } else { $name }
                [System.Management.Automation.CompletionResult]::new(
                    "'$name'",
                    $name,
                    'ParameterValue',
                    $dn
                )
            }
        }
    }
    catch {
        return
    }
}
