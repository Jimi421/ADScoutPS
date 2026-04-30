[CmdletBinding()]
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))
$modulePath = Join-Path $RepoRoot 'ADScoutPS\ADScoutPS.psm1'
$outPath = Join-Path $RepoRoot 'ADScout.ps1'
$module = Get-Content $modulePath -Raw
$wrapperTop = @'
<# ADScoutPS Standalone - generated from module source #>
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
'@
$wrapperBottom = @'
if ($LoadOnly) { Write-Host "[+] ADScoutPS v$script:ADScoutVersion functions loaded." -ForegroundColor Green; return }
Invoke-ADScout -Preset $Preset -Server $Server -Credential $Credential -SearchBase $SearchBase -OutputPath $OutputPath -OutputFormat $OutputFormat -SkipAclSweep:$SkipAclSweep -IncludeAclSweep:$IncludeAclSweep -Gui:$Gui -View $View -Report:$Report -NoExport:$NoExport
'@
$wrapperTop + [Environment]::NewLine + $module + [Environment]::NewLine + $wrapperBottom | Out-File -FilePath $outPath -Encoding UTF8
Write-Host "Generated $outPath"
