#requires -version 5.1
<#
 ZahersComparativeSMBPerfScript_v1.ps1
#>

param(
    [string]$RemoteFolder = "\\10.10.5.7\MyShare",
    [string]$LocalFolder  = "C:\Software\copy",
    [string]$FileName     = "test_file.iso",
    [int]$Runs = 3,
    [int]$WaitBetweenRunsSeconds = 5,
    [switch]$AcceptDefaults,
    [string]$LogCsv = "C:\Software\copy\perf_runs_v1.csv",
    [switch]$Zaher
)

$ErrorActionPreference = 'Continue'
$CopyEngine    = 'CopyItem'
$ScriptVersion = 'v1'
$ConnectorVersion = 'N/A'
$ConnectorVMLocation = 'N/A'
$ConnectorRegion = 'N/A'
$GSAClientVersion = 'N/A' # used only for console display when applicable
$DeviceId = 'N/A'
$TenantId = 'N/A'
$OSVersion = 'N/A'
$PowerPlan = 'N/A'

# ===================== Helper Functions =====================
function Path-Exists([string]$p){ try { return (Test-Path -LiteralPath $p) } catch { return $false } }
function Join-FolderFile([string]$folder,[string]$name){
    if([string]::IsNullOrWhiteSpace($name)){ throw "FileName is empty." }
    $f = $folder -replace '[\\/]+$',''
    return "$f\$name"
}
function Ensure-LocalFolder([string]$folderPath){
    if([string]::IsNullOrWhiteSpace($folderPath)){ return }
    if($folderPath -like '\\*'){ return } # safeguard: don't try to create UNC as local folder
    if(-not (Test-Path -LiteralPath $folderPath)){
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    }
}
function ForDisplay([string]$s){
    if([string]::IsNullOrWhiteSpace($s)){ return $s }
    ($s -replace '/', '\') -replace '\\{2,}','\'
}
function Assert-ValidUnc {
    param([Parameter(Mandatory)][string]$unc)
    if([string]::IsNullOrWhiteSpace($unc)){ throw "RemoteFolder is empty." }
    $unc = $unc.Trim() -replace '[\\/]+$',''
    if($unc -notmatch '^[\\]{2}'){ throw "RemoteFolder must start with '\\' (UNC). Provided: $unc" }
    # Very basic \\server\share[...\...] check
    $pattern = '^[\\]{2}[^\\/\\]+[\\][^\\/\\]+(?:[\\][^\r\n]*)?$'
    if(-not ([regex]::IsMatch($unc,$pattern))){ throw "RemoteFolder must be in the form \\server\share[\sub...]" }
    return $unc
}
function Get-ExePathFromServicePath([string]$PathName){
    if([string]::IsNullOrWhiteSpace($PathName)){return $null}
    $p=$PathName.Trim()
    if($p.StartsWith('"')){
        if($p -match '^"(?<exe>[A-Za-z]:\\.*?\.exe)"'){ return $Matches['exe'] }
    } else {
        if($p -match '^(?<exe>[A-Za-z]:\\.*?\.exe)'){ return $Matches['exe'] }
    }
    return $null
}
function Get-UninstallVersion([string]$nameLike){
    $roots=@('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach($r in $roots){
        try {
            Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $p=Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                    if($p.DisplayName -and $p.DisplayName -like $nameLike){ return $p.DisplayVersion }
                } catch {}
            }
        } catch {}
    }
    return $null
}
function Get-FileVersionIfExists([string]$path){ try{ if($path -and (Test-Path -LiteralPath $path)){ return (Get-Item $path).VersionInfo.FileVersion } }catch{} ; return $null }
function Normalize-Version($v){
    if($null -eq $v){return $null}
    if($v -is [array]){ $v = $v | Select-Object -First 1 }
    $s=[string]$v; return ($s.Trim() -replace '\s+',' ' -replace ',', '.')
}

# --- VPN/Client detection helpers ---
function Detect-WireGuardActive { try { $wg = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*WireGuard*' -and $_.Status -eq 'Up' } ; return ($wg -ne $null) } catch { return $false } }
function Get-WireGuardVersion { $ver=Get-UninstallVersion 'WireGuard*'; if(-not $ver){ $ver=Get-FileVersionIfExists 'C:\Program Files\WireGuard\wireguard.exe' } return (Normalize-Version $ver) }

function Detect-WarpActive {
    try {
        $ad = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { ($_.Name -eq 'CloudflareWARP' -or $_.InterfaceDescription -like '*Cloudflare*WARP*') -and $_.Status -eq 'Up' }
        $ipif = Get-NetIPInterface -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like '*Cloudflare*WARP*' -and $_.ConnectionState -eq 'Connected' }
        return ($ad -and $ipif)
    } catch { return $false }
}
function Get-WarpVersion {
    $ver = Get-UninstallVersion 'Cloudflare WARP*'
    if(-not $ver){ $ver = Get-FileVersionIfExists 'C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe' }
    if(-not $ver){ $ver = Get-FileVersionIfExists 'C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe' }
    if(-not $ver){
        try {
            $svcPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\warp-svc' -ErrorAction SilentlyContinue).ImagePath
            if($svcPath){
                $exe = ($svcPath -replace '"','') -replace '(^.*?)([A-Za-z]:\\.*?\.exe).*','$2'
                if(Test-Path $exe){ $ver = Get-FileVersionIfExists $exe }
            }
        } catch {}
    }
    return (Normalize-Version $ver)
}

function Detect-Gsa {
    $out=[pscustomobject]@{ Active=$false; Version='' }
    try{
        $engine='Global Secure Access Engine Service'
        $tunnel='Global Secure Access Tunneling Service'
        $manager='Global Secure Access Client Manager Service'
        $policy='Global Secure Access Policy Retriever Service'
        $gsaSvcs=Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -in @($engine,$tunnel,$manager,$policy) }
        if($gsaSvcs){
            $running=$gsaSvcs | Where-Object { $_.State -eq 'Running' }
            $out.Active = ( ($running | Where-Object DisplayName -eq $engine) -ne $null -and ($running | Where-Object DisplayName -eq $tunnel) -ne $null )
            $exeVersions=@()
            foreach($svc in $gsaSvcs){
                $exe=Get-ExePathFromServicePath $svc.PathName
                if($exe){ $ver=Get-FileVersionIfExists $exe; if($ver){ $exeVersions+=$ver } }
            }
            $uninstallVer=Get-UninstallVersion '*Global Secure Access*'
            $allVers=@($exeVersions + $uninstallVer) | Where-Object { $_ }
            if($allVers.Count -gt 0){ $out.Version = Normalize-Version ( ($allVers | Sort-Object -Descending | Select-Object -First 1) ) }
        }
    } catch {}
    return $out
}

# --- WAN ---
function Invoke-WanLookup([int]$TimeoutSeconds=3){
    function Test-ValidIP([string]$ip){ if([string]::IsNullOrWhiteSpace($ip)){ return $false } try{ [void][System.Net.IPAddress]::Parse($ip); return $true } catch { return $false } }
    try {
        $resp = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec $TimeoutSeconds
        if($resp -and (Test-ValidIP $resp.ip)){
            return [pscustomobject]@{ WanIP=$resp.ip; City=$resp.city; Region=$resp.region; Country=$resp.country; Org=$resp.org; Source='ipinfo.io' }
        }
    } catch {}
    try {
        $resp = Invoke-RestMethod -Uri 'https://ipapi.co/json' -TimeoutSec $TimeoutSeconds
        if($resp -and (Test-ValidIP $resp.ip)){
            $org = if($resp.org){$resp.org} elseif($resp.asn){$resp.asn} else {$null}
            return [pscustomobject]@{ WanIP=$resp.ip; City=$resp.city; Region=$resp.region; Country=$resp.country; Org=$org; Source='ipapi.co' }
        }
    } catch {}
    try {
        $resp = Invoke-RestMethod -Uri 'https://ifconfig.co/json' -TimeoutSec $TimeoutSeconds
        if($resp -and (Test-ValidIP $resp.ip)){
            $org = if($resp.asn_org){$resp.asn_org} elseif($resp.asn){$resp.asn} else {$null}
            return [pscustomobject]@{ WanIP=$resp.ip; City=$resp.city; Region=$resp.region_name; Country=$resp.country; Org=$org; Source='ifconfig.co' }
        }
    } catch {}
    try {
        $resp = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec $TimeoutSeconds
        if($resp -and (Test-ValidIP $resp.ip)){
            return [pscustomobject]@{ WanIP=$resp.ip; City=$null; Region=$null; Country=$null; Org=$null; Source='ipify.org' }
        }
    } catch {}
    return $null
}

# --- Route/NIC snapshot + OS/Plan (for CSV + console OS/Plan) ---
function Resolve-ServerIp([string]$Server){
    try{ [void][System.Net.IPAddress]::Parse($Server); return $Server } catch {
        try{ $ips=[System.Net.Dns]::GetHostAddresses($Server) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }; if($ips){ return $ips[0].IPAddressToString } } catch {}
    }
    return $null
}
function Get-RouteSnapshot([string]$TargetIP){
    $rt = Get-NetRoute -DestinationPrefix "$TargetIP/32" -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric, InterfaceMetric | Select-Object -First 1
    if(-not $rt){
        $rt = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric, InterfaceMetric | Select-Object -First 1
    }
    if(-not $rt){ return $null }
    $iface = Get-NetIPInterface -InterfaceIndex $rt.InterfaceIndex -ErrorAction SilentlyContinue | Sort-Object -Property ConnectionState, NlMtu -Descending | Select-Object -First 1
    $ni = Get-NetAdapter -InterfaceIndex $rt.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
    [pscustomobject]@{
        ActiveIfAlias     = if($iface){ [string]$iface.InterfaceAlias } else { 'N/A' }
        ActiveIfMtu       = if($iface){ [int]$iface.NlMtu } else { 0 }
        ActiveIfLinkSpeed = if($ni){ [string]$ni.LinkSpeed } else { 'N/A' }
    }
}
function Get-ActivePowerPlanName {
    try{
        $out = powercfg /GETACTIVESCHEME 2>$null
        if($out){
            $m = ($out | Select-String -Pattern '\((?<name>.+)\)' -AllMatches).Matches
            if($m.Count -gt 0){ return $m[0].Groups['name'].Value.Trim() }
        }
    } catch {}
    return 'Unknown'
}
function Invoke-Preflight([string]$RemoteFolder){
    # We still compute OS/Plan and NIC info for CSV and later console display, but we do NOT print a "Preflight" section.
    $parts = ($RemoteFolder -replace '^\\','') -split '\\'
    $serverRaw = $parts[0]
    $resolved = Resolve-ServerIp -Server $serverRaw
    $route = if($resolved){ Get-RouteSnapshot -TargetIP $resolved } else { $null }
    $os = Get-CimInstance Win32_OperatingSystem
    $osVer = ("{0} {1} build {2}" -f $os.Caption, $os.Version, $os.BuildNumber)
    $pp = Get-ActivePowerPlanName
    [pscustomobject]@{
        OSVersion=$osVer; PowerPlan=$pp;
        ActiveIfAlias= if($route){ $route.ActiveIfAlias } else { 'N/A' }
        ActiveIfMtu= if($route){ $route.ActiveIfMtu } else { 'N/A' }
        ActiveIfLinkSpeed= if($route){ $route.ActiveIfLinkSpeed } else { 'N/A' }
    }
}

# ===================== Early Validation & Detection =====================
try { $RemoteFolder = Assert-ValidUnc $RemoteFolder } catch { Write-Host ("UNC validation failed: {0}" -f (ForDisplay $_.Exception.Message)) -ForegroundColor Red; exit 1 }
$Hostname = $env:COMPUTERNAME
$wgActive = Detect-WireGuardActive; $wgVersion = Get-WireGuardVersion
$gsa = Detect-Gsa
$warpActive = Detect-WarpActive; $warpVersion = Get-WarpVersion

$VpnClientVersion='N/A'
$GSAClientVersion = if ($gsa -and -not [string]::IsNullOrWhiteSpace($gsa.Version)) { $gsa.Version } else { 'N/A' }

# --- PS 5.1-safe (expanded) assignments here ---
if ($gsa.Active -and -not $wgActive -and -not $warpActive) {
    $VpnClientVersion = $GSAClientVersion
}
elseif ($wgActive -and -not $gsa.Active -and -not $warpActive) {
    if ([string]::IsNullOrWhiteSpace($wgVersion)) { $VpnClientVersion = 'N/A' }
    else { $VpnClientVersion = $wgVersion }
}
elseif ($warpActive -and -not $gsa.Active -and -not $wgActive) {
    if ([string]::IsNullOrWhiteSpace($warpVersion)) { $VpnClientVersion = 'N/A' }
    else { $VpnClientVersion = $warpVersion }
}

$ProductUsed = if     ($warpActive){ 'Cloudflare WARP' }
               elseif ($wgActive) { 'WireGuard' }
               elseif ($gsa.Active){ 'Entra Private Access' }
               else { 'None' }

# Compute OS/Plan + NIC snapshot once (no printing)
$pre = Invoke-Preflight -RemoteFolder $RemoteFolder
$OSVersion = $pre.OSVersion
$PowerPlan = $pre.PowerPlan

# ===================== WAN =====================
$WanIP='N/A'; $WanCity='N/A'; $WanRegion='N/A'; $WanCountry='N/A'; $WanOrg='N/A'; $WanSource='N/A'
try{
    $wan = Invoke-WanLookup -TimeoutSeconds 3
    if($wan){
        $WanIP=$wan.WanIP; $WanCity = if($wan.City){$wan.City}else{'N/A'}
        $WanRegion = if($wan.Region){$wan.Region}else{'N/A'}
        $WanCountry = if($wan.Country){$wan.Country}else{'N/A'}
        $WanOrg = if($wan.Org){$wan.Org}else{'N/A'}
        $WanSource = if($wan.Source){$wan.Source}else{'N/A'}
    }
}catch{}

if (-not $Zaher) {
    Write-Host ""
    Write-Host "WAN" -ForegroundColor Blue
    Write-Host "---------" -ForegroundColor Blue
    Write-Host ("WanIP : {0}" -f $WanIP)
    Write-Host ("City : {0}" -f $WanCity)
    Write-Host ("Region: {0}" -f $WanRegion)
    Write-Host ("Country: {0}" -f $WanCountry)
    Write-Host ("Org : {0}" -f $WanOrg)
    Write-Host ("Source: {0}" -f $WanSource)
}
if ($Zaher) {
    Write-Host ""
    Write-Host "WAN" -ForegroundColor Blue
    Write-Host "---------" -ForegroundColor Blue
    Write-Host ("WanIP : {0}" -f $WanIP)
    Write-Host ("City : {0}" -f $WanCity)
    Write-Host ("Region: {0}" -f $WanRegion)
    Write-Host ("Country: {0}" -f $WanCountry)
    Write-Host ("Org : {0}" -f $WanOrg)
    Write-Host ("Source: {0}" -f $WanSource)
}

# ===================== Zaher mode Client Detection & prompts =====================
if ($Zaher) {
    Write-Host ""
    Write-Host "Client Detection" -ForegroundColor Blue
    Write-Host "----------------" -ForegroundColor Blue
    if     ($ProductUsed -eq 'Cloudflare WARP'){ Write-Host 'VPN=Cloudflare WARP'; Write-Host ("WARP Version={0}" -f $VpnClientVersion) }
    elseif ($ProductUsed -eq 'WireGuard'){ Write-Host 'VPN=WireGuard'; Write-Host ("WireGuard Version={0}" -f $VpnClientVersion) }
    elseif ($ProductUsed -eq 'Entra Private Access'){ Write-Host 'VPN=Entra Private Access'; Write-Host ("GSA Version={0}" -f $GSAClientVersion) }
    else { Write-Host ("VPN={0}" -f $ProductUsed); Write-Host ("Version={0}" -f $VpnClientVersion) }

    # DeviceId & TenantId (DeviceId first), Hostname, then OS/Plan
    try {
        $dsOut = (& dsregcmd /status) | Out-String
        if($dsOut -match 'DeviceId\s*:\s*([0-9a-fA-F\-]{36})'){ $DeviceId=$Matches[1] }
        if($dsOut -match 'TenantId\s*:\s*([0-9a-fA-F\-]{36})'){ $TenantId=$Matches[1] }
    } catch {}
    Write-Host ("DeviceId : {0}" -f $DeviceId)
    Write-Host ("TenantId : {0}" -f $TenantId)
    Write-Host ("Hostname: {0}" -f $Hostname)
    Write-Host ("OS: {0}" -f $OSVersion)
    Write-Host ("Plan: {0}" -f $PowerPlan)
    Write-Host "" # spacer

    # ===== Zaher picker and connector prompts =====
    function Select-ClientVmAndLocation {
        $menu = @"
Select CLIENT VM / Location:
[A] AZVM01, UK South
[B] AZVM02, Italy
[C] AZVM03, Germany West
[D] AZVM04, Qatar Central
[E] AZVM05, UAE North
[F] AZVM06, East US
[G] AZVM07, Central Canada
[Z] New client/location (auto-fill hostname)
Enter A-G or Z
"@
        $map = @{
          'A'=@{VM='AZVM01';Loc='UK South'};
          'B'=@{VM='AZVM02';Loc='Italy'};
          'C'=@{VM='AZVM03';Loc='Germany West'};
          'D'=@{VM='AZVM04';Loc='Qatar Central'};
          'E'=@{VM='AZVM05';Loc='UAE North'};
          'F'=@{VM='AZVM06';Loc='East US'};
          'G'=@{VM='AZVM07';Loc='Central Canada'};
        }
        while ($true) {
            $choice = Read-Host -Prompt ($menu.TrimEnd())
            if([string]::IsNullOrWhiteSpace($choice)){ continue }
            $choice = $choice.Trim().ToUpperInvariant()
            if($map.ContainsKey($choice)){
                Write-Host "" # blank line after input
                return [pscustomobject]@{
                    ClientVM = $map[$choice].VM
                    ClientCityCountry = $map[$choice].Loc
                    Hostname = $map[$choice].VM
                }
            }
            elseif ($choice -eq 'Z') {
                $defaultHost = $env:COMPUTERNAME
                $vm = Read-Host -Prompt ("Enter Client VM name (Enter for '{0}')" -f $defaultHost)
                if([string]::IsNullOrWhiteSpace($vm)){ $vm = $defaultHost }
                $loc = Read-Host -Prompt "Enter City, Country (e.g., London, UK)"
                if([string]::IsNullOrWhiteSpace($loc)){ $loc = 'Unknown' }
                Write-Host "" # blank line after input
                return [pscustomobject]@{
                    ClientVM = $vm
                    ClientCityCountry = $loc
                    Hostname = $defaultHost
                }
            }
            else {
                Write-Host "Invalid selection. Please enter A-G or Z." -ForegroundColor Yellow
            }
        }
    }

    $pick = Select-ClientVmAndLocation
    $clientSel = $pick
    $Hostname = $pick.Hostname

    # GSA-only connector prompts; defaults follow selection
    $defaultConnectorVersion  = "1.5.4522.0"
    $defaultConnectorVMLocation = $pick.ClientCityCountry
    $defaultConnectorRegion   = "EMEA"
    if ($gsa.Active) {
        Write-Host ""
        Write-Host "Entra Private Access Connector Details" -ForegroundColor Blue
        Write-Host "-------------------------------------" -ForegroundColor Blue
        $in = Read-Host ("Connector Version (Enter for '{0}')" -f $defaultConnectorVersion)
        $ConnectorVersion    = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorVersion } else { $in }
        $in = Read-Host ("Connector VM Location (Enter for '{0}')" -f $defaultConnectorVMLocation)
        $ConnectorVMLocation = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorVMLocation } else { $in }
        $in = Read-Host ("Connector Region (Enter for '{0}')" -f $defaultConnectorRegion)
        $ConnectorRegion     = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorRegion } else { $in }
    }
}

# ===================== Client Detection (normal mode print) =====================
if (-not $Zaher) {
    Write-Host ""
    Write-Host "Client Detection" -ForegroundColor Blue
    Write-Host "----------------" -ForegroundColor Blue
    if     ($ProductUsed -eq 'Cloudflare WARP'){ Write-Host 'VPN=Cloudflare WARP'; Write-Host ("WARP Version={0}" -f $VpnClientVersion) }
    elseif ($ProductUsed -eq 'WireGuard'){ Write-Host 'VPN=WireGuard'; Write-Host ("WireGuard Version={0}" -f $VpnClientVersion) }
    elseif ($ProductUsed -eq 'Entra Private Access'){ Write-Host 'VPN=Entra Private Access'; Write-Host ("GSA Version={0}" -f $GSAClientVersion) }
    else { Write-Host ("VPN={0}" -f $ProductUsed); Write-Host ("Version={0}" -f $VpnClientVersion) }

    # DeviceId & TenantId (DeviceId first), then Hostname, then OS/Plan
    try {
        $dsOut = (& dsregcmd /status) | Out-String
        if($dsOut -match 'DeviceId\s*:\s*([0-9a-fA-F\-]{36})'){ $DeviceId=$Matches[1] }
        if($dsOut -match 'TenantId\s*:\s*([0-9a-fA-F\-]{36})'){ $TenantId=$Matches[1] }
    } catch {}
    Write-Host ("DeviceId : {0}" -f $DeviceId)
    Write-Host ("TenantId : {0}" -f $TenantId)
    Write-Host ("Hostname: {0}" -f $Hostname)
    Write-Host ("OS: {0}" -f $OSVersion)
    Write-Host ("Plan: {0}" -f $PowerPlan)

    # City/Country prompt AFTER Hostname/OS/Plan
    $ClientLocation = Read-Host "Enter City, Country (e.g., London, UK)"
    if([string]::IsNullOrWhiteSpace($ClientLocation)){ $ClientLocation = 'N/A' }
    $clientSel = [pscustomobject]@{ ClientCityCountry = $ClientLocation; Hostname = $Hostname }

    # GSA-only connector prompts (normal)
    $defaultConnectorVersion  = "1.5.4522.0"
    $defaultConnectorVMLocation = "UK South"
    $defaultConnectorRegion   = "EMEA"
    if ($gsa.Active) {
        Write-Host ""
        Write-Host "Entra Private Access Connector Details" -ForegroundColor Blue
        Write-Host "-------------------------------------" -ForegroundColor Blue
        $in = Read-Host ("Connector Version (Enter for '{0}')" -f $defaultConnectorVersion)
        $ConnectorVersion    = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorVersion } else { $in }
        $in = Read-Host ("Connector VM Location (Enter for '{0}')" -f $defaultConnectorVMLocation)
        $ConnectorVMLocation = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorVMLocation } else { $in }
        $in = Read-Host ("Connector Region (Enter for '{0}')" -f $defaultConnectorRegion)
        $ConnectorRegion     = if([string]::IsNullOrWhiteSpace($in)){ $defaultConnectorRegion } else { $in }
    }
}

# ===================== CSV helpers =====================
# NOTE: Live ping stats columns are positioned immediately after Mbps.
$CsvColumns = @(
    'ProductUsed','VpnClientVersion','ClientCityCountry','Hostname','DeviceId','TenantId',
    'OSVersion','PowerPlan',
    'WanIP','WanCity','WanRegion','WanCountry','WanOrg','WanSource',
    'ConnectorVersion','ConnectorVMLocation','ConnectorRegion',
    'Direction','Run','StartUTC','EndUTC','Seconds','Mbps',
    'PingAvgMs','PingMinMs','PingMaxMs','PingLossPct',
    'FileMB','CopyEngine','ScriptVersion','SourcePath','TargetPath',
    'ActiveIfAlias','ActiveIfMtu','ActiveIfLinkSpeed'
)

function Initialize-Csv {
    if(-not (Test-Path -LiteralPath $LogCsv)){
        $header=[pscustomobject]@{}
        foreach($c in $CsvColumns){ $header | Add-Member -NotePropertyName $c -NotePropertyValue $null }
        $header | Export-Csv -LiteralPath $LogCsv -NoTypeInformation
        (Get-Content -LiteralPath $LogCsv) | Select-Object -First 1 | Set-Content -LiteralPath $LogCsv
    }
}

function Write-LogRow {
    param(
        [string]$Direction,[int]$Run,[datetime]$StartUtc,[datetime]$EndUtc,[double]$Seconds,[double]$Mbps,[double]$FileMB,
        [string]$SourcePath,[string]$TargetPath,[Nullable[int]]$Tcp445LatencyMsParam,[pscustomobject]$Pre,

        # New optional ping parameters (live network health)
        [Nullable[double]]$PingAvgMs = $null,
        [Nullable[double]]$PingMinMs = $null,
        [Nullable[double]]$PingMaxMs = $null,
        [Nullable[double]]$PingLossPct = $null
    )

    $row=[pscustomobject]@{
        ProductUsed        = $ProductUsed; VpnClientVersion = $VpnClientVersion;
        ClientCityCountry  = $clientSel.ClientCityCountry; Hostname = $clientSel.Hostname; DeviceId = $DeviceId; TenantId = $TenantId;
        OSVersion          = $OSVersion; PowerPlan = $PowerPlan;
        WanIP              = $WanIP; WanCity = $WanCity; WanRegion = $WanRegion; WanCountry = $WanCountry; WanOrg = $WanOrg; WanSource = $WanSource;
        ConnectorVersion   = $ConnectorVersion; ConnectorVMLocation = $ConnectorVMLocation; ConnectorRegion = $ConnectorRegion;

        Direction          = $Direction; Run = $Run; StartUTC = $StartUtc.ToString('s'); EndUTC = $EndUtc.ToString('s');
        Seconds            = [math]::Round($Seconds,2);
        Mbps               = [math]::Round($Mbps,2);

        # Live ping stats right after Mbps (PS 5.1-safe null handling)
        PingAvgMs          = [math]::Round($(if($PingAvgMs  -ne $null){$PingAvgMs }else{0}),1);
        PingMinMs          = [math]::Round($(if($PingMinMs  -ne $null){$PingMinMs }else{0}),1);
        PingMaxMs          = [math]::Round($(if($PingMaxMs  -ne $null){$PingMaxMs }else{0}),1);
        PingLossPct        = [math]::Round($(if($PingLossPct -ne $null){$PingLossPct}else{0}),1);

        FileMB             = [math]::Round($FileMB,2);
        CopyEngine         = $CopyEngine; ScriptVersion = $ScriptVersion; SourcePath = $SourcePath; TargetPath = $TargetPath;
        ActiveIfAlias      = $Pre.ActiveIfAlias; ActiveIfMtu = $Pre.ActiveIfMtu; ActiveIfLinkSpeed = $Pre.ActiveIfLinkSpeed
    }

    $row | Export-Csv -LiteralPath $LogCsv -NoTypeInformation -Append
}

# ===================== Copy engines =====================
function Invoke-ExplorerUICopy([string]$SourcePath,[string]$DestPath){
    $srcFolder=Split-Path -Parent $SourcePath
    $srcName=[IO.Path]::GetFileName($SourcePath)
    $dstFolder=Split-Path -Parent $DestPath
    $shell=New-Object -ComObject Shell.Application
    $dstNS=$shell.NameSpace($dstFolder)
    if(-not $dstNS){ return [pscustomobject]@{ Ok=$false; Error=("ExplorerUI: destination not accessible: {0}" -f $dstFolder) } }
    $srcNS=$shell.NameSpace($srcFolder)
    if(-not $srcNS){ return [pscustomobject]@{ Ok=$false; Error=("ExplorerUI: source folder not accessible: {0}" -f $srcFolder) } }
    $item=$srcNS.ParseName($srcName)
    if(-not $item){ return [pscustomobject]@{ Ok=$false; Error=("ExplorerUI: cannot parse source item: {0}" -f $srcName) } }
    try{ $srcLen=(Get-Item -LiteralPath $SourcePath).Length } catch { return [pscustomobject]@{ Ok=$false; Error=("Source file not readable: {0}" -f $SourcePath) } }
    $FOF_NOCONFIRMATION=0x0010; $FOF_NOCONFIRMMKDIR=0x0200; $FOF_NOERRORUI=0x0400
    $flags=$FOF_NOCONFIRMATION -bor $FOF_NOCONFIRMMKDIR -bor $FOF_NOERRORUI
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    $dstNS.CopyHere($item,$flags)
    $stallTimeoutSec=90; $overallTimeoutSec=2*60*60; $maxReKicks=2; $reKicks=0; $lastLen=-1; $lastChange=Get-Date
    while($true){
        $now=Get-Date
        if(Test-Path -LiteralPath $DestPath){
            $len=(Get-Item -LiteralPath $DestPath).Length
            if($len -ge $srcLen){ break }
            if($len -gt $lastLen){ $lastLen=$len; $lastChange=$now }
        }
        if(($now - $lastChange).TotalSeconds -ge $stallTimeoutSec){
            if($reKicks -lt $maxReKicks){
                $reKicks++
                Write-Host ("ExplorerUI: no growth for {0}s - re-kick {1}/{2}" -f $stallTimeoutSec,$reKicks,$maxReKicks) -ForegroundColor Yellow
                $dstNS.CopyHere($item,$flags)
                $lastChange=Get-Date
            } else {
                $sw.Stop()
                return [pscustomobject]@{ Ok=$false; Error=("ExplorerUI stalled: no size growth for {0}s (after {1} re-kicks)" -f $stallTimeoutSec,$reKicks) }
            }
        }
        if($sw.Elapsed.TotalSeconds -ge $overallTimeoutSec){
            $sw.Stop()
            return [pscustomobject]@{ Ok=$false; Error=("ExplorerUI timeout after {0} minutes" -f ($overallTimeoutSec/60)) }
        }
        Start-Sleep -Milliseconds 200
    }
    # Stabilisation
    $stable=0; $prev=-1
    while($true){
        if(-not (Test-Path -LiteralPath $DestPath)){ return [pscustomobject]@{ Ok=$false; Error=("Destination file vanished during stabilisation: {0}" -f $DestPath) } }
        $len=(Get-Item -LiteralPath $DestPath).Length
        if($len -eq $prev){ $stable++ } else { $stable=0 }
        $prev=$len
        if($stable -ge 3){ break }
        Start-Sleep -Milliseconds 200
    }
    $sw.Stop()
    $secs=[math]::Max($sw.Elapsed.TotalSeconds,0.001)
    $Mbps=[math]::Round(((($srcLen/1MB)/$secs)*8),2)
    return [pscustomobject]@{ Ok=$true; Seconds=$secs; Mbps=$Mbps }
}
function Invoke-CopyItemCopy([string]$SourcePath,[string]$DestPath){
    try{ $srcLen=(Get-Item -LiteralPath $SourcePath).Length } catch { return [pscustomobject]@{ Ok=$false; Error=("Source file not readable: {0}" -f $SourcePath) } }
    $sw=[System.Diagnostics.Stopwatch]::StartNew()
    try{ Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force -ErrorAction Stop } catch{ $sw.Stop(); return [pscustomobject]@{ Ok=$false; Error=("Copy-Item failed: {0}" -f $_.Exception.Message) } }
    $sw.Stop()
    $secs=[math]::Max($sw.Elapsed.TotalSeconds,0.001)
    $Mbps=[math]::Round(((($srcLen/1MB)/$secs)*8),2)
    return [pscustomobject]@{ Ok=$true; Seconds=$secs; Mbps=$Mbps }
}
function Invoke-FileCopy([string]$SourcePath,[string]$DestPath){
    if($CopyEngine -eq 'CopyItem'){ return Invoke-CopyItemCopy -SourcePath $SourcePath -DestPath $DestPath } else { return Invoke-ExplorerUICopy -SourcePath $SourcePath -DestPath $DestPath }
}

# ===================== Ping helpers (job + summary) =====================
function Start-PingJob {
    param([Parameter(Mandatory)][string]$Target, [int]$IntervalMs = 1000)
    Start-Job -ScriptBlock {
        param($T,$I)
        while ($true) {
            try {
                $r = Test-Connection -ComputerName $T -Count 1 -ErrorAction SilentlyContinue
                if($r){ $ms = ($r | Select-Object -First 1 -ExpandProperty ResponseTime); [pscustomobject]@{ Success=$true; Ms=[double]$ms } }
                else  { [pscustomobject]@{ Success=$false; Ms=$null } }
            } catch { [pscustomobject]@{ Success=$false; Ms=$null } }
            Start-Sleep -Milliseconds $I
        }
    } -ArgumentList $Target,$IntervalMs
}
function Get-PingJobStats {
    param([Parameter(Mandatory)][System.Management.Automation.Job]$Job)
    $data = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
    if(-not $data){ return $null }
    $total = ($data | Measure-Object).Count
    if($total -eq 0){ return $null }
    $succ = ($data | Where-Object { $_.Success })
    $succCount = ($succ | Measure-Object).Count
    $lossPct = if($total -gt 0){ [math]::Round(100.0 * ($total - $succCount) / $total, 1) } else { 0 }
    if($succCount -eq 0){ return [pscustomobject]@{ MinMs=0; AvgMs=0; MaxMs=0; LossPct=100 } }
    $minMs = [math]::Round( ($succ | Measure-Object -Property Ms -Minimum).Minimum,1 )
    $avgMs = [math]::Round( ($succ | Measure-Object -Property Ms -Average).Average,1 )
    $maxMs = [math]::Round( ($succ | Measure-Object -Property Ms -Maximum).Maximum,1 )
    [pscustomobject]@{ MinMs=$minMs; AvgMs=$avgMs; MaxMs=$maxMs; LossPct=$lossPct }
}

# ===================== Live ticker (single-line console updates) =====================
$script:__ticker_Timer = $null
$script:__ticker_Event = $null

function Start-LivePingTicker {
    param([Parameter(Mandatory)][int]$PingJobId)

    Stop-LivePingTicker  # ensure clean state

    $script:__ticker_Timer = New-Object System.Timers.Timer
    $script:__ticker_Timer.Interval = 1000
    $script:__ticker_Timer.AutoReset = $true

    $script:__ticker_Event = Register-ObjectEvent -InputObject $script:__ticker_Timer -EventName Elapsed -Action {
        try {
            $data = Receive-Job -Id $using:PingJobId -Keep -ErrorAction SilentlyContinue
            if(-not $data){ $line = "Network health (live): collecting..." }
            else{
                $total = ($data | Measure-Object).Count
                $succ  = $data | Where-Object { $_.Success }
                $succCount = ($succ | Measure-Object).Count
                if($succCount -eq 0){
                    $line = "Network health (live): no replies yet (loss=100%)"
                } else {
                    $minMs = [math]::Round( ($succ | Measure-Object -Property Ms -Minimum).Minimum, 1 )
                    $avgMs = [math]::Round( ($succ | Measure-Object -Property Ms -Average ).Average, 1 )
                    $maxMs = [math]::Round( ($succ | Measure-Object -Property Ms -Maximum).Maximum, 1 )
                    $loss  = [math]::Round( 100.0 * ($total - $succCount) / $total, 1 )
                    $line = "Network health (live): 8.8.8.8 avg=$avgMs ms min=$minMs max=$maxMs loss=$loss%"
                }
            }
            # Overwrite same console line
            $width = $Host.UI.RawUI.WindowSize.Width
            $text  = "`r$line"
            $pad   = ' ' * [Math]::Max(0, $width - $line.Length - 1)
            [Console]::Write($text + $pad)
        } catch {
            # swallow UI errors
        }
    }

    $script:__ticker_Timer.Start()
}

function Stop-LivePingTicker {
    try {
        if($script:__ticker_Timer){ $script:__ticker_Timer.Stop() }
        if($script:__ticker_Event){ Unregister-Event -SubscriptionId $script:__ticker_Event.Id -ErrorAction SilentlyContinue }
    } catch {}
    finally {
        $script:__ticker_Event = $null
        if($script:__ticker_Timer){ $script:__ticker_Timer.Dispose(); $script:__ticker_Timer = $null }
        # Clear the ticker line (carriage return + spaces + carriage return)
        try {
            $width = $Host.UI.RawUI.WindowSize.Width
            [Console]::Write("`r" + (' ' * ($width - 1)) + "`r")
        } catch {}
    }
}

# ===================== Copy loops =====================
Initialize-Csv
$extJob = Start-PingJob -Target '8.8.8.8' -IntervalMs 1000

$srcPathDL = Join-FolderFile $RemoteFolder $FileName
$dstPathDL = Join-FolderFile $LocalFolder $FileName
$srcPathUL = Join-FolderFile $LocalFolder $FileName
$dstPathUL = Join-FolderFile $RemoteFolder $FileName

Ensure-LocalFolder (Split-Path -Parent $dstPathDL)
Ensure-LocalFolder (Split-Path -Parent $srcPathUL)

if(-not (Test-Path -LiteralPath $srcPathUL)){
    Write-Host ("ERROR: Local ISO not found: {0}" -f (ForDisplay $srcPathUL)) -ForegroundColor Red
    Write-Host "Place your ISO at the above path or update -LocalFolder/-FileName, then re-run." -ForegroundColor Yellow
    exit 99
}

if(-not $Zaher){ Write-Host "" }
Write-Host "Mode: Download" -ForegroundColor Blue
Write-Host "-------------" -ForegroundColor Blue
# display-only: quote the path so \\ renders correctly; variables remain untouched for copy ops
Write-Host ("Source : '{0}'" -f $srcPathDL) -ForegroundColor Gray
Write-Host ("Destination : '{0}'" -f $dstPathDL) -ForegroundColor Gray

if(-not (Path-Exists $srcPathDL)){
    Write-Host ("Source not found on remote: {0}" -f (ForDisplay $srcPathDL)) -ForegroundColor Yellow
    exit 12
}

1..$Runs | ForEach-Object {
    $run = $_

    # --- Start live ticker BEFORE copy begins (best-effort; PS 5.1 may defer UI) ---
    Start-LivePingTicker -PingJobId $extJob.Id

    $start=(Get-Date).ToUniversalTime()
    $prev = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        $res = Invoke-FileCopy -SourcePath $srcPathDL -DestPath $dstPathDL
    } finally {
        $ProgressPreference = $prev
        # --- Stop ticker immediately when copy ends ---
        Stop-LivePingTicker
    }
    $end=(Get-Date).ToUniversalTime()

    if(-not $res.Ok){ Write-Host ("Download Run {0} failed: {1}" -f $run,(ForDisplay $res.Error)) -ForegroundColor Red; exit 20 }
    $bytes=(Get-Item -LiteralPath $srcPathDL).Length
    $fileMB=[math]::Round($bytes/1MB,2)
    Write-Host ("[OK] Download Run {0}: {1:N2}s @ {2:N2} Mbps" -f $run,$res.Seconds,$res.Mbps) -ForegroundColor Green

    # One-off snapshot AFTER run (stable) for console & CSV
    $extStats = Get-PingJobStats -Job $extJob
    if($extStats){
        Write-Host ("Network health (live): 8.8.8.8 avg={0} ms min={1} max={2} loss={3}%" -f $extStats.AvgMs,$extStats.MinMs,$extStats.MaxMs,$extStats.LossPct)
    } else {
        Write-Host "Network health (live): external ping stats unavailable this run." -ForegroundColor Yellow
    }
    # PS 5.1-safe variables for CSV
    $pingAvg=$null; $pingMin=$null; $pingMax=$null; $pingLoss=$null
    if($extStats){ $pingAvg=$extStats.AvgMs; $pingMin=$extStats.MinMs; $pingMax=$extStats.MaxMs; $pingLoss=$extStats.LossPct }

    Write-LogRow -Direction 'Download' -Run $run -StartUtc $start -EndUtc $end -Seconds $res.Seconds -Mbps $res.Mbps `
      -FileMB $fileMB -SourcePath $srcPathDL -TargetPath $dstPathDL -Tcp445LatencyMsParam $null -Pre $pre `
      -PingAvgMs $pingAvg -PingMinMs $pingMin -PingMaxMs $pingMax -PingLossPct $pingLoss

    if($run -lt $Runs){
        Write-Host (" Waiting {0} seconds before next run..." -f $WaitBetweenRunsSeconds) -ForegroundColor Gray
        Start-Sleep -Seconds $WaitBetweenRunsSeconds
    }
}

Write-Host ""
Write-Host "Mode: Upload" -ForegroundColor Blue
Write-Host "-----------" -ForegroundColor Blue
# display-only: quote the path so \\ renders correctly; variables remain untouched for copy ops
Write-Host ("Source : '{0}'" -f $srcPathUL) -ForegroundColor Gray
Write-Host ("Destination : '{0}'" -f $dstPathUL) -ForegroundColor Gray

if(-not (Path-Exists $srcPathUL)){
    Write-Host ("Source not found locally: {0}" -f (ForDisplay $srcPathUL)) -ForegroundColor Yellow
    exit 12
}

1..$Runs | ForEach-Object {
    $run = $_

    # --- Start live ticker BEFORE copy begins (best-effort; PS 5.1 may defer UI) ---
    Start-LivePingTicker -PingJobId $extJob.Id

    $start=(Get-Date).ToUniversalTime()
    $prev = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        $res = Invoke-FileCopy -SourcePath $srcPathUL -DestPath $dstPathUL
    } finally {
        $ProgressPreference = $prev
        # --- Stop ticker immediately when copy ends ---
        Stop-LivePingTicker
    }
    $end=(Get-Date).ToUniversalTime()

    if(-not $res.Ok){ Write-Host ("Upload Run {0} failed: {1}" -f $run,(ForDisplay $res.Error)) -ForegroundColor Red; exit 21 }
    $bytes=(Get-Item -LiteralPath $srcPathUL).Length
    $fileMB=[math]::Round($bytes/1MB,2)
    Write-Host ("[OK] Upload Run {0}: {1:N2}s @ {2:N2} Mbps" -f $run,$res.Seconds,$res.Mbps) -ForegroundColor Green

    # One-off snapshot AFTER run (stable) for console & CSV
    $extStats = Get-PingJobStats -Job $extJob
    if($extStats){
        Write-Host ("Network health (live): 8.8.8.8 avg={0} ms min={1} max={2} loss={3}%" -f $extStats.AvgMs,$extStats.MinMs,$extStats.MaxMs,$extStats.LossPct)
    } else {
        Write-Host "Network health (live): external ping stats unavailable this run." -ForegroundColor Yellow
    }
    # PS 5.1-safe variables for CSV
    $pingAvg=$null; $pingMin=$null; $pingMax=$null; $pingLoss=$null
    if($extStats){ $pingAvg=$extStats.AvgMs; $pingMin=$extStats.MinMs; $pingMax=$extStats.MaxMs; $pingLoss=$extStats.LossPct }

    Write-LogRow -Direction 'Upload' -Run $run -StartUtc $start -EndUtc $end -Seconds $res.Seconds -Mbps $res.Mbps `
      -FileMB $fileMB -SourcePath $srcPathUL -TargetPath $dstPathUL -Tcp445LatencyMsParam $null -Pre $pre `
      -PingAvgMs $pingAvg -PingMinMs $pingMin -PingMaxMs $pingMax -PingLossPct $pingLoss

    if($run -lt $Runs){
        Write-Host (" Waiting {0} seconds before next run..." -f $WaitBetweenRunsSeconds) -ForegroundColor Gray
        Start-Sleep -Seconds $WaitBetweenRunsSeconds
    }
}

try{ Stop-Job $extJob -ErrorAction SilentlyContinue } catch {}
Write-Host ("`nDONE - results saved to: {0}" -f $LogCsv) -ForegroundColor Green