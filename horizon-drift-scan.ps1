#Requires -Version 5.1
<#
.SYNOPSIS
    Horizon CPA - Golden Image Drift Detector
.DESCRIPTION
    Detects golden image drift across Global Desktop Entitlements in a Horizon CPA federation.
    Authenticates to each pod independently, compares master image VMs and snapshots,
    and generates a self-contained HTML report.
.NOTES
    Author  : Guy Hemed
    Company : Terasky
.EXAMPLE
    .\horizon-drift-scan.ps1 -ConnectionServer cs01.corp.local -Domain corp
#>
param(
    [Parameter(Mandatory=$true)]  [string]$ConnectionServer,
    [Parameter(Mandatory=$true)]  [string]$Domain,
    [Parameter(Mandatory=$false)] [string]$ReportPath = ".\horizon-drift-report.html"
)

if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Coalesce() {
    foreach ($v in $args) { if ($null -ne $v -and "$v" -ne '') { return $v } }
    return ''
}
function HvGet {
    param([string]$Fqdn, [string]$Token, [string]$Path)
    $r = Invoke-RestMethod -Uri "https://$Fqdn/rest$Path" `
        -Headers @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' } `
        -ErrorAction Stop
    if ($r -is [array]) { return $r }
    if ($null -eq $r)   { return @() }
    $keys = $r.PSObject.Properties.Name
    $allNum = $true
    foreach ($k in $keys) { if (-not [int]::TryParse($k, [ref]$null)) { $allNum = $false; break } }
    if ($allNum -and $keys.Count -gt 0) { return $keys | Sort-Object { [int]$_ } | ForEach-Object { $r.$_ } }
    return @($r)
}
function HvLogin {
    param([string]$Fqdn, [string]$Domain, [string]$User, [string]$Pass)
    $body = @{ domain = $Domain; username = $User; password = $Pass } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri "https://$Fqdn/rest/login" -Method POST `
        -Body $body -ContentType 'application/json' -ErrorAction Stop
    if (-not $r.access_token) { throw "No token from $Fqdn" }
    return $r.access_token
}
function HvLogout {
    param([string]$Fqdn, [string]$Token)
    try { Invoke-RestMethod -Uri "https://$Fqdn/rest/logout" -Method POST `
        -Headers @{ Authorization = "Bearer $Token" } -ErrorAction SilentlyContinue | Out-Null } catch {}
}
function Log-Step { param([string]$Msg, [string]$Color = 'Cyan') Write-Host "  $Msg" -ForegroundColor $Color }

$cred = Get-Credential -Message "Horizon credentials for $ConnectionServer"
$user = $cred.UserName
$pass = $cred.GetNetworkCredential().Password

Write-Host "" ; Write-Host "PHASE 1 - CPA Discovery" -ForegroundColor Magenta
Log-Step "Authenticating to $ConnectionServer ..."
$tokens = @{}
$tokens[$ConnectionServer] = HvLogin -Fqdn $ConnectionServer -Domain $Domain -User $user -Pass $pass
Log-Step "Authenticated as $user" "Green"

$allPods = HvGet -Fqdn $ConnectionServer -Token $tokens[$ConnectionServer] -Path '/federation/v1/pods'
Log-Step "Federation pods: $(($allPods | ForEach-Object { $_.name }) -join ', ')"

$podInfo = @{}
foreach ($pod in $allPods) {
    $podInfo[$pod.id] = @{ name = $pod.name; fqdn = $null }
    if ($pod.local_pod -eq $true) {
        $podInfo[$pod.id].fqdn = $ConnectionServer
        Log-Step "Local pod '$($pod.name)' -> $ConnectionServer"
        continue
    }
    $epIds = @()
    if ($pod.endpoints) {
        foreach ($ep in $pod.endpoints) {
            if ($ep -is [string]) { $epIds += $ep } elseif ($ep.id) { $epIds += $ep.id }
        }
    }
    foreach ($epId in $epIds) {
        try {
            $epData = HvGet -Fqdn $ConnectionServer -Token $tokens[$ConnectionServer] `
                -Path "/federation/v1/pods/$($pod.id)/endpoints/$epId"
            if ($epData -is [array] -and $epData.Count -gt 0) { $epData = $epData[0] }
            $rawAddr = Coalesce $epData.server_address $epData.address $epData.fqdn ''
            $fqdn = ($rawAddr -replace '^https?://', '') -replace ':\d+.*$', ''
            $fqdn = $fqdn.Trim('/').Trim()
            $epStatus = Coalesce $epData.status 'ENABLED'
            if ($fqdn -and $epStatus -eq 'ENABLED') {
                $podInfo[$pod.id].fqdn = $fqdn
                Log-Step "Remote pod '$($pod.name)' -> $fqdn"
                break
            }
        } catch { Log-Step "  Endpoint $epId failed: $_" "Yellow" }
    }
    if (-not $podInfo[$pod.id].fqdn) { Log-Step "No CS found for pod '$($pod.name)'" "Yellow" }
}

foreach ($pod in $allPods) {
    if ($pod.local_pod -eq $true) { continue }
    $fqdn = $podInfo[$pod.id].fqdn
    if (-not $fqdn) { continue }
    try {
        $tokens[$fqdn] = HvLogin -Fqdn $fqdn -Domain $Domain -User $user -Pass $pass
        Log-Step "Authenticated to '$($pod.name)'" "Green"
    } catch {
        Log-Step "Auth failed for '$($pod.name)': $_" "Yellow"
        $podInfo[$pod.id].fqdn = $null
    }
}

Write-Host "" ; Write-Host "PHASE 2+3 - Inventory and Translation" -ForegroundColor Magenta
$podData = @{}
foreach ($pod in $allPods) {
    $fqdn = $podInfo[$pod.id].fqdn
    if (-not $fqdn -or -not $tokens.ContainsKey($fqdn)) { Log-Step "Skipping '$($pod.name)' - no token" "Yellow"; continue }
    $tok = $tokens[$fqdn]
    Log-Step "--- Pod: $($pod.name) ($fqdn) ---" "White"
    $podData[$pod.id] = @{ pools = @(); gdeNames = @{}; vmLookup = @{}; snapLookup = @{} }
    $pools = @()
    foreach ($ver in @('v3', 'v2', 'v1')) {
        try { $pools = HvGet -Fqdn $fqdn -Token $tok -Path "/inventory/$ver/desktop-pools"
              Log-Step "  $($pools.Count) pool(s) from inventory/$ver" "Green"; break
        } catch { }
    }
    $podData[$pod.id].pools = $pools
    try {
        $gdes = HvGet -Fqdn $fqdn -Token $tok -Path '/inventory/v1/global-desktop-entitlements'
        foreach ($g in $gdes) { $podData[$pod.id].gdeNames[$g.id] = Coalesce $g.display_name $g.name $g.id }
        Log-Step "  $($gdes.Count) GDE name(s) mapped" "Green"
    } catch { Log-Step "  GDE mapping failed: $_" "Yellow" }
    $processedVc   = @()
    $processedPair = @()
    foreach ($pool in $pools) {
        $ps     = $pool.provisioning_settings
        if (-not $ps) { continue }
        $vmId   = Coalesce $ps.parent_vm_id ''
        $snapId = Coalesce $ps.base_snapshot_id ''
        $vcId   = Coalesce $pool.vcenter_id ''
        if (-not $vmId -or -not $vcId) { continue }
        if ($processedVc -notcontains $vcId) {
            $processedVc += $vcId
            try {
                $vms = HvGet -Fqdn $fqdn -Token $tok -Path "/external/v1/virtual-machines?vcenter_id=$vcId"
                foreach ($vm in $vms) { if ($vm.id) { $podData[$pod.id].vmLookup[$vm.id] = Coalesce $vm.name $vm.id } }
                Log-Step "  VM lookup: $($vms.Count) VMs" "Green"
            } catch { Log-Step "  VM lookup failed: $_" "Yellow" }
        }
        $pair = "$vcId|$vmId"
        if ($processedPair -notcontains $pair) {
            $processedPair += $pair
            try {
                $snaps = HvGet -Fqdn $fqdn -Token $tok -Path "/external/v2/base-snapshots?vcenter_id=$vcId&base_vm_id=$vmId"
                foreach ($s in $snaps) { if ($s.id) { $podData[$pod.id].snapLookup[$s.id] = Coalesce $s.name $s.id } }
                Log-Step "  Snapshots: $($snaps.Count) for VM $vmId" "Green"
            } catch { Log-Step "  Snapshot lookup failed: $_" "Yellow" }
        }
    }
}

Write-Host "" ; Write-Host "PHASE 4 - Drift Comparison" -ForegroundColor Magenta
$geMap = @{}
foreach ($pod in $allPods) {
    $pd = $podData[$pod.id]
    if (-not $pd) { continue }
    foreach ($pool in $pd.pools) {
        $geId = Coalesce $pool.global_desktop_entitlement_id ''
        if (-not $geId) { continue }
        if (-not $geMap.ContainsKey($geId)) { $geMap[$geId] = @{ name = (Coalesce $pd.gdeNames[$geId] $geId); rows = @() } }
        $ps       = $pool.provisioning_settings
        $vmId     = if ($ps) { Coalesce $ps.parent_vm_id '' }   else { '' }
        $snapId   = if ($ps) { Coalesce $ps.base_snapshot_id '' } else { '' }
        $vmName   = if ($vmId)   { Coalesce $pd.vmLookup[$vmId]   $vmId }   else { 'non-IC pool' }
        $snapName = if ($snapId) { Coalesce $pd.snapLookup[$snapId] $snapId } else { 'non-IC pool' }
        $geMap[$geId].rows += [PSCustomObject]@{
            Pod = $pod.name; Pool = (Coalesce $pool.display_name $pool.name $pool.id)
            VmName = $vmName; SnapName = $snapName; ImgDrift = $false; SnapDrift = $false
        }
    }
}
$report = @()
foreach ($geId in $geMap.Keys) {
    $ge    = $geMap[$geId]; $rows = $ge.rows
    $vrows = @($rows | Where-Object { $_.VmName -ne 'non-IC pool' })
    $dVm   = (@($vrows | Select-Object -ExpandProperty VmName   -Unique)).Count -gt 1
    $dSnap = (@($vrows | Select-Object -ExpandProperty SnapName -Unique)).Count -gt 1
    $hasDrift = $dVm -or $dSnap
    if ($hasDrift) {
        foreach ($row in $rows) {
            if ($row.VmName   -ne 'non-IC pool') { $row.ImgDrift  = $dVm }
            if ($row.SnapName -ne 'non-IC pool') { $row.SnapDrift = $dSnap }
        }
    }
    if ($hasDrift) { Log-Step "DRIFT: $($ge.name)" "Yellow" } else { Log-Step "Sync:  $($ge.name)" "Green" }
    $report += [PSCustomObject]@{ Id = $geId; Name = $ge.name; HasDrift = $hasDrift; Rows = $rows }
}

# ---- HTML Report ----
$totalGes   = $report.Count
$driftGes   = @($report | Where-Object { $_.HasDrift }).Count
$syncGes    = $totalGes - $driftGes
$totalPools = 0; foreach ($g in $report) { $totalPools += $g.Rows.Count }
$scanTime   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$css = @'
:root {
  --navy-900: #050c18;
  --navy-800: #08111f;
  --navy-700: #0c1928;
  --navy-600: #132236;
  --glass: rgba(12, 25, 40, 0.65);
  --glass-hi: rgba(20, 35, 58, 0.8);
  --border: rgba(255,255,255,0.06);
  --border-hi: rgba(255,255,255,0.12);
  --tx: #ddeeff;
  --tx2: #6b90b8;
  --tx3: #2d4a68;
  --green: #05e898;
  --green-bg: rgba(5,232,152,0.08);
  --green-bd: rgba(5,232,152,0.18);
  --amber: #f59e0b;
  --amber-bg: rgba(245,158,11,0.08);
  --amber-bd: rgba(245,158,11,0.2);
  --blue: #60a5fa;
  --blue-bg: rgba(96,165,250,0.08);
  --blue-bd: rgba(96,165,250,0.15);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body {
  background: var(--navy-900);
  color: var(--tx);
  font-family: Outfit, sans-serif;
  font-size: 13px;
  min-height: 100vh;
  background-image:
    radial-gradient(ellipse 90% 60% at 0% -5%, rgba(10,35,90,0.7) 0%, transparent 55%),
    radial-gradient(ellipse 50% 40% at 100% 105%, rgba(2,60,45,0.3) 0%, transparent 55%);
}

/* HEADER */
header {
  position: sticky; top: 0; z-index: 50;
  height: 56px;
  background: rgba(5,12,24,0.82);
  backdrop-filter: blur(28px);
  -webkit-backdrop-filter: blur(28px);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  padding: 0 32px; gap: 14px;
}
.logo {
  width: 28px; height: 28px; flex-shrink: 0;
  background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%);
  border-radius: 7px;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: 12px; color: #fff;
  box-shadow: 0 0 18px rgba(59,130,246,0.35), inset 0 1px 0 rgba(255,255,255,0.25);
}
.h-title { font-size: 13px; font-weight: 600; color: var(--tx); letter-spacing: 0.01em; }
.h-sub { font-size: 10px; color: var(--tx3); font-family: IBM Plex Mono, monospace; margin-top: 1px; }
.h-time { margin-left: auto; font-size: 10px; color: var(--tx3); font-family: IBM Plex Mono, monospace; display: flex; align-items: center; gap: 7px; }
.live-dot { width: 6px; height: 6px; background: var(--green); border-radius: 50%; box-shadow: 0 0 8px var(--green); animation: blink 2s ease-in-out infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

/* MAIN */
main { padding: 28px 32px; max-width: 1280px; margin: 0 auto; }

/* STATS */
.strip { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
.stat {
  border-radius: 14px;
  padding: 16px 20px;
  min-width: 128px;
  background: var(--glass);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  position: relative; overflow: hidden;
  transition: border-color .2s, transform .2s;
  animation: up .5s ease both;
}
.stat:hover { border-color: var(--border-hi); transform: translateY(-2px); }
.stat::after { content:""; position:absolute; top:0; left:16px; right:16px; height:1px; background: linear-gradient(90deg,transparent,rgba(255,255,255,0.1),transparent); }
.stat.blue::before { content:""; position:absolute;inset:0; background:radial-gradient(ellipse at top left,rgba(59,130,246,0.09),transparent 65%); }
.stat.green::before { content:""; position:absolute;inset:0; background:radial-gradient(ellipse at top left,rgba(5,232,152,0.09),transparent 65%); }
.stat.amber::before { content:""; position:absolute;inset:0; background:radial-gradient(ellipse at top left,rgba(245,158,11,0.09),transparent 65%); }
.stat.grey::before { content:""; position:absolute;inset:0; background:radial-gradient(ellipse at top left,rgba(107,144,184,0.06),transparent 65%); }
.stat-num {
  font-size: 30px; font-weight: 700; line-height: 1; margin-bottom: 5px;
  letter-spacing: -0.03em;
}
.stat.blue .stat-num  { color: var(--blue); }
.stat.green .stat-num { color: var(--green); }
.stat.amber .stat-num { color: var(--amber); }
.stat.grey .stat-num  { color: var(--tx2); }
.stat-label { font-size: 9px; color: var(--tx3); text-transform: uppercase; letter-spacing: 0.15em; font-weight: 500; }

/* SECTION LABEL */
.section-label {
  font-size: 9px; color: var(--tx3); text-transform: uppercase; letter-spacing: 0.2em;
  font-weight: 500; font-family: IBM Plex Mono, monospace;
  margin-bottom: 12px; padding-left: 2px;
  display: flex; align-items: center; gap: 8px;
}
.section-label::after { content:""; flex:1; height:1px; background: var(--border); }

/* GE CARD */
.ge {
  background: var(--glass);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 16px;
  margin-bottom: 14px;
  overflow: hidden;
  position: relative;
  transition: border-color .25s, box-shadow .25s;
  animation: up .45s ease both;
}
.ge:nth-child(2){animation-delay:.06s}.ge:nth-child(3){animation-delay:.12s}.ge:nth-child(4){animation-delay:.18s}
@keyframes up { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:translateY(0)} }
.ge::after { content:""; position:absolute; top:0; left:24px; right:24px; height:1px; background: linear-gradient(90deg,transparent,rgba(255,255,255,0.08),transparent); }
.ge:hover { border-color: var(--border-hi); box-shadow: 0 8px 32px rgba(0,0,0,0.25); }
.ge.drift { border-color: var(--amber-bd); }
.ge.drift::before { content:""; position:absolute; top:0;left:0;right:0; height:2px; background: linear-gradient(90deg,transparent 10%,var(--amber) 50%,transparent 90%); opacity:.7; }

.ge-head {
  display: flex; align-items: center; gap: 14px;
  padding: 15px 22px;
  cursor: pointer; user-select: none;
  transition: background .15s;
}
.ge-head:hover { background: rgba(255,255,255,0.018); }

.chev-btn {
  width: 20px; height: 20px; flex-shrink: 0;
  border: 1px solid var(--border-hi); border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
  color: var(--tx3); font-size: 7px;
  transition: all .2s;
}
.open .chev-btn { background: var(--blue-bg); border-color: var(--blue-bd); color: var(--blue); transform: rotate(90deg); }

.ge-name { font-size: 14px; font-weight: 600; color: var(--tx); flex: 1; }
.ge-meta { font-size: 10px; color: var(--tx3); font-family: IBM Plex Mono, monospace; }

.badge {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 12px; border-radius: 20px;
  font-size: 10px; font-weight: 400; letter-spacing: 0.05em;
  font-family: IBM Plex Mono, monospace;
}
.badge-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
.badge.ok { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-bd); }
.badge.ok .badge-dot { background: var(--green); box-shadow: 0 0 7px var(--green); animation: blink 2s infinite; }
.badge.warn { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-bd); }
.badge.warn .badge-dot { background: var(--amber); box-shadow: 0 0 7px var(--amber); }

/* TABLE */
.ge-divider { height: 1px; background: var(--border); }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
th {
  padding: 9px 22px; text-align: left;
  font-family: IBM Plex Mono, monospace;
  font-size: 9px; font-weight: 400;
  text-transform: uppercase; letter-spacing: 0.18em;
  color: var(--tx3);
  background: rgba(0,0,0,0.18);
  border-bottom: 1px solid var(--border);
}
td {
  padding: 13px 22px;
  border-bottom: 1px solid rgba(255,255,255,0.025);
  color: var(--tx2); vertical-align: middle;
  font-family: IBM Plex Mono, monospace; font-weight: 300;
  transition: background .12s;
}
td:first-child { font-family: Outfit, sans-serif; font-weight: 400; }
td:nth-child(2) { color: var(--tx); font-weight: 400; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.018); }
tr.drift-row td { background: rgba(245,158,11,0.03); }
tr.drift-row:hover td { background: rgba(245,158,11,0.06); }
td.drifted { color: var(--amber); }

.pod-tag {
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--blue-bg); color: var(--blue);
  border: 1px solid var(--blue-bd);
  border-radius: 6px; padding: 3px 9px;
  font-size: 10px; font-family: IBM Plex Mono, monospace; font-weight: 400;
}
.pod-tag-dot { width: 4px; height: 4px; background: var(--blue); border-radius: 50%; box-shadow: 0 0 5px var(--blue); }

.drift-tag {
  display: inline-flex; align-items: center; gap: 4px;
  background: var(--amber-bg); color: var(--amber);
  border: 1px solid var(--amber-bd); border-radius: 4px;
  padding: 1px 6px; font-size: 9px; margin-left: 8px;
  text-transform: uppercase; letter-spacing: 0.07em;
}
.status-ok {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--green); font-size: 10px; font-family: IBM Plex Mono, monospace;
}
.status-ok::before { content:""; width:5px;height:5px;background:var(--green);border-radius:50%;box-shadow:0 0 7px var(--green);animation:blink 2s infinite;flex-shrink:0; }
.status-warn {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--amber); font-size: 10px; font-family: IBM Plex Mono, monospace;
}
.status-warn::before { content:""; width:5px;height:5px;background:var(--amber);border-radius:50%;flex-shrink:0; }

'@

$geHtml = ''
foreach ($ge in $report) {
    $dClass = if ($ge.HasDrift) { 'drift' } else { '' }
    $bClass = if ($ge.HasDrift) { 'warn' } else { 'ok' }
    $bText  = if ($ge.HasDrift) { 'Drift Detected' } else { 'In Sync' }
    $rowHtml = ''
    foreach ($row in $ge.Rows) {
        $rd     = $row.ImgDrift -or $row.SnapDrift
        $rClass = if ($rd) { 'drift-row' } else { '' }
        $iClass = if ($row.ImgDrift)  { 'drifted' } else { '' }
        $sClass = if ($row.SnapDrift) { 'drifted' } else { '' }
        $iDTag  = if ($row.ImgDrift)  { '<span class="tag-d">drift</span>' } else { '' }
        $sDTag  = if ($row.SnapDrift) { '<span class="tag-d">drift</span>' } else { '' }
        $stTag  = if ($rd) { '<span class=''status-warn''>Out of Sync</span>' } else { '<span class=''status-ok''>Synchronized</span>' }
        $ePod   = [System.Web.HttpUtility]::HtmlEncode($row.Pod)
        $ePool  = [System.Web.HttpUtility]::HtmlEncode($row.Pool)
        $eVm    = [System.Web.HttpUtility]::HtmlEncode($row.VmName)
        $eSnap  = [System.Web.HttpUtility]::HtmlEncode($row.SnapName)
        $rowHtml += "<tr class='$rClass'><td><span class='pod-tag'><span class='pod-tag-dot'></span>$ePod</span></td><td>$ePool</td><td class='$iClass'>$eVm$iDTag</td><td class='$sClass'>$eSnap$sDTag</td><td>$stTag</td></tr>"
    }
    if (-not $rowHtml) { $rowHtml = '<tr><td colspan="5" class="empty-row">No pools found.</td></tr>' }
    $eName   = [System.Web.HttpUtility]::HtmlEncode($ge.Name)
    $geHtml += "<div class='ge $dClass'><div class='ge-head' onclick='tog(this)'><div class='chev-btn'>&#9654;</div><div class='ge-name'>$eName</div><div class='ge-meta'>$($ge.Rows.Count) pool(s) &middot; FEDERATION</div><span class='badge $bClass'><span class='badge-dot'></span>$bText</span></div><div class='ge-body'><div class='ge-divider'></div><div class='tbl-wrap'><table><thead><tr><th>Pod</th><th>Pool Name</th><th>Master Image</th><th>Snapshot</th><th>Status</th></tr></thead><tbody>$rowHtml</tbody></table></div></div></div>"
}

$fontLink = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@300;400;500&display=swap" rel="stylesheet">'
$html  = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>$fontLink<title>Horizon Drift $scanTime</title><style>$css</style></head><body>"
$html  = "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>$fontLink<title>Horizon Drift $scanTime</title><style>$css</style></head><body>"
$html += "<header><div class='logo'>H</div><div><div class='h-title'>Horizon CPA &mdash; Image Drift Report</div><div class='h-sub'>$ConnectionServer</div></div><div class='h-time'><div class='live-dot'></div>$scanTime</div></header>"
$html += "<main><div class='strip'>"
$html += "<div class='stat blue'><div class='stat-num'>$totalGes</div><div class='stat-label'>Entitlements</div></div>"
$html += "<div class='stat green'><div class='stat-num'>$syncGes</div><div class='stat-label'>In Sync</div></div>"
$html += "<div class='stat amber'><div class='stat-num'>$driftGes</div><div class='stat-label'>Drift Detected</div></div>"
$html += "<div class='stat grey'><div class='stat-num'>$totalPools</div><div class='stat-label'>Pools Scanned</div></div>"
$html += "</div><div class='section-label'>Global Entitlements</div>$geHtml</main>"
$html += "<script>function tog(el){var b=el.querySelector('.ge-body'),c=el.querySelector('.chev-btn');if(!b)return;if(b.style.display==='none'){b.style.display='';el.classList.add('open')}else{b.style.display='none';el.classList.remove('open')}}<\/script>"

$utf8bom = New-Object System.Text.UTF8Encoding $true
$absPath = [System.IO.Path]::GetFullPath($ReportPath)
[System.IO.File]::WriteAllText($absPath, $html, $utf8bom)
Write-Host "" ; Write-Host "Report saved: $absPath" -ForegroundColor Green
Start-Process $absPath
foreach ($fqdn in $tokens.Keys) { HvLogout -Fqdn $fqdn -Token $tokens[$fqdn] }
Write-Host "Done." -ForegroundColor Gray