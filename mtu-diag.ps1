<#
.SYNOPSIS
  MTU / PMTU black-hole diagnostic. Run on the problem network.

.USAGE
  Right-click PowerShell -> Run as administrator (optional, enables firewall/WFP check), then:
    powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\mtu-diag.ps1"
  Optional packet capture during the TCP tests (needs Wireshark/tshark installed):
    powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\mtu-diag.ps1" -Capture

  Writes a report (and optional .pcapng) to the Desktop. Changes no settings.
#>
param(
    [switch]$Capture,
    [string[]]$Targets = @('1.1.1.1', '8.8.8.8', '9.9.9.9', '151.101.1.91', '160.79.104.10')
)

$ErrorActionPreference = 'Continue'
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$desktop = [Environment]::GetFolderPath('Desktop')
$report  = Join-Path $desktop "mtu-diag-$stamp.txt"
$pcap    = Join-Path $desktop "mtu-diag-$stamp.pcapng"
Start-Transcript -Path $report | Out-Null

function Section($t) { Write-Host ''; Write-Host ('=' * 70); Write-Host "  $t"; Write-Host ('=' * 70) }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
Section 'Network identity'
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
if (-not $route) { Write-Host 'No default route - not connected?'; Stop-Transcript | Out-Null; exit 1 }
$ifIndex = $route.InterfaceIndex
$adapter = Get-NetAdapter -InterfaceIndex $ifIndex
$ipIf    = Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4
$ifMtu   = [int]$ipIf.NlMtu
$maxPayload = $ifMtu - 28   # IPv4 (20) + ICMP (8)

Write-Host "Time            : $(Get-Date)"
Write-Host "Admin           : $isAdmin"
Write-Host "Adapter         : $($adapter.Name)  ($($adapter.InterfaceDescription))"
Write-Host "Link speed      : $($adapter.LinkSpeed)"
Write-Host "IPv4 address    : $((Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).IPAddress -join ', ')"
Write-Host "Gateway         : $($route.NextHop)"
Write-Host "DNS             : $((Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).ServerAddresses -join ', ')"
Write-Host "Interface MTU   : $ifMtu   (max DF ping payload = $maxPayload)"
Write-Host "DHCP            : $($ipIf.Dhcp)"
$wlan = netsh wlan show interfaces 2>$null | Select-String '^\s*(SSID|BSSID|Radio type|Channel|Signal|Receive rate|Transmit rate)\s*:'
if ($wlan) { $wlan | ForEach-Object { Write-Host ('Wi-Fi ' + $_.Line.Trim()) } }
try { $pub = (curl.exe -s --max-time 8 https://api.ipify.org); Write-Host "Public IP       : $pub" } catch {}
try { $isp = (curl.exe -s --max-time 8 https://ipinfo.io/org); Write-Host "ISP / ASN       : $isp" } catch {}

# ---------------------------------------------------------------------------
# DF ping helpers (locale-independent, uses .NET instead of parsing ping.exe)
$pinger = New-Object System.Net.NetworkInformation.Ping
$dfOpts = New-Object System.Net.NetworkInformation.PingOptions(128, $true)

function Test-DfSize([string]$hostName, [int]$payload, [int]$tries = 3) {
    # Returns Success / PacketTooBig / TimedOut / other status. Success if any try succeeds.
    $last = 'TimedOut'
    for ($i = 0; $i -lt $tries; $i++) {
        try {
            $r = $pinger.Send($hostName, 1500, (New-Object byte[] $payload), $dfOpts)
            if ($r.Status -eq 'Success') { return 'Success' }
            $last = [string]$r.Status
        } catch { $last = 'Error' }
    }
    return $last
}

function Get-Loss([string]$hostName, [int]$payload, [int]$count = 20) {
    $lost = 0; $rtts = @()
    for ($i = 0; $i -lt $count; $i++) {
        try {
            $r = $pinger.Send($hostName, 1500, (New-Object byte[] $payload), $dfOpts)
            if ($r.Status -eq 'Success') { $rtts += $r.RoundtripTime } else { $lost++ }
        } catch { $lost++ }
        Start-Sleep -Milliseconds 100
    }
    $avg = if ($rtts.Count) { [math]::Round(($rtts | Measure-Object -Average).Average) } else { '-' }
    [pscustomobject]@{ Payload = $payload; IPSize = $payload + 28; Sent = $count; Lost = $lost; LossPct = [math]::Round(100 * $lost / $count); AvgRttMs = $avg }
}

# ---------------------------------------------------------------------------
Section 'Gateway reachability'
Get-Loss $route.NextHop 56 10 | Format-Table -AutoSize | Out-String | Write-Host

# ---------------------------------------------------------------------------
Section "Path MTU search (DF set, binary search 548..$maxPayload payload)"
Write-Host 'TooBig = an ICMP "fragmentation needed" came back (PMTUD works).'
Write-Host 'Timeout at large sizes but OK at small sizes = BLACK HOLE.'
$pmtu = @()
foreach ($t in $Targets) {
    $small = Test-DfSize $t 64
    if ($small -ne 'Success') { $pmtu += [pscustomobject]@{ Target = $t; Reachable = $false; MaxPayload = '-'; PathMTU = '-'; FullSize = '-'; Notes = "small ping: $small" }; continue }
    $full = Test-DfSize $t $maxPayload
    $sawTooBig = $false
    if ($full -eq 'Success') { $best = $maxPayload }
    else {
        $lo = 548; $hi = $maxPayload - 1; $best = 0
        if ((Test-DfSize $t $lo) -ne 'Success') { $lo = 0 }
        while ($lo -le $hi) {
            $mid = [int][math]::Floor(($lo + $hi) / 2)
            $s = Test-DfSize $t $mid
            if ($s -eq 'Success') { $best = $mid; $lo = $mid + 1 } else { if ($s -eq 'PacketTooBig') { $sawTooBig = $true }; $hi = $mid - 1 }
        }
        if ($full -eq 'PacketTooBig') { $sawTooBig = $true }
    }
    $note = if ($full -eq 'Success') { 'full interface MTU passes' } elseif ($sawTooBig) { 'limit signalled via ICMP (OK)' } else { 'SILENT DROP above limit (black hole)' }
    $pmtu += [pscustomobject]@{ Target = $t; Reachable = $true; MaxPayload = $best; PathMTU = $best + 28; FullSize = $full; Notes = $note }
}
$pmtu | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

# ---------------------------------------------------------------------------
Section 'Locate the dropping hop (TTL-limited DF pings: 64 B vs 1028 B)'
Write-Host 'Each hop answers "TtlExpired" if the packet reached it. Where small still'
Write-Host 'reaches but big stops, the drop is on the link just before that hop.'
function Probe-Hop([string]$hostName, [int]$payload, [int]$ttl) {
    $o = New-Object System.Net.NetworkInformation.PingOptions($ttl, $true)
    $last = 'TimedOut'
    for ($i = 0; $i -lt 3; $i++) {
        try {
            $r = $pinger.Send($hostName, 1500, (New-Object byte[] $payload), $o)
            if ($r.Status -eq 'Success' -or $r.Status -eq 'TtlExpired') { return "$($r.Status) $($r.Address)" }
            $last = [string]$r.Status
        } catch { $last = 'Error' }
    }
    return $last
}
$hopTargets = @($pmtu | Where-Object { $_.Reachable -and $_.Notes -like 'SILENT*' } | ForEach-Object Target)
$cleanRef   = ($pmtu | Where-Object { $_.Reachable -and $_.FullSize -eq 'Success' } | Select-Object -First 1).Target
if ($cleanRef) { $hopTargets += $cleanRef }
foreach ($t in $hopTargets) {
    Write-Host ''
    Write-Host "-- $t"
    for ($ttl = 1; $ttl -le 15; $ttl++) {
        $s = Probe-Hop $t 64 $ttl
        $b = Probe-Hop $t 1000 $ttl
        $flag = if ($s -ne 'TimedOut' -and $b -eq 'TimedOut') { '   <-- big packet lost here' } else { '' }
        Write-Host ("{0,2}  small: {1,-32} big: {2}{3}" -f $ttl, $s, $b, $flag)
        if ($s -like 'Success*') { break }
    }
}

# ---------------------------------------------------------------------------
Section 'Loss by packet size (20 DF pings each, first reachable target)'
$lossTarget = ($pmtu | Where-Object Reachable | Select-Object -First 1).Target
if ($lossTarget) {
    Write-Host "Target: $lossTarget"
    $sizes = @(36, 500, 1000, 1200, 1300, $maxPayload) | Where-Object { $_ -le $maxPayload } | Sort-Object -Unique
    $sizes | ForEach-Object { Get-Loss $lossTarget $_ 20 } | Format-Table -AutoSize | Out-String | Write-Host
}

# ---------------------------------------------------------------------------
Section 'TCP tests (uploads are what failed in pcap3)'
$tsharkProc = $null
if ($Capture) {
    $tshark = 'C:\Program Files\Wireshark\tshark.exe'
    if (Test-Path $tshark) {
        $dev = '\Device\NPF_' + $adapter.InterfaceGuid
        Write-Host "Capturing on $dev -> $pcap"
        $tsharkProc = Start-Process -FilePath $tshark -ArgumentList @('-i', $dev, '-f', 'tcp or icmp', '-w', $pcap) -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 3
    } else { Write-Host 'tshark not found - skipping capture.' }
}

$fmt = '%{http_code} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s up=%{size_upload}B down=%{size_download}B'
$https = @('https://www.google.com', 'https://www.cloudflare.com', 'https://www.fastly.com', 'https://www.microsoft.com', 'https://claude.ai')
Write-Host '-- HTTPS handshake + GET (timeout 15s each)'
foreach ($u in $https) {
    $o = curl.exe -s -o NUL --max-time 15 -w $fmt $u 2>&1
    Write-Host ("{0,-28} exit={1} {2}" -f $u, $LASTEXITCODE, $o)
}

Write-Host ''
Write-Host '-- Same, but with a 3 KB request header so the request needs full-size TCP segments.'
Write-Host '   (Browsers send big TLS ClientHellos and requests; plain curl does not.)'
Write-Host '   exit=28 here but exit=0 above = black hole for large packets to that site.'
$pad = 'x' * 3000
$bigUrls = $https + @('https://api.anthropic.com/', 'https://www.reddit.com')
foreach ($u in $bigUrls) {
    $o = curl.exe -s -o NUL --max-time 15 -H "X-Pad: $pad" -w $fmt $u 2>&1
    Write-Host ("{0,-28} exit={1} {2}" -f $u, $LASTEXITCODE, $o)
}

$upFile = Join-Path $env:TEMP "mtu-diag-upload-$stamp.bin"
[IO.File]::WriteAllBytes($upFile, (New-Object byte[] (512 * 1024)))
Write-Host ''
Write-Host '-- Upload 512 KB to speed.cloudflare.com (timeout 30s). Fails/stalls on a black hole.'
for ($i = 1; $i -le 3; $i++) {
    $o = curl.exe -s -o NUL --max-time 30 -w $fmt -X POST --data-binary "@$upFile" 'https://speed.cloudflare.com/__up' 2>&1
    Write-Host ("  try {0}: exit={1} {2}" -f $i, $LASTEXITCODE, $o)
}
Write-Host '-- Download 5 MB from speed.cloudflare.com (timeout 30s)'
$o = curl.exe -s -o NUL --max-time 30 -w $fmt 'https://speed.cloudflare.com/__down?bytes=5000000' 2>&1
Write-Host ("  exit={0} {1}" -f $LASTEXITCODE, $o)
Remove-Item $upFile -ErrorAction SilentlyContinue
Write-Host '(curl exit 28 = timed out, 35 = TLS handshake failed, 56 = connection reset)'

if ($tsharkProc) { Start-Sleep -Seconds 2; Stop-Process -Id $tsharkProc.Id -ErrorAction SilentlyContinue; Write-Host "Capture saved: $pcap" }

# ---------------------------------------------------------------------------
Section 'Traceroute to 1.1.1.1 (no DNS, 15 hops)'
tracert -d -h 15 -w 1000 1.1.1.1 | Write-Host

# ---------------------------------------------------------------------------
Section 'TCP/IP settings'
netsh interface ipv4 show subinterfaces | Write-Host
netsh int tcp show global | Write-Host
$tp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue
Write-Host "EnablePMTUDiscovery=$($tp.EnablePMTUDiscovery)  EnablePMTUBHDetect=$($tp.EnablePMTUBHDetect)  (blank = Windows default)"

# ---------------------------------------------------------------------------
Section 'VPN leftovers (Proton / WireGuard / TAP)'
Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -match 'Proton|WireGuard|Wintun|TAP|OpenVPN' } | Format-Table Name, InterfaceDescription, Status, MtuSize -AutoSize | Out-String | Write-Host
Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match 'proton|wireguard|wintun|tap0901|ovpn' } | Format-Table Name, State, StartMode, PathName -AutoSize | Out-String -Width 200 | Write-Host
Get-Service | Where-Object { $_.Name -match 'proton|wireguard' -or $_.DisplayName -match 'proton|wireguard' } | Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Host
if ($isAdmin) {
    $wfp = Join-Path $env:TEMP "mtu-diag-wfp-$stamp.xml"
    Push-Location $env:TEMP; netsh wfp show filters file="$wfp" | Out-Null; Pop-Location
    if (Test-Path $wfp) {
        $hits = (Select-String -Path $wfp -Pattern 'proton|wireguard|wintun' -AllMatches).Matches.Count
        Write-Host "WFP filter text mentioning Proton/WireGuard/Wintun: $hits"
        Remove-Item $wfp -ErrorAction SilentlyContinue
    }
} else { Write-Host 'WFP filter check skipped (run as administrator to include it).' }

# ---------------------------------------------------------------------------
Section 'VERDICT'
$reach = $pmtu | Where-Object Reachable
if (-not $reach) { Write-Host 'No targets reachable by ping - ICMP may be blocked; rely on the TCP tests above.' }
else {
    $minMtu = ($reach | Measure-Object PathMTU -Minimum).Minimum
    $holes  = $reach | Where-Object { $_.Notes -like 'SILENT*' }
    $clean  = $reach | Where-Object { $_.FullSize -eq 'Success' }
    if ($holes -and $clean) {
        Write-Host "DESTINATION-SPECIFIC black hole."
        Write-Host "  Full $ifMtu passes to: $($clean.Target -join ', ')"
        foreach ($h in $holes) { Write-Host "  Silent drop above IP size $($h.PathMTU) to: $($h.Target)" }
        Write-Host ''
        Write-Host 'Your local link carries full-size packets, so lowering the PC MTU is only a'
        Write-Host 'workaround (and may need to be very low). Use the hop table above to see where'
        Write-Host 'big packets die: hop 1 = your router, hop 2+ = the ISP. Note that some servers'
        Write-Host 'rate-limit large pings, so trust the padded-header curl results over pings.'
    } elseif ($minMtu -ge $ifMtu) {
        Write-Host "Path passes the full interface MTU ($ifMtu) to all targets. No MTU limit seen at this size."
        if ($ifMtu -lt 1500) { Write-Host 'Note: interface is set below 1500, so sizes above it were not tested.' }
    } else {
        Write-Host "Smallest path MTU found: $minMtu  (interface is $ifMtu)"
        if ($holes) { Write-Host "BLACK HOLE: oversized packets were dropped silently to: $($holes.Target -join ', ')" }
        $rec = [math]::Min($minMtu, 1500)
        Write-Host ''
        Write-Host "Suggested workaround (admin prompt):"
        Write-Host "  netsh interface ipv4 set subinterface `"$($adapter.Name)`" mtu=$rec store=persistent"
        Write-Host 'Real fix: enable TCP MSS clamping on the router, and/or allow ICMP type 3 code 4 through.'
    }
}
Write-Host ''
Write-Host "Report saved: $report"
Stop-Transcript | Out-Null
