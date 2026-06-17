#Requires -Version 5.1
<#
.SYNOPSIS
    Live in-process smoke test for the SI Analyzer HTTP server (demo data).
.DESCRIPTION
    Starts Open-SiAnalyzer.ps1 in a background PowerShell process (demo data),
    reads the per-session token from the served HTML, then exercises every API
    endpoint and asserts both surfaces return data:
      /api/status, /api/worklist, /api/prestaged, /api/prestaged/run,
      /api/verdict, /api/adhoc, /api/management, and a 401 without the token.
    NEVER opens a browser. Tears the server down at the end. Exit non-zero on fail.
.NOTES
    Uses a free random port. Heartbeats are sent so the 60s self-terminate
    doesn't fire mid-test.
#>
param([int]$Port = 0)

$ErrorActionPreference = 'Stop'
$fail = 0
function Ok($m){ Write-Host "  OK: $m" -ForegroundColor Green }
function Bad($m){ Write-Host "  FAIL: $m" -ForegroundColor Red; $script:fail++ }

Write-Host "SI Analyzer live server smoke (demo data)" -ForegroundColor Cyan

if ($Port -lt 1) {
    $tmp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tmp.Start(); $Port = ([System.Net.IPEndPoint]$tmp.LocalEndpoint).Port; $tmp.Stop()
}
$base = "http://127.0.0.1:$Port"
$analyzer = Join-Path (Split-Path -Parent $PSScriptRoot) 'analyzer\Open-SiAnalyzer.ps1'
if (-not (Test-Path $analyzer)) { $analyzer = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\analyzer\Open-SiAnalyzer.ps1' }

$proc = Start-Process -FilePath powershell.exe -PassThru -WindowStyle Hidden `
    -ArgumentList @('-NoProfile','-File',$analyzer,'-UseDemoData','-Port',"$Port")

try {
    # Wait for the listener to accept.
    $up = $false
    for ($i=0; $i -lt 30; $i++) {
        try { $null = Invoke-WebRequest -Uri "$base/" -UseBasicParsing -TimeoutSec 2; $up = $true; break } catch { Start-Sleep -Milliseconds 400 }
    }
    if (-not $up) { Bad "server did not come up on $base"; throw "server down" }
    Ok "server is up on $base"

    $html = (Invoke-WebRequest -Uri "$base/" -UseBasicParsing).Content
    $token = ([regex]::Match($html, 'var TOKEN = "([0-9a-f]+)"')).Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($token)) { Bad "could not read session token from HTML"; throw "no token" }
    Ok "served HTML carries a session token"
    $h = @{ Authorization = "Bearer $token" }

    # 401 without token.
    try { $null = Invoke-RestMethod -Uri "$base/api/status"; Bad "/api/status allowed without token" }
    catch { if ($_.Exception.Response.StatusCode.value__ -eq 401) { Ok "/api/* rejects requests without the token (401)" } else { Bad "expected 401, got $($_.Exception.Message)" } }

    Invoke-RestMethod -Uri "$base/api/heartbeat" -Headers $h | Out-Null

    $status = Invoke-RestMethod -Uri "$base/api/status" -Headers $h
    if ($status.allowedTables.Count -ge 8 -and $status.demoMode) { Ok "status: demoMode=$($status.demoMode), aiAvailable=$($status.aiAvailable), $($status.allowedTables.Count) allowed tables" }
    else { Bad "status payload unexpected" }

    $wl = Invoke-RestMethod -Uri "$base/api/worklist" -Headers $h
    if ($wl.count -ge 1 -and $wl.worklist[0].RiskScoreTotal) { Ok "worklist: $($wl.count) rows, top='$($wl.worklist[0].ConfigurationName)' score=$($wl.worklist[0].RiskScoreTotal) (source=$($wl.source))" }
    else { Bad "worklist returned no rows" }
    # snapshot-correct: top should be the latest-snapshot highest score.
    if ([double]$wl.worklist[0].RiskScoreTotal -ge [double]$wl.worklist[-1].RiskScoreTotal) { Ok "worklist sorted highest-risk first" } else { Bad "worklist not sorted by score" }

    $ps = Invoke-RestMethod -Uri "$base/api/prestaged" -Headers $h
    if ($ps.analyses.Count -ge 3) { Ok "prestaged: $($ps.analyses.Count) analyses" } else { Bad "fewer than 3 prestaged analyses" }

    $run = Invoke-RestMethod -Uri "$base/api/prestaged/run" -Headers $h -Method Post -ContentType 'application/json' -Body (@{ id = $ps.analyses[0].Id } | ConvertTo-Json)
    if ($run.verdict -and $run.kql) { Ok "prestaged/run: verdict produced (aiUsed=$($run.aiUsed)), rows=$($run.rowCount)" } else { Bad "prestaged/run produced no verdict" }

    $vd = Invoke-RestMethod -Uri "$base/api/verdict" -Headers $h -Method Post -ContentType 'application/json' -Body (@{ rows = @($wl.worklist[0]) } | ConvertTo-Json -Depth 6)
    if ($vd.verdict) { Ok "verdict: per-row verdict produced (aiUsed=$($vd.aiUsed))" } else { Bad "verdict produced nothing" }

    # Ad-hoc with no AI -> falls back to a guardrailed top-worklist query and explains.
    $ad = Invoke-RestMethod -Uri "$base/api/adhoc" -Headers $h -Method Post -ContentType 'application/json' -Body (@{ question = 'show the riskiest assets' } | ConvertTo-Json)
    if ($ad.kql -and $ad.explanation) { Ok "adhoc: composed/ran a guardrailed query, explanation produced (aiUsed=$($ad.aiUsed))" } else { Bad "adhoc produced nothing" }

    # Ad-hoc guardrail: an edited destructive query must be rejected with 400.
    try {
        $null = Invoke-RestMethod -Uri "$base/api/adhoc" -Headers $h -Method Post -ContentType 'application/json' -Body (@{ kql = '.drop table SI_Endpoint_Profile_CL' } | ConvertTo-Json)
        Bad "adhoc allowed a destructive .drop query"
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 400) { Ok "adhoc guardrail rejects a destructive edited query (400)" } else { Bad "expected 400 for destructive query" }
    }

    $mg = Invoke-RestMethod -Uri "$base/api/management" -Headers $h
    if ($mg.timeline.Count -ge 2 -and $mg.summary) { Ok "management: timeline $($mg.timeline.Count) pts, new=$($mg.diff.newCount) closed=$($mg.diff.closedCount) scoreDelta=$($mg.diff.scoreDelta), summary produced (aiUsed=$($mg.aiUsed))" }
    else { Bad "management payload incomplete" }

} catch {
    Bad "exception: $($_.Exception.Message)"
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

if ($fail -gt 0) { Write-Host "SERVER SMOKE FAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "SERVER SMOKE PASSED" -ForegroundColor Green
exit 0
