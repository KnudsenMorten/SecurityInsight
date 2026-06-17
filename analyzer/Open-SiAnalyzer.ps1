#Requires -Version 5.1
<#
.SYNOPSIS
    Open the SecurityInsight Analyzer -- a standalone, PIM-Manager-style web app
    that explains the top SI risk findings (KQL facts + AI plain-language verdict)
    and reports risk-over-time for management.

.DESCRIPTION
    Self-contained PowerShell + HTML SPA server (same shape as Open-PimManager.ps1).
    Two surfaces:
      * Analyst   -- top-100 worklist (highest RiskScoreTotal, latest snapshot),
                     prestaged one-click analyses, an ad-hoc prompt box that
                     composes a READ-ONLY KQL (guardrailed) and an AI verdict.
      * Management -- risk score over time, new/closed/open since last snapshot,
                     AI executive summary + recommendations in plain language.

    Reuses the SI data plane (Invoke-AzOperationalInsightsQuery via the existing
    Connect-AzAccount session) and the SI Azure OpenAI config ($global:OpenAI_*).
    AI is OPTIONAL and fail-soft -- without OpenAI the app still serves KQL facts +
    a templated summary. Demo/seed data fallback when no workspace is reachable.

    Security model (server mode), mirroring Open-PimManager.ps1:
      * Listener binds 127.0.0.1 only.
      * A per-session bearer token (new GUID each start) is embedded in the HTML
        and required on every /api/* call (401 without it).
      * Self-terminates after 60s without a /api/heartbeat ping.
      * Read-only data plane; all KQL (prestaged AND ad-hoc) passes the read-only
        guardrail before any execution.

    NEVER auto-opens a browser (operator rule). Print the URL; the operator opens it.

.PARAMETER Port
    Force a specific port instead of a random free one. Binds 127.0.0.1 only.

.PARAMETER UseDemoData
    Force the demo/seed snapshot (offline). Otherwise the live workspace is tried
    first and demo data is the fallback when it's unreachable.

.PARAMETER NoServer
    Don't start the server. Render the SPA to a temp HTML file (or -OutHtml) for a
    headless render check, and exit. No token, no API.

.PARAMETER OutHtml
    With -NoServer, the path for the rendered HTML. Defaults to a temp file.

.PARAMETER SelfTest
    Run the offline core checks (guardrail + builders + diff over demo data) and
    exit non-zero on failure. No server. For CI / smoke.

.NOTES
    PowerShell 5.1 compatible. Chart drawn with inline canvas JS (no CDN needed for
    the POC). Never opens a browser.
#>
[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(ParameterSetName='Server')][int]$Port = 0,
    [switch]$UseDemoData,
    [Parameter(ParameterSetName='Render')][switch]$NoServer,
    [Parameter(ParameterSetName='Render')][string]$OutHtml,
    [Parameter(ParameterSetName='SelfTest')][switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Load the cores.
# ---------------------------------------------------------------------------
$libDir = Join-Path $PSScriptRoot 'lib'
. (Join-Path $libDir 'SiAnalyzer-Kql.ps1')
. (Join-Path $libDir 'SiAnalyzer-Diff.ps1')
. (Join-Path $libDir 'SiAnalyzer-Ai.ps1')
. (Join-Path $libDir 'SiAnalyzer-Data.ps1')

$htmlTemplate = Join-Path $PSScriptRoot 'si-analyzer.html'

# ---------------------------------------------------------------------------
# Helpers shared by API + render.
# ---------------------------------------------------------------------------
function Get-SiWorklistModel {
    param([switch]$Demo)
    $kql = Build-SiTopWorklistKql -Top 100 -Domain 'all'
    $res = Get-SiAnalyzerRows -Query $kql -UseDemoData:$Demo
    # Snapshot-correct: keep only the latest snapshot, sort by score, take 100.
    $latest = Get-SiLatestSnapshot -Rows @($res.Rows)
    $worklist = @($latest | Sort-Object { [double]$_.RiskScoreTotal } -Descending | Select-Object -First 100)
    return [pscustomobject]@{
        Worklist = $worklist
        FullSnapshot = @($latest)
        Source = $res.Source
        Warning = $res.Warning
        Kql = $kql
    }
}

function Get-SiManagementModel {
    param([switch]$Demo)
    # For the rollup we want ALL snapshots (timeline + diff), not just the latest.
    # The worklist query is latest-only; for management pull the full demo set or a
    # timeline query. In demo mode Get-SiDemoRows returns every snapshot.
    if ($Demo -or -not (Test-SiWorkspaceConfigured)) {
        $rows = @(Get-SiDemoRows)
        $source = 'demo'
        $warning = 'Using demo/seed data (offline mode).'
    } else {
        try {
            $rows = @(Invoke-SiAnalyzerQuery -Query (Build-SiScoreTimelineKql -LookbackDays 180))
            $source = 'workspace'
            $warning = $null
        } catch {
            $rows = @(Get-SiDemoRows)
            $source = 'demo'
            $warning = ("Live workspace unavailable -- using demo data. ({0})" -f $_.Exception.Message)
        }
    }
    $timeline = Get-SiScoreTimeline -Rows $rows
    $diff = Get-SiSnapshotDiff -Rows $rows
    return [pscustomobject]@{
        Timeline = $timeline
        Diff = $diff
        Rows = $rows
        Source = $source
        Warning = $warning
    }
}

function ConvertTo-SiJson {
    param($Object)
    return ($Object | ConvertTo-Json -Depth 12)
}

# ---------------------------------------------------------------------------
# SelfTest -- offline core checks. Exits non-zero on failure.
# ---------------------------------------------------------------------------
if ($SelfTest) {
    $fail = 0
    Write-Host "SI Analyzer self-test (offline cores)" -ForegroundColor Cyan

    $lib = Test-SiPrestagedLibrary
    if ($lib.Count -gt 0) { Write-Host "  FAIL: prestaged library has guardrail failures: $($lib | ConvertTo-Json -Compress)" -ForegroundColor Red; $fail++ }
    else { Write-Host "  OK: all prestaged queries pass the read-only guardrail" -ForegroundColor Green }

    $bad = Test-SiKqlReadOnly -Query '.drop table SI_Endpoint_Profile_CL'
    if ($bad.Allowed) { Write-Host "  FAIL: guardrail allowed a .drop control command" -ForegroundColor Red; $fail++ }
    else { Write-Host "  OK: guardrail rejected a destructive query" -ForegroundColor Green }

    $rows = @(Get-SiDemoRows)
    $diff = Get-SiSnapshotDiff -Rows $rows
    if ($diff.NewCount -lt 1) { Write-Host "  FAIL: diff found no new findings in demo data" -ForegroundColor Red; $fail++ }
    else { Write-Host "  OK: snapshot diff: $($diff.NewCount) new, $($diff.ClosedCount) closed, delta $($diff.ScoreDelta)" -ForegroundColor Green }

    $tl = Get-SiScoreTimeline -Rows $rows
    if ($tl.Count -lt 2) { Write-Host "  FAIL: timeline has < 2 points" -ForegroundColor Red; $fail++ }
    else { Write-Host "  OK: timeline has $($tl.Count) snapshots" -ForegroundColor Green }

    Write-Host ("AI available: {0}" -f (Test-SiAiAvailable)) -ForegroundColor DarkGray
    if ($fail -gt 0) { Write-Host "SELF-TEST FAILED ($fail)" -ForegroundColor Red; exit 1 }
    Write-Host "SELF-TEST PASSED" -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Render the SPA HTML (token injected for server mode; blank for static render).
# ---------------------------------------------------------------------------
function Get-SiRenderedHtml {
    param([string]$Token, [string]$BaseUrl)
    $html = Get-Content -LiteralPath $htmlTemplate -Raw -Encoding UTF8
    $html = $html.Replace('__SI_TOKEN__', $Token)
    $html = $html.Replace('__SI_BASEURL__', $BaseUrl)
    return $html
}

# ---------------------------------------------------------------------------
# -NoServer: render to file (headless render check) and exit. No browser.
# ---------------------------------------------------------------------------
if ($NoServer) {
    if ([string]::IsNullOrWhiteSpace($OutHtml)) {
        $OutHtml = Join-Path ([System.IO.Path]::GetTempPath()) ("si-analyzer-{0}.html" -f ([guid]::NewGuid().ToString('N')))
    }
    $html = Get-SiRenderedHtml -Token '' -BaseUrl ''
    Set-Content -LiteralPath $OutHtml -Value $html -Encoding UTF8
    Write-Host "Rendered SI Analyzer SPA to: $OutHtml (no server, no browser)" -ForegroundColor Green
    Write-Output $OutHtml
    return
}

# ---------------------------------------------------------------------------
# Server mode.
# ---------------------------------------------------------------------------
$token = [guid]::NewGuid().ToString('N')
if ($Port -lt 1) {
    # Pick a free port: bind a temp TcpListener on 0 and read the assigned port.
    $tmp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tmp.Start(); $Port = ([System.Net.IPEndPoint]$tmp.LocalEndpoint).Port; $tmp.Stop()
}
$prefix = "http://127.0.0.1:$Port/"
$baseUrl = "http://127.0.0.1:$Port"

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()

$script:LastBeat = Get-Date
$script:DemoMode = [bool]$UseDemoData

Write-Host ""
Write-Host "SecurityInsight Analyzer (POC) is running." -ForegroundColor Cyan
Write-Host "  URL : $baseUrl/  (localhost only)" -ForegroundColor Green
Write-Host "  Mode: $(if ($script:DemoMode) { 'demo data (forced)' } else { 'live workspace, demo fallback' })" -ForegroundColor DarkGray
Write-Host "  AI  : $(if (Test-SiAiAvailable) { 'enabled (SI Azure OpenAI)' } else { 'unavailable -- templated summaries (fail-soft)' })" -ForegroundColor DarkGray
Write-Host "  This window stays open; the server self-terminates ~60s after the tab closes." -ForegroundColor DarkGray
Write-Host "  (No browser was opened -- open the URL above yourself.)" -ForegroundColor DarkGray
Write-Host ""

function Write-SiJson {
    param($Response, $Object, [int]$Status = 200)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-SiJson $Object))
    try {
        $Response.StatusCode = $Status
        $Response.ContentType = 'application/json; charset=utf-8'
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        # Client closed the tab/connection before we finished writing -- OutputStream
        # throws. Nothing to recover; swallow (same pattern as Open-PimManager.ps1).
        Write-Verbose ("Write-SiJson: client connection dropped ({0})" -f $_.Exception.Message)
    }
}

function Write-SiHtml {
    param($Response, [string]$Html)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    try {
        $Response.StatusCode = 200
        $Response.ContentType = 'text/html; charset=utf-8'
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        Write-Verbose ("Write-SiHtml: client connection dropped ({0})" -f $_.Exception.Message)
    }
}

function Read-SiBody {
    param($Request)
    if (-not $Request.HasEntityBody) { return $null }
    $reader = [System.IO.StreamReader]::new($Request.InputStream, $Request.ContentEncoding)
    $raw = $reader.ReadToEnd(); $reader.Close()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

try {
    while ($listener.IsListening) {
        # Self-terminate if no heartbeat for 60s.
        if (((Get-Date) - $script:LastBeat).TotalSeconds -gt 60) {
            Write-Host "No heartbeat for 60s -- shutting down." -ForegroundColor DarkGray
            break
        }

        $ctxTask = $listener.GetContextAsync()
        if (-not $ctxTask.Wait(2000)) { continue }  # poll so the heartbeat check runs
        $ctx = $ctxTask.Result
        $req = $ctx.Request
        $res = $ctx.Response
        $path = $req.Url.AbsolutePath

        try {
            if ($path -eq '/' -or $path -eq '/index.html') {
                Write-SiHtml -Response $res -Html (Get-SiRenderedHtml -Token $token -BaseUrl $baseUrl)
                continue
            }

            # All /api/* require the bearer token.
            if ($path.StartsWith('/api/')) {
                $auth = $req.Headers['Authorization']
                if ($auth -ne "Bearer $token") {
                    Write-SiJson -Response $res -Object @{ error = 'unauthorized' } -Status 401
                    continue
                }
            }

            switch -Regex ($path) {
                '^/api/heartbeat$' {
                    $script:LastBeat = Get-Date
                    Write-SiJson -Response $res -Object @{ ok = $true }
                }
                '^/api/status$' {
                    Write-SiJson -Response $res -Object @{
                        aiAvailable = (Test-SiAiAvailable)
                        workspaceConfigured = (Test-SiWorkspaceConfigured)
                        demoMode = $script:DemoMode
                        allowedTables = (Get-SiAnalyzerAllowedTables)
                    }
                }
                '^/api/worklist$' {
                    $m = Get-SiWorklistModel -Demo:$script:DemoMode
                    Write-SiJson -Response $res -Object @{
                        worklist = $m.Worklist
                        count = @($m.Worklist).Count
                        snapshotCount = @($m.FullSnapshot).Count
                        source = $m.Source
                        warning = $m.Warning
                        kql = $m.Kql
                    }
                }
                '^/api/prestaged$' {
                    $list = @(Get-SiPrestagedAnalyses | Select-Object Id, Title, Plain, Domain)
                    Write-SiJson -Response $res -Object @{ analyses = $list }
                }
                '^/api/prestaged/run$' {
                    $body = Read-SiBody -Request $req
                    $id = ''
                    if ($body -and ($body.PSObject.Properties.Name -contains 'id') -and $body.id) { $id = [string]$body.id }
                    $analysis = @(Get-SiPrestagedAnalyses) | Where-Object { $_.Id -eq $id } | Select-Object -First 1
                    if (-not $analysis) { Write-SiJson -Response $res -Object @{ error = "unknown analysis '$id'" } -Status 400; continue }

                    $gate = Test-SiKqlReadOnly -Query $analysis.Kql
                    if (-not $gate.Allowed) { Write-SiJson -Response $res -Object @{ error = 'guardrail rejected the prestaged query'; reasons = $gate.Reasons } -Status 400; continue }

                    $r = Get-SiAnalyzerRows -Query $analysis.Kql -UseDemoData:$script:DemoMode
                    $rows = @($r.Rows)
                    # In demo mode the demo file has no per-analysis filtering, so present the
                    # latest snapshot rows as the evidence set for the POC.
                    if ($r.Source -eq 'demo') { $rows = @(Get-SiLatestSnapshot -Rows $rows) }

                    $prompt = Build-SiGroundedPrompt -Instruction $analysis.AiTemplate -Rows $rows -Audience 'analyst'
                    $ai = Invoke-SiAiChat -SystemPrompt 'You are a concise security advisor.' -UserPrompt $prompt
                    $verdict = if ($ai) { $ai } else { Get-SiTemplatedSummary -Rows $rows -Audience 'analyst' }

                    Write-SiJson -Response $res -Object @{
                        id = $id; title = $analysis.Title
                        rows = $rows; rowCount = @($rows).Count
                        verdict = $verdict; aiUsed = [bool]$ai
                        kql = $analysis.Kql; source = $r.Source; warning = $r.Warning
                    }
                }
                '^/api/verdict$' {
                    # Per-row analyst verdict for the worklist (grounded, AI-optional).
                    $body = Read-SiBody -Request $req
                    # NB: assign @() first then populate -- an `else { @() }` if-expression
                    # branch collapses an empty array to $null under PS 5.1 StrictMode.
                    $rows = @()
                    if ($body -and ($body.PSObject.Properties.Name -contains 'rows') -and $body.rows) { $rows = @($body.rows) }
                    if (@($rows).Count -eq 0) { Write-SiJson -Response $res -Object @{ error = 'no rows' } -Status 400; continue }
                    $prompt = Build-SiGroundedPrompt -Instruction 'Explain this finding: what it is, why it matters, what to do, how urgent.' -Rows $rows -Audience 'analyst' -MaxRows 5
                    $ai = Invoke-SiAiChat -SystemPrompt 'You are a concise security advisor.' -UserPrompt $prompt
                    $verdict = if ($ai) { $ai } else { Get-SiTemplatedSummary -Rows $rows -Audience 'analyst' }
                    Write-SiJson -Response $res -Object @{ verdict = $verdict; aiUsed = [bool]$ai }
                }
                '^/api/adhoc$' {
                    # Ad-hoc NL prompt -> AI composes a read-only KQL -> guardrail -> run -> AI explains.
                    $body = Read-SiBody -Request $req
                    # StrictMode: guard property access -- a missing prop on a PSCustomObject throws.
                    $question = ''
                    if ($body -and ($body.PSObject.Properties.Name -contains 'question') -and $body.question) { $question = [string]$body.question }
                    $editedKql = ''
                    if ($body -and ($body.PSObject.Properties.Name -contains 'kql') -and $body.kql) { $editedKql = [string]$body.kql }

                    if (-not [string]::IsNullOrWhiteSpace($editedKql)) {
                        $kql = $editedKql
                        $composed = $false
                    } else {
                        if ([string]::IsNullOrWhiteSpace($question)) { Write-SiJson -Response $res -Object @{ error = 'no question or kql' } -Status 400; continue }
                        $nlPrompt = Build-SiNlToKqlPrompt -Question $question -AllowedTables (Get-SiAnalyzerAllowedTables)
                        $kql = Invoke-SiAiChat -SystemPrompt 'You output only a single read-only KQL query.' -UserPrompt $nlPrompt
                        $composed = $true
                        if ([string]::IsNullOrWhiteSpace($kql)) {
                            # AI unavailable: fall back to the top-worklist query so the box still does something.
                            $kql = Build-SiTopWorklistKql -Top 25 -Domain 'all'
                            $composed = $false
                        }
                        # Strip any markdown fences the model might add.
                        $kql = ($kql -replace '(?s)```[a-zA-Z]*','' -replace '```','').Trim()
                    }

                    $gate = Test-SiKqlReadOnly -Query $kql
                    if (-not $gate.Allowed) {
                        Write-SiJson -Response $res -Object @{ error = 'guardrail rejected the generated query'; reasons = $gate.Reasons; kql = $kql } -Status 400
                        continue
                    }

                    $r = Get-SiAnalyzerRows -Query $kql -UseDemoData:$script:DemoMode
                    $rows = @($r.Rows)
                    if ($r.Source -eq 'demo') { $rows = @(Get-SiLatestSnapshot -Rows $rows) }

                    $explainPrompt = Build-SiGroundedPrompt -Instruction "Explain the result of this analysis in plain language. Question asked: $question" -Rows $rows -Audience 'analyst'
                    $ai = Invoke-SiAiChat -SystemPrompt 'You are a concise security advisor.' -UserPrompt $explainPrompt
                    $explanation = if ($ai) { $ai } else { Get-SiTemplatedSummary -Rows $rows -Audience 'analyst' }

                    Write-SiJson -Response $res -Object @{
                        kql = $kql; composedByAi = $composed
                        rows = $rows; rowCount = @($rows).Count
                        explanation = $explanation; aiUsed = [bool]$ai
                        tables = $gate.Tables; source = $r.Source; warning = $r.Warning
                    }
                }
                '^/api/management$' {
                    $m = Get-SiManagementModel -Demo:$script:DemoMode
                    $latest = Get-SiLatestSnapshot -Rows @($m.Rows)
                    $prompt = Build-SiGroundedPrompt -Instruction (
                        "Write a board-ready executive summary of the current security posture and trend, then the top 5 fixes for the biggest risk reduction, each with the affected asset count. " +
                        "New since last snapshot: $($m.Diff.NewCount). Closed: $($m.Diff.ClosedCount). Score delta: $($m.Diff.ScoreDelta)."
                    ) -Rows @($latest) -Audience 'management'
                    $ai = Invoke-SiAiChat -SystemPrompt 'You are an executive security advisor writing for non-technical leaders.' -UserPrompt $prompt
                    $summary = if ($ai) { $ai } else { Get-SiTemplatedSummary -Rows @($latest) -Audience 'management' -Diff $m.Diff }

                    Write-SiJson -Response $res -Object @{
                        timeline = $m.Timeline
                        diff = @{
                            newCount = $m.Diff.NewCount; closedCount = $m.Diff.ClosedCount
                            openCount = $m.Diff.OpenCount; regressedCount = $m.Diff.RegressedCount
                            improvedCount = $m.Diff.ImprovedCount
                            scoreDelta = $m.Diff.ScoreDelta; currentTotal = $m.Diff.CurrentTotal; previousTotal = $m.Diff.PreviousTotal
                            new = $m.Diff.New; closed = $m.Diff.Closed
                        }
                        summary = $summary; aiUsed = [bool]$ai
                        source = $m.Source; warning = $m.Warning
                    }
                }
                default {
                    Write-SiJson -Response $res -Object @{ error = 'not found' } -Status 404
                }
            }
        } catch {
            Write-SiJson -Response $res -Object @{ error = $_.Exception.Message } -Status 500
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
    Write-Host "SI Analyzer stopped." -ForegroundColor DarkGray
}
