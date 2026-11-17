#Requires -Version 7.0
<#
    Renders the customer-facing texts of the data-quality notice, the "data is from an older read" note and the
    asset-drop hold from the REAL functions, with realistic numbers, as Markdown -- BEFORE (the code at -Base) and AFTER
    (this tree). Azure test runner only (never on the development machine):
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/plain-mails/Render-PlainMailPreview.ps1 -Base <sha> -Out plain-mails-preview.md
    -One <SI root>: render one tree to stdout (the script runs itself once per tree, in its own process, so the two
    versions of the same functions never meet).
#>
param([string]$Base = '', [string]$Out = 'plain-mails-preview.md', [string]$One = '', [string]$Label = '')
$ErrorActionPreference = 'Stop'

if ($One) {
    $root = $One
    . (Join-Path $root 'engine/data-model/SI-Conditions.ps1')
    . (Join-Path $root 'engine/data-model/SI-RecordCapture.ps1')
    . (Join-Path $root 'engine/data-model/SI-RecordSql.ps1')
    . (Join-Path $root 'engine/_shared/SI-SourceState.ps1')
    . (Join-Path $root 'engine/_shared/SI-Guard.ps1')
    . (Join-Path $root 'engine/pro-data/_shared/SI-DataQuality.ps1')
    $env1 = '[PROD] {0} - '
    $sb = New-Object System.Text.StringBuilder
    $add = { param($s) [void]$sb.AppendLine([string]$s) }
    $mail = {
        param($title, $install, $set)
        $m = ConvertTo-SIDataQualityMail -Anomalies $set -CollectionTime ([datetime]'2026-11-16T02:00:00Z') -WebBaseUrl 'https://si.example.test' -RunId 'run-1'
        & $add ("#### {0}" -f $title)
        & $add ''
        & $add ('**Subject:** `' + ($env1 -f $install) + $m.Subject + ' [SecurityInsight]`')
        & $add ''
        & $add '**First lines (as the mail text reads):**'
        & $add ''
        & $add '```text'
        $lines = @($m.Text -split "`r?`n")
        $cut = 0; for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^(?i)(why this|the numbers|since the last)') { $cut = $i; break } }
        if (-not $cut) { $cut = [math]::Min(18, $lines.Count) }
        foreach ($l in @($lines | Select-Object -First $cut)) { & $add $l }
        & $add '```'
        & $add ''
        $heads = @([regex]::Matches($m.Html, '<h[1-3][^>]*>(.*?)</h[1-3]>') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) })
        & $add ('**Section headings:** ' + (($heads | ForEach-Object { '"' + $_ + '"' }) -join ' / '))
        & $add ''
        $tail = @($lines | Select-Object -Skip $cut | Where-Object { $_.Trim() })
        & $add '**Rest of the mail (the reasons, what you can do, the numbers):**'
        & $add ''
        & $add '```text'
        foreach ($l in @($tail | Select-Object -First 40)) { & $add $l }
        & $add '```'
        & $add ''
    }
    & $add ("### {0}" -f $Label)
    & $add ''
    & $add '#### 1. The daily data-quality mail'
    & $add ''
    $none = Get-SIDataQualityCause -Anomaly ([pscustomobject]@{ Key = 'class.workstation'; Label = 'x'; Fields = @() }) -Changes @() -Since 'the previous run'
    $contoso = @(
        [pscustomobject]@{ Key = 'class.workstation'; Kind = 'class'; Label = 'Active CIs of type workstation'; Step = 'asset-correlation'; Rule = 'class-shift'; Direction = 'rise'; Earlier = @(1010.0, 1000.0, 990.0); Expected = 1000.0; Now = 1400.0; ChangePct = 40.0; Cause = $none; CauseChangeIds = @(); Fields = @() },
        [pscustomobject]@{ Key = 'tier.2'; Kind = 'tier'; Label = 'Active CIs in tier 2'; Step = 'ptc'; Rule = 'tier-shift'; Direction = 'rise'; Earlier = @(610.0, 600.0, 590.0); Expected = 600.0; Now = 850.0; ChangePct = 25.0; Cause = $none; CauseChangeIds = @(); Fields = @() },
        [pscustomobject]@{ Key = 'ci.to_retire'; Kind = 'retire'; Label = 'CIs not seen any more (to retire)'; Step = 'asset-correlation'; Rule = 'retire-rise'; Direction = 'rise'; Earlier = @(20.0, 25.0, 30.0); Expected = 25.0; Now = 235.0; ChangePct = 21.0; Cause = $none; CauseChangeIds = @(); Fields = @() }
    )
    & $mail 'contoso-like: 3 numbers higher than usual, the biggest +40 %' 'contoso-prod' $contoso
    $exampleADq = @([pscustomobject]@{ Key = 'assets.endpoint'; Kind = 'assets'; Label = 'Assets from Defender for Endpoint (endpoint profiler)'; Step = 'endpoint'; Rule = 'asset-drop'; Direction = 'drop'; Earlier = @(995.0, 990.0, 985.0); Expected = 990.0; Now = 697.0; ChangePct = -29.6; Cause = $none; CauseChangeIds = @(); Fields = @() })
    & $mail 'example A: devices 990 -> 697' 'contoso-prod' $exampleADq

    & $add '#### 2. A data source is behind (example B: Defender data 2 days old)'
    & $add ''
    $now = [datetime]::SpecifyKind([datetime]'2026-11-16T12:00:00', 'Utc')
    $good = $now.AddDays(-2.2)
    & $add '**The note every SecurityInsight mail carries while a data source is on its last good read (and the banner on every web page):**'
    & $add ''
    & $add ('> ' + (Get-SISourceNoteText -Source 'endpoint' -LastGoodUtc $good))
    & $add ''
    & $add '**The line in the run report (Operations > Jobs):**'
    & $add ''
    $src = [pscustomobject]@{ Source = 'endpoint'; LastGoodUtc = $good; LastAttemptUtc = $now; Ok = $false; DroppedSinceUtc = $now.AddDays(-2); Detail = '' }
    foreach ($l in @(Get-SISourceAgeText -Sources @($src) -NowUtc $now)) { & $add ('> ' + $l) }
    & $add ''

    & $add '#### 3. The hold when a data source sends far fewer assets (example A: devices 990 -> 697, held)'
    & $add ''
    $rows = @([pscustomobject]@{ Provider = 'mde'; RecordType = 'device'; NowRecords = 697; CollectionTime = $now; Records = 990; State = 'good' })
    $inv = { param($Sql, $Params, $Mode) , @($rows) }.GetNewClosure()
    $drops = @(Get-SIRecordFeedDrops -Feeds @([ordered]@{ Provider = 'mde'; RecordType = 'device' }) -Invoke $inv -CollectionTimeText '2026-11-16T02:00:00.000Z' -Engine 'endpoint' `
        -Settings ([pscustomobject]@{ Percent = 15; Action = 'confirm'; MinRecords = 20 }) -ShardCount 1 -IdentityChoice ([pscustomobject]@{ Any = $false }) 6>$null)
    $call = @(Get-SIGuardCallsForRecordDrop -Drops $drops -Engine 'endpoint')[0]
    $ev = New-SIGuardEvent -GuardId $call.GuardId -Outcome $call.Outcome -Subject $call.Subject -HeldCount $call.HeldCount -Detail $call.Detail -Values $call.Values -Job $call.Job -NowUtc $now
    $p = Get-SIGuardParts -Event $ev
    $def = Get-SIGuardDefinition -Id 'collection.source.asset-drop'
    & $add ('**Guards page name:** ' + $def.name)
    & $add ''
    & $add '**Guards page (what happened / why / what it means for you / what to do):**'
    & $add ''
    & $add '```text'
    & $add ('What happened: ' + $p.What)
    & $add ('Why: ' + $p.Why)
    & $add ('What it means for you: ' + $p.Consequence)
    $i = 0; foreach ($s in @($p.Steps)) { $i++; & $add ('{0}. {1}' -f $i, $s) }
    & $add '```'
    & $add ''
    & $add '**The line in the run report and the run log:**'
    & $add ''
    & $add ('> ' + (Format-SIGuardSummary -Event $ev))
    & $add ''
    & $add '(This check sends no mail of its own -- catalog "mail": "never".)'
    & $add ''
    $sb.ToString()
    return
}

$si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$repo = Split-Path -Parent (Split-Path -Parent $si)
$parts = New-Object System.Collections.Generic.List[string]
if ($Base) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-before-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $tar = Join-Path $tmp 'before.tar'
    & git -C $repo archive --format=tar -o $tar $Base 'SOLUTIONS/SecurityInsight/engine' 'SOLUTIONS/SecurityInsight/config'
    if ($LASTEXITCODE -ne 0) { throw "git archive of $Base failed" }
    & tar -xf $tar -C $tmp
    $parts.Add((& pwsh -NoProfile -File $PSCommandPath -One (Join-Path $tmp 'SOLUTIONS/SecurityInsight') -Label ("BEFORE (the code at {0})" -f $Base.Substring(0, [math]::Min(9, $Base.Length))) | Out-String))
}
$parts.Add((& pwsh -NoProfile -File $PSCommandPath -One $si -Label 'AFTER (this branch)' | Out-String))
$md = ($parts -join "`n")
[IO.File]::WriteAllText((Join-Path (Get-Location) $Out), $md)
Write-Host $md
