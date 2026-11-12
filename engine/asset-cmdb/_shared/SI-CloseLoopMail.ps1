#Requires -Version 5.1
<#
    SecurityInsight Pro -- the vulnerability close-loop's DAILY MAIL.

    What changed in the last 24 hours on the close-loop's own record (sql\si-vulnerability-target.sql):
      * opened, closed and reopened -- by severity and by asset tier;
      * what is open now, severity x tier -- in the five SI severity words (Very High .. Low; a source's Critical is
        Very High: Critical is only ever a RISK RATING, never a severity);
      * the newly opened and the closed items (top N of each);
      * the last 7 days from sidata.VulnLifecycleDaily, when the Pro data backend fills it;
      * a link to the close-loop page of the Pro web app, when its public address is known.
    A day with no change still sends a short "nothing changed" mail -- a missing mail must never be read as a
    quiet day.

    TWO SEAMS, so the whole thing is testable offline:
      -Invoke  the SQL seam of the vulnerability target and the data sync (sql, params, 'reader'|'scalar'|'nonquery');
      -Send    (to, subject, html) -- by default Send-SICloseLoopMail, which uses the ONE mail transport
               (engine\_shared\SI-MailTransport.ps1: Send-SIMail -- shared mailbox or SMTP, SI_Mail_Mode). There is no
               second mail stack here.

    Asset tier: the close-loop record carries no tier, so it is looked up in the Pro data backend (sidata.Asset, by
    the asset key or by the SI_AssetId identifier). Without the data backend every item is "Unknown" tier.

    PS 5.1 safe. Read only: nothing here writes to the database.
#>

# MAIL-1: the one mail transport (Send-SIMail, Get-SIMailSettings)
if (-not (Get-Command -Name Send-SIMail -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-MailTransport.ps1')) }
# #728: the one mail layout (summary, "Topic: text" lines, the frame -- no tables)
if (-not (Get-Command -Name New-SIMailFrameHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-MailLayout.ps1')) }

# the five SI severity words, most severe first (owner 2026-10-15: severity is never "Critical" -- that word belongs to the
# risk rating). The item's severity is the finding's SecuritySeverity, so "Very High" rows must land in "Very High" --
# keyed on 'Critical' they fell into "Other" and the top column showed 0.
$script:SICloseLoopSeverities = @('Very High', 'High', 'Medium-High', 'Medium', 'Low', 'Other')
$script:SICloseLoopTiers      = @('Tier 0', 'Tier 1', 'Tier 2', 'Tier 3', 'Unknown')
# closes that are NOT a fix: the asset went away or left the scope -- they are counted as closed, never as fixed
$script:SICloseLoopNotAFix    = @('AssetRetired', 'NoLongerMonitored', 'Out of scope', 'Duplicate', 'Linked', 'Asset deleted in Entra ID', 'Asset deleted in Azure', 'Asset deleted in Intune')
# the close-loop page of the Pro web app (pro-management\src\SI.Management.Web\Pages\Admin\CloseLoop.cshtml)
$script:SICloseLoopPagePath   = '/Admin/CloseLoop'
$script:SICloseLoopInvariant  = [System.Globalization.CultureInfo]::InvariantCulture
# The tenant as the mails show it: '<primary domain> (<tenant id>)' (#243).
if (-not (Get-Command -Name Get-SITenantDisplayName -ErrorAction SilentlyContinue)) {
    $__siTenantDisplay = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-TenantDisplay.ps1')
    if (Test-Path -LiteralPath $__siTenantDisplay) { . $__siTenantDisplay }
}

# ------------------------------------------------------------------------------------------------------------------
#  SETTINGS
# ------------------------------------------------------------------------------------------------------------------

function ConvertTo-SICloseLoopBool {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ("$Value".Trim() -in '1', 'true', 'True', 'TRUE', 'yes', 'Yes', 'on')
}

function Get-SICloseLoopMailRecipients {
    <# PURE. A list, or one string separated by ',' or ';' -> the non-empty addresses, trimmed, each once. #>
    param([AllowNull()][object]$Value)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($p in ("$v" -split '[,;]')) {
            $t = $p.Trim()
            if ($t -and -not ($out -contains $t)) { $out.Add($t) }
        }
    }
    return $out.ToArray()
}

function Get-SICloseLoopMailSettings {
    <#
        PURE. The mail's settings from the live globals (-Globals: name -> value).
        Returns @{ Enabled; Reason; To; Server; Database; WebBaseUrl }. Enabled is false -- with the one line the run
        prints -- when the mail is switched off or has no recipients.
        The database: the close-loop's own (SI_VulnSync_SqlServer / _SqlDatabase), else the Pro data backend's
        (SI_Pro_DataSqlServer / _SqlDatabase), else the Pro database (SI_ProSqlServer / SI_ProSqlDatabase).
    #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    $to = @(Get-SICloseLoopMailRecipients -Value (& $g 'Mail_CloseLoop_Daily_To'))
    $server = ''; $db = ''
    foreach ($pair in @(@('SI_VulnSync_SqlServer', 'SI_VulnSync_SqlDatabase'), @('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'), @('SI_ProSqlServer', 'SI_ProSqlDatabase'))) {
        $s = "$(& $g $pair[0])".Trim(); $d = "$(& $g $pair[1])".Trim()
        if ($s -and $d) { $server = $s; $db = $d; break }
    }
    $web = "$(& $g 'SIWeb_PublicBaseUrl')".Trim().TrimEnd('/')
    $enabled = $true; $reason = ''
    if (-not (ConvertTo-SICloseLoopBool (& $g 'Mail_CloseLoop_Daily_SendMail'))) {
        $enabled = $false; $reason = 'The close-loop daily mail is switched off (Mail_CloseLoop_Daily_SendMail) -- nothing was sent.'
    } elseif (@($to).Count -eq 0) {
        $enabled = $false; $reason = 'The close-loop daily mail has no recipients (Mail_CloseLoop_Daily_To) -- nothing was sent.'
    }
    [pscustomobject]@{ Enabled = $enabled; Reason = $reason; To = @($to); Server = $server; Database = $db; WebBaseUrl = $web }
}

function Get-SICloseLoopMailSmtp {
    <#
        PURE. How the mail goes out -- the SAME settings every SecurityInsight mail uses (Get-SIMailSettings, MAIL-1):
        SI_Mail_Mode (sharedMailbox | smtp | none) and SI_Mail_From; for smtp SmtpServer, SMTPPort, SMTP_UseSSL, SMTPFrom
        (else MailFrom, else SMTPUser), Mail_SendAnonymous, SMTPUser + SMTPPassword (the password from Key Vault; in a
        container it arrives as the SMTP_PASSWORD secret). No user and no password, and anonymous not switched off
        explicitly = an anonymous relay, as the Risk Analysis mail infers it.
        Returns @{ Mode; Off; Server; Port; UseSsl; From; Anonymous; User; Password; SharedMailbox; Problems; ... }.
    #>
    param([hashtable]$Globals = @{})
    Get-SIMailSettings -Globals $Globals
}

# ------------------------------------------------------------------------------------------------------------------
#  SQL -- pure text, read only
# ------------------------------------------------------------------------------------------------------------------

function Get-SICloseLoopMailProbeSql {
    "SELECT CASE WHEN OBJECT_ID('vuln.VulnerabilityItem') IS NOT NULL AND OBJECT_ID('vuln.VulnerabilityEvent') IS NOT NULL THEN 1 ELSE 0 END AS HasVuln, " +
    "CASE WHEN OBJECT_ID('sidata.Asset') IS NOT NULL AND OBJECT_ID('sidata.AssetIdentifier') IS NOT NULL THEN 1 ELSE 0 END AS HasTier, " +
    "CASE WHEN OBJECT_ID('sidata.VulnLifecycleDaily') IS NOT NULL THEN 1 ELSE 0 END AS HasLifecycle, " +
    "CASE WHEN OBJECT_ID('cfg.Setting') IS NOT NULL THEN 1 ELSE 0 END AS HasSettings"
}

function Get-SICloseLoopTierApplySql {
    <# The tier of item i: the CI keyed by its asset id, else the CI that lists it as an SI_AssetId identifier. #>
    @'
OUTER APPLY (SELECT TOP (1) a.Tier FROM sidata.Asset AS a WHERE a.AssetKey = i.CorrelationId) AS t1
OUTER APPLY (SELECT TOP (1) a.Tier FROM sidata.AssetIdentifier AS ai JOIN sidata.Asset AS a ON a.AssetKey = ai.AssetKey
             WHERE ai.IdentifierValue = LOWER(i.CorrelationId) AND ai.IdentifierType = N'SI_AssetId' ORDER BY a.Tier) AS t2
'@
}

function Get-SICloseLoopMailEventsSql {
    <# The window's state changes (not 'Seen'), newest first, with the item they belong to. #>
    param([switch]$WithTier)
    $tier = if ($WithTier) { 'COALESCE(t1.Tier, t2.Tier)' } else { 'CAST(NULL AS tinyint)' }
    $apply = if ($WithTier) { Get-SICloseLoopTierApplySql } else { '' }
    @"
SELECT e.EventId, e.[At], e.Action, e.Reason, i.Cve, i.AssetName, i.CorrelationId, i.Severity, i.FirstSeen, i.State, $tier AS Tier
FROM vuln.VulnerabilityEvent AS e
JOIN vuln.VulnerabilityItem AS i ON i.SysId = e.SysId
$apply
WHERE e.[At] >= CONVERT(datetime2(0), @Since, 126) AND e.[At] < CONVERT(datetime2(0), @Until, 126)
  AND e.Action IN (N'Open', N'Close', N'EngineerClose', N'Reopen')
ORDER BY e.[At] DESC, e.EventId DESC;
"@
}

function Get-SICloseLoopMailOpenSql {
    <# What is open now, counted per severity x tier (grouped in SQL: the open set can be large). #>
    param([switch]$WithTier)
    $tier = if ($WithTier) { 'COALESCE(t1.Tier, t2.Tier)' } else { 'CAST(NULL AS tinyint)' }
    $apply = if ($WithTier) { Get-SICloseLoopTierApplySql } else { '' }
    @"
SELECT ISNULL(i.Severity, N'') AS Severity, $tier AS Tier, COUNT_BIG(*) AS Items
FROM vuln.VulnerabilityItem AS i
$apply
WHERE i.State = N'Open'
GROUP BY ISNULL(i.Severity, N''), $tier;
"@
}

function Get-SICloseLoopMailLifecycleSql {
    "SELECT [Day], Opened, Closed, Reopened, OpenAtEndOfDay FROM sidata.VulnLifecycleDaily WHERE [Day] >= CONVERT(date, @Since, 126) ORDER BY [Day] DESC;"
}

function Get-SICloseLoopMailWebUrlSql {
    # the web app's own setting (scope engine:management-web), which no engine layer loads
    "SELECT TOP (1) ValueJson FROM cfg.Setting WHERE Name = N'SIWeb_PublicBaseUrl' AND Scope = N'engine:management-web';"
}

function Format-SICloseLoopSqlTime {
    param([Parameter(Mandatory)][datetime]$Time)
    $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', $script:SICloseLoopInvariant)
}

function Get-SICloseLoopValue {
    <# A column of a reader row (hashtable or object); a database NULL reads as $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    return $v
}

function Read-SICloseLoopMailData {
    <#
        Reads everything the mail shows through the -Invoke seam. Read only.
        Returns @{ Events; Open; Lifecycle; WebBaseUrl; HasTier; HasLifecycle }. (No time to fix: the owner took it out of
        every mail and page on 2026-10-15 -- "it makes no value"; the close-loop's own record keeps every date.)
        Throws -- the run fails -- when the close-loop tables are not in the database: a mail that says "nothing
        changed" about a database it could not read would be a lie.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$Since, [Parameter(Mandatory)][datetime]$Until)
    $probeRaw = (& $Invoke (Get-SICloseLoopMailProbeSql) @{} 'reader')
    $probe = @($probeRaw | Where-Object { $null -ne $_ }) | Select-Object -First 1
    if (-not $probe -or [int](Get-SICloseLoopValue $probe 'HasVuln') -ne 1) {
        throw 'the vulnerability close-loop tables (vuln.VulnerabilityItem, vuln.VulnerabilityEvent) are not in this database. Run setup\Initialize-SIVulnTargetSql.ps1, or point SI_VulnSync_SqlServer / SI_VulnSync_SqlDatabase at the close-loop''s database.'
    }
    $hasTier = ([int](Get-SICloseLoopValue $probe 'HasTier') -eq 1)
    $hasLife = ([int](Get-SICloseLoopValue $probe 'HasLifecycle') -eq 1)
    $hasCfg  = ([int](Get-SICloseLoopValue $probe 'HasSettings') -eq 1)
    $win = @{ Since = (Format-SICloseLoopSqlTime -Time $Since); Until = (Format-SICloseLoopSqlTime -Time $Until) }
    $evRaw = (& $Invoke (Get-SICloseLoopMailEventsSql -WithTier:$hasTier) $win 'reader')
    $events = @($evRaw | Where-Object { $null -ne $_ })
    $openRaw = (& $Invoke (Get-SICloseLoopMailOpenSql -WithTier:$hasTier) @{} 'reader')
    $open = @($openRaw | Where-Object { $null -ne $_ })
    $life = @()
    if ($hasLife) {
        $lRaw = (& $Invoke (Get-SICloseLoopMailLifecycleSql) @{ Since = $Until.AddDays(-7).ToUniversalTime().ToString('yyyy-MM-dd', $script:SICloseLoopInvariant) } 'reader')
        $life = @($lRaw | Where-Object { $null -ne $_ })
    }
    $web = ''
    if ($hasCfg) {
        $j = & $Invoke (Get-SICloseLoopMailWebUrlSql) @{} 'scalar'
        if ($null -ne $j -and -not ($j -is [System.DBNull]) -and "$j".Trim()) {
            try { $web = [string](ConvertFrom-Json -InputObject ([string]$j)) } catch { $web = '' }
        }
    }
    [pscustomobject]@{ Events = $events; Open = $open; Lifecycle = $life; WebBaseUrl = "$web".Trim().TrimEnd('/')
                       HasTier = $hasTier; HasLifecycle = $hasLife }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE REPORT -- pure, from rows
# ------------------------------------------------------------------------------------------------------------------

function ConvertTo-SICloseLoopSeverity {
    <#
        PURE. A stored severity -> one of the five SI words: 'Very High' / 'very-high' / a source's 'Critical' -> Very High,
        High, 'Medium-High' -> Medium-High, 'Medium' / 'Moderate' -> Medium, Low; anything else (or none) -> Other.
        The item's severity is the finding's SecuritySeverity ("Very High" ..), so the top step must be keyed on Very High.
    #>
    param([AllowNull()][object]$Severity)
    $s = ("$Severity".Trim().ToLowerInvariant()) -replace '[\s_-]+', ''
    switch -regex ($s) {
        '^(veryhigh|crit)'  { return 'Very High' }
        '^mediumhigh'       { return 'Medium-High' }
        '^high'             { return 'High' }
        '^(med|moderate)'   { return 'Medium' }
        '^low'              { return 'Low' }
        default             { return 'Other' }
    }
}

function ConvertTo-SICloseLoopTier {
    <# PURE. 0..3 -> 'Tier 0'..'Tier 3'; no tier -> 'Unknown'. #>
    param([AllowNull()][object]$Tier)
    if ($null -eq $Tier -or $Tier -is [System.DBNull]) { return 'Unknown' }
    $t = "$Tier".Trim()
    if ($t -match '^[0-3]$') { return ('Tier {0}' -f $t) }
    return 'Unknown'
}

function New-SICloseLoopCounter {
    param([string[]]$Keys)
    $h = [ordered]@{}
    foreach ($k in $Keys) { $h[$k] = 0 }
    $h['Total'] = 0
    return $h
}

function Test-SICloseLoopIsFix {
    <# PURE. Is a close event a FIX? An engineer's close is; SI's close is unless the asset was retired / left the scope. #>
    param([string]$Action, [AllowNull()][string]$Reason)
    if ($Action -eq 'EngineerClose') { return $true }
    if ($Action -ne 'Close') { return $false }
    # the event reason is "<reason>: <why>" -- the reason is what precedes the first colon (#279)
    return -not ($script:SICloseLoopNotAFix -contains ("$Reason" -split ':', 2)[0].Trim())
}

function Get-SICloseLoopMailReport {
    <#
        PURE. Everything the mail shows, from the rows Read-SICloseLoopMailData returned.
        Returns @{ Since; Until; Opened; Closed; Fixed; Reopened; OpenNow; NothingChanged;
                   BySeverity (Opened/Closed/Reopened -> severity counters); ByTier (same, per tier);
                   OpenMatrix (severity -> tier counters); OpenByTier (tier totals);
                   NewlyOpened; ClosedItems (each the top -Top, most severe first); Lifecycle; HasTier }.
        Severity counters are keyed on the five SI words (Very High, High, Medium-High, Medium, Low) and Other.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Events = @(),
        [AllowEmptyCollection()][object[]]$Open = @(),
        [AllowEmptyCollection()][object[]]$Lifecycle = @(),
        [Parameter(Mandatory)][datetime]$Since,
        [Parameter(Mandatory)][datetime]$Until,
        [int]$Top = 15,
        [bool]$HasTier = $true
    )
    $sev = $script:SICloseLoopSeverities; $tiers = $script:SICloseLoopTiers
    $bySev = [ordered]@{ Opened = (New-SICloseLoopCounter $sev); Closed = (New-SICloseLoopCounter $sev); Reopened = (New-SICloseLoopCounter $sev) }
    $byTier = [ordered]@{ Opened = (New-SICloseLoopCounter $tiers); Closed = (New-SICloseLoopCounter $tiers); Reopened = (New-SICloseLoopCounter $tiers) }
    $opened = New-Object System.Collections.Generic.List[object]
    $closed = New-Object System.Collections.Generic.List[object]
    $sevRank = @{ 'Very High' = 0; 'High' = 1; 'Medium-High' = 2; 'Medium' = 3; 'Low' = 4; 'Other' = 5 }

    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $action = "$(Get-SICloseLoopValue $e 'Action')".Trim()
        $kind = switch ($action) { 'Open' { 'Opened' } 'Reopen' { 'Reopened' } 'Close' { 'Closed' } 'EngineerClose' { 'Closed' } default { '' } }
        if (-not $kind) { continue }
        $s = ConvertTo-SICloseLoopSeverity (Get-SICloseLoopValue $e 'Severity')
        $t = ConvertTo-SICloseLoopTier (Get-SICloseLoopValue $e 'Tier')
        $bySev[$kind][$s]++; $bySev[$kind]['Total']++
        $byTier[$kind][$t]++; $byTier[$kind]['Total']++
        $at = Get-SICloseLoopValue $e 'At'
        $reason = [string](Get-SICloseLoopValue $e 'Reason')
        $item = [pscustomobject]@{
            At = $at; Severity = $s; SeverityRank = $sevRank[$s]; Tier = $t; Cve = [string](Get-SICloseLoopValue $e 'Cve')
            AssetName = [string](Get-SICloseLoopValue $e 'AssetName'); Action = $action; Reason = $reason; IsFix = $false
        }
        if ($kind -eq 'Opened') { $opened.Add($item) }
        elseif ($kind -eq 'Closed') {
            $item.IsFix = (Test-SICloseLoopIsFix -Action $action -Reason $reason)
            $closed.Add($item)
        }
    }

    $matrix = [ordered]@{}
    foreach ($s in $sev) { $matrix[$s] = New-SICloseLoopCounter $tiers }
    $matrix['Total'] = New-SICloseLoopCounter $tiers
    foreach ($r in @($Open)) {
        if ($null -eq $r) { continue }
        $s = ConvertTo-SICloseLoopSeverity (Get-SICloseLoopValue $r 'Severity')
        $t = ConvertTo-SICloseLoopTier (Get-SICloseLoopValue $r 'Tier')
        $n = [long](Get-SICloseLoopValue $r 'Items')
        $matrix[$s][$t] += $n; $matrix[$s]['Total'] += $n
        $matrix['Total'][$t] += $n; $matrix['Total']['Total'] += $n
    }

    $order = { param($list) @($list | Sort-Object -Property @{ Expression = 'SeverityRank' }, @{ Expression = 'Tier' }, @{ Expression = { $_.At }; Descending = $true }) }
    $topOpened = @(& $order $opened.ToArray() | Select-Object -First $Top)
    $topClosed = @(& $order $closed.ToArray() | Select-Object -First $Top)
    $nothing = (($bySev.Opened.Total + $bySev.Closed.Total + $bySev.Reopened.Total) -eq 0)
    [pscustomobject]@{
        Since = $Since; Until = $Until
        Opened = [int]$bySev.Opened.Total; Closed = [int]$bySev.Closed.Total; Reopened = [int]$bySev.Reopened.Total
        Fixed = @($closed | Where-Object { $_.IsFix }).Count
        OpenNow = [long]$matrix['Total']['Total']; NothingChanged = $nothing
        BySeverity = $bySev; ByTier = $byTier; OpenMatrix = $matrix
        NewlyOpened = $topOpened; NewlyOpenedTotal = $opened.Count
        ClosedItems = $topClosed; ClosedTotal = $closed.Count
        Lifecycle = @($Lifecycle | Where-Object { $null -ne $_ }); HasTier = $HasTier
    }
}

function Get-SICloseLoopMailSubject {
    param([Parameter(Mandatory)][object]$Report, [string]$TenantTag)
    $day = $Report.Until.ToUniversalTime().ToString('yyyy-MM-dd', $script:SICloseLoopInvariant)
    $what = if ($Report.NothingChanged) { 'nothing changed' }
            else { ('{0} opened, {1} closed, {2} reopened' -f $Report.Opened, $Report.Closed, $Report.Reopened) }
    # MAIL-3 (#653): the transport names the environment and the product (Get-SIMailSubject); no severity word (a report)
    $s = "Vulnerability close-loop | $day | $what"
    if ("$TenantTag".Trim()) { $s += " | $TenantTag" }
    $s
}

# ------------------------------------------------------------------------------------------------------------------
#  THE HTML -- the one SI mail layout (#728: summary first, "Topic: text" lines, one line per record, NO tables)
# ------------------------------------------------------------------------------------------------------------------

function ConvertTo-SICloseLoopMailHtml {
    <#
        PURE. The mail body, in the one SI mail layout (engine\_shared\SI-MailLayout.ps1; #728: no tables, readable on a
        phone). A summary first (what changed, the numbers, whether to act), then sections, each with its heading so the
        tests can find it: "Changes by severity", "Changes by asset tier", "Open now by severity and tier", "Newly opened", "Closed", "Last 7 days" (when the data backend's daily statistics exist) -- ONE LINE PER
        RECORD, the topic in bold -- and the link to the close-loop page (when the web app's address is known). A day with
        no change renders the short "nothing changed" mail.
    #>
    param(
        [Parameter(Mandatory)][object]$Report,
        [string]$TenantTag,
        [string]$WebBaseUrl,
        [string]$Version,
        # one line each, shown under the summary as "Warnings" (the ServiceNow outputs whose newest check is not ok)
        [AllowEmptyCollection()][string[]]$Warnings = @()
    )
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $inv = $script:SICloseLoopInvariant
    $warnBlock = ''
    $warnList = @($Warnings | Where-Object { "$_".Trim() })
    if ($warnList.Count) {
        $warnBlock = (ConvertTo-SIMailHeadingHtml 'Warnings') + (($warnList | ForEach-Object { ConvertTo-SIMailLineHtml -Topic 'ServiceNow' -Html (& $enc $_) }) -join '')
    }
    # owner 2026-10-20: no green for any severity (every severity is a risk) -- Low is the web app's slate (app.css --rs-low)
    $sevInk = @{ 'Very High' = '#7a1414'; 'High' = '#8a3d00'; 'Medium-High' = '#7a4f00'; 'Medium' = '#7a5d00'; 'Low' = '#2f4256'; 'Other' = '#5a6a7a' }
    $line = { param($topic, $html) ConvertTo-SIMailLineHtml -Topic $topic -Html $html }
    $note = { param($text) ('<p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;line-height:1.5;color:#5a6a7a;margin:0 0 14px 0;">{0}</p>' -f $text) }
    $window = ('{0} {1} {2} UTC' -f $Report.Since.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv), [char]0x2013, $Report.Until.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', $inv))
    $tenantLabel = if ("$TenantTag".Trim()) { "$TenantTag".Trim() } else { [string][char]0x2014 }
    $ver = if ("$Version".Trim()) { "$Version".Trim() } else { '(dev)' }
    $pageUrl = ''
    if ("$WebBaseUrl".Trim() -match '^https?://') { $pageUrl = ("$WebBaseUrl".Trim().TrimEnd('/') + $script:SICloseLoopPagePath) }
    $linkBlock = ''
    if ($pageUrl) {
        $linkBlock = ('<p data-mail-button style="font-family:Segoe UI,Arial,sans-serif;margin:8px 0 18px 0;line-height:1.2;"><a href="{0}" target="_blank" style="font-family:Segoe UI,Arial,sans-serif;display:inline-block;background:#1B4FE4;border:2px solid #1B4FE4;border-radius:8px;padding:12px 24px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;">Open the close-loop page</a></p>' -f (& $enc $pageUrl)) +
            (& $note (& $enc $pageUrl))
    }
    # owner 2026-10-16: "See details and history: <the install's page in the Invardia portal>" at the TOP, right under the
    # banner, above the summary -- the mail transport (Send-SIMail) fills this place-holder only when the environment id is
    # known, else it is removed (engine\_shared\SI-InvardiaPortalLink.ps1). The summary block below is therefore NOT marked
    # data-mail-summary: that marker would move the line under the summary instead of keeping it where it is.
    $portal = '<!-- SI portal link -->'
    $summary = { param([string[]]$html) (ConvertTo-SIMailSummaryHtml -Html $html).Replace('data-mail-summary', 'data-close-loop-summary') }
    $footer = ('SecurityInsight Pro &middot; Vulnerability close-loop &middot; the last 24 hours of the close-loop''s own record &middot; Build <strong>v{0}</strong>' -f (& $enc $ver))
    $brand = 'SecurityInsight ' + [char]0x00B7 + ' Vulnerability close-loop'
    $subtitle = 'Daily report ' + [char]0x00B7 + ' ' + $tenantLabel + ' ' + [char]0x00B7 + ' ' + $window

    if ($Report.NothingChanged) {
        $are = if ($Report.OpenNow -eq 1) { 'y is' } else { 'ies are' }
        $content = $portal +
            (& $summary @(
                '<strong>Nothing changed in the last 24 hours</strong>',
                ('<strong>{0}</strong> vulnerabilit{1} open now.' -f $Report.OpenNow, $are),
                $(if ($warnList.Count) { '<strong>Action:</strong> a ServiceNow check is not ok -- see Warnings.' } else { 'No action needed.' }))) +
            $warnBlock +
            (ConvertTo-SIMailParagraphHtml -Text ('No vulnerability was opened, closed or reopened between {0}.' -f $window)) +
            (& $note 'This mail is sent every day, so a quiet day is never mistaken for a missing report.') +
            $linkBlock
        return (New-SIMailFrameHtml -Brand $brand -Subtitle $subtitle -ContentHtml $content -FooterHtml $footer)
    }

    # one line per change kind: "Opened: 3 -- Very High 1, High 2, Medium-High 0, Medium 0, Low 0"
    $sevCols = @($script:SICloseLoopSeverities | Where-Object { $_ -ne 'Other' -or ($Report.BySeverity.Opened.Other + $Report.BySeverity.Closed.Other + $Report.BySeverity.Reopened.Other) -gt 0 })
    $sevLines = ''
    foreach ($k in 'Opened', 'Closed', 'Reopened') {
        $c = $Report.BySeverity[$k]
        $parts = @($sevCols | ForEach-Object { '<span style="color:{0};">{1}</span> {2}' -f $sevInk[$_], $_, $c[$_] })
        $sevLines += (& $line $k ('<strong>{0}</strong> &mdash; {1}' -f $c['Total'], ($parts -join ', ')))
    }
    $tierCols = $script:SICloseLoopTiers
    $tierLines = ''
    foreach ($k in 'Opened', 'Closed', 'Reopened') {
        $c = $Report.ByTier[$k]
        $parts = @($tierCols | ForEach-Object { '{0} {1}' -f $_, $c[$_] })
        $tierLines += (& $line $k ('<strong>{0}</strong> &mdash; {1}' -f $c['Total'], ($parts -join ', ')))
    }
    $matLines = ''
    foreach ($s in @($script:SICloseLoopSeverities) + @('Total')) {
        $c = $Report.OpenMatrix[$s]
        if ($s -eq 'Other' -and $c['Total'] -eq 0) { continue }
        $parts = @($tierCols | ForEach-Object { '{0} {1}' -f $_, $c[$_] })
        $matLines += (ConvertTo-SIMailLineHtml -Topic $s -Html ('<strong>{0}</strong> &mdash; {1}' -f $c['Total'], ($parts -join ', ')) -Color $(if ($s -eq 'Total') { '' } else { $sevInk[$s] }))
    }
    $tierNote = if ($Report.HasTier) { '' } else { & $note 'Asset tiers come from the Pro data backend, which is not set up in this database, so every item shows as Unknown.' }

    # one line per item: "<strong>host-1 -- CVE-2026-0001:</strong> Very High, Tier 0, opened 2026-10-16 04:00"
    $itemLines = {
        param($items, [int]$total, [bool]$closedList)
        if (@($items).Count -eq 0) { return (& $note 'None in the last 24 hours.') }
        $out = ''
        foreach ($i in @($items)) {
            $at = if ($i.At -is [datetime]) { $i.At.ToString('yyyy-MM-dd HH:mm', $inv) } else { & $enc $i.At }
            $topic = ('{0} {1} {2}' -f $i.AssetName, [char]0x2014, $i.Cve)
            $what = ('<span style="color:{0};font-weight:600;">{1}</span>, {2}' -f $sevInk[$i.Severity], $i.Severity, (& $enc $i.Tier))
            if ($closedList) {
                $why = if ($i.Action -eq 'EngineerClose') { 'closed by an engineer' } elseif ("$($i.Reason)".Trim()) { ConvertTo-SIMailInlineHtml $i.Reason } else { '&mdash;' }
                # no time to fix (owner 2026-10-15); the "not a fix" note stays, beside the reason
                $what += (', {0}{1}' -f $why, $(if ($i.IsFix) { '' } else { ', not a fix' }))
            } else {
                $what += (', opened {0} UTC' -f $at)
            }
            $out += (& $line $topic $what)
        }
        if ($total -gt @($items).Count) { $out += (& $note ('Showing the {0} most severe of {1}. The close-loop page lists them all.' -f @($items).Count, $total)) }
        $out
    }

    $life = ''
    if (@($Report.Lifecycle).Count) {
        $life = ConvertTo-SIMailHeadingHtml 'Last 7 days'
        foreach ($d in @($Report.Lifecycle)) {
            $day = Get-SICloseLoopValue $d 'Day'
            $dayText = if ($day -is [datetime]) { $day.ToString('yyyy-MM-dd', $inv) } else { [string]$day }
            $life += (& $line $dayText ('{0} opened, {1} closed, {2} reopened, <strong>{3}</strong> open at end of day' -f `
                (Get-SICloseLoopValue $d 'Opened'), (Get-SICloseLoopValue $d 'Closed'), (Get-SICloseLoopValue $d 'Reopened'), (Get-SICloseLoopValue $d 'OpenAtEndOfDay')))
        }
    }

    $act = if (($Report.Opened + $Report.Reopened) -gt 0) { '<strong>Action:</strong> review the newly opened and reopened vulnerabilities below.' } elseif ($warnList.Count) { '<strong>Action:</strong> a ServiceNow check is not ok -- see Warnings.' } else { 'No action needed.' }
    $content = $portal +
        (& $summary @(
            ('<strong>{0}</strong> opened, <strong>{1}</strong> closed ({2} fixed), <strong>{3}</strong> reopened in the last 24 hours.' -f $Report.Opened, $Report.Closed, $Report.Fixed, $Report.Reopened),
            ('<strong>{0}</strong> open now.' -f $Report.OpenNow),
            $act)) +
        $warnBlock +
        (ConvertTo-SIMailHeadingHtml 'Changes by severity') + $sevLines +
        (ConvertTo-SIMailHeadingHtml 'Changes by asset tier') + $tierLines +
        (ConvertTo-SIMailHeadingHtml 'Open now by severity and tier') + $matLines + $tierNote +
        (ConvertTo-SIMailHeadingHtml ('Newly opened ({0})' -f $Report.NewlyOpenedTotal)) + (& $itemLines $Report.NewlyOpened $Report.NewlyOpenedTotal $false) +
        (ConvertTo-SIMailHeadingHtml ('Closed ({0}, of which {1} fixed)' -f $Report.ClosedTotal, $Report.Fixed)) + (& $itemLines $Report.ClosedItems $Report.ClosedTotal $true) +
        $life + $linkBlock
    return (New-SIMailFrameHtml -Brand $brand -Subtitle $subtitle -ContentHtml $content -FooterHtml $footer)
}

# ------------------------------------------------------------------------------------------------------------------
#  SENDING -- through the one mail transport (Send-SIMail), never a second stack
# ------------------------------------------------------------------------------------------------------------------

function Send-SICloseLoopMail {
    <#
        Sends through the ONE mail transport, Send-SIMail (engine\_shared\SI-MailTransport.ps1: the shared mailbox over
        Microsoft Graph, or the SMTP relay through RA-Mail.ps1's transports). THROWS with the reason when the mail does
        not go out -- an undelivered daily mail is a failed run, never a green one. Mail switched off on purpose
        (SI_Mail_Mode = none) is not a failure: one line says so and $false is returned.
    #>
    param(
        [Parameter(Mandatory)][object]$Smtp,
        [Parameter(Mandatory)][string[]]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$BodyHtml,
        # #574: no PDF copy of a mail that carries a one-time secret (the department sign-in link or code)
        [switch]$NoPdf,
        # MAIL-3 (#653): the subject's severity word (Failed | Warning | ActionNeeded); a sender may also write it first in
        # -Subject ('Action needed: ...') -- the transport builds the whole subject either way
        [AllowNull()][AllowEmptyString()][string]$Severity,
        # files the mail carries (the management summary's PowerPoint); the transport leaves one out over the attachment budget
        [AllowEmptyCollection()][string[]]$Attachments = @()
    )
    if ($Smtp.Off) { Write-Host '[INFO] mail is off (SI_Mail_Mode = none) -- the mail was not sent'; return $false }
    if (@($Smtp.Problems).Count) { throw ('the close-loop mail cannot be sent: ' + (@($Smtp.Problems) -join '; ')) }
    $r = Send-SIMail -Settings $Smtp -To $To -Subject $Subject -BodyHtml $BodyHtml -Priority 'Normal' -NoPdf:$NoPdf -Severity $Severity -Attachments @($Attachments | Where-Object { "$_".Trim() })
    if (-not $r.Sent) { throw ('the close-loop mail was not sent: ' + $(if ($r.Error) { [string]$r.Error } else { 'the mail was not accepted' })) }
    return $true
}

function Get-SICloseLoopTenantTag {
    <# The tenant in the subject and header: '<primary domain> (<tenant id>)', the same display as the Risk Analysis
       mail (#243, engine\_shared\SI-TenantDisplay.ps1). -GraphGet is the seam for the /organization read. #>
    param([hashtable]$Globals = @{}, [scriptblock]$GraphGet = $null)
    if (Get-Command -Name Get-SITenantDisplayName -ErrorAction SilentlyContinue) {
        try { return [string](Get-SITenantDisplayName -Globals $Globals -GraphGet $GraphGet) } catch { }
    }
    foreach ($n in 'TenantShort', 'TenantNameOrganization', 'AzureTenantID', 'SpnTenantId', 'SI_SPN_TenantId') {
        if ($Globals.ContainsKey($n) -and "$($Globals[$n])".Trim()) { return "$($Globals[$n])".Trim() }
    }
    ''
}

function Invoke-SICloseLoopMailCore {
    <#
        The whole run behind the two seams. -NewInvoke (server, database) -> the SQL seam; -Send (to, subject, html).
        Off or no recipients -> @{ Sent = $false; Reason } and NOTHING is read. Otherwise reads, builds, sends.
        Returns @{ Sent; Reason; Subject; Html; Report; To }.
    #>
    param(
        [hashtable]$Globals = @{},
        [Parameter(Mandatory)][scriptblock]$NewInvoke,
        [Parameter(Mandatory)][scriptblock]$Send,
        [datetime]$Now = [datetime]::UtcNow,
        [int]$Top = 15,
        [string]$Version,
        [switch]$DryRun,
        [scriptblock]$Log = { param($level, $msg) Write-Host ("[{0}] {1}" -f $level, $msg) },
        # the mail's Warnings lines (the ServiceNow outputs whose newest check is not ok)
        [AllowEmptyCollection()][string[]]$Warnings = @()
    )
    $s = Get-SICloseLoopMailSettings -Globals $Globals
    if (-not $s.Enabled) {
        & $Log 'INFO' $s.Reason
        return [pscustomobject]@{ Sent = $false; Reason = $s.Reason; Subject = ''; Html = ''; Report = $null; To = @() }
    }
    if (-not $s.Server -or -not $s.Database) {
        throw 'the close-loop daily mail has no database to read: set SI_VulnSync_SqlServer and SI_VulnSync_SqlDatabase (the close-loop''s database).'
    }
    $until = $Now.ToUniversalTime(); $since = $until.AddHours(-24)
    & $Log 'INFO' ("database  : {0}/{1}" -f $s.Server, $s.Database)
    & $Log 'INFO' ("window    : {0:u} .. {1:u}" -f $since, $until)
    $invoke = & $NewInvoke $s.Server $s.Database
    $data = Read-SICloseLoopMailData -Invoke $invoke -Since $since -Until $until
    $report = Get-SICloseLoopMailReport -Events $data.Events -Open $data.Open -Lifecycle $data.Lifecycle `
                -Since $since -Until $until -Top $Top -HasTier ([bool]$data.HasTier)
    $web = if ($s.WebBaseUrl) { $s.WebBaseUrl } else { $data.WebBaseUrl }
    $tag = Get-SICloseLoopTenantTag -Globals $Globals
    $html = ConvertTo-SICloseLoopMailHtml -Report $report -TenantTag $tag -WebBaseUrl $web -Version $Version -Warnings @($Warnings)
    $subject = Get-SICloseLoopMailSubject -Report $report -TenantTag $tag
    & $Log 'OK' ("report    : opened {0} | closed {1} ({2} fixed) | reopened {3} | open now {4}{5}" -f $report.Opened, $report.Closed, $report.Fixed, $report.Reopened, $report.OpenNow, $(if ($report.NothingChanged) { ' -- nothing changed' } else { '' }))
    if ($DryRun) {
        & $Log 'INFO' 'DRY RUN -- the mail was built and NOT sent.'
        return [pscustomobject]@{ Sent = $false; Reason = 'dry run'; Subject = $subject; Html = $html; Report = $report; To = $s.To }
    }
    & $Send $s.To $subject $html
    & $Log 'OK' ("sent      : '{0}' to {1}" -f $subject, ($s.To -join ', '))
    [pscustomobject]@{ Sent = $true; Reason = ''; Subject = $subject; Html = $html; Report = $report; To = $s.To }
}
