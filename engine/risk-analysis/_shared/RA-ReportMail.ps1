#Requires -Version 5.1
<#
    THE RISK ANALYSIS REPORT MAIL -- its body, in the one SI mail layout (engine\_shared\SI-MailLayout.ps1).

    REQUIREMENTS #728 (owner: "Drop the tables in emails as it becomes hard to read on mobiles / Make line with topic: /
    Then text. / Use bold where it can add important context / Use line spacing where needed"). The mail was a 720 px table
    layout (a KPI hero beside a domain x severity table, four domain tiles side by side); on a phone it was unreadable.
    Now, with the same content and the same numbers:
      - the SUMMARY first (data-mail-summary): the PROTECTION SCORE in its two views (#636, owner 2026-10-19: it replaces the
        old 0-100 KPI everywhere), the totals per severity, whether to act -- the
        portal link line (Add-SIInvardiaPortalLink) goes directly under it;
      - a notice about the workbook (not attached / too large), when there is one;
      - "Findings by domain": ONE LINE PER DOMAIN ("Endpoint: 900 -- Very High 3, High 30, Medium 500, Low 367"; the KPI's Critical count is the SI severity Very High -- Critical is only ever a risk rating, owner 2026-10-15) and the
        total in bold, then the note why the Summary and Detailed reports count differently;
      - "Protection score by asset type": one line per asset type, both views (engine\_shared\SI-ProtectionScore.ps1);
      - the workbook sentence, the error references, the AI analysis, the footer -- as paragraphs.
    No <table>, no fixed width. Numbers are written as they always were (plain integers).

    PURE: ConvertTo-RAReportMailHtml builds the HTML from its parameters; Invoke-RiskAnalysis.ps1 hands it the run's KPI
    and the sections it builds itself (the AI analysis, the error references, the workbook notice).
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.
if (-not (Get-Command -Name New-SIMailFrameHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-MailLayout.ps1')) }

function Get-RAReportMailValue {
    <# PURE. -Key of a hashtable or an object (a KPI read back from JSON is an object), $null when absent. #>
    param($From, [string]$Key)
    if ($null -eq $From) { return $null }
    if ($From -is [System.Collections.IDictionary]) { if ($From.Contains($Key)) { return $From[$Key] }; return $null }
    if ($From.PSObject.Properties[$Key]) { return $From.$Key }
    $null
}

function ConvertTo-RAReportMailSeverityText {
    <# PURE. "Very High 3, High 30, Medium 500, Low 367" as HTML (the KPI key Critical is printed as the SI severity Very High); a very high or high count above zero in bold. #>
    param($Counts)
    $get = { param($k) $v = 0; try { $x = Get-RAReportMailValue $Counts $k; if ($null -ne $x) { $v = [int]$x } } catch { $v = 0 }; $v }
    $parts = foreach ($k in @('Critical', 'High', 'Medium', 'Low')) {
        $n = [int](& $get $k)
        if ($n -gt 0 -and $k -eq 'Critical') { '<strong style="color:#7a1414;">Very High {0}</strong>' -f $n }
        elseif ($n -gt 0 -and $k -eq 'High') { '<strong style="color:#8a3d00;">High {0}</strong>' -f $n }
        else { '{0} {1}' -f $(if ($k -eq 'Critical') { 'Very High' } else { $k }), $n }
    }
    ($parts -join ', ')
}

# The two places of the protection score in a mail that waits for it (Pro: the data sync fills them from the stored key figures --
# engine\_shared\data-sql\SI-RaMailOutbox.ps1). HTML comments: a mail that is sent never carries them (they are replaced first).
$script:RAMailProtectionSummaryMark = '<!--SI:PROTECTION-SUMMARY-->'
$script:RAMailProtectionTypesMark = '<!--SI:PROTECTION-TYPES-->'

function ConvertTo-RAReportMailProtectionHtml {
    <#
        PURE. THE protection score of the Risk Analysis mail, in its two places: @{ Summary = the summary block's lines (joined
        with <br>); Types = the "Protection Score by asset type" section }. ONE renderer for both editions and both sources:
        -Protection is Complete-SIProtectionTally's answer (Community) or ConvertFrom-SIProtectionKeyFigures's (Pro: the stored
        figures the web app shows). Format as the web app's mail (owner 2026-10-22): "96.5 % [middle dot] Very Good" (invariant 0.0), the
        band's words and ink. Without a score: ONE plain line why (-Reason, else the stored score's Note) and no section.
    #>
    param($Protection, [string]$Reason)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $dot = [string][char]0x00B7
    $L = $script:SIMailLayout
    if (-not (Get-Command -Name Get-SIProtectionBand -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-ProtectionScore.ps1')) }
    if ($null -eq $Protection -or $null -eq (Get-RAReportMailValue $Protection 'Lifecycle')) {
        $t = [System.Net.WebUtility]::HtmlEncode((Get-SIProtectionNoScoreText -Score $Protection -Reason $Reason))
        return @{ Summary = ('<strong>Protection Score:</strong> <span data-mail-protection="none">{0}</span>' -f $t); Types = '' }
    }
    # owner 2026-10-20: the two names, each value in its band's words and colour (protection-score-bands.locked.json)
    $bl = Get-SIProtectionBand -Score $Protection.Lifecycle; $bt = Get-SIProtectionBand -Score $Protection.Technical
    $sum = (@(
        [string]::Format($inv, '<strong>Protection Score, within Accepted Lifecycle:</strong> <strong data-band="{2}" style="color:{1};">{0:0.0} % {3} {4}</strong> (higher is better)', [double]$Protection.Lifecycle, $bl.Ink, $bl.Tone, $dot, $bl.Name),
        [string]::Format($inv, '<strong>Protection Score, Actual Risks:</strong> <strong data-band="{2}" style="color:{1};">{0:0.0} % {3} {4}</strong> (higher is better)', [double]$Protection.Technical, $bt.Ink, $bt.Tone, $dot, $bt.Name)
    ) -join '<br>')
    # ----- the protection score by asset type: one line per type, both views (#636) -----
    $c = New-Object System.Text.StringBuilder
    [void]$c.Append((ConvertTo-SIMailHeadingHtml 'Protection Score by asset type'))
    $pr = @(Get-RAReportMailValue $Protection 'Rows')
    foreach ($ty in 'Devices', 'Identities', 'Cloud resources', 'Public IPs') {
        $l = @($pr | Where-Object { $_.Figure -eq 'lifecycle' -and $_.Dim1 -eq $ty -and $_.Dim2 -eq '(all)' })
        $tc = @($pr | Where-Object { $_.Figure -eq 'technical' -and $_.Dim1 -eq $ty -and $_.Dim2 -eq '(all)' })
        if ($l.Count -eq 0 -or $null -eq $l[0].Value) { continue }
        [void]$c.Append((ConvertTo-SIMailLineHtml -Topic $ty -Html ([string]::Format($inv, '<strong>{0:0.0} %</strong> within Accepted Lifecycle {1} {2:0.0} % Actual Risks {1} {3:N0} assets', [double]$l[0].Value, $dot, [double]$tc[0].Value, [int]$l[0].Total))))
    }
    $gr = Get-RAReportMailValue $Protection 'Grace'; $gv = @(@($(if ($gr -is [System.Collections.IDictionary]) { $gr.Values } elseif ($null -ne $gr) { $gr.PSObject.Properties | ForEach-Object { $_.Value } })) | Sort-Object -Unique)
    $gw = $(if ($gv.Count -eq 1) { [string]::Format($inv, '{0} days', $gv[0]) } else { 'per asset type (your settings)' })
    [void]$c.Append([string]::Format($inv, '<p style="{0}font-size:12px;line-height:1.5;color:{1};margin:4px 0 14px 0;">Higher is better {2} the share of active assets with no open Very High / High finding, tier-weighted {2} accepted lifecycle: {3} (per your settings) {2} {4:N0} of {5:N0} counted findings had no usable date and count as open.</p>', $L.Font, $L.Muted, $dot, $gw, [long]$Protection.NoDate, [long]$Protection.Findings))
    @{ Summary = $sum; Types = $c.ToString() }
}

function Set-RAReportMailProtection {
    <#
        PURE. A mail that waited for its score (ConvertTo-RAReportMailHtml -ProtectionPending) with the score put in its two
        places (ConvertTo-RAReportMailProtectionHtml). A body without the marks is returned as it is.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, $Protection, [string]$Reason)
    $p = ConvertTo-RAReportMailProtectionHtml -Protection $Protection -Reason $Reason
    $BodyHtml.Replace($script:RAMailProtectionSummaryMark, [string]$p.Summary).Replace($script:RAMailProtectionTypesMark, [string]$p.Types)
}

function ConvertTo-RAReportMailHeldHtml {
    <#
        PURE. SUP-2026-00322: the reports SI held ON PURPOSE this run (#901: a source that went silent, an incomplete role
        read) as plain "Topic: text" lines (#728, no table) -- "Held on purpose: <report> -- <why>. Its last complete result is
        shown; nothing of it is closed." Every value encoded (ConvertTo-SIMailLineHtml -Text). '' when there is none.
    #>
    # #902: an entry with KeptResultAt says when the kept result is from; an ESCALATED entry (Escalated: a Detailed hold of
    # escalateAfterDetailedRuns runs in a row -- a real problem) is a "Needs attention" line with its runs and its code
    # (data-model/hold-kinds.locked.json escalationCode) -- the result is still the last complete one, nothing is closed.
    param([AllowEmptyCollection()][object[]]$Held = @())
    $sb = New-Object System.Text.StringBuilder
    foreach ($h in @($Held | Where-Object { $_ })) {
        $r = [string](Get-RAReportMailValue $h 'Report')
        if (-not $r.Trim()) { continue }
        $w = ([string](Get-RAReportMailValue $h 'Why')).Trim().TrimEnd('.')
        $kept = Get-RAReportMailValue $h 'KeptResultAt'
        $keptText = ''
        if ($null -ne $kept -and "$kept" -ne '') { try { $keptText = (' The kept result is from {0} UTC.' -f ([datetime]$kept).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)) } catch { $keptText = '' } }
        if ([bool](Get-RAReportMailValue $h 'Escalated')) {
            $code = ''; try { if (Get-Command -Name Get-SIHoldKindCode -ErrorAction SilentlyContinue) { $code = Get-SIHoldKindCode -Kind ([string](Get-RAReportMailValue $h 'Kind')) -Escalated } } catch { $code = '' }
            $n = 0; [void][int]::TryParse([string](Get-RAReportMailValue $h 'HeldRuns'), [ref]$n)
            $t = ('{0} has kept its last complete result for {1} Detailed runs in a row{2}. Nothing of it is closed.{3} SecurityInsight support has been told{4}.' -f $r, $n, $(if ($w) { ' -- ' + $w } else { '' }), $keptText, $(if ($code) { ' (' + $code + ')' } else { '' }))
            [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic 'Needs attention' -Text $t))
            continue
        }
        $t = if ($w) { '{0} -- {1}. Its last complete result is shown; nothing of it is closed.' -f $r, $w } else { '{0}. Its last complete result is shown; nothing of it is closed.' -f $r }
        $t += $keptText
        [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic 'Held on purpose' -Text $t))
    }
    $sb.ToString()
}

function ConvertTo-RAReportMailHtml {
    <#
        PURE. The Risk Analysis report mail (#728 layout). -Kpi: $global:RA_KPI's shape (SevCount, SevByDomain, TotalRows,
        Protection = Complete-SIProtectionTally's answer, $null in a run without it -- the Summary run). -ReportLabel / -TenantTag / -GeneratedAt / -SolutionVersion: plain text (encoded
        here). -NoticeHtml / -GrainNoteHtml / -CodeSectionHtml / -AiSectionHtml: trusted fragments the engine built with
        encoded values. -NotComplete: a report of this run did not complete (the summary says so). -GroupingsHtml (#636):
        the management summary of the Detailed findings (ConvertTo-RAReportMailGroupingsHtml), after the risk by domain.
        Returns the HTML.
    #>
    param([Parameter(Mandatory)]$Kpi, [string]$ReportLabel, [string]$TenantTag, [string]$GeneratedAt, [string]$SolutionVersion,
          [string]$NoticeHtml, [string]$GrainNoteHtml, [string]$CodeSectionHtml, [string]$AiSectionHtml, [switch]$NotComplete,
          [string]$GroupingsHtml,
          # #636: "Missing patches" by patch cycle (engine\_shared\SI-PatchCycle.ps1 ConvertTo-SIPatchCycleMailHtml) -- after the summary
          [string]$PatchHtml,
          # the one plain reason when -Kpi carries no score (Get-SIProtectionReason); -ProtectionPending (Pro): the score is not
          # known yet -- its two places are marked and the data sync fills them from the stored figures (Set-RAReportMailProtection)
          [string]$ProtectionReason, [switch]$ProtectionPending,
          # SUP-2026-00322: the reports held ON PURPOSE this run (#901; Split-RAReportFailures .Held -- @{ Report; Kind; Why }):
          # one plain line each, as information, never in the 'Not complete' line (that one is -NotComplete: the real ones)
          [AllowEmptyCollection()][object[]]$HeldReports = @())
    $L = $script:SIMailLayout
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $dot = [string][char]0x00B7
    $sev = $Kpi.SevCount
    $sbd = $Kpi.SevByDomain
    $prot = Get-RAReportMailValue $Kpi 'Protection'
    $crit = [int](Get-RAReportMailValue $sev 'Critical'); $high = [int](Get-RAReportMailValue $sev 'High')
    $total = [long]$Kpi.TotalRows
    $protHtml = $(if ($ProtectionPending) { @{ Summary = $script:RAMailProtectionSummaryMark; Types = $script:RAMailProtectionTypesMark } }
                  else { ConvertTo-RAReportMailProtectionHtml -Protection $prot -Reason $ProtectionReason })

    # ----- the summary: 2-4 short lines -----
    $sum = New-Object System.Collections.Generic.List[string]
    $sum.Add([string]$protHtml.Summary)
    $sum.Add(('Total: <strong>{0}</strong> {1} {2}' -f $total, [char]0x2014, (ConvertTo-RAReportMailSeverityText $sev)))
    if ($NotComplete) { $sum.Add('<strong>Not complete:</strong> a report of this run did not finish &mdash; see the references below.') }
    if ($crit -gt 0) { $sum.Add(('<strong>Action needed:</strong> {0} very high &mdash; start with those.' -f $crit)) }
    elseif ($high -gt 0) { $sum.Add(('No very high findings; {0} high to plan.' -f $high)) }
    else { $sum.Add('No very high or high findings &mdash; no action needed.') }

    $c = New-Object System.Text.StringBuilder
    [void]$c.Append((ConvertTo-SIMailSummaryHtml -Html @($sum)))
    if ("$NoticeHtml".Trim()) { [void]$c.Append($NoticeHtml) }
    # ----- the reports held on purpose: one plain line each, every value encoded (SUP-2026-00322) -----
    [void]$c.Append((ConvertTo-RAReportMailHeldHtml -Held $HeldReports))
    # #636 (owner 2026-10-19: "include both angles with gaps vs. monthly lifecycle"): the missing patches as their three groups
    if ("$PatchHtml".Trim()) { [void]$c.Append($PatchHtml) }

    # ----- findings by domain: one line per domain, the total in bold -----
    [void]$c.Append((ConvertTo-SIMailHeadingHtml 'Findings by domain'))
    foreach ($d in @(@('Endpoint', 'Endpoint'), @('Identity', 'Identity'), @('Azure', 'Azure'), @('Public IP', 'PublicIP'))) {
        $row = Get-RAReportMailValue $sbd $d[1]
        $n = 0; try { $x = Get-RAReportMailValue $row 'Total'; if ($null -ne $x) { $n = $x } } catch { }
        [void]$c.Append((ConvertTo-SIMailLineHtml -Topic $d[0] -Html ('{0} {1} {2}' -f $n, [char]0x2014, (ConvertTo-RAReportMailSeverityText $row))))
    }
    [void]$c.Append((ConvertTo-SIMailLineHtml -Topic 'Total' -Html ('<strong>{0}</strong> {1} {2}' -f $total, [char]0x2014, (ConvertTo-RAReportMailSeverityText $sev))))
    if ("$GrainNoteHtml".Trim()) { [void]$c.Append(('<p style="{0}font-size:12px;line-height:1.5;color:{1};margin:4px 0 14px 0;">{2}</p>' -f $L.Font, $L.Muted, $GrainNoteHtml)) }

    # ----- the protection score by asset type: one line per type, both views (#636) -----
    if ("$($protHtml.Types)") { [void]$c.Append([string]$protHtml.Types) }
    # ----- the management summary: the Summary groupings of this run (#636) -----
    if ("$GroupingsHtml".Trim()) { [void]$c.Append($GroupingsHtml) }

    # ----- the body copy -----
    [void]$c.Append(('<p style="{0}font-size:14px;line-height:1.55;margin:18px 0 14px 0;">The attached Excel report contains the full prioritized list of findings ranked by RiskScore, with evidence and asset detail on the <em>Details</em> sheet.</p>' -f $L.Font))
    if ("$CodeSectionHtml".Trim()) { [void]$c.Append($CodeSectionHtml) }
    if ("$AiSectionHtml".Trim()) { [void]$c.Append($AiSectionHtml) }

    # ----- the footer: plain lines -----
    $ver = if ("$SolutionVersion".Trim()) { [string]$SolutionVersion } else { '(dev)' }
    $a = { param($href, $text) '<a href="{0}" style="color:#2c5a8e;text-decoration:none;">{1}</a>' -f $href, $text }
    $foot = ('SecurityInsight {0} Risk Analysis {0} {1}<br>' -f $dot, (& $a 'https://github.com/KnudsenMorten/SecurityInsight' 'github.com/KnudsenMorten/SecurityInsight')) +
            ('Support: Community {0} {1} {0} Pro {0} {2} {0} Contact {0} {3}<br>' -f $dot, (& $a 'https://github.com/KnudsenMorten/SecurityInsight/issues' 'GitHub issues'), (& $a 'mailto:support@invardia.com' 'support@invardia.com'), (& $a 'mailto:info@invardia.com' 'info@invardia.com')) +
            ('Invardia &ndash; a brand of 2LINKIT, founded and owned by Morten Knudsen.<br>') +
            ('<strong>Build:</strong> v{0}' -f (& $e $ver))

    $sub = @(@($ReportLabel, $TenantTag, $GeneratedAt) | Where-Object { "$_".Trim() }) -join (' ' + $dot + ' ')
    New-SIMailFrameHtml -Brand ('SecurityInsight ' + $dot + ' Risk Analysis') -Subtitle $sub -ContentHtml $c.ToString() -FooterHtml $foot
}

function ConvertTo-RAReportMailGroupingsHtml {
    <#
        PURE. #636 THE MANAGEMENT SUMMARY of the Detailed findings (owner 2026-10-19: "community must switch" / "same core
        functionality"): the groupings THE engine function computed (Invoke-SISummaryGrouping, data-model\
        summary-groupings.locked.json) as mail lines, in the #728 layout -- per tier, per security domain, the top
        recommendations with their affected assets, per risk rating. What the Summary report's mail carried, now from the
        Detailed result; no second summary logic. -Result: Invoke-SISummaryGrouping's rows. -Counted: the variant without the
        exempted findings (SI_Exempted_CountInManagement). -Top: how many recommendations are listed. '' when there is nothing.
    #>
    param([AllowEmptyCollection()][object[]]$Result = @(), [bool]$Counted = $false, [int]$Top = 10)
    if (-not @($Result).Count) { return '' }
    if (-not (Get-Command -Name Select-SISummaryGroupingRows -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-SummaryGroupings.ps1')) }
    $L = $script:SIMailLayout
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $dash = [string][char]0x2014
    $line = { param($r) '<strong>{0}</strong> finding(s) on <strong>{1}</strong> asset(s)' -f [long]$r.Findings, [long]$r.Assets }
    $c = New-Object System.Text.StringBuilder
    [void]$c.Append((ConvertTo-SIMailHeadingHtml 'Management summary'))
    [void]$c.Append(('<p style="{0}font-size:12px;line-height:1.5;color:{1};margin:0 0 10px 0;">Grouped from the detailed findings of this run: every finding is counted (one finding = one issue on one asset).</p>' -f $L.Font, $L.Muted))
    $tiers = @(Select-SISummaryGroupingRows -Result $Result -GroupingId 'tier' -Counted $Counted | Sort-Object { if ($_.Key1 -match '^\d$') { [int]$_.Key1 } else { 9 } })
    foreach ($r in $tiers) {
        $topic = if ($r.Key1 -match '^\d$') { 'Tier ' + $r.Key1 } else { 'Unclassified' }
        [void]$c.Append((ConvertTo-SIMailLineHtml -Topic $topic -Html (& $line $r)))
    }
    $doms = @(Select-SISummaryGroupingRows -Result $Result -GroupingId 'domain' -Counted $Counted)
    if ($doms.Count) {
        [void]$c.Append((ConvertTo-SIMailHeadingHtml 'Findings per domain'))
        foreach ($r in $doms) { [void]$c.Append((ConvertTo-SIMailLineHtml -Topic $(if ($r.Key1) { [string]$r.Key1 } else { '(no domain)' }) -Html (& $line $r))) }
    }
    $recs = @(Select-SISummaryGroupingRows -Result $Result -GroupingId 'recommendation' -Counted $Counted |
        Sort-Object -Property @{ Expression = { [long]$_.Assets }; Descending = $true }, @{ Expression = { [double]$(if ($null -ne $_.MaxRisk) { $_.MaxRisk } else { 0 }) }; Descending = $true }, @{ Expression = { [string]$_.Key1 } } |
        Select-Object -First $Top)
    if ($recs.Count) {
        [void]$c.Append((ConvertTo-SIMailHeadingHtml ('Top {0} recommendations by affected assets' -f $recs.Count)))
        foreach ($r in $recs) {
            $name = if ("$($r.Label)".Trim()) { [string]$r.Label } else { [string]$r.Key1 }
            [void]$c.Append((ConvertTo-SIMailLineHtml -Topic $name -Html ('<strong>{0}</strong> asset(s) {1} {2} finding(s)' -f [long]$r.Assets, $dash, [long]$r.Findings)))
        }
    }
    $ratings = @(Select-SISummaryGroupingRows -Result $Result -GroupingId 'risk-rating' -Counted $Counted | Where-Object { $_.Key1 })
    if ($ratings.Count) {
        [void]$c.Append((ConvertTo-SIMailHeadingHtml 'Per risk rating'))
        foreach ($r in $ratings) { [void]$c.Append((ConvertTo-SIMailLineHtml -Topic ([string]$r.Key1) -Html (& $line $r))) }
    }
    $c.ToString()
}
