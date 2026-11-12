#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE EXEMPTION MAILS (#252), a step of the close-loop mail job.

    1. The OUTBOX: the web app queues a request mail (to a domain's approvers) and a decision mail (to the requester) in
       cfg.ExemptionMail; this step sends every queued mail and stamps SentAt (a failure counts Attempts and keeps
       LastError; after 5 attempts a mail is left alone).
    2. EXPIRY WARNINGS: once per exemption, end date and owner, when an active exemption comes within
       SIWeb_ExemptionExpiryWarningDays of its end, each of its owners gets ONE mail listing all of theirs.
    3. THE MONTHLY REVIEW: from SIWeb_ExemptionReviewDayOfMonth on, once per OWNER per month, every owner gets ONE
       review of everything they own -- expiring soon, expired, and all active -- with ONE link to the web app's review
       page. A person who owns several domains / categories gets one combined review, never one per node.
    Warnings and reviews are queued in cfg.ExemptionMail too (Kind expiry | review, one recipient each) and then sent like
    the rest, so there is one send path, and the table is what tells the next run what was already sent (per recipient:
    a per-domain review queued before #283 counts for every person it went to).

    Owners (#283, two levels): the Domain Owners (cfg.DomainRole, Role 'owner') of the exemption's domain plus the '*'
    (every domain) owners, AND the Category Owners (cfg.CategoryRole) of the exemption's category in that domain. A
    category owner's review lists the exemptions of their category; a domain owner's the whole domain. An exemption made
    before domains existed belongs to the '*' owners. One nobody owns is reported, not mailed.
    Settings: the web app's own (scope 'engine:management-web' in cfg.Setting), read here directly -- as the close-loop
    mail already reads the web app's address. SIWeb_ExemptionMailEnabled off = nothing is queued or sent.

    TWO SEAMS, so it is testable offline: -Invoke (sql, params, 'reader'|'scalar'|'nonquery') and -Send (to, subject,
    html) -- by default Send-SICloseLoopMail, i.e. the Risk Analysis SMTP transports. There is no second SMTP stack.
    Writes ONLY cfg.ExemptionMail. PS 5.1 safe.
#>

# MAIL-2 / #573: the one mail layout (free text keeps its line breaks)
if (-not (Get-Command -Name ConvertTo-SIMailInlineHtml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-MailLayout.ps1')) }
# owner 2026-10-16: the management summary carries "See details and history: <portal link>" at its top (SI-InvardiaPortalLink.ps1)
if (-not (Get-Command -Name Add-SIInvardiaPortalLinkAnchor -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-InvardiaPortalLink.ps1')) }
$script:SIExemptionInvariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:SIExemptionMaxAttempts = 5
$script:SIExemptionReviewPath = '/Exemptions/Review'

# ------------------------------------------------------------------------------------------------------------------
#  SQL -- pure text
# ------------------------------------------------------------------------------------------------------------------

function Get-SIExemptionMailProbeSql {
    "SELECT CASE WHEN OBJECT_ID('cfg.ExemptionMail') IS NOT NULL AND OBJECT_ID('cfg.DomainRole') IS NOT NULL AND COL_LENGTH('cfg.Exemption', 'ReviewedAt') IS NOT NULL THEN 1 ELSE 0 END AS Ready"
}

function Get-SIExemptionMailSettingsSql {
    "SELECT Name, ValueJson FROM cfg.Setting WHERE Scope = N'engine:management-web' AND (Name LIKE N'SIWeb[_]Exemption%' OR Name = N'SIWeb_PublicBaseUrl');"
}

function Get-SIExemptionMailOwnersSql {
    # #283: both levels; a database without cfg.CategoryRole yet answers the domain owners only (Category NULL)
    "IF OBJECT_ID(N'cfg.CategoryRole') IS NOT NULL SELECT Domain, CAST(NULL AS nvarchar(128)) AS Category, Principal FROM cfg.DomainRole WHERE Role = N'owner' AND RemovedAt IS NULL UNION ALL SELECT Domain, Category, Principal FROM cfg.CategoryRole WHERE Role = N'owner' AND RemovedAt IS NULL; ELSE SELECT Domain, CAST(NULL AS nvarchar(128)) AS Category, Principal FROM cfg.DomainRole WHERE Role = N'owner' AND RemovedAt IS NULL;"
}

function Get-SIExemptionMailExemptionsSql {
    # #283: with the exemption's Category where the database carries it (through sp_executesql: the column may not exist yet)
    $cols = 'ExemptionId, Scope, ReportName, ConfigurationId, Cve, AssetKey, Reason, ExpiresAt, CreatedBy, CreatedAt, Domain, ApprovedBy, ApprovedAt, ReviewedAt'
    "IF COL_LENGTH(N'cfg.Exemption', N'Category') IS NOT NULL EXEC sp_executesql N'SELECT $cols, Category FROM cfg.Exemption WHERE RevokedAt IS NULL;'; ELSE SELECT $cols, CAST(NULL AS nvarchar(128)) AS Category FROM cfg.Exemption WHERE RevokedAt IS NULL;"
}

function Get-SIExemptionMailHistorySql {
    "SELECT Kind, Domain, PeriodKey, ItemsJson, ToList FROM cfg.ExemptionMail WHERE Kind IN (N'expiry', N'review') AND QueuedAt > DATEADD(day, -400, SYSUTCDATETIME());"
}

function Get-SIExemptionMailPendingSql {
    "SELECT TOP (500) MailId, Kind, ToList, Subject, BodyHtml, Attempts FROM cfg.ExemptionMail WHERE SentAt IS NULL AND Attempts < $($script:SIExemptionMaxAttempts) ORDER BY MailId;"
}

function Get-SIExemptionMailQueueSql {
    "INSERT cfg.ExemptionMail (Kind, Domain, PeriodKey, ToList, Subject, BodyHtml, ItemsJson, QueuedBy) VALUES (@Kind, @Domain, @PeriodKey, @ToList, @Subject, @BodyHtml, @ItemsJson, N'SecurityInsight');"
}

function Get-SIExemptionMailSentSql {
    "UPDATE cfg.ExemptionMail SET SentAt = SYSUTCDATETIME(), Attempts = Attempts + 1, LastError = NULL WHERE MailId = @MailId AND SentAt IS NULL;"
}

# #258: the department SIGN-IN mails (a personal link, a one-time code) wait in their own outbox, cfg.SignInMail. One
# older than a day is never sent (its link or code is dead by then), and a sent one's body is BLANKED: it carried a
# one-time secret, and the database keeps only the hashes the web app stored.
function Get-SIExemptionMailSignInPendingSql {
    "IF OBJECT_ID(N'cfg.SignInMail') IS NOT NULL SELECT TOP (200) MailId, Kind, ToList, Subject, BodyHtml, Attempts FROM cfg.SignInMail WHERE SentAt IS NULL AND Attempts < $($script:SIExemptionMaxAttempts) AND QueuedAt > DATEADD(hour, -24, SYSUTCDATETIME()) ORDER BY MailId;"
}

function Get-SIExemptionMailSignInSentSql {
    "UPDATE cfg.SignInMail SET SentAt = SYSUTCDATETIME(), Attempts = Attempts + 1, LastError = NULL, BodyHtml = N'(removed once sent: it carried a one-time sign-in secret)' WHERE MailId = @MailId AND SentAt IS NULL;"
}

function Get-SIExemptionMailSignInFailedSql {
    "UPDATE cfg.SignInMail SET Attempts = Attempts + 1, LastError = LEFT(@Error, 1000) WHERE MailId = @MailId AND SentAt IS NULL;"
}

# #291: the scheduled management summaries (and "send now") wait in their own outbox, cfg.ReportMail; the body is kept.
function Get-SIReportMailPendingSql {
    # owner 2026-10-29: a management summary mail carries the management presentation (PowerPoint) -- AttachmentName /
    # AttachmentBytes, written by the web app with the mail. A database without the columns yet (the settings schema adds
    # them) is read as before: the mail goes without the file, and it says where to download it.
    $cols = 'MailId, ToList, Subject, BodyHtml, Attempts'
    $where = "FROM cfg.ReportMail WHERE SentAt IS NULL AND Attempts < $($script:SIExemptionMaxAttempts) ORDER BY MailId;"
    "IF OBJECT_ID(N'cfg.ReportMail') IS NOT NULL BEGIN IF COL_LENGTH(N'cfg.ReportMail', N'AttachmentBytes') IS NOT NULL EXEC sp_executesql N'SELECT TOP (200) $cols, AttachmentName, AttachmentBytes $where'; ELSE SELECT TOP (200) $cols $where END"
}

function ConvertTo-SIReportMailFileName {
    <# PURE. The attachment's file name as the mail shows it: no character a file system refuses, at most 120 characters,
       always .pptx (the only file this outbox carries); empty = 'SecurityInsight - Monthly management pack.pptx'. #>
    param([AllowNull()][AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    # a FIXED set (Windows' refused characters: control characters and " < > | : * ? \ /), never the OS's list -- the
    # engine runs in Linux containers, where [IO.Path]::GetInvalidFileNameChars() is only NUL and '/', and the recipient
    # saves the attachment on Windows
    $n = $n -replace '[\x00-\x1F"<>|:*?\\/]', ' '
    $n = ($n -replace '\s+', ' ').Trim()
    if ($n -match '(?i)\.pptx$') { $n = $n.Substring(0, $n.Length - 5).Trim() }
    if (-not $n) { $n = 'SecurityInsight - Monthly management pack' }
    if ($n.Length -gt 120) { $n = $n.Substring(0, 120).Trim() }
    $n + '.pptx'
}

function Get-SIReportMailAttachmentBytes {
    <# The attachment of a pending row, as byte[] (null = none). Read in plain statements: a byte[] returned through the
       pipeline would be unrolled into single bytes, so the caller gets it wrapped in a one-element array. #>
    param($Row)
    $b = $null
    if ($null -eq $Row) { return , $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('AttachmentBytes')) { $b = $Row['AttachmentBytes'] } }
    elseif ($Row.PSObject.Properties['AttachmentBytes']) { $b = $Row.AttachmentBytes }
    if ($b -is [System.DBNull]) { $b = $null }
    if ($b -isnot [byte[]] -or $b.Length -eq 0) { return , $null }
    return , $b
}

function Get-SIReportMailSentSql {
    "UPDATE cfg.ReportMail SET SentAt = SYSUTCDATETIME(), Attempts = Attempts + 1, LastError = NULL WHERE MailId = @MailId AND SentAt IS NULL;"
}

function Get-SIReportMailFailedSql {
    "UPDATE cfg.ReportMail SET Attempts = Attempts + 1, LastError = LEFT(@Error, 1000) WHERE MailId = @MailId AND SentAt IS NULL;"
}

function Get-SIExemptionMailFailedSql {
    "UPDATE cfg.ExemptionMail SET Attempts = Attempts + 1, LastError = LEFT(@Error, 1000) WHERE MailId = @MailId AND SentAt IS NULL;"
}

# ------------------------------------------------------------------------------------------------------------------
#  PURE
# ------------------------------------------------------------------------------------------------------------------

function Get-SIExemptionValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [System.DBNull]) { return $null }
    return $v
}

function ConvertTo-SIExemptionMailSettings {
    <# PURE. cfg.Setting rows (Name, ValueJson) -> @{ MailEnabled; ReviewDay; WarningDays; WebBaseUrl }, defaults on anything unreadable. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $vals = @{}
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $n = [string](Get-SIExemptionValue $r 'Name'); $j = Get-SIExemptionValue $r 'ValueJson'
        if (-not $n -or $null -eq $j) { continue }
        try { $vals[$n] = ConvertFrom-Json -InputObject ([string]$j) } catch { }
    }
    $int = {
        param($n, $def, $min, $max)
        $x = 0
        if ($vals.ContainsKey($n) -and [int]::TryParse([string]$vals[$n], [ref]$x) -and $x -ge $min -and $x -le $max) { return $x }
        return $def
    }
    $enabled = $true
    if ($vals.ContainsKey('SIWeb_ExemptionMailEnabled')) { $enabled = -not ("$($vals['SIWeb_ExemptionMailEnabled'])" -in 'False', 'false', '0') }
    [pscustomobject]@{
        MailEnabled = [bool]$enabled
        ReviewDay   = (& $int 'SIWeb_ExemptionReviewDayOfMonth' 1 1 28)
        WarningDays = (& $int 'SIWeb_ExemptionExpiryWarningDays' 30 0 180)
        WebBaseUrl  = $(if ($vals.ContainsKey('SIWeb_PublicBaseUrl')) { "$($vals['SIWeb_PublicBaseUrl'])".Trim().TrimEnd('/') } else { '' })
    }
}

function Get-SIExemptionDomainKey {
    param($Exemption)
    $d = [string](Get-SIExemptionValue $Exemption 'Domain')
    if ($d.Trim()) { return $d.Trim() }
    return '*'
}

function Get-SIExemptionCategoryKey {
    <# PURE. A category as the roster keys it (#283): trimmed, at most 128 characters; blank = none. #>
    param($Value)
    $c = ([string]$Value).Trim()
    if (-not $c) { return '' }
    if ($c.Length -gt 128) { $c = $c.Substring(0, 128) }
    return $c
}

function Get-SIExemptionOwnersOf {
    <# PURE. The Domain Owners of a domain: its own plus the '*' (every domain) owners -- domain level only -- lower case, each once. #>
    param([AllowEmptyCollection()][object[]]$Owners = @(), [string]$Domain)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($o in @($Owners | Where-Object { $null -ne $_ })) {
        if (Get-SIExemptionCategoryKey (Get-SIExemptionValue $o 'Category')) { continue }
        $d = [string](Get-SIExemptionValue $o 'Domain')
        if ($d -ieq $Domain -or $d -eq '*') {
            $p = ([string](Get-SIExemptionValue $o 'Principal')).Trim().ToLowerInvariant()
            if ($p -and -not $out.Contains($p)) { $out.Add($p) }
        }
    }
    return $out.ToArray()
}

function Get-SIExemptionReviewersOf {
    <#
        PURE (#283). Who reviews an exemption of (Domain, Category): the Category Owners of that category in that domain
        plus the Domain Owners (its own and '*'), lower case, each once.
    #>
    param([AllowEmptyCollection()][object[]]$Owners = @(), [string]$Domain, [string]$Category = '')
    $out = New-Object System.Collections.Generic.List[string]
    $cat = Get-SIExemptionCategoryKey $Category
    if ($cat) {
        foreach ($o in @($Owners | Where-Object { $null -ne $_ })) {
            $oc = Get-SIExemptionCategoryKey (Get-SIExemptionValue $o 'Category')
            if ($oc -and $oc -ieq $cat -and ([string](Get-SIExemptionValue $o 'Domain')) -ieq $Domain) {
                $p = ([string](Get-SIExemptionValue $o 'Principal')).Trim().ToLowerInvariant()
                if ($p -and -not $out.Contains($p)) { $out.Add($p) }
            }
        }
    }
    foreach ($p in @(Get-SIExemptionOwnersOf -Owners $Owners -Domain $Domain)) { if (-not $out.Contains($p)) { $out.Add($p) } }
    return $out.ToArray()
}

function Get-SIExemptionNodeLabel {
    <# PURE. 'Identity', 'Identity / Authentication', 'every domain'. #>
    param([string]$Domain, [string]$Category = '')
    $d = if ($Domain -eq '*') { 'every domain' } else { $Domain }
    if ($Category) { return ('{0} / {1}' -f $d, $Category) }
    return $d
}

function Get-SIExemptionOwnedNodes {
    <# PURE. The nodes one person owns, both levels, as @{ Domain; Category } (Category '' = the whole domain), sorted. #>
    param([AllowEmptyCollection()][object[]]$Owners = @(), [string]$Person)
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in @($Owners | Where-Object { $null -ne $_ })) {
        if (([string](Get-SIExemptionValue $o 'Principal')).Trim() -ine $Person) { continue }
        $d = [string](Get-SIExemptionValue $o 'Domain'); $c = Get-SIExemptionCategoryKey (Get-SIExemptionValue $o 'Category')
        $k = ('{0}|{1}' -f $d, $c).ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out.Add([pscustomobject]@{ Domain = $d; Category = $c })
    }
    return @($out.ToArray() | Sort-Object Domain, Category)
}

function Get-SIExemptionWhat {
    param($E)
    $what = [string](Get-SIExemptionValue $E 'Cve'); if (-not $what) { $what = [string](Get-SIExemptionValue $E 'ConfigurationId') }
    $asset = [string](Get-SIExemptionValue $E 'AssetKey')
    switch ([string](Get-SIExemptionValue $E 'Scope')) {
        'asset' { return ('every finding on {0}' -f $asset) }
        'issue' { return ('{0} on every asset' -f $what) }
        default { return ('{0} on {1}' -f $what, $asset) }
    }
}

function Get-SIExemptionExpiryKey {
    param($E)
    $x = Get-SIExemptionValue $E 'ExpiresAt'
    $t = if ($x) { ([datetime]$x).ToString('yyyy-MM-ddTHH:mm:ss', $script:SIExemptionInvariant) } else { '' }
    return ('{0}|{1}' -f [string](Get-SIExemptionValue $E 'ExemptionId'), $t)
}

function ConvertTo-SIExemptionMailHtml {
    <#
        PURE. One mail in the one SI mail layout (#728: no tables, readable on a phone): a summary first (the lede -- what
        to do -- and the count per section), then each section with its heading and ONE LINE PER EXEMPTION
        ("#12 CVE-... on dc-a: until 2026-11-30, Endpoint -- Reason: ..."), then the one link button.
    #>
    param([string]$Title, [string]$Lede, [object[]]$Sections = @(), [string]$Link, [string]$LinkText = 'Review them')
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $muted = 'font-family:Segoe UI,Arial,sans-serif;font-size:12px;line-height:1.5;color:#5a6a7a;margin:0 0 14px 0;'
    $counts = @(@($Sections) | ForEach-Object { '{0}: <strong>{1}</strong>' -f (& $enc $_.Title), @($_.Rows).Count })
    $summary = @((ConvertTo-SIMailInlineHtml $Lede))
    if ($counts.Count) { $summary += ($counts -join ' &middot; ') }
    $body = New-Object System.Text.StringBuilder
    [void]$body.Append((ConvertTo-SIMailSummaryHtml -Html $summary))
    foreach ($s in @($Sections)) {
        $rows = @($s.Rows)
        [void]$body.Append((ConvertTo-SIMailHeadingHtml ('{0} ({1})' -f $s.Title, $rows.Count)))
        if ($rows.Count -eq 0) { [void]$body.Append(('<p style="{0}">None.</p>' -f $muted)); continue }
        foreach ($e in ($rows | Select-Object -First 200)) {
            $x = Get-SIExemptionValue $e 'ExpiresAt'
            $until = if ($x) { ([datetime]$x).ToString('yyyy-MM-dd', $script:SIExemptionInvariant) } else { 'no end date' }
            # #283: which domain / category it is filed under -- a combined review spans several
            $scope = Get-SIExemptionNodeLabel -Domain (Get-SIExemptionDomainKey $e) -Category (Get-SIExemptionCategoryKey (Get-SIExemptionValue $e 'Category'))
            $reason = ConvertTo-SIMailInlineHtml (Get-SIExemptionValue $e 'Reason')
            $text = ('until <strong>{0}</strong> &middot; <span style="color:#5a6a7a;">{1}</span>' -f $until, (& $enc $scope))
            if ($reason) { $text += ('<br>Reason: {0}' -f $reason) }
            [void]$body.Append((ConvertTo-SIMailLineHtml -Topic ('#{0} {1}' -f (Get-SIExemptionValue $e 'ExemptionId'), (Get-SIExemptionWhat $e)) -Html $text))
        }
        if ($rows.Count -gt 200) { [void]$body.Append(('<p style="{0}">... and {1} more -- the link shows them all.</p>' -f $muted, ($rows.Count - 200))) }
    }
    if ("$Link" -match '^https?://') {
        [void]$body.Append((ConvertTo-SIMailButtonHtml -Url $Link -Text $LinkText))
        [void]$body.Append(('<p style="{0}">{1}</p>' -f $muted, (& $enc $Link)))
    }
    return (New-SIMailFrameHtml -Brand ('SecurityInsight ' + [char]0x00B7 + ' ' + $Title) -ContentHtml $body.ToString() -FooterHtml 'SecurityInsight Pro &middot; Exemptions')
}
function Get-SIExemptionMailPlan {
    <#
        PURE. What this run queues, PER OWNER (#283): each person who owns something -- a domain (level 1) or a category
        (level 2) -- gets ONE expiry warning listing their exemptions newly within the warning window (once per exemption,
        end date and person) and, from the review day on, ONE monthly review of everything they own (once per person per
        month). A person owning several nodes gets one combined mail, never one per node. -History = cfg.ExemptionMail
        rows of kind expiry / review (sent or still queued) with their ToList: a row counts for every person it went to,
        so a per-domain review queued before #283 is not sent again to its recipients. Returns @{ Mails; NoOwner } --
        NoOwner = the domains with exemptions nobody owns (neither a category nor a domain owner).
    #>
    param(
        [AllowEmptyCollection()][object[]]$Exemptions = @(),
        [AllowEmptyCollection()][object[]]$Owners = @(),
        [AllowEmptyCollection()][object[]]$History = @(),
        [Parameter(Mandatory)][datetime]$Now,
        [int]$ReviewDay = 1,
        [int]$WarningDays = 30,
        [string]$WebBaseUrl = ''
    )
    $now = $Now.ToUniversalTime()
    $soonDays = [Math]::Max($WarningDays, 1)
    $mails = New-Object System.Collections.Generic.List[object]
    $noOwner = New-Object System.Collections.Generic.List[string]
    $recipients = {
        param($h)
        @(([string](Get-SIExemptionValue $h 'ToList')) -split '[;,]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }

    # what was already queued: reviews per (person, month), warnings per (person, exemption, end date)
    $warned = @{}; $reviewed = @{}
    foreach ($h in @($History | Where-Object { $null -ne $_ })) {
        $k = [string](Get-SIExemptionValue $h 'Kind')
        $to = & $recipients $h
        if ($k -eq 'review') {
            $pk = [string](Get-SIExemptionValue $h 'PeriodKey')
            foreach ($p in $to) { $reviewed[('{0}|{1}' -f $p, $pk)] = $true }
        }
        elseif ($k -eq 'expiry') {
            $j = Get-SIExemptionValue $h 'ItemsJson'
            if ($j) {
                try {
                    foreach ($i in @(ConvertFrom-Json -InputObject ([string]$j))) {
                        # PowerShell 7 turns a date-looking string into a [datetime]: compare in ONE text form
                        $x = $i.expiresAt
                        $t = if ($x -is [datetime]) { $x.ToString('yyyy-MM-ddTHH:mm:ss', $script:SIExemptionInvariant) } else { [string]$x }
                        foreach ($p in $to) { $warned[('{0}|{1}|{2}' -f $p, $i.id, $t)] = $true }
                    }
                } catch { }
            }
        }
    }

    # who reviews what: every exemption to each of its owners (its category's owners + its domain's owners), each once
    $live = @($Exemptions | Where-Object { $null -ne $_ })
    $byPerson = @{}
    foreach ($e in $live) {
        $d = Get-SIExemptionDomainKey $e
        $c = Get-SIExemptionCategoryKey (Get-SIExemptionValue $e 'Category')
        $to = @(Get-SIExemptionReviewersOf -Owners $Owners -Domain $d -Category $c)
        if ($to.Count -eq 0) {
            $label = Get-SIExemptionNodeLabel -Domain $d
            if (-not $noOwner.Contains($label)) { $noOwner.Add($label) }
            continue
        }
        foreach ($p in $to) {
            if (-not $byPerson.ContainsKey($p)) { $byPerson[$p] = New-Object System.Collections.Generic.List[object] }
            $byPerson[$p].Add($e)
        }
    }

    $isExpired = { param($e) $x = Get-SIExemptionValue $e 'ExpiresAt'; ($null -ne $x -and ([datetime]$x) -le $now) }
    $period = $now.ToString('yyyy-MM', $script:SIExemptionInvariant)
    foreach ($person in @($byPerson.Keys | Sort-Object)) {
        $mine = @($byPerson[$person].ToArray())
        $nodes = @(Get-SIExemptionOwnedNodes -Owners $Owners -Person $person)
        $labels = @($nodes | ForEach-Object { Get-SIExemptionNodeLabel -Domain $_.Domain -Category $_.Category })
        $label = if ($labels.Count -le 3) { $labels -join ', ' } else { ('{0} and {1} more' -f (($labels | Select-Object -First 3) -join ', '), ($labels.Count - 3)) }
        # the one domain (and category) everything they own is in, for the mail's Domain column and its link
        $domainsOwned = @($nodes | ForEach-Object { $_.Domain } | Sort-Object -Unique)
        $oneDomain = if ($domainsOwned.Count -eq 1) { [string]$domainsOwned[0] } else { $null }
        $link = ''
        if ("$WebBaseUrl" -match '^https?://') {
            $q = @()
            if ($oneDomain -and $oneDomain -ne '*') {
                $q += 'domain=' + [uri]::EscapeDataString($oneDomain)
                if ($nodes.Count -eq 1 -and $nodes[0].Category) { $q += 'category=' + [uri]::EscapeDataString($nodes[0].Category) }
            }
            $link = "$WebBaseUrl".TrimEnd('/') + $script:SIExemptionReviewPath + $(if ($q.Count) { '?' + ($q -join '&') } else { '' })
        }
        $active = @($mine | Where-Object { -not (& $isExpired $_) })
        $expired = @($mine | Where-Object { & $isExpired $_ })
        $soon = @($active | Where-Object { $x = Get-SIExemptionValue $_ 'ExpiresAt'; $null -ne $x -and ([datetime]$x) -le $now.AddDays($soonDays) } | Sort-Object { Get-SIExemptionValue $_ 'ExpiresAt' })

        # expiry warning: the ones newly within the window, for this person
        if ($WarningDays -gt 0) {
            $new = @($soon | Where-Object { -not $warned.ContainsKey(('{0}|{1}' -f $person, (Get-SIExemptionExpiryKey $_))) })
            if ($new.Count -gt 0) {
                $items = @($new | ForEach-Object { $p = (Get-SIExemptionExpiryKey $_) -split '\|', 2; [ordered]@{ id = $p[0]; expiresAt = $p[1] } })
                $mails.Add([pscustomobject]@{
                    Kind = 'expiry'; Domain = $oneDomain; PeriodKey = $null; To = @($person)
                    Subject = ('Action needed: {0} exemption(s) you own end within {1} days ({2})' -f $new.Count, $WarningDays, $label)
                    BodyHtml = (ConvertTo-SIExemptionMailHtml -Title ('Exemptions ending soon: ' + $label) -Link $link -LinkText 'Extend, keep or end them' `
                        -Lede ('These exemptions you own ({0}) end within {1} days. Extend the ones still needed; the rest end on their date and their findings count again.' -f $label, $WarningDays) `
                        -Sections @([pscustomobject]@{ Title = 'Ending soon'; Rows = $new }))
                    ItemsJson = (ConvertTo-Json -InputObject @($items) -Compress -Depth 3)
                })
            }
        }

        # monthly review: once per person per month, from the review day on -- everything they own in one mail
        if ($now.Day -ge $ReviewDay -and -not $reviewed.ContainsKey(('{0}|{1}' -f $person, $period))) {
            $mails.Add([pscustomobject]@{
                Kind = 'review'; Domain = $oneDomain; PeriodKey = $period; To = @($person)
                Subject = ('Action needed: Monthly exemption review: {0} -- {1} active, {2} ending soon, {3} expired' -f $label, $active.Count, $soon.Count, $expired.Count)
                BodyHtml = (ConvertTo-SIExemptionMailHtml -Title ('Monthly exemption review: ' + $label) -Link $link -LinkText 'Review them' `
                    -Lede ('As an owner of {0}, review its exemptions: extend what is still needed, keep what stays as it is, end the rest. An exemption nobody reviews is flagged.' -f $label) `
                    -Sections @(
                        [pscustomobject]@{ Title = ('Ending within {0} days' -f $soonDays); Rows = $soon }
                        [pscustomobject]@{ Title = 'Expired'; Rows = $expired }
                        [pscustomobject]@{ Title = 'All active'; Rows = $active }))
                ItemsJson = $null
            })
        }
    }
    [pscustomobject]@{ Mails = $mails.ToArray(); NoOwner = $noOwner.ToArray() }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE RUN
# ------------------------------------------------------------------------------------------------------------------

function Read-SIExemptionRows {
    <# The rows of one read through the -Invoke seam ('reader' hands back ONE array object: unwrap it, drop nulls). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql)
    $raw = (& $Invoke $Sql @{} 'reader')
    , @($raw | Where-Object { $null -ne $_ })
}

function Get-SIExemptionMailDatabase {
    <# PURE. The Pro database: SI_ProSqlServer / _SqlDatabase, else the data backend's, else the close-loop's. #>
    param([hashtable]$Globals = @{})
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    foreach ($pair in @(@('SI_ProSqlServer', 'SI_ProSqlDatabase'), @('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'), @('SI_VulnSync_SqlServer', 'SI_VulnSync_SqlDatabase'))) {
        $s = "$(& $g $pair[0])".Trim(); $d = "$(& $g $pair[1])".Trim()
        if ($s -and $d) { return [pscustomobject]@{ Server = $s; Database = $d } }
    }
    $null
}

function Invoke-SIExemptionMailCore {
    <#
        The whole step behind the two seams. -OutboxOnly (the web app's nudge, SI_EXEMPTION_MAIL_ONLY=1): only send what
        is queued. -SmtpReady $false: nothing is sent and nothing is planned -- the queue waits (one line says why).
        Returns @{ Skipped; Queued; Sent; Failed; Errors; NoOwner }. Never throws for a single mail: the caller fails the
        run when Failed > 0, after every mail was tried.
    #>
    param(
        [hashtable]$Globals = @{},
        [Parameter(Mandatory)][scriptblock]$NewInvoke,
        [Parameter(Mandatory)][scriptblock]$Send,
        [datetime]$Now = [datetime]::UtcNow,
        [bool]$SmtpReady = $true,
        [switch]$OutboxOnly,
        # PRO-COMMUNITY-SAME: the expiry warnings and monthly reviews are governance mails (licensed) -- -NoPlan leaves them
        # out; the outbox (every mail the web app queued: the Get Started reminder, sign-ins, report and test mails) still goes
        [switch]$NoPlan,
        [switch]$DryRun,
        [scriptblock]$Log = { param($level, $msg) Write-Host ("[{0}] {1}" -f $level, $msg) }
    )
    $res = [pscustomobject]@{ Skipped = ''; Queued = 0; Sent = 0; Failed = 0; Errors = @(); NoOwner = @(); Planned = @() }
    $db = Get-SIExemptionMailDatabase -Globals $Globals
    if (-not $db) { $res.Skipped = 'no Pro database is configured (SI_ProSqlServer / SI_ProSqlDatabase) -- no exemption mail.'; & $Log 'INFO' $res.Skipped; return $res }
    $invoke = & $NewInvoke $db.Server $db.Database
    $probeRows = Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailProbeSql)
    $probe = $probeRows | Select-Object -First 1
    if (-not $probe -or [int](Get-SIExemptionValue $probe 'Ready') -ne 1) {
        $res.Skipped = 'the exemption tables are not in the Pro database yet (setup\Import-SIProSettings.ps1 adds them) -- no exemption mail.'; & $Log 'INFO' $res.Skipped; return $res
    }
    $s = ConvertTo-SIExemptionMailSettings -Rows (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailSettingsSql))
    if (-not $s.MailEnabled) { $res.Skipped = 'exemption mails are switched off (SIWeb_ExemptionMailEnabled) -- nothing was sent.'; & $Log 'INFO' $res.Skipped; return $res }
    if (-not $SmtpReady) { $res.Skipped = 'mail is not set up, or is off (SI_Mail_Mode) -- the exemption mails wait in the outbox.'; & $Log 'WARN' $res.Skipped; return $res }

    if (-not $OutboxOnly -and -not $NoPlan) {
        $plan = Get-SIExemptionMailPlan -Exemptions (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailExemptionsSql)) `
            -Owners (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailOwnersSql)) `
            -History (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailHistorySql)) `
            -Now $Now -ReviewDay $s.ReviewDay -WarningDays $s.WarningDays -WebBaseUrl $s.WebBaseUrl
        $res.NoOwner = @($plan.NoOwner)
        $res.Planned = @($plan.Mails)
        foreach ($n in @($plan.NoOwner)) { & $Log 'WARN' ("exemptions in {0} have no owner to review them -- set one on Configuration > Security owners" -f $n) }
        foreach ($m in @($plan.Mails)) {
            if ($DryRun) { & $Log 'INFO' ("would queue {0} for {1}: {2}" -f $m.Kind, $m.Domain, $m.Subject); continue }
            & $invoke (Get-SIExemptionMailQueueSql) @{ Kind = $m.Kind; Domain = $m.Domain; PeriodKey = $m.PeriodKey; ToList = (@($m.To) -join ';'); Subject = $m.Subject; BodyHtml = $m.BodyHtml; ItemsJson = $m.ItemsJson } 'nonquery' | Out-Null
            $res.Queued++
        }
    }
    if ($DryRun) { & $Log 'INFO' 'DRY RUN -- nothing was queued or sent.'; return $res }

    foreach ($p in (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailPendingSql))) {
        $id = Get-SIExemptionValue $p 'MailId'
        $to = @(([string](Get-SIExemptionValue $p 'ToList')) -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        try {
            if ($to.Count -eq 0) { throw 'the mail has no recipient' }
            & $Send $to ([string](Get-SIExemptionValue $p 'Subject')) ([string](Get-SIExemptionValue $p 'BodyHtml'))
            & $invoke (Get-SIExemptionMailSentSql) @{ MailId = $id } 'nonquery' | Out-Null
            $res.Sent++
        } catch {
            $err = $_.Exception.Message
            & $invoke (Get-SIExemptionMailFailedSql) @{ MailId = $id; Error = $err } 'nonquery' | Out-Null
            $res.Failed++; $res.Errors += ('mail {0}: {1}' -f $id, $err)
            & $Log 'WARN' ("exemption mail {0} was not sent: {1}" -f $id, $err)
        }
    }
    # #258: the department sign-in mails, from their own outbox -- the same SMTP path; a sent one's body is blanked
    foreach ($p in (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIExemptionMailSignInPendingSql))) {
        $id = Get-SIExemptionValue $p 'MailId'
        $to = @(([string](Get-SIExemptionValue $p 'ToList')) -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        try {
            if ($to.Count -eq 0) { throw 'the mail has no recipient' }
            # #574: a sign-in link / one-time code never gets a PDF copy (4th argument: no PDF); the test mail does
            $noPdf = ([string](Get-SIExemptionValue $p 'Kind')) -ne 'mail-test'
            & $Send $to ([string](Get-SIExemptionValue $p 'Subject')) ([string](Get-SIExemptionValue $p 'BodyHtml')) $noPdf
            & $invoke (Get-SIExemptionMailSignInSentSql) @{ MailId = $id } 'nonquery' | Out-Null
            $res.Sent++
        } catch {
            $err = $_.Exception.Message
            & $invoke (Get-SIExemptionMailSignInFailedSql) @{ MailId = $id; Error = $err } 'nonquery' | Out-Null
            $res.Failed++; $res.Errors += ('sign-in mail {0}: {1}' -f $id, $err)
            & $Log 'WARN' ("sign-in mail {0} was not sent: {1}" -f $id, $err)
        }
    }
    # #291: the management summaries, from their own outbox -- the same SMTP path
    foreach ($p in (Read-SIExemptionRows -Invoke $invoke -Sql (Get-SIReportMailPendingSql))) {
        $id = Get-SIExemptionValue $p 'MailId'
        $to = @(([string](Get-SIExemptionValue $p 'ToList')) -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        try {
            if ($to.Count -eq 0) { throw 'the mail has no recipient' }
            # owner 2026-10-16: the line to the install's page in the Invardia portal goes at the TOP of a management
            # summary (it has no summary block); the transport fills the place-holder only when the id is known. A mail
            # of this outbox that HAS a summary (the get-started reminder) keeps the line under it.
            $body = Add-SIInvardiaPortalLinkAnchor -BodyHtml ([string](Get-SIExemptionValue $p 'BodyHtml'))
            # the management presentation, when the mail carries one: a file of its own for the transport (which leaves it out
            # over the attachment budget -- the mail's body says where to download it), removed right after the send
            $attBytes = Get-SIReportMailAttachmentBytes $p
            $attDir = $null
            $attPaths = @()
            if ($attBytes -is [byte[]]) {
                $attDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-reportmail-' + [guid]::NewGuid().ToString('N')))
                [void][IO.Directory]::CreateDirectory($attDir)
                $attPath = [IO.Path]::Combine($attDir, (ConvertTo-SIReportMailFileName ([string](Get-SIExemptionValue $p 'AttachmentName'))))
                [IO.File]::WriteAllBytes($attPath, $attBytes)
                $attPaths = @($attPath)
            }
            try { & $Send $to ([string](Get-SIExemptionValue $p 'Subject')) $body $false $attPaths }
            finally { if ($attDir) { Remove-Item -LiteralPath $attDir -Recurse -Force -ErrorAction SilentlyContinue } }
            & $invoke (Get-SIReportMailSentSql) @{ MailId = $id } 'nonquery' | Out-Null
            $res.Sent++
        } catch {
            $err = $_.Exception.Message
            & $invoke (Get-SIReportMailFailedSql) @{ MailId = $id; Error = $err } 'nonquery' | Out-Null
            $res.Failed++; $res.Errors += ('management summary {0}: {1}' -f $id, $err)
            & $Log 'WARN' ("management summary mail {0} was not sent: {1}" -f $id, $err)
        }
    }
    & $Log 'OK' ("exemption mails: {0} queued, {1} sent, {2} failed" -f $res.Queued, $res.Sent, $res.Failed)
    return $res
}
