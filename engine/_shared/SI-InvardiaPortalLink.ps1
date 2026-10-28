#Requires -Version 5.1
<#
    SecurityInsight -- THE CUSTOMER MAIL LINKS STRAIGHT TO THE INSTALL'S PAGE IN THE INVARDIA PORTAL (#710; framework
    DOCS/REQUIREMENTS.md 8.16 "Order and links"; Invardia 1.0.488).

    HOW:
      1. Every IDENTIFIED status report Invardia takes is answered 202 { environmentId } (+ supersededBy when relevant).
         The engine run that hears an id it does not have yet records it in the Pro database (cfg.InstallState
         'InvardiaEnvironment' = {"environmentId":"<guid>","seenUtc":"..."}), on the connection the run already has
         ($global:SI_ProSettingsStore). An anonymous install never gets an id (Invardia returns none) and never a link.
      2. The Pro settings layer reads the row at run start with the other install facts (Read-SIInstallRingFacts ->
         $global:SI_InstallRingFacts.InvardiaEnvironment).
      3. Send-SIMail (SI-MailTransport.ps1) puts ONE line directly under the mail's summary (owner 2026-10-16):
             See details and history: https://portal.invardia.com/#/environments/<environmentId>
         -- only when the id is known (a GUID), only in a mail that HAS a summary, never in a mail that carries a
         one-time secret (-NoPdf: the sign-in mails). No id = no line (never a broken or a start-page link).
         Two mails without a summary carry it at their TOP (owner 2026-10-16, "Add to both"): the daily close-loop mail
         (a place-holder row under its banner) and the management summary (Add-SIInvardiaPortalLinkAnchor, set by the mail
         job before it sends) -- same rules: only a known id, HTML-encoded, once.

    The id is a lower-case GUID (Invardia's inv.SupportEnvironments.EnvironmentId). Anything else is ignored.
    PS 5.1 + 7. No modules.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIPortalLink = @{
    StateName = 'InvardiaEnvironment'                                  # cfg.InstallState row
    UrlFormat = 'https://portal.invardia.com/#/environments/{0}'       # framework 8.16, Invardia 1.0.488
    Text      = 'See details and history:'                             # the owner's wording, 2026-10-16
    Marker    = 'data-si-portal-link'
    Anchor    = '<!-- SI portal link -->'                              # the top of a mail without a summary (flow content)
    RowAnchor = '<!-- SI portal link row -->'                          # the same (kept for an older body; filled like Anchor)
    Guid      = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
}

function ConvertTo-SIInvardiaEnvironmentIdOrEmpty {
    <# PURE. An Invardia environment id as the lower-case GUID it is, or '' when it is not GUID-shaped. #>
    param([AllowNull()][AllowEmptyString()][string]$EnvironmentId)
    $v = "$EnvironmentId".Trim()
    if ($v -match $script:SIPortalLink.Guid) { return $v.ToLowerInvariant() }
    ''
}

function Get-SIInvardiaEnvironmentIdFromAnswer {
    <# PURE. The environmentId of an uplink answer (a parsed body, or its text), '' when none / not a GUID. #>
    param([AllowNull()]$Answer)
    if ($null -eq $Answer) { return '' }
    $o = $Answer
    if ($Answer -is [string]) { if (-not $Answer.Trim()) { return '' }; try { $o = $Answer | ConvertFrom-Json -ErrorAction Stop } catch { return '' } }
    if ($null -eq $o) { return '' }
    $v = ''
    if ($o -is [System.Collections.IDictionary]) { if ($o.Contains('environmentId')) { $v = [string]$o['environmentId'] } }
    elseif ($o.PSObject.Properties['environmentId']) { $v = [string]$o.environmentId }
    ConvertTo-SIInvardiaEnvironmentIdOrEmpty $v
}

function ConvertTo-SIInvardiaEnvironmentValue {
    <# PURE. The cfg.InstallState 'InvardiaEnvironment' value for -EnvironmentId (compact JSON). Throws on a non-GUID. #>
    param([Parameter(Mandatory)][string]$EnvironmentId, $NowUtc)
    $id = ConvertTo-SIInvardiaEnvironmentIdOrEmpty $EnvironmentId
    if (-not $id) { throw "not an Invardia environment id: '$EnvironmentId'" }
    $at = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    ([ordered]@{ environmentId = $id; seenUtc = $at.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress)
}

function Get-SIInvardiaEnvironmentIdFromValue {
    <# PURE. The id in a cfg.InstallState 'InvardiaEnvironment' value (its JSON, or a bare GUID), '' when none. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    if ($v -match $script:SIPortalLink.Guid) { return $v.ToLowerInvariant() }
    Get-SIInvardiaEnvironmentIdFromAnswer $v
}

function Get-SIInvardiaPortalUrl {
    <# PURE. The install's page in the Invardia customer portal, '' when the id is not a GUID. #>
    param([AllowNull()][AllowEmptyString()][string]$EnvironmentId)
    $id = ConvertTo-SIInvardiaEnvironmentIdOrEmpty $EnvironmentId
    if (-not $id) { return '' }
    $script:SIPortalLink.UrlFormat -f $id
}

function Get-SIInvardiaPortalLinkHtml {
    <# PURE. The one line, as HTML (every value encoded); '' when the id is not a GUID. #>
    param([AllowNull()][AllowEmptyString()][string]$EnvironmentId)
    $url = Get-SIInvardiaPortalUrl $EnvironmentId
    if (-not $url) { return '' }
    $u = [System.Net.WebUtility]::HtmlEncode($url)
    ('<p {0}="1" style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5;color:#0B1633;margin:0 0 14px 0;">{1} <a href="{2}" style="color:#1B4FE4;text-decoration:underline;">{2}</a></p>' -f `
        $script:SIPortalLink.Marker, [System.Net.WebUtility]::HtmlEncode($script:SIPortalLink.Text), $u)
}

function Test-SIInvardiaPortalLinkSummary {
    <# PURE. $true when -BodyHtml has a summary the line goes under (the summary block, data-mail-summary: every SI mail's
       summary since #728, the Risk Analysis mail's included; a <table> summary only in a mail queued by an older web app). #>
    param([AllowNull()][AllowEmptyString()][string]$BodyHtml)
    if (-not $BodyHtml) { return $false }
    $BodyHtml -match '(?is)<(div|table)\b[^>]*\bdata-mail-summary\b'
}

function Add-SIInvardiaPortalLinkAnchor {
    <#
        PURE. Owner 2026-10-16 ("Add to both"): a mail WITHOUT a summary that still gets the line -- the daily close-loop
        mail and the management summary -- carries it at the TOP. This marks the top of -BodyHtml (right after its <body>
        tag, else at its start) with the place-holder Add-SIInvardiaPortalLink fills. A body that has a summary (the line
        goes under it), already has a place-holder or the line, or is empty: unchanged. Invisible when no id is known
        (an HTML comment; Send-SIMail removes it before sending).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml)
    if (-not $BodyHtml) { return $BodyHtml }
    if ((Test-SIInvardiaPortalLinkSummary $BodyHtml) -or $BodyHtml -match $script:SIPortalLink.Marker -or $BodyHtml.Contains($script:SIPortalLink.Anchor) -or $BodyHtml.Contains($script:SIPortalLink.RowAnchor)) { return $BodyHtml }
    $b = [regex]::Match($BodyHtml, '(?i)<body\b[^>]*>')
    if ($b.Success) { $at = $b.Index + $b.Length; return $BodyHtml.Substring(0, $at) + $script:SIPortalLink.Anchor + $BodyHtml.Substring($at) }
    $script:SIPortalLink.Anchor + $BodyHtml
}

function Remove-SIInvardiaPortalLinkAnchor {
    <# PURE. -BodyHtml without the place-holders (an unused one is never sent). #>
    param([AllowNull()][AllowEmptyString()][string]$BodyHtml)
    if (-not $BodyHtml) { return $BodyHtml }
    $BodyHtml.Replace($script:SIPortalLink.RowAnchor, '').Replace($script:SIPortalLink.Anchor, '')
}

function Add-SIInvardiaPortalLink {
    <#
        PURE. -BodyHtml with the one line directly UNDER its summary. The summary is found as:
          1. the summary block (data-mail-summary, #728: every SI mail's summary, the Risk Analysis mail's included): the line
             follows it;
          2. a mail queued by an older web app: its <table data-mail-summary> box -- the line follows its table.
        A mail without a summary that asks for the line at its top (owner 2026-10-16: the daily close-loop mail and the
        management summary) carries a place-holder there:
          3. "<!-- SI portal link row -->" (an older body): the line in its place;
          4. "<!-- SI portal link -->" (Add-SIInvardiaPortalLinkAnchor): the line in its place.
        No summary and no place-holder, no / not-a-GUID id, or the line already there = the body unchanged. Returns the body.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, [AllowNull()][AllowEmptyString()][string]$EnvironmentId)
    if (-not $BodyHtml -or $BodyHtml -match $script:SIPortalLink.Marker) { return $BodyHtml }
    $line = Get-SIInvardiaPortalLinkHtml $EnvironmentId
    if (-not $line) { return $BodyHtml }
    if (-not (Test-SIInvardiaPortalLinkSummary $BodyHtml)) {
        # 3. / 4. the place-holder at the top (the first one only: the line is never there twice)
        $r = $BodyHtml.IndexOf($script:SIPortalLink.RowAnchor, [StringComparison]::Ordinal)
        if ($r -ge 0) { return $BodyHtml.Substring(0, $r) + $line + $BodyHtml.Substring($r + $script:SIPortalLink.RowAnchor.Length) }
        $a = $BodyHtml.IndexOf($script:SIPortalLink.Anchor, [StringComparison]::Ordinal)
        if ($a -ge 0) { return $BodyHtml.Substring(0, $a) + $line + $BodyHtml.Substring($a + $script:SIPortalLink.Anchor.Length) }
        return $BodyHtml
    }
    # 1. the summary block: <div ... data-mail-summary ...> ... </div> (no div inside it); the line follows it
    $m = [regex]::Match($BodyHtml, '(?is)<div\b[^>]*\bdata-mail-summary\b[^>]*>.*?</div>')
    if ($m.Success) { $at = $m.Index + $m.Length; return $BodyHtml.Substring(0, $at) + $line + $BodyHtml.Substring($at) }
    # 2. a mail queued by an older web app: its <table ... data-mail-summary ...> box (no table inside it)
    $m = [regex]::Match($BodyHtml, '(?is)<table\b[^>]*\bdata-mail-summary\b[^>]*>.*?</table>')
    if ($m.Success) { $at = $m.Index + $m.Length; return $BodyHtml.Substring(0, $at) + $line + $BodyHtml.Substring($at) }
    $BodyHtml
}

function Get-SIInvardiaEnvironmentIdKnown {
    <#
        The id this process knows (never throws, '' when none): -Facts (default $global:SI_InstallRingFacts, read by the
        Pro settings layer at run start) .InvardiaEnvironment.
    #>
    param($Facts = $global:SI_InstallRingFacts)
    try {
        if ($null -eq $Facts) { return '' }
        $v = if ($Facts -is [System.Collections.IDictionary]) { if ($Facts.Contains($script:SIPortalLink.StateName)) { [string]$Facts[$script:SIPortalLink.StateName] } else { '' } }
             elseif ($Facts.PSObject.Properties[$script:SIPortalLink.StateName]) { [string]$Facts.($script:SIPortalLink.StateName) } else { '' }
        return (Get-SIInvardiaEnvironmentIdFromValue $v)
    } catch { return '' }
}

function Save-SIInvardiaEnvironmentMark {
    <# Records the environment id Invardia named (cfg.InstallState 'InvardiaEnvironment') on -Store. Throws on failure. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$EnvironmentId, $NowUtc)
    $v = ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $EnvironmentId -NowUtc $NowUtc
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
    COMMIT;
END
'@
    $null = & $Store.Invoke $sql ([ordered]@{ Name = $script:SIPortalLink.StateName; Value = $v; By = 'si-engine (Invardia uplink)' }) 'nonquery'
}

function Invoke-SIInvardiaEnvironmentNotice {
    <#
        #710: Invardia named this install's environment (-EnvironmentId). Recorded for the customer mails: -OnEnvironment
        (tests), else the Pro database this run opened ($global:SI_ProSettingsStore). The in-process facts
        ($global:SI_InstallRingFacts) carry it at once, so a later mail of the same process links it too. NEVER throws;
        $true when recorded.
    #>
    param([Parameter(Mandatory)][string]$EnvironmentId, [scriptblock]$OnEnvironment, $NowUtc)
    $id = ConvertTo-SIInvardiaEnvironmentIdOrEmpty $EnvironmentId
    if (-not $id) { return $false }
    $done = $false
    try {
        if ($OnEnvironment) { $null = & $OnEnvironment $id; $done = $true }
        elseif ($global:SI_ProSettingsStore) { Save-SIInvardiaEnvironmentMark -Store $global:SI_ProSettingsStore -EnvironmentId $id -NowUtc $NowUtc; $done = $true }
    } catch { $done = $false }
    try {
        $val = ConvertTo-SIInvardiaEnvironmentValue -EnvironmentId $id -NowUtc $NowUtc
        $f = $global:SI_InstallRingFacts
        if ($f -is [System.Collections.IDictionary]) { $f[$script:SIPortalLink.StateName] = $val }
        elseif ($null -ne $f) { $f | Add-Member -NotePropertyName $script:SIPortalLink.StateName -NotePropertyValue $val -Force }
    } catch { }
    $done
}
