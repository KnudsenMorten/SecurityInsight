#Requires -Version 5.1
<#
    SECURITYINSIGHT -- EVERY MAIL NAMES ITS ENVIRONMENT BY HANDLE AND ITS TENANT (framework 12.11a MAIL-ENV, 8.14
    ENV-NAME-MASTER; owner, support: "What eng is this" / "In the mail I see only prod and not tailspin-prod").

    THE ONE PLACE that says which environment a mail comes from. Send-SIMail (SI-MailTransport.ps1) is the only sender
    and calls it for every mail -- the engines' reports, alerts, guard and data-health mails, the close-loop family and
    every mail the web app queues in its outbox (the web app never talks to a mail server):

        subject     [<KIND>] <handle>[ (<display name>)] - <severity word: ><what happened> [<ticket>] [SecurityInsight]
        first line  the same text, the first line of the body
        tenant line Tenant: <tenant name> (<tenant id>)          (a sign-in mail -- -Short -- keeps only the first line)

    <KIND>          Invardia's kind of the environment: Production -> PROD, Test -> TEST, Development -> DEV; unknown = none
    <handle>        Invardia's handle (e.g. "adatum-prod"); without Invardia (a Community install without the opt-in has no
                    install key) the install's OWN configured name (the web app header's name, else the tenant's name)
    <display name>  only when it differs from the handle AND says more (a display name can be just "PROD")
    Never another customer's name: Invardia's customer / managedBy names are never read into a mail.

    THE SOURCE: the heartbeat's full tick reads GET /api/enrollments/environment with the install key and keeps the last
    GOOD answer in cfg.InstallState 'InvardiaEnvironment' (SI-InvardiaEnvironment.ps1; a failed read never blanks it).
    This file only READS that row -- it never calls Invardia, so an install without the key sends nothing anywhere. The
    row is read once per 10 minutes per process; a read that fails keeps the value this process read last.

    PS 5.1 safe. No modules. No network call.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIMailEnvRowName    = 'InvardiaEnvironment'
$script:SIMailEnvHandleMax  = 48
$script:SIMailEnvDisplayMax = 40
$script:SIMailEnvLabelMax   = 72
$script:SIMailEnvCacheMin   = 10
$script:SIMailEnvCache      = $null

function Initialize-SIMailEnvironmentState {
    if ($null -eq $script:SIMailEnvRowName)    { $script:SIMailEnvRowName = 'InvardiaEnvironment' }
    if ($null -eq $script:SIMailEnvHandleMax)  { $script:SIMailEnvHandleMax = 48 }
    if ($null -eq $script:SIMailEnvDisplayMax) { $script:SIMailEnvDisplayMax = 40 }
    if ($null -eq $script:SIMailEnvLabelMax)   { $script:SIMailEnvLabelMax = 72 }
    if ($null -eq $script:SIMailEnvCacheMin)   { $script:SIMailEnvCacheMin = 10 }
}

function ConvertTo-SIMailKindTag {
    <# PURE. Invardia's kind -> the subject's tag: Production -> PROD, Test -> TEST, Development -> DEV; anything else ''. #>
    param([AllowNull()][AllowEmptyString()][string]$Kind)
    $k = ("$Kind" -replace '[^A-Za-z]', '').Trim()
    if ($k -match '^(?i)prod(uction)?$') { return 'PROD' }
    if ($k -match '^(?i)test$') { return 'TEST' }
    if ($k -match '^(?i)dev(elopment)?$') { return 'DEV' }
    ''
}

function ConvertTo-SIMailEnvText {
    <# PURE. One short line for a subject: no control characters, no brackets or parentheses (they carry the format), cut. #>
    param($Value, [int]$Max = 48)
    if ($null -eq $Value -or $Value -is [DBNull]) { return '' }
    $s = ([string]$Value -replace '[\x00-\x1F\x7F]+', ' ' -replace '[\[\]\(\)]', '' -replace '\s+', ' ').Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, [Math]::Max(1, $Max - 3)).TrimEnd() + '...' }
    $s
}

function ConvertFrom-SIMailInvardiaRecord {
    <#
        PURE. The kept row's value (cfg.InstallState 'InvardiaEnvironment': { name, id, kind, handle, tenantId, displayName,
        readUtc }) or Invardia's own answer ({ environmentName, environmentId, kind, handle, tenantId, displayName }) -- JSON
        text or an object -> @{ Name; Handle; Kind; DisplayName; TenantId; EnvironmentId } or $null. ONLY these fields are
        read: the customer's and the managing company's names never reach a mail.
    #>
    param($Value)
    try {
        if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
        $o = if ($Value -is [string]) { if (-not "$Value".Trim()) { return $null }; ("$Value".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop) } else { $Value }
        if ($null -eq $o -or $o -is [string] -or $o -is [ValueType] -or $o -is [array]) { return $null }
        $get = { param($names) foreach ($n in $names) { $p = $o.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value -and -not ($p.Value -is [DBNull]) -and ($p.Value -is [string] -or $p.Value -is [ValueType])) { $v = ([string]$p.Value -replace '[\x00-\x1F\x7F]+', ' ').Trim(); if ($v) { return $v } } }; '' }
        $r = [pscustomobject]@{
            Name          = & $get @('name', 'environmentName')
            Handle        = & $get @('handle')
            Kind          = & $get @('kind')
            DisplayName   = & $get @('displayName')
            TenantId      = & $get @('tenantId')
            EnvironmentId = & $get @('id', 'environmentId')
        }
        if (-not $r.Name -and -not $r.Handle) { return $null }
        $r
    } catch { $null }
}

function Get-SIMailInvardiaRecordSql {
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    SELECT Value FROM cfg.InstallState WHERE Name = N'InvardiaEnvironment';
'@
}

function Get-SIMailInvardiaRecord {
    <#
        The environment as Invardia named it last (ConvertFrom-SIMailInvardiaRecord), or $null (none kept, no database).
          -Globals given        PURE: only -Globals['SI_MailInvardiaEnvironment'] (tests, callers that know it)
          $global:SI_MailInvardiaEnvironment   a job (or a test) that set it
          else                  the kept row in the SecurityInsight database (the send record's SQL seam), once per
                                10 minutes per process; a read that fails keeps the value read last (the LAST GOOD one)
        Never calls Invardia. Never throws.
    #>
    param([System.Collections.IDictionary]$Globals, [scriptblock]$Invoke, [switch]$NoCache)
    Initialize-SIMailEnvironmentState
    try {
        if ($Globals) { if ($Globals.Contains('SI_MailInvardiaEnvironment')) { return (ConvertFrom-SIMailInvardiaRecord $Globals['SI_MailInvardiaEnvironment']) }; return $null }
        $g = Get-Variable -Name 'SI_MailInvardiaEnvironment' -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $g) { return (ConvertFrom-SIMailInvardiaRecord $g) }
        if (-not $NoCache -and $script:SIMailEnvCache -and $script:SIMailEnvCache.Until -gt [datetime]::UtcNow) { return $script:SIMailEnvCache.Value }
        $last = if ($script:SIMailEnvCache) { $script:SIMailEnvCache.Value } else { $null }
        $inv = $Invoke
        if (-not $inv -and (Get-Command -Name Get-SIMailSendRecordInvoke -ErrorAction SilentlyContinue)) { $inv = Get-SIMailSendRecordInvoke }
        if (-not $inv) { return $last }
        $val = $last
        try {
            $rows = @(& $inv (Get-SIMailInvardiaRecordSql) @{} 'rows' | ForEach-Object { $_ })
            $val = $null
            foreach ($row in $rows) {
                $v = $null
                if ($row -is [System.Collections.IDictionary]) { if ($row.Contains('Value')) { $v = $row['Value'] } }
                elseif ($row -is [string]) { $v = $row }
                elseif ($row -and $row.PSObject.Properties['Value']) { $v = $row.Value }
                $val = ConvertFrom-SIMailInvardiaRecord $v
                if ($val) { break }
            }
            # a row that is gone or unreadable never blanks a name this process already had
            if (-not $val) { $val = $last }
        } catch { $val = $last }
        $script:SIMailEnvCache = @{ Value = $val; Until = [datetime]::UtcNow.AddMinutes($script:SIMailEnvCacheMin) }
        $val
    } catch { $null }
}

function Test-SIMailDisplaySaysMore {
    <# PURE. A display name is shown next to the handle only when it differs and says more: not the handle, not a part of
       it ("PROD" in "tailspin-prod"), not the kind alone. #>
    param([AllowEmptyString()][string]$Handle, [AllowEmptyString()][string]$Display, [AllowEmptyString()][string]$KindTag)
    $norm = { param($s) ("$s" -replace '[^A-Za-z0-9]', '').ToLowerInvariant() }
    $d = & $norm $Display; $h = & $norm $Handle
    if (-not $d) { return $false }
    if ($d -eq $h -or ($h -and $h.Contains($d))) { return $false }
    if ($d -in @('prod', 'production', 'test', 'dev', 'development', (& $norm $KindTag))) { return $false }
    $true
}

function Get-SIMailEnvIdentity {
    <#
        PURE. From an environment (Get-SIMailEnvironment, or any object with Name / Handle / Kind / EnvDisplayName /
        TenantName / TenantId) -> what every mail says about where it comes from:
          Kind        PROD | TEST | DEV | ''      Handle   the handle (else the configured name; '' = none known)
          Display     the display name when it says more, else ''
          Label       '[PROD] adatum-prod' / '[PROD] contoso (Contoso production)' / 'Contoso' / ''
          Prefix      Label + ' - ' (or '')
          TenantLine  'Tenant: <name> (<id>)' / 'Tenant: <id>' / 'Tenant: <name>' / ''
    #>
    param($Environment)
    Initialize-SIMailEnvironmentState
    $prop = { param($n) if ($Environment -and $Environment.PSObject.Properties[$n] -and $null -ne $Environment.$n) { "$($Environment.$n)".Trim() } else { '' } }
    $handle = ConvertTo-SIMailEnvText (& $prop 'Handle') $script:SIMailEnvHandleMax
    if (-not $handle -and $Environment -and (Get-Command -Name Get-SIMailSubjectEnvironment -ErrorAction SilentlyContinue)) {
        $handle = ConvertTo-SIMailEnvText (Get-SIMailSubjectEnvironment -Environment $Environment) $script:SIMailEnvHandleMax
    }
    $kind = ConvertTo-SIMailKindTag (& $prop 'Kind')
    $display = ConvertTo-SIMailEnvText (& $prop 'EnvDisplayName') $script:SIMailEnvDisplayMax
    if (-not $handle -or -not (Test-SIMailDisplaySaysMore -Handle $handle -Display $display -KindTag $kind)) { $display = '' }
    $label = ''
    if ($handle) {
        $label = $(if ($kind) { '[' + $kind + '] ' } else { '' }) + $handle
        # a subject keeps room for what happened: a display name that would make the label too long is left to the body
        if ($display -and ($label.Length + $display.Length + 3) -le $script:SIMailEnvLabelMax) { $label += ' (' + $display + ')' } else { $display = '' }
    }
    $tName = (& $prop 'TenantName') -replace '[\x00-\x1F\x7F]+', ' '
    $tId = & $prop 'TenantId'
    $tenant = if ($tName -and $tId) { 'Tenant: {0} ({1})' -f $tName, $tId } elseif ($tId) { 'Tenant: ' + $tId } elseif ($tName) { 'Tenant: ' + $tName } else { '' }
    [pscustomobject]@{ Kind = $kind; Handle = $handle; Display = $display; Label = $label
                       Prefix = $(if ($label) { $label + ' - ' } else { '' }); TenantLine = $tenant }
}

function Add-SIMailEnvironmentLines {
    <#
        PURE. The FIRST line of the body -- the mail's subject ('[PROD] adatum-prod - Warning: ...') -- and under it the tenant
        line, as the first thing inside <body> (before the SecurityInsight bar), else at the start. -Short (a sign-in mail):
        the first line only. Added once (data-si-mail-env). Everything is encoded here.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, [Parameter(Mandatory)][AllowEmptyString()][string]$Subject,
          $Environment, [switch]$Short)
    if ($BodyHtml -match 'data-si-mail-env=') { return $BodyHtml }
    $id = Get-SIMailEnvIdentity -Environment $Environment
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $first = ([string]$Subject -replace '[\r\n\t]+', ' ').Trim()
    if (-not $first) { $first = $id.Label }
    if (-not $first) { return $BodyHtml }
    $font = 'font-family:Segoe UI,Arial,sans-serif;'
    $html = '<div data-si-mail-env="1" style="' + $font + 'max-width:680px;margin:0 auto;padding:8px 12px 0 12px;font-size:13px;line-height:1.45;color:#1f2d3d;">' +
            '<p style="margin:0;font-weight:600;">' + (& $enc $first) + '</p>'
    if (-not $Short -and $id.TenantLine) { $html += '<p style="margin:2px 0 0 0;color:#5a6a7a;">' + (& $enc $id.TenantLine) + '</p>' }
    $html += '</div>'
    $m = [regex]::Match($BodyHtml, '(?i)<body\b[^>]*>')
    if ($m.Success) { return $BodyHtml.Substring(0, $m.Index + $m.Length) + $html + $BodyHtml.Substring($m.Index + $m.Length) }
    $html + $BodyHtml
}
