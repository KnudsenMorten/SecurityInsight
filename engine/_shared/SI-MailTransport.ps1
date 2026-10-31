#Requires -Version 5.1
<#
    SECURITYINSIGHT -- THE ONE MAIL TRANSPORT (MAIL-1). Every mail SecurityInsight sends goes through Send-SIMail:
    the Risk Analysis report, the guard mails (Send-SIGuardMailDefault), the close-loop, exemption, sign-in, governance,
    department and task-digest mails (Send-SICloseLoopMail) and the updater's licence mail. tests\pester\
    SIv3-MailTransport.Tests.ps1 fails when any other file talks SMTP itself.

    SI_Mail_Mode (the setting; install parameter mailMode):
      sharedMailbox  Microsoft Graph app-only: POST /v1.0/users/{SI_Mail_From}/sendMail, as SecurityInsight's OWN
                     identity (the job's managed identity in a container). The recommended mode for every new install.
                     The send right is Exchange Online's 'Application Mail.Send' role scoped to that one mailbox (RBAC
                     for Applications) -- and SecurityInsight REFUSES to send until it has verified the restriction
                     (Get-SIMailRestriction), saying why.
      smtp           your own relay (anonymous, or signed in; the password from Key Vault) -- RA-Mail.ps1's transports.
      none           no mail.
      not set        smtp when SmtpServer is set (an existing install keeps working on upgrade), else none.
    SI_Mail_From      the shared mailbox; also the From for smtp (wins over SMTPFrom / MailFrom / SMTPUser).
    SI_Mail_ProbeMailbox  a mailbox OUTSIDE the scope: sending as it must be refused, which proves the restriction.

    Attachments with sharedMailbox: Graph takes an attachment inline in sendMail only up to ~3 MB (the whole request
    at most 4 MB). A larger one would need an upload session, which needs Mail.ReadWrite on the mailbox -- a wider
    right than Mail.Send. So a larger attachment is NOT sent: the mail goes without it and says where the file is
    (the workbook stays on disk / in the export storage) -- the same trade the SMTP size guard makes.

    PS 5.1 safe. No modules. Every network call goes through a seam (-Http, -TokenProvider) so the tests run offline.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIMailTransportRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# MAIL-2 / #573: the one mail layout -- Send-SIMail formats every body with it (Format-SIMailBody)
if (-not (Get-Command -Name Format-SIMailBody -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-MailLayout.ps1')) }
# #574: the mail PDF -- Send-SIMail attaches one to every mail that reports something (New-SIMailPdf)
if (-not (Get-Command -Name New-SIMailPdf -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-MailPdf.ps1')) }
# #710: the line under a mail's summary that links the install's page in the Invardia portal (Add-SIInvardiaPortalLink)
if (-not (Get-Command -Name Add-SIInvardiaPortalLink -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaPortalLink.ps1')) }
$script:SIMailGraphInlineMaxMb = 3
$script:SIMailRestrictionCache = @{}
$script:SIMailAllowedStates = @('verified', 'legacy-policy')

function Get-SIMailSetting {
    param([Parameter(Mandatory)][string]$Name, [System.Collections.IDictionary]$Globals)
    if ($Globals) { if ($Globals.Contains($Name)) { return $Globals[$Name] }; return $null }
    Get-Variable -Name $Name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
}

function ConvertTo-SIMailFlag {
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return $Value }
    $s = "$Value".Trim()
    if (-not $s) { return $Default }
    switch -Regex ($s) { '^(?i)(1|true|yes|on|\$true)$' { return $true } '^(?i)(0|false|no|off|\$false)$' { return $false } }
    $Default
}

function Resolve-SIMailMode {
    <#
        PURE. The mail mode from SI_Mail_Mode and, when it is not set, from SmtpServer (an existing install).
        Returns @{ Mode = none | smtp | sharedMailbox; Source = setting | legacy-smtp | default; Problem }.
    #>
    param([AllowNull()]$Value, [AllowNull()][string]$SmtpServer)
    $v = if ($null -eq $Value) { '' } else { "$Value".Trim() }
    if ($v) {
        switch -Regex ($v) {
            '^(?i)(sharedmailbox|shared|graph|sharedmailbox365|o365)$' { return [pscustomobject]@{ Mode = 'sharedMailbox'; Source = 'setting'; Problem = $null } }
            '^(?i)smtp$'                                               { return [pscustomobject]@{ Mode = 'smtp'; Source = 'setting'; Problem = $null } }
            '^(?i)(none|off|disabled)$'                                { return [pscustomobject]@{ Mode = 'none'; Source = 'setting'; Problem = $null } }
        }
        return [pscustomobject]@{ Mode = 'none'; Source = 'setting'; Problem = ("SI_Mail_Mode '{0}' is not one of none, smtp, sharedMailbox" -f $v) }
    }
    if ("$SmtpServer".Trim()) { return [pscustomobject]@{ Mode = 'smtp'; Source = 'legacy-smtp'; Problem = $null } }
    [pscustomobject]@{ Mode = 'none'; Source = 'default'; Problem = $null }
}

function Resolve-SIInstallMailMode {
    <#
        PURE. The install parameter: mailMode (sharedMailbox | smtp | none), else the older bool 'mail' (true = smtp,
        false = none), else sharedMailbox (the default for a new install). Returns the mode.
    #>
    param([System.Collections.IDictionary]$Values)
    $m = if ($Values -and $Values.Contains('mailMode')) { "$($Values['mailMode'])".Trim() } else { '' }
    if ($m) { return (Resolve-SIMailMode -Value $m).Mode }
    if ($Values -and $Values.Contains('mail') -and $null -ne $Values['mail']) { if (ConvertTo-SIMailFlag $Values['mail']) { return 'smtp' } else { return 'none' } }
    'sharedMailbox'
}

function Test-SIMailAddress { param([string]$Value) "$Value".Trim() -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' }

function Get-SIMailEnvironment {
    <#
        PURE (reads -Globals, else the live settings; the VERSION file). WHICH environment a mail comes from -- every mail
        names it in its subject and footer (MAIL-1; owner: "i cannot see which tenant it is wrong"). Never "this tenant".
          Name     SIWeb_EnvironmentName (the web app header's name; Pro runs read it from the web app's settings), else
                   SI_EnvironmentName, else the tenant's name (SIWeb_TenantName / SI_TenantDomain /
                   TenantNameOrganization), else '' -- never an id (a GUID or the install id)
          Display  '<Name> (ring <n>, PRO|COMMUNITY)' -- as the web app's header shows it; the footer and the PDF carry it,
                   the SUBJECT carries the Name only (MAIL-3, #653: Get-SIMailSubject)
          Tenant   SIWeb_TenantName / SI_TenantDomain / TenantNameOrganization / TenantShort, and the tenant id
          Version  SecurityInsight's version; WebUrl  SIWeb_PublicBaseUrl
          InvardiaEnvironmentId  #710: the install's environment in the Invardia portal (SI_InstallRingFacts
                   .InvardiaEnvironment, recorded from Invardia's answer), '' when not known
    #>
    param([System.Collections.IDictionary]$Globals)
    $g = { param($n) $v = Get-SIMailSetting -Name $n -Globals $Globals; if ($null -eq $v) { '' } else { "$v".Trim() } }
    $first = { param([string[]]$names) foreach ($n in $names) { $v = & $g $n; if ($v) { return $v } }; '' }
    # a subject never shows an id (support: "it shows tenant id" -- the install id GUID stood where the name belongs): the
    # environment's name, else the tenant's name / primary domain; with neither, no name (the subject then has no
    # bracket, the footer says "your SecurityInsight"). A value that is only an id (a GUID, an inv-... id) is never a name.
    $isId = { param([string]$s) $s -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$' -or $s -eq (& $g 'SI_InstallId') }
    $name = ''
    foreach ($n in @('SIWeb_EnvironmentName', 'SI_EnvironmentName', 'SIWeb_TenantName', 'SI_TenantDomain', 'TenantNameOrganization')) {
        $v = & $g $n; if ($v -and -not (& $isId $v)) { $name = $v; break }
    }
    $ring = & $g 'SI_UpdateRing'
    $edition = if ((& $g 'SI_ProSqlServer') -or (& $g 'SI_Edition') -match '^(?i)pro$') { 'PRO' } else { 'COMMUNITY' }
    $inside = @(@($(if ("$ring" -match '^\d$') { 'ring ' + $ring }), $edition) | Where-Object { $_ }) -join ', '
    # #449: a name that already says it -- "Internal (ring 1, PRO)" on ring 1 -- is shown as it is: never "... (PRO)" twice
    $display = if ($name -match '\([^()]*\)\s*$') { $name.Trim() } else { '{0} ({1})' -f $(if ($name) { $name } else { 'your SecurityInsight' }), $inside }
    $tid = & $first @('SI_SPN_TenantId', 'SpnTenantId', 'AzureTenantId', 'HighPriv_Modern_TenantID', 'TenantId')
    $tname = & $first @('SIWeb_TenantName', 'SI_TenantDomain', 'TenantNameOrganization', 'TenantShort')
    $ver = & $g 'SI_Version'
    if (-not $ver) { try { $vf = [IO.Path]::Combine($script:SIMailTransportRoot, 'VERSION'); if (Test-Path -LiteralPath $vf) { $ver = ([IO.File]::ReadAllText($vf)).Trim() } } catch { } }
    $web = (& $g 'SIWeb_PublicBaseUrl').TrimEnd('/')
    $envId = ''
    try { if (Get-Command -Name Get-SIInvardiaEnvironmentIdKnown -ErrorAction SilentlyContinue) { $envId = Get-SIInvardiaEnvironmentIdKnown -Facts (Get-SIMailSetting -Name 'SI_InstallRingFacts' -Globals $Globals) } } catch { $envId = '' }
    [pscustomobject]@{ Name = $name; Display = $display; Ring = "$ring"; Edition = $edition; TenantName = $tname; TenantId = $tid
                       Solution = 'SecurityInsight'; Version = $ver; WebUrl = $(if ($web -match '^https://') { $web } else { '' }); InvardiaEnvironmentId = $envId }
}

# MAIL-3 (#653): one subject format for every mail SecurityInsight sends
$script:SIMailProduct = 'SecurityInsight'
$script:SIMailSubjectMax = 120
$script:SIMailSubjectEnvMax = 48

function ConvertTo-SIMailSeverityWord {
    <# PURE. The subject's severity word from a -Severity value: 'Failed' | 'Warning' | 'Action needed' | '' (none). #>
    param([AllowNull()][AllowEmptyString()][string]$Severity)
    switch -Regex ("$Severity".Trim()) {
        '^(?i)fail(ed|ure)?$'            { return 'Failed' }
        '^(?i)warn(ing)?$'               { return 'Warning' }
        '^(?i)action[\s_-]*(needed)?$'   { return 'Action needed' }
    }
    ''
}

function Get-SIMailSubjectEnvironment {
    <#
        PURE. The environment as the subject names it: the NAME the web app's header shows (Get-SIMailEnvironment .Name),
        never the ring or the edition (the owner: only the name; they stay in the footer). A name that carries them itself
        ('Internal (ring 1, PRO)') loses that part here; brackets are taken out (they would break the format).
    #>
    param($Environment)
    if (-not $Environment) { return '' }
    $n = "$($Environment.Name)".Trim()
    if (-not $n -and -not $Environment.PSObject.Properties['Name']) { $n = "$($Environment.Display)".Trim() }
    # never an id in a subject (a GUID-shaped name, from an older setting or caller)
    if ($n -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$') { $n = '' }
    $n = ($n -replace '(?i)\s*\([^()]*\b(ring\s*\d|pro|community)\b[^()]*\)\s*$', '').Trim()
    $n = ($n -replace '[\[\]]', '').Trim()
    if ($n.Length -gt $script:SIMailSubjectEnvMax) { $n = $n.Substring(0, $script:SIMailSubjectEnvMax - 3).TrimEnd() + '...' }
    $n
}

function Get-SIMailSubject {
    <#
        PURE. THE ONE PLACE that builds a mail's whole subject (MAIL-3, #653):
            [<Environment>] <severity word: if relevant><what happened> [<ticket if any>] [SecurityInsight]
        - <Environment>   the web app header's name (Get-SIMailSubjectEnvironment) -- no ring, no edition
        - severity word   -Severity (Failed | Warning | ActionNeeded), else a leading 'Failed:' / 'Warning:' /
                          'Action needed:' the sender wrote itself; none for reports, digests and information mails
        - <what happened> the sender's text, with a leading product name taken out ('SecurityInsight <middle dot> ',
                          'SecurityInsight -- ', 'SecurityInsight: ', 'Security Insights | ' ...): the product is named once,
                          at the end. Mails the web app queued in SQL come through here too, so a row queued by an older
                          web app is put right as it is sent.
        - at most -MaxLength (120) characters: ONLY <what happened> is shortened, with '...'; the brackets, the severity
          word and the ticket are always kept.
        - idempotent: a subject already in the format is returned as it is (never wrapped twice).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Subject, $Environment,
          [AllowNull()][AllowEmptyString()][string]$Severity, [AllowNull()][AllowEmptyString()][string]$Ticket, [int]$MaxLength = $script:SIMailSubjectMax)
    $product = ' [' + $script:SIMailProduct + ']'
    $name = Get-SIMailSubjectEnvironment -Environment $Environment
    $prefix = if ($name) { '[' + $name + '] ' } else { '' }
    $word = ConvertTo-SIMailSeverityWord $Severity
    $t = "$Ticket".Trim().Trim('[', ']').Trim()
    $s = ([string]$Subject -replace '[\r\n\t]+', ' ').Trim()
    # already in the format: never wrapped twice
    if ($s.EndsWith($product) -and $s.Length -le $MaxLength -and (-not $prefix -or $s.StartsWith($prefix)) -and
        (-not $word -or $s.StartsWith($prefix + $word + ':')) -and (-not $t -or $s.Contains('[' + $t + ']'))) { return $s }
    # take the subject apart: product, environment (also the older '[<Name> (ring n, PRO)] ' one), ticket
    if ($s.EndsWith($product)) { $s = $s.Substring(0, $s.Length - $product.Length).TrimEnd() }
    $old = if ($Environment) { "$($Environment.Display)".Trim() } else { '' }
    if ($prefix -and $s.StartsWith($prefix)) { $s = $s.Substring($prefix.Length).TrimStart() }
    elseif ($old -and $s.StartsWith('[' + $old + '] ')) { $s = $s.Substring($old.Length + 3).TrimStart() }
    if ($t -and $s.EndsWith('[' + $t + ']')) { $s = $s.Substring(0, $s.Length - $t.Length - 2).TrimEnd() }
    # the product is named once, at the end (separators: middle dot, bar, colon, hyphen(s), en / em dash -- written as
    # [char] so this file stays plain ASCII)
    $dot = [string][char]0x00B7; $en = [string][char]0x2013; $em = [string][char]0x2014
    $s = $s -replace ('^(?i)Security\s?Insights?(\s+Pro)?\s*(' + $dot + '|\||:|-{1,2}|' + $en + '|' + $em + ')\s*'), ''
    $s = $s -replace '^(?i)SecurityInsight\s+(?=test mail$)', ''
    # a severity word the sender wrote first
    $m = [regex]::Match($s, ('^(?i)(Failed|Warning|Action needed)\s*(:|-{1,2}|' + $en + ')\s*'))
    if ($m.Success) { if (-not $word) { $word = ConvertTo-SIMailSeverityWord $m.Groups[1].Value }; $s = $s.Substring($m.Length) }
    $s = $s.Trim()
    if (-not $s) { $s = 'Notification' }
    $s = $s.Substring(0, 1).ToUpperInvariant() + $s.Substring(1)
    $sev = if ($word) { $word + ': ' } else { '' }
    $tail = $(if ($t) { ' [' + $t + ']' } else { '' }) + $product
    $room = $MaxLength - $prefix.Length - $sev.Length - $tail.Length
    if ($s.Length -gt $room) { $keep = [Math]::Max(1, $room - 3); $s = $s.Substring(0, [Math]::Min($keep, $s.Length)).TrimEnd() + '...' }
    $prefix + $sev + $s + $tail
}

function Get-SIMailFooterHtml {
    <# PURE. The footer every mail carries: environment, tenant name + id, solution + version, the web app's link. #>
    param([Parameter(Mandatory)]$Environment)
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $tenant = if ($Environment.TenantName -and $Environment.TenantId) { '{0} ({1})' -f $Environment.TenantName, $Environment.TenantId }
              elseif ($Environment.TenantId) { $Environment.TenantId } elseif ($Environment.TenantName) { $Environment.TenantName } else { 'not recorded' }
    $parts = @(
        ('Environment: <b>{0}</b>' -f (& $e $Environment.Display))
        ('Tenant: {0}' -f (& $e $tenant))
        ('{0}{1}' -f (& $e $Environment.Solution), $(if ($Environment.Version) { ' v' + (& $e $Environment.Version) } else { '' }))
    )
    if ($Environment.WebUrl) { $parts += ('<a href="{0}" style="color:#2c5a8e;">{0}</a>' -f (& $e $Environment.WebUrl)) }
    '<div data-si-mail-footer style="margin-top:16px;padding:8px 12px;border-top:1px solid #e0e6ed;font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#5a6a7a;">' + ($parts -join ' &middot; ') + '</div>'
}

function Add-SIMailFooter {
    <# PURE. The footer, inside </body> when the mail is a full HTML document, else at the end. Added once. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, [Parameter(Mandatory)]$Environment)
    if ($BodyHtml -match 'data-si-mail-footer') { return $BodyHtml }
    $f = Get-SIMailFooterHtml -Environment $Environment
    $i = $BodyHtml.LastIndexOf('</body>', [StringComparison]::OrdinalIgnoreCase)
    if ($i -ge 0) { return $BodyHtml.Substring(0, $i) + $f + $BodyHtml.Substring($i) }
    $BodyHtml + $f
}

function Add-SIMailSourceNote {
    <# PURE. The source note(s) -- "Endpoint data is from ... -- the last collection from that source did not complete." --
       as one paragraph at the end of the mail's body (inside </body> when it is a full HTML document; the footer follows).
       Added once; no notes = the body unchanged. The text is encoded here. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, [AllowEmptyCollection()][string[]]$Notes = @())
    $lines = @($Notes | Where-Object { "$_".Trim() })
    if (-not $lines.Count -or $BodyHtml -match 'data-si-source-note') { return $BodyHtml }
    $enc = @($lines | ForEach-Object { [System.Net.WebUtility]::HtmlEncode([string]$_) }) -join '<br>'
    $p = '<p data-si-source-note="1" style="font-family:Segoe UI,Arial,sans-serif;font-size:13px;line-height:1.5;color:#8a4b00;background:#fff4e0;border-left:4px solid #d98a00;padding:8px 12px;margin:12px 24px;">' + $enc + '</p>'
    $i = $BodyHtml.LastIndexOf('</body>', [StringComparison]::OrdinalIgnoreCase)
    if ($i -ge 0) { return $BodyHtml.Substring(0, $i) + $p + $BodyHtml.Substring($i) }
    $BodyHtml + $p
}

function Get-SIMailSettings {    <#
        PURE (reads -Globals, else the live $global: settings). Everything a sender needs, for either mode:
        @{ Mode; ModeSource; Off; From; SharedMailbox; ProbeMailbox; Server; Port; UseSsl; From; Anonymous; User; Password;
           Problems }. Off = mail is switched off on purpose (SI_Mail_Mode = none): nothing is sent and that is not a
        failure. A mode that is not set up has Problems (said, never guessed).
        Kept property-compatible with the older relay object (Get-SIGuardSmtp / Get-SICloseLoopMailSmtp return it).
    #>
    param([System.Collections.IDictionary]$Globals)
    $g = { param($n) Get-SIMailSetting -Name $n -Globals $Globals }
    $problems = New-Object System.Collections.Generic.List[string]
    $server = "$(& $g 'SmtpServer')".Trim()
    $mode = Resolve-SIMailMode -Value (& $g 'SI_Mail_Mode') -SmtpServer $server
    if ($mode.Problem) { $problems.Add($mode.Problem) }
    $useSsl = ConvertTo-SIMailFlag (& $g 'SMTP_UseSSL')
    $portRaw = "$(& $g 'SMTPPort')".Trim()
    $port = if ($portRaw -match '^\d+$') { [int]$portRaw } elseif ($useSsl) { 587 } else { 25 }
    $mailFrom = "$(& $g 'SI_Mail_From')".Trim()
    $from = $mailFrom
    if (-not $from) { foreach ($n in 'SMTPFrom', 'MailFrom', 'SMTPUser') { $v = "$(& $g $n)".Trim(); if ($v) { $from = $v; break } } }
    $user = "$(& $g 'SMTPUser')".Trim()
    $passRaw = & $g 'SMTPPassword'
    $pass = if ($passRaw -is [securestring]) { (New-Object System.Management.Automation.PSCredential ('x', $passRaw)).GetNetworkCredential().Password } else { "$passRaw" }
    $cred = & $g 'SecureCredentialsSMTP'
    if ($cred -is [System.Management.Automation.PSCredential]) { $user = $cred.UserName; $pass = $cred.GetNetworkCredential().Password }
    $anonRaw = & $g 'Mail_SendAnonymous'
    $anon = ConvertTo-SIMailFlag $anonRaw
    $probe = "$(& $g 'SI_Mail_ProbeMailbox')".Trim()
    $off = $false
    switch ($mode.Mode) {
        'smtp' {
            if (-not $server) { $problems.Add('no mail server is configured (SmtpServer)') }
            if (-not $from) { $problems.Add('no sender address is configured (SI_Mail_From or SMTPFrom)') }
            if (-not $anon) {
                $explicitOff = ($null -ne $anonRaw -and "$anonRaw".Trim() -ne '')
                if (-not $user -and -not $pass -and -not $explicitOff) { $anon = $true }
                elseif (-not $user -or -not $pass) {
                    $missing = @(@(@{ n = 'SMTPUser'; v = $user }, @{ n = 'SMTPPassword'; v = $pass }) | Where-Object { -not $_.v } | ForEach-Object { $_.n }) -join ' and '
                    $problems.Add(("authenticated SMTP is configured but {0} is empty -- store the password in Key Vault (secret SI-Smtp-Password, setup\Set-SIMail.ps1 -Mode smtp) and re-run setup, or set Mail_SendAnonymous = true for an anonymous relay" -f $missing))
                }
            }
        }
        'sharedMailbox' {
            if (-not $mailFrom) { $problems.Add('no shared mailbox is configured (SI_Mail_From) -- run setup\Set-SIMail.ps1 or Settings > E-mail > Set up mail') }
            elseif (-not (Test-SIMailAddress $mailFrom)) { $problems.Add(("SI_Mail_From '{0}' is not a mail address" -f $mailFrom)) }
            $from = $mailFrom
        }
        default {
            if ($mode.Source -eq 'setting' -and -not $mode.Problem) { $off = $true }
            elseif (-not $mode.Problem) { $problems.Add('mail is not set up (no SI_Mail_Mode, and no SmtpServer) -- run setup\Set-SIMail.ps1, or Settings > E-mail > Set up mail') }
        }
    }
    $maxMb = 24
    $mm = & $g 'SI_MaxMailAttachmentMB'
    if ("$mm" -match '^\d+(\.\d+)?$' -and [double]$mm -gt 0) { $maxMb = [double]$mm }
    if ($mode.Mode -eq 'sharedMailbox') { $maxMb = [Math]::Min($maxMb, $script:SIMailGraphInlineMaxMb) }
    [pscustomobject]@{
        Mode = $mode.Mode; ModeSource = $mode.Source; Off = [bool]$off
        Server = $server; Port = $port; UseSsl = [bool]$useSsl; From = $from; Anonymous = [bool]$anon; User = $user; Password = $pass
        SharedMailbox = $(if ($mode.Mode -eq 'sharedMailbox') { $mailFrom } else { '' }); ProbeMailbox = $probe
        Attestation = "$(& $g 'SI_Mail_RestrictionAttestation')".Trim()
        MaxAttachmentMb = $maxMb
        Environment = (Get-SIMailEnvironment -Globals $Globals)
        Problems = $problems.ToArray()
    }
}

function Get-SIMailAttachmentPlan {
    <#
        PURE (reads file sizes). Which attachments go with the mail: the encoded size (base64, ~37% more) of ALL of them
        together must stay within -MaxMb (sharedMailbox: 3 MB, Graph's inline limit; smtp: the relay budget). A file that
        does not fit is left out, largest first kept out. Returns @{ Include; Dropped (@{ Path; DiskMb; EncodedMb }); MaxMb }.
    #>
    param([string[]]$Paths = @(), [double]$MaxMb = 24, [scriptblock]$SizeOf = { param($p) (Get-Item -LiteralPath $p).Length })
    $inc = New-Object System.Collections.Generic.List[string]; $drop = New-Object System.Collections.Generic.List[object]
    $budget = $MaxMb * 1MB; $used = 0.0
    foreach ($p in @($Paths | Where-Object { "$_".Trim() })) {
        $size = [double](& $SizeOf $p); $enc = $size * 1.37
        if ($used + $enc -le $budget) { $inc.Add($p); $used += $enc }
        else { $drop.Add([pscustomobject]@{ Path = $p; DiskMb = [Math]::Round($size / 1MB, 1); EncodedMb = [Math]::Round($enc / 1MB, 1) }) }
    }
    [pscustomobject]@{ Include = $inc.ToArray(); Dropped = $drop.ToArray(); MaxMb = $MaxMb }
}

function New-SIGraphSendMailBody {
    <#
        PURE. The Graph sendMail request: HTML body, To / Cc, importance, attachments as fileAttachment (base64), not
        saved to Sent Items. -Attachments = @(@{ Name; ContentType; Bytes }).
    #>
    param([Parameter(Mandatory)][string[]]$To, [string[]]$Cc = @(), [Parameter(Mandatory)][string]$Subject, [Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml,
          [ValidateSet('Normal', 'High', 'Low')][string]$Priority = 'Normal', [object[]]$Attachments = @(), [bool]$SaveToSentItems = $false)
    $rcp = { param($list) , @(@($list) | Where-Object { "$_".Trim() } | ForEach-Object { @{ emailAddress = @{ address = "$_".Trim() } } }) }
    $msg = [ordered]@{
        subject      = $Subject
        body         = [ordered]@{ contentType = 'HTML'; content = $BodyHtml }
        toRecipients = (& $rcp $To)
        importance   = $Priority.ToLowerInvariant()
    }
    $cc2 = & $rcp $Cc
    if (@($cc2).Count) { $msg.ccRecipients = $cc2 }
    if (@($Attachments).Count) {
        $msg.attachments = @(@($Attachments) | ForEach-Object {
            [ordered]@{ '@odata.type' = '#microsoft.graph.fileAttachment'; name = [string]$_.Name
                        contentType = $(if ($_.ContentType) { [string]$_.ContentType } else { 'application/octet-stream' })
                        contentBytes = [Convert]::ToBase64String([byte[]]$_.Bytes) } })
    }
    [ordered]@{ message = $msg; saveToSentItems = $SaveToSentItems }
}

function Get-SIMailContentType {
    param([string]$Path)
    switch -Regex ([IO.Path]::GetExtension("$Path").ToLowerInvariant()) {
        '^\.xlsx$' { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
        '^\.pptx$' { 'application/vnd.openxmlformats-officedocument.presentationml.presentation' }
        '^\.csv$'  { 'text/csv' }
        '^\.json$' { 'application/json' }
        '^\.html?$' { 'text/html' }
        '^\.pdf$'  { 'application/pdf' }
        default    { 'application/octet-stream' }
    }
}

function Invoke-SIMailHttp {
    <# The default HTTP seam: POST JSON, never throws on a status code. Returns @{ StatusCode; Body }. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)]$Body, [int]$TimeoutSec = 120)
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = New-Object System.Net.Http.HttpClient
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $Uri)
        [void]$req.Headers.TryAddWithoutValidation('Authorization', 'Bearer ' + $Token)
        $json = ConvertTo-Json -InputObject $Body -Depth 12 -Compress
        $content = New-Object System.Net.Http.ByteArrayContent(, [Text.Encoding]::UTF8.GetBytes($json))
        $content.Headers.Remove('Content-Type') | Out-Null
        [void]$content.Headers.TryAddWithoutValidation('Content-Type', 'application/json; charset=utf-8')
        $req.Content = $content
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $text = ''; if ($resp.Content) { $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
        [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Body = $text }
    } finally { $client.Dispose() }
}

function Get-SIMailGraphToken {
    <# SecurityInsight's own Graph token: the run's identity (managed identity in a container), else Get-SIGraphToken. #>
    if (-not (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue)) {
        $restFile = [IO.Path]::Combine($script:SIMailTransportRoot, 'engine', '_shared', 'SI-AzRest.ps1')
        $li = [IO.Path]::Combine($script:SIMailTransportRoot, 'engine', '_shared', 'SI-LogIngest.ps1')
        if ((Test-Path -LiteralPath $restFile) -and (Test-Path -LiteralPath $li)) { . $li; . $restFile }
    }
    if (Get-Command -Name Get-SIAzureToken -ErrorAction SilentlyContinue) { return (Get-SIAzureToken -Audience Graph) }
    if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { return (Get-SIGraphToken) }
    throw 'no Microsoft Graph token: SecurityInsight''s sign-in is not loaded'
}

function Get-SIMailGraphError {
    <# PURE. @{ Code; Message } from a Graph error body. #>
    param([string]$Body)
    try { $e = (ConvertFrom-Json -InputObject $Body).error; return [pscustomobject]@{ Code = [string]$e.code; Message = [string]$e.message } } catch { }
    [pscustomobject]@{ Code = ''; Message = "$Body" }
}

function Get-SIMailProbeVerdict {
    <#
        PURE. The answer to a probe -- sendMail as a mailbox with NO recipient, so nothing can be delivered:
          allowed    400 ErrorInvalidRecipients (or 202): the identity MAY send as that mailbox -- the request got past
                     authorization and failed only on the missing recipient
          denied     401 / 403 (ErrorAccessDenied): it may not
          not-found  404 / ErrorInvalidUser: no such mailbox
          error      anything else
    #>
    param([int]$StatusCode, [string]$Body)
    $e = Get-SIMailGraphError -Body $Body
    if ($StatusCode -eq 202) { return 'allowed' }
    if ($StatusCode -eq 400 -and ("$($e.Code)" -match '(?i)InvalidRecipients' -or "$($e.Message)" -match '(?i)recipient')) { return 'allowed' }
    if ($StatusCode -in 401, 403 -or "$($e.Code)" -match '(?i)AccessDenied|Authorization_RequestDenied') { return 'denied' }
    if ($StatusCode -eq 404 -or "$($e.Code)" -match '(?i)InvalidUser|ResourceNotFound|MailboxNotEnabled') { return 'not-found' }
    'error'
}

function Get-SIMailRestrictionVerdict {
    <#
        PURE. Is SecurityInsight's send right restricted to the shared mailbox? From: whether its Graph token carries a
        tenant-wide Mail.Send (roles claim), the probe as the shared mailbox (-Self) and as another mailbox (-Other, empty
        when there is none), and an Exchange administrator's attestation. Returns @{ State; Detail; AllowsSend }:
          verified       may send as the shared mailbox, may NOT send as another one (RBAC for Applications)
          legacy-policy  the same, but through a tenant-wide Mail.Send that an Application Access Policy restricts --
                         works; move to RBAC for Applications
          unrestricted   may send as another mailbox -- REFUSED, in red
          not-granted    may not send as the shared mailbox yet (role assignment missing, or not active yet)
          unverified     (no longer answered when the identity holds no tenant-wide Mail.Send: see below)
        Owner 2026-10-19 ("you cannot do that. we need a generic fix for this"): an identity WITHOUT the tenant-wide Graph
        Mail.Send (roles claim) that may send as the shared mailbox can only send through Exchange's role scoped to that
        mailbox -- that IS the restriction, proved by the token itself: 'verified', no probe mailbox needed. A probe mailbox
        stays an extra proof; a probe that cannot be used (e.g. it does not exist) never blocks sending, it adds a note.
          error          a probe failed in a way that says nothing
    #>
    param([bool]$TokenHasMailSend, [string]$Self, [string]$Other, [string]$Mailbox, [string]$ProbeMailbox, [string]$Attestation)
    $s = { param($st, $d) [pscustomobject]@{ State = $st; Detail = $d; AllowsSend = ($script:SIMailAllowedStates -contains $st) } }
    if ($Self -eq 'not-found') { return (& $s 'not-granted' ("the mailbox {0} does not exist (or is not a mailbox)" -f $Mailbox)) }
    if ($Self -eq 'denied') { return (& $s 'not-granted' ("SecurityInsight may not send as {0} yet: Exchange's 'Application Mail.Send' role assignment for its identity is missing or not active yet (it can take up to 2 hours) -- setup\Set-SIMail.ps1" -f $Mailbox)) }
    if ($Self -ne 'allowed') { return (& $s 'error' ("the send right on {0} could not be checked" -f $Mailbox)) }
    if ($Other -eq 'allowed') {
        $why = if ($TokenHasMailSend) { 'its identity holds the tenant-wide Microsoft Graph permission Mail.Send -- remove it (setup\Set-SIMail.ps1 -Apply does)' } else { 'its Exchange role assignment is not scoped to the shared mailbox' }
        return (& $s 'unrestricted' ("Mail.Send is not restricted to the shared mailbox: SecurityInsight could also send as {0}; {1}" -f $ProbeMailbox, $why))
    }
    if ($Other -eq 'denied') {
        if ($TokenHasMailSend) { return (& $s 'legacy-policy' ("restricted to {0} by an Application Access Policy (the older way) -- move to Exchange RBAC for Applications (setup\Set-SIMail.ps1)" -f $Mailbox)) }
        return (& $s 'verified' ("restricted to {0}: sending as {1} is refused" -f $Mailbox, $ProbeMailbox))
    }
    if ($TokenHasMailSend) { return (& $s 'unrestricted' 'SecurityInsight''s identity holds the tenant-wide Microsoft Graph permission Mail.Send and no other mailbox proved it restricted -- remove it (setup\Set-SIMail.ps1 -Apply does)') }
    if ("$Attestation".Trim()) { return (& $s 'verified' ("restricted to {0} (confirmed by the Exchange administrator: {1})" -f $Mailbox, "$Attestation".Trim())) }
    # no tenant-wide Mail.Send + allowed as the shared mailbox: the only send right is the role scoped to that mailbox
    $d = "restricted by Exchange RBAC for Applications: the identity holds no tenant-wide Mail.Send; its only send right is the role scoped to {0}" -f $Mailbox
    if ("$ProbeMailbox".Trim()) {
        if ($Other -eq 'not-found') { $d += ("; the probe mailbox {0} does not exist -- remove or correct SI_Mail_ProbeMailbox" -f "$ProbeMailbox".Trim()) }
        elseif ("$Other".Trim()) { $d += ("; the probe mailbox {0} could not be used ({1})" -f "$ProbeMailbox".Trim(), $Other) }
    }
    & $s 'verified' $d
}

function Get-SIMailRestriction {
    <#
        Probes the restriction as SecurityInsight's identity (two sendMail calls with no recipient: nothing is sent) and
        returns @{ State; Detail; AllowsSend; Mailbox; CheckedUtc }. Cached per process and mailbox. Never throws.
    #>
    param([Parameter(Mandatory)]$Settings, [scriptblock]$Http, [scriptblock]$TokenProvider, [switch]$Force)
    $mb = [string]$Settings.SharedMailbox
    $key = ('{0}|{1}' -f $mb, $Settings.ProbeMailbox).ToLowerInvariant()
    if (-not $Force -and $script:SIMailRestrictionCache.ContainsKey($key)) { return $script:SIMailRestrictionCache[$key] }
    if (-not $Http) { $Http = { param($u, $t, $b) Invoke-SIMailHttp -Uri $u -Token $t -Body $b } }
    if (-not $TokenProvider) { $TokenProvider = { Get-SIMailGraphToken } }
    $now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    try {
        $tok = [string](& $TokenProvider)
        $roles = @()
        try { $p = $tok.Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }; $roles = @(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).roles) } catch { }
        $probeBody = [ordered]@{ message = [ordered]@{ subject = 'SecurityInsight permission check (never delivered: no recipient)'; body = [ordered]@{ contentType = 'Text'; content = '-' }; toRecipients = @() }; saveToSentItems = $false }
        $ask = { param($box) $r = & $Http ('https://graph.microsoft.com/v1.0/users/{0}/sendMail' -f [uri]::EscapeDataString($box)) $tok $probeBody; Get-SIMailProbeVerdict -StatusCode ([int]$r.StatusCode) -Body ([string]$r.Body) }
        $self = & $ask $mb
        $other = ''
        if ($self -eq 'allowed' -and "$($Settings.ProbeMailbox)".Trim() -and "$($Settings.ProbeMailbox)".Trim() -ne $mb) { $other = & $ask ([string]$Settings.ProbeMailbox) }
        $v = Get-SIMailRestrictionVerdict -TokenHasMailSend ($roles -contains 'Mail.Send') -Self $self -Other $other -Mailbox $mb -ProbeMailbox ([string]$Settings.ProbeMailbox) -Attestation ([string]$Settings.Attestation)
    } catch {
        $v = [pscustomobject]@{ State = 'error'; Detail = ('the send right could not be checked: {0}' -f $_.Exception.Message); AllowsSend = $false }
    }
    $out = [pscustomobject]@{ State = $v.State; Detail = $v.Detail; AllowsSend = [bool]$v.AllowsSend; Mailbox = $mb; CheckedUtc = $now }
    $script:SIMailRestrictionCache[$key] = $out
    $out
}

function ConvertTo-SIMailRestrictionJson {
    <# PURE. The cfg.InstallState 'MailRestriction' value (<= 400 characters). #>
    param([Parameter(Mandatory)]$Restriction)
    $d = [string]$Restriction.Detail
    $mk = { param($det) ConvertTo-Json -Compress -InputObject ([ordered]@{ state = [string]$Restriction.State; detail = $det; mailbox = [string]$Restriction.Mailbox; checkedUtc = [string]$Restriction.CheckedUtc }) }
    $j = & $mk $d
    while ($j.Length -gt 400 -and $d.Length -gt 10) { $d = $d.Substring(0, [Math]::Max(10, $d.Length - ($j.Length - 400) - 3)) + '...'; $j = & $mk $d }
    $j
}

function Write-SIMailRestrictionState {
    <# The restriction, for the web app's Mail card and home banner: cfg.InstallState 'MailRestriction'. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Restriction, [string]$By = 'SecurityInsight mail')
    $sql = @'
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
MERGE cfg.InstallState AS t USING (SELECT N'MailRestriction' AS Name) AS s ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHEN NOT MATCHED THEN INSERT (Name, Value, UpdatedBy) VALUES (N'MailRestriction', @Value, @By);
'@
    try { $null = & $Invoke $sql @{ Value = (ConvertTo-SIMailRestrictionJson -Restriction $Restriction); By = $By } 'nonquery'; $true } catch { $false }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE SEND RECORD (#719, 2026-10-17): every mail Send-SIMail tries to send leaves its outcome in cfg.InstallState --
#  'MailLastSent' (the newest mail handed over) and 'MailLastFailed' (the newest one that was not, with its error). The
#  heartbeat's Mail field reads both (Get-SIHeartbeatMail): the close-loop, RA, guard, management-summary and other
#  mails do not go through an outbox, so the outboxes alone left Mail.lastSentUtc days behind. Written by the engine in
#  the same way as 'MailRestriction' (Write-SIMailRestrictionState); the web app never writes these rows.
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-SIMailSendRecordJson {
    <# PURE. The cfg.InstallState 'MailLastSent' / 'MailLastFailed' value (<= 400 characters): { utc, mode[, error] }. #>
    param([Parameter(Mandatory)][datetime]$Utc, [AllowEmptyString()][string]$Mode = '', [AllowNull()][AllowEmptyString()][string]$ErrorText)
    $u = $Utc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $mk = { param($e) $o = [ordered]@{ utc = $u; mode = [string]$Mode }; if ($null -ne $e) { $o.error = $e }; ConvertTo-Json -Compress -InputObject $o }
    if (-not "$ErrorText".Trim()) { return (& $mk $null) }
    $e = ("$ErrorText".Trim() -replace '\s+', ' ')
    if ($e.Length -gt 300) { $e = $e.Substring(0, 297) + '...' }
    $j = & $mk $e
    while ($j.Length -gt 400 -and $e.Length -gt 10) { $e = $e.Substring(0, [Math]::Max(10, $e.Length - ($j.Length - 400) - 3)) + '...'; $j = & $mk $e }
    $j
}

function Get-SIMailSendRecordSql {
    <# PURE. One row of cfg.InstallState by its key (@Name = MailLastSent | MailLastFailed). #>
@'
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
MERGE cfg.InstallState WITH (HOLDLOCK) AS t USING (SELECT @Name AS Name) AS s ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHEN NOT MATCHED THEN INSERT (Name, Value, UpdatedBy) VALUES (@Name, @Value, @By);
'@
}

function Write-SIMailSendRecord {
    <# The outcome of one send -> cfg.InstallState 'MailLastSent' (-Sent) or 'MailLastFailed'. Never throws; $true when written. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [bool]$Sent, [AllowNull()][AllowEmptyString()][string]$ErrorText,
          [AllowEmptyString()][string]$Mode = '', [datetime]$NowUtc = [datetime]::UtcNow, [string]$By = 'SecurityInsight mail')
    $name = if ($Sent) { 'MailLastSent' } else { 'MailLastFailed' }
    $err = if ($Sent) { $null } elseif ("$ErrorText".Trim()) { $ErrorText } else { 'the mail was not sent' }
    try { $null = & $Invoke (Get-SIMailSendRecordSql) @{ Name = $name; Value = (ConvertTo-SIMailSendRecordJson -Utc $NowUtc -Mode $Mode -ErrorText $err); By = $By } 'nonquery'; $true } catch { $false }
}

function Get-SIMailSendRecordInvoke {
    <#
        The SQL seam the send record uses: $global:SI_MailSendRecordInvoke when a job (or a test) set one; else, once per
        process, the Pro database from the job's globals (SI_ProSqlServer / _SqlDatabase, else the data backend's) through
        New-SIDataSqlInvoke when the job loaded it. $null = no record (no database, or none could be opened). Never throws.
    #>
    if ($global:SI_MailSendRecordInvoke -is [scriptblock]) { return $global:SI_MailSendRecordInvoke }
    if ($global:SI_MailSendRecordUnavailable) { return $null }
    $inv = $null
    try {
        if (Get-Command -Name New-SIDataSqlInvoke -ErrorAction SilentlyContinue) {
            foreach ($pair in @(@('SI_ProSqlServer', 'SI_ProSqlDatabase'), @('SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase'))) {
                $s = "$(Get-Variable -Name $pair[0] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
                $d = "$(Get-Variable -Name $pair[1] -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
                if ($s -and $d) { $inv = New-SIDataSqlInvoke -Server $s -Database $d -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint; break }
            }
        }
    } catch { $inv = $null }
    if ($inv -is [scriptblock]) { $global:SI_MailSendRecordInvoke = $inv; return $inv }
    $global:SI_MailSendRecordUnavailable = $true
    $null
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE MAIL FORWARD (#765, owner 2026-10-19: "is it possible to define mail forward on accounts like in pim, so each admin
#  account also get the repots but using their normal office"). A person on the Access page (cfg.AccessAssignment) may have
#  ForwardTo -- "Send SecurityInsight mail to". Send-SIMail applies it to EVERY mail it sends (the jobs' own report and
#  alert mails, and every mail the web app queued in an outbox: approvals, owners, notifications, management summaries):
#  a recipient that names that person -- by object id, their own mail / sign-in name, or a name shown that is a mail
#  address, case-insensitively -- gets the mail at the forward instead, never at both; the list is de-duplicated. Anyone
#  not in the table is unchanged. The web app validates the address before it is stored (Auth\MailForward.cs, the same
#  rules and the same test cases: MailForwardTests / SIv3-MailForward.Tests.ps1); a stored value that is not a real
#  address is never used.
# ---------------------------------------------------------------------------------------------------------------------
$script:SIMailForwardSentinels = @('false', 'none', 'n/a', 'na', 'null', 'nil', 'no', '0', '-', '--', 'empty')
$script:SIMailForwardCache = $null
$script:SIMailForwardWarned = $false

function Test-SIMailAddress {
    <# PURE. A real mail address: one local part, one @, a domain with a dot and a letter top-level domain; no name, no list. #>
    param([AllowNull()][AllowEmptyString()][string]$Address)
    $v = "$Address".Trim()
    if ($v.Length -le 5 -or $v.Length -gt 320) { return $false }
    if ($v.Contains('..') -or $v.StartsWith('.') -or $v.Contains('.@')) { return $false }
    return ($v -cmatch '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
}

function ConvertTo-SIMailForward {
    <# PURE. A stored / typed forward as the transport uses it: '' for a blank or a sentinel (FALSE, none, n/a, 0, ...) and
       for anything that is not a real mail address (never used); else the address, lower-case. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v -or $script:SIMailForwardSentinels -contains $v.ToLowerInvariant()) { return '' }
    if (-not (Test-SIMailAddress $v)) { return '' }
    $v.ToLowerInvariant()
}

function Get-SIMailForwardSql {
    <# PURE. The people with a forward (no column yet = none: a database one schema version behind). #>
@'
IF OBJECT_ID(N'cfg.AccessAssignment') IS NOT NULL AND COL_LENGTH(N'cfg.AccessAssignment', N'ForwardTo') IS NOT NULL
    EXEC (N'SELECT PrincipalId, DisplayName, AccountMail, ForwardTo FROM cfg.AccessAssignment WHERE PrincipalType = N''User'' AND ForwardTo IS NOT NULL;');
ELSE
    SELECT CAST(NULL AS nvarchar(64)) AS PrincipalId, CAST(NULL AS nvarchar(256)) AS DisplayName, CAST(NULL AS nvarchar(320)) AS AccountMail, CAST(NULL AS nvarchar(320)) AS ForwardTo WHERE 1 = 0;
'@
}

function ConvertTo-SIMailForwardMap {
    <# PURE. Rows (PrincipalId, DisplayName, AccountMail, ForwardTo) -> @{ '<key, lower-case>' = '<forward>' }: the object id, the
       account mail and a mail-address name of every person whose forward is a real address. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $get = { param($n) if ($r -is [System.Collections.IDictionary]) { "$($r[$n])" } elseif ($r.PSObject.Properties[$n]) { "$($r.$n)" } else { '' } }
        $f = ConvertTo-SIMailForward (& $get 'ForwardTo')
        if (-not $f) { continue }
        $keys = @((& $get 'PrincipalId').Trim().ToLowerInvariant())
        foreach ($n in 'AccountMail', 'DisplayName') { $k = (& $get $n).Trim(); if (Test-SIMailAddress $k) { $keys += $k.ToLowerInvariant() } }
        foreach ($k in $keys) { if ($k -and -not $map.ContainsKey($k)) { $map[$k] = $f } }
    }
    $map
}

function Resolve-SIMailRecipients {
    <# PURE. The list as it is sent: each address the map names is replaced by its forward (never both), de-duplicated
       case-insensitively (the first place of each kept). Returns @{ To (string[]); Changed (@{ From; To }[]) }. #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$To = @(), [AllowNull()][hashtable]$Map)
    $out = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $changed = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($To | ForEach-Object { "$_" -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        $target = $raw
        if ($Map) {
            $k = $raw.ToLowerInvariant()
            if ($Map.ContainsKey($k) -and $Map[$k] -and $Map[$k] -ne $k) { $target = [string]$Map[$k]; $changed.Add([pscustomobject]@{ From = $raw; To = $target }) }
        }
        if ($seen.Add($target)) { $out.Add($target) }
    }
    [pscustomobject]@{ To = [string[]]$out.ToArray(); Changed = @($changed.ToArray()) }
}

function Get-SIMailForwardMap {
    <# The forwards of the people with access, read once per 10 minutes per process: $global:SI_MailForwardMap when a job (or a
       test) set one; else the Pro database through the same seam as the send record (Get-SIMailSendRecordInvoke). Cannot
       be read = @{} (every address as given) and ONE line in the log. Never throws. #>
    param([scriptblock]$Invoke)
    if ($global:SI_MailForwardMap -is [hashtable]) { return $global:SI_MailForwardMap }
    if ($script:SIMailForwardCache -and $script:SIMailForwardCache.Until -gt [datetime]::UtcNow) { return $script:SIMailForwardCache.Map }
    $map = @{}
    try {
        $inv = if ($Invoke) { $Invoke } else { Get-SIMailSendRecordInvoke }
        # the reader answers its rows as ONE array (', $rows'): unrolled here, so each row is a row
        if ($inv) { $map = ConvertTo-SIMailForwardMap -Rows @(& $inv (Get-SIMailForwardSql) @{} 'rows' | ForEach-Object { $_ }) }
        $script:SIMailForwardCache = @{ Map = $map; Until = [datetime]::UtcNow.AddMinutes(10) }
    } catch {
        if (-not $script:SIMailForwardWarned) { Write-Host ('   note: the mail forwards of the people with access could not be read ({0}) -- every mail goes to the addresses as given' -f $_.Exception.Message); $script:SIMailForwardWarned = $true }
        $script:SIMailForwardCache = @{ Map = @{}; Until = [datetime]::UtcNow.AddMinutes(10) }
    }
    $map
}

function Send-SIMail {
    <#
        THE send. -Settings from Get-SIMailSettings (or Get-SIGuardSmtp / Get-SICloseLoopMailSmtp, the same object).
        Returns @{ Sent; Mode; Off; Error; Dropped (attachments left out); Restriction; Text; Pdf (its file name); PdfError }.
        NEVER throws; diagnostics are
        written to the host. -Http / -TokenProvider are the Graph seams (tests); -PdfBuilder the PDF seam ({ param($Subject, $Html) @{ Bytes; Error } }); -NoPdf: no PDF (a sign-in mail).
    #>
    param([Parameter(Mandatory)]$Settings, [Parameter(Mandatory)][string[]]$To, [string[]]$Cc = @(), [Parameter(Mandatory)][string]$Subject,
          [Parameter(Mandatory)][AllowEmptyString()][string]$BodyHtml, [string[]]$Attachments = @(),
          [ValidateSet('Normal', 'High', 'Low')][string]$Priority = 'Normal', [scriptblock]$Http, [scriptblock]$TokenProvider,
          [switch]$NoPdf, [scriptblock]$PdfBuilder,
          # MAIL-3 (#653): the subject's severity word (Failed | Warning | ActionNeeded; none = a report or information mail)
          # and a support ticket number -- both optional; Get-SIMailSubject builds the whole subject
          [AllowNull()][AllowEmptyString()][string]$Severity, [AllowNull()][AllowEmptyString()][string]$Ticket)
    $res = [ordered]@{ Sent = $false; Mode = [string]$Settings.Mode; Off = [bool]$Settings.Off; Error = $null; Dropped = @(); Restriction = $null; Text = ''; Pdf = $null; PdfError = $null }
    $fail = { param($m) $res.Error = $m; Write-Host ('   mail NOT sent: ' + $m); [pscustomobject]$res }
    $mode = if ($Settings.Mode) { [string]$Settings.Mode } else { 'smtp' }
    if ($Settings.Off) { Write-Host '   mail is off (SI_Mail_Mode = none) -- not sent'; $res.Error = 'mail is off (SI_Mail_Mode = none)'; return [pscustomobject]$res }
    if (@($Settings.Problems).Count) { return (& $fail ((@($Settings.Problems)) -join '; ')) }
    $to = @($To | ForEach-Object { "$_" -split '[;,]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $to.Count) { return (& $fail 'the mail has no recipient') }
    # #765 (owner 2026-10-19, "mail forward on accounts like in pim"): a recipient who is a person on the Access page with
    # "Send SecurityInsight mail to" gets the mail THERE, never at both; the list is de-duplicated. A mail that carries a
    # one-time secret (-NoPdf: a sign-in link or code) goes only to the address it was made for. Never fails a mail: the
    # forwards that cannot be read leave every address as it is (one line says so).
    if (-not $NoPdf) {
        try {
            $fwMap = Get-SIMailForwardMap
            $fw = Resolve-SIMailRecipients -To $to -Map $fwMap
            foreach ($c in @($fw.Changed)) { Write-Host ('   mail for {0} goes to {1} (their "Send SecurityInsight mail to" on Access)' -f $c.From, $c.To) }
            $to = @($fw.To)
            if (@($Cc | Where-Object { "$_".Trim() }).Count) {
                $ccr = Resolve-SIMailRecipients -To $Cc -Map $fwMap
                $Cc = @(@($ccr.To) | Where-Object { $to -notcontains $_ })
            }
        } catch { Write-Host ('   note: the mail forwards could not be applied ({0}) -- sent to the addresses as given' -f $_.Exception.Message) }
    }
    # MAIL-1 / MAIL-3: every mail names its environment -- the subject ('[<Name>] ... [SecurityInsight]') and the footer
    # (name, ring, edition), built here once for every sender
    $envInfo = if ($Settings.PSObject.Properties['Environment'] -and $Settings.Environment) { $Settings.Environment } else { Get-SIMailEnvironment }
    $Subject = Get-SIMailSubject -Subject $Subject -Environment $envInfo -Severity $Severity -Ticket $Ticket
    # MAIL-2 / #573: EVERY body goes through the one layout -- real paragraphs, explicit spacing, never raw text in HTML.
    # One HTML body: Graph sendMail takes one body, and so does the SMTP transport; .Text is the CRLF text rendering.
    $formatted = Format-SIMailBody -BodyHtml $BodyHtml -Title $Subject
    $BodyHtml = [string]$formatted.Html
    # #710 (owner 2026-10-16): ONE line under the summary -- "See details and history: <the install's page in the Invardia
    # portal>" -- only when Invardia has named the environment, only in a mail that has a summary (or a place-holder at
    # its top: the daily close-loop mail and the management summary, owner 2026-10-16), never in a mail that
    # carries a one-time secret (-NoPdf). Never fails a mail.
    if (-not $NoPdf) {
        try {
            $eid = if ($envInfo -and $envInfo.PSObject.Properties['InvardiaEnvironmentId']) { [string]$envInfo.InvardiaEnvironmentId } else { '' }
            if ($eid) { $BodyHtml = Add-SIInvardiaPortalLink -BodyHtml $BodyHtml -EnvironmentId $eid }
        } catch { }
    }
    # the place-holder of a mail that asks for the line at its top is never sent (no id, or a -NoPdf mail)
    try { $BodyHtml = Remove-SIInvardiaPortalLinkAnchor $BodyHtml } catch { }
    # a source on its last good collection: every mail that carries data says so, in the same sentence the pages show
    # (never fails a mail; a sign-in mail -- -NoPdf -- carries no data and no note)
    if (-not $NoPdf) {
        try {
            if (-not (Get-Command -Name Get-SISourceMailNotes -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SourceState.ps1') }
            $BodyHtml = Add-SIMailSourceNote -BodyHtml $BodyHtml -Notes @(Get-SISourceMailNotes)
        } catch { }
    }
    $BodyHtml = Add-SIMailFooter -BodyHtml $BodyHtml -Environment $envInfo
    $res.Text = ConvertTo-SIMailText -Html $BodyHtml

    # #574: ONE PDF of the mail -- its summary, facts and detail, exactly what the body shows (built from the body as it is
    # sent). Attached LAST, so a large report workbook keeps its place; over the attachment budget it is left out like
    # any attachment. A PDF that cannot be built never blocks the mail: it goes without it, and says so. -NoPdf: a mail
    # that carries a one-time secret (a sign-in link or code) never gets a copy of it in a file.
    $pdfPath = $null
    if (-not $NoPdf) {
        $pdf = $null
        try {
            $pdf = if ($PdfBuilder) { & $PdfBuilder $Subject $BodyHtml } else { New-SIMailPdf -Title $Subject -Html $BodyHtml -Footer ('SecurityInsight' + $(if ($envInfo -and $envInfo.Display) { ' - ' + [string]$envInfo.Display } else { '' })) }
        } catch { $pdf = [pscustomobject]@{ Bytes = $null; Error = ('the PDF could not be built: ' + $_.Exception.Message) } }
        if ($pdf -and $pdf.Bytes) {
            try {
                $pdfPath = Save-SIMailPdf -Bytes ([byte[]]$pdf.Bytes) -Subject $Subject
                $Attachments = @(@($Attachments | Where-Object { "$_".Trim() }) + @($pdfPath))
                $res.Pdf = Split-Path -Leaf $pdfPath
            } catch { $res.PdfError = 'the PDF could not be saved: ' + $_.Exception.Message }
        } else {
            $res.PdfError = if ($pdf -and $pdf.Error) { [string]$pdf.Error } else { 'the PDF could not be built' }
        }
        if ($res.PdfError) { Write-Host ('   warning: the mail goes without its PDF -- ' + $res.PdfError) }
    }
    try {

    if ($mode -eq 'sharedMailbox') {
        $r = Get-SIMailRestriction -Settings $Settings -Http $Http -TokenProvider $TokenProvider
        $res.Restriction = $r
        if (-not $r.AllowsSend) { return (& $fail ('Mail.Send is not restricted to the shared mailbox yet -- SecurityInsight does not send until it is. ' + $r.Detail)) }
        if ($r.State -eq 'legacy-policy') { Write-Host ('   note: ' + $r.Detail) }
        $plan = Get-SIMailAttachmentPlan -Paths $Attachments -MaxMb ([double]$Settings.MaxAttachmentMb)
        $res.Dropped = @($plan.Dropped)
        foreach ($d in $plan.Dropped) { Write-Host ('   attachment left out: {0} ({1} MB, ~{2} MB encoded; Microsoft Graph takes at most {3} MB in one mail) -- the file stays where it is' -f (Split-Path $d.Path -Leaf), $d.DiskMb, $d.EncodedMb, $plan.MaxMb) }
        $att = @(); foreach ($p in $plan.Include) { $att += @{ Name = (Split-Path $p -Leaf); ContentType = (Get-SIMailContentType $p); Bytes = [IO.File]::ReadAllBytes($p) } }
        $body = New-SIGraphSendMailBody -To $to -Cc $Cc -Subject $Subject -BodyHtml $BodyHtml -Priority $Priority -Attachments $att
        if (-not $Http) { $Http = { param($u, $t, $b) Invoke-SIMailHttp -Uri $u -Token $t -Body $b } }
        if (-not $TokenProvider) { $TokenProvider = { Get-SIMailGraphToken } }
        Write-Host ("Sending mail (shared mailbox {0}) to {1} with subject '{2}'" -f $Settings.SharedMailbox, ($to -join ', '), $Subject)
        try {
            $tok = [string](& $TokenProvider)
            $resp = & $Http ('https://graph.microsoft.com/v1.0/users/{0}/sendMail' -f [uri]::EscapeDataString([string]$Settings.SharedMailbox)) $tok $body
        } catch { return (& $fail ('Microsoft Graph could not be reached: ' + $_.Exception.Message)) }
        if ([int]$resp.StatusCode -eq 202) { $res.Sent = $true; return [pscustomobject]$res }
        $e = Get-SIMailGraphError -Body ([string]$resp.Body)
        $hint = if ([int]$resp.StatusCode -eq 403) { ' -- SecurityInsight may not send as this mailbox (Exchange role assignment)' } elseif ([int]$resp.StatusCode -eq 413) { ' -- the mail is too large for Microsoft Graph' } else { '' }
        $script:SIMailRestrictionCache.Clear()
        # the status with its name ('403 (Forbidden)'), so the heartbeat's error class reads it (#719: Mail.lastErrorCode)
        $sc = [int]$resp.StatusCode; $scName = ''; try { $scName = ' ({0})' -f ([System.Net.HttpStatusCode]$sc) } catch { $scName = '' }
        return (& $fail ('Microsoft Graph answered {0}{1} {2}: {3}{4}' -f $sc, $scName, $e.Code, $e.Message, $hint))
    }

    # smtp -- the Risk Analysis transports (RA-Mail.ps1), the one place that talks SMTP
    if (-not (Get-Command -Name Send-MailAnonymous -ErrorAction SilentlyContinue)) {
        $ra = [IO.Path]::Combine($script:SIMailTransportRoot, 'engine', 'risk-analysis', '_shared', 'RA-Mail.ps1')
        if (Test-Path -LiteralPath $ra) { . $ra }
    }
    if (-not (Get-Command -Name Send-MailAnonymous -ErrorAction SilentlyContinue)) { return (& $fail 'the SMTP transports (RA-Mail.ps1) are not available') }
    $plan = Get-SIMailAttachmentPlan -Paths $Attachments -MaxMb ([double]$Settings.MaxAttachmentMb)
    $res.Dropped = @($plan.Dropped)
    $smtpArgs = @{ SmtpServer = [string]$Settings.Server; Port = [int]$Settings.Port; UseSsl = [bool]$Settings.UseSsl; From = [string]$Settings.From; To = $to; Subject = $Subject; BodyHtml = $BodyHtml; Priority = $Priority }
    if (@($plan.Include).Count) { $smtpArgs.Attachments = @($plan.Include) }
    if ($Settings.Anonymous) {
        $out = @(Send-MailAnonymous @smtpArgs)
        $lines = @($out | Where-Object { $_ -isnot [bool] } | ForEach-Object { [string]$_ })
        foreach ($l in $lines) { Write-Host $l }
        $verdict = @($out | Where-Object { $_ -is [bool] }) | Select-Object -Last 1
        if (-not $verdict) {
            $detail = @($lines | Where-Object { $_ -match 'FAILED|Message\s*:|StatusCode|InnerException' } | ForEach-Object { $_.Trim() }) -join ' | '
            if (-not $detail) { $detail = 'the relay did not accept the message' }
            $res.Error = $detail; return [pscustomobject]$res
        }
        $res.Sent = $true; return [pscustomobject]$res
    }
    try {
        $smtpArgs.Credential = New-Object System.Management.Automation.PSCredential ([string]$Settings.User, (ConvertTo-SecureString ([string]$Settings.Password) -AsPlainText -Force))
        $out = @(Send-MailSecure @smtpArgs -ErrorAction Stop)
        foreach ($l in $out) { Write-Host ([string]$l) }
        $res.Sent = $true
    } catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m += ' (' + $_.Exception.InnerException.Message + ')' }
        $res.Error = $m
    }
    [pscustomobject]$res
    } finally {
        # #574: the PDF's temp copy goes once the mail is handed over (sent or not)
        if ($pdfPath) { Remove-Item -LiteralPath (Split-Path -Parent $pdfPath) -Recurse -Force -ErrorAction SilentlyContinue }
        # #719: every send leaves its outcome for the heartbeat (cfg.InstallState 'MailLastSent' / 'MailLastFailed'); never fails a mail
        try { $recInv = Get-SIMailSendRecordInvoke; if ($recInv) { $null = Write-SIMailSendRecord -Invoke $recInv -Sent ([bool]$res.Sent) -ErrorText ([string]$res.Error) -Mode $mode } } catch { }
    }
}
