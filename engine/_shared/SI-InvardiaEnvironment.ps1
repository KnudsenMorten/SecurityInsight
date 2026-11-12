#Requires -Version 5.1
<#
    SecurityInsight -- INVARDIA IS THE MASTER OF THE ENVIRONMENT NAME (#1151 (5) NAM-02 / OPEN-11; framework §8.14 ENV-NAME-MASTER,
    owner 2026-10-11; Invardia DESIGN "For SI and PIM": GET /api/enrollments/environment).

    Customers rename their environments in the Invardia portal; the product READS the name from Invardia. On every FULL heartbeat
    (once per half hour, engine\heartbeat\Invoke-SIHeartbeat.ps1) the heartbeat job asks:

      GET <Invardia>/api/enrollments/environment   header X-Invardia-Install-Key = the install key
        200 { environmentId, environmentName, kind, handle, tenantId, customer: { name }, managedBy: { name } | null, displayName }

    and keeps the LAST GOOD value in the Pro database (cfg.InstallState 'InvardiaEnvironment' = { name, id, kind, handle,
    tenantId, displayName, readUtc } -- #1211: every mail names the handle, the kind and the tenant from it, SI-MailEnvironment.ps1;
    the customer's and the managing company's names are never kept),
    at most 400 characters). A FAILED read NEVER blanks it: 404 (the route is not live), 5xx, no answer, an answer that is
    not the agreed shape, or an empty environmentName all leave the stored value as it was (said in one line). An anonymous
    install (Community, no install key) asks nothing: its own configured name stays. Names are never keys -- the tenant id
    is the identity everywhere; this value is only ever SHOWN.

    Nothing of it goes back to Invardia (the uplink's wire contract is closed: no new key is sent). The mails show the kept
    handle / kind (#1211); showing the kept name in the web app's header is a later step (it changes who owns the
    "Environment name" setting).

    NEVER THROWS where the job calls it (Invoke-SIInvardiaEnvironmentRead). PowerShell 5.1 and 7. No PowerShell modules.
    The one HTTP call goes through Invoke-SIUpdateNowHttp (engine\_shared\SI-UpdateNowSignal.ps1 -- the raw-call ratchet).
#>

if (-not (Get-Command -Name Invoke-SIUpdateNowHttp -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-UpdateNowSignal.ps1')) }

$script:SIInvardiaEnv = @{
    Row        = 'InvardiaEnvironment'
    Path       = '/api/enrollments/environment'
    Header     = 'X-Invardia-Install-Key'
    TimeoutSec = 5
    NameMax    = 200
    KindMax    = 40
}

# =====================================================================================================================
#  PURE
# =====================================================================================================================
function Get-SIInvardiaEnvironmentUri {
    <# PURE. The ORIGIN of the uplink endpoint this install reports to (https only; else Invardia's) + /api/enrollments/environment. #>
    param([AllowNull()][AllowEmptyString()][string]$Endpoint)
    $origin = 'https://invardia.com'
    if ("$Endpoint".Trim() -match '^(https://[^/\s?#]+)') { $origin = $Matches[1] }
    $origin + $script:SIInvardiaEnv.Path
}

function ConvertTo-SIInvardiaEnvironmentText {
    <# PURE. One line of text: control characters to spaces, trimmed, cut at -Max. '' for $null. #>
    param($Value, [int]$Max = 200)
    if ($null -eq $Value -or $Value -is [DBNull]) { return '' }
    $s = ([string]$Value -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max).TrimEnd() }
    $s
}

function ConvertFrom-SIInvardiaEnvironment {
    <# PURE. Invardia's answer (JSON text or an object) -> @{ Name; Id; Kind }, or $null when it is not the agreed shape: an object
       whose environmentName is a non-empty text (an empty name is NOT a name -- it never replaces a kept one). #>
    param($Body)
    try {
        $o = if ($Body -is [string]) { if (-not "$Body".Trim()) { return $null }; ("$Body".TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop) } else { $Body }
        if ($null -eq $o -or $o -is [string] -or $o -is [ValueType] -or $o -is [array] -or -not $o.PSObject.Properties['environmentName']) { return $null }
        if ($null -ne $o.environmentName -and -not ($o.environmentName -is [string])) { return $null }
        $name = ConvertTo-SIInvardiaEnvironmentText $o.environmentName $script:SIInvardiaEnv.NameMax
        if (-not $name) { return $null }
        $id = if ($o.PSObject.Properties['environmentId']) { ConvertTo-SIInvardiaEnvironmentText $o.environmentId 64 } else { '' }
        $kind = if ($o.PSObject.Properties['kind']) { ConvertTo-SIInvardiaEnvironmentText $o.kind $script:SIInvardiaEnv.KindMax } else { '' }
        # #1211 MAIL-ENV: the handle, the tenant id and the display name every mail names; the customer's and the managing
        # company's names are never kept (a mail never carries another customer's name)
        $txt = { param($n, [int]$max) $p = $o.PSObject.Properties[$n]; if ($p -and ($p.Value -is [string])) { ConvertTo-SIInvardiaEnvironmentText $p.Value $max } else { '' } }
        $display = & $txt 'displayName' $script:SIInvardiaEnv.NameMax
        [pscustomobject]@{ Name = $name; Id = $id; Kind = $kind; Handle = (& $txt 'handle' 64); TenantId = (& $txt 'tenantId' 64)
                           DisplayName = $(if ($display -and $display -cne $name) { $display } else { '' }) }
    } catch { $null }
}

function New-SIInvardiaEnvironmentStateValue {
    <# PURE. The cfg.InstallState 'InvardiaEnvironment' value: { name, id, kind, readUtc } -- at most 400 characters (kind, then
       id are dropped first, then the name is shortened). #>
    param([Parameter(Mandatory)]$Environment, [Parameter(Mandatory)][datetime]$ReadUtc)
    $opt = { param($n) if ($Environment.PSObject.Properties[$n] -and "$($Environment.$n)") { [string]$Environment.$n } else { $null } }
    $o = [ordered]@{ name = [string]$Environment.Name; id = (& $opt 'Id'); kind = (& $opt 'Kind')
                     handle = (& $opt 'Handle'); tenantId = (& $opt 'TenantId'); displayName = (& $opt 'DisplayName')
                     readUtc = $ReadUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    # what a mail needs most stays longest: the handle, then the kind (#1211 MAIL-ENV)
    foreach ($drop in @('', 'displayName', 'id', 'tenantId', 'kind')) {
        if ($drop) { $o[$drop] = $null }
        $v = $o | ConvertTo-Json -Compress
        if ($v.Length -le 400) { return $v }
    }
    while ($o.name.Length -gt 1) { $o.name = $o.name.Substring(0, [Math]::Max(1, $o.name.Length - 10)).TrimEnd(); $v = $o | ConvertTo-Json -Compress; if ($v.Length -le 400) { return $v } }
    $o | ConvertTo-Json -Compress
}

function ConvertFrom-SIInvardiaEnvironmentStateRow {
    <# PURE. The stored row (the store's answer, any shape) -> @{ Name; Id; Kind; ReadUtc } or $null. #>
    param($Answer)
    try {
        $rows = @(ConvertTo-SIHeartbeatSqlRows $Answer)
        if (-not $rows.Count) { return $null }
        $v = Get-SIHeartbeatRowValue $rows[0] 'Value'
        if ($null -eq $v -and ($rows[0] -is [string])) { $v = $rows[0] }
        if (-not "$v".Trim()) { return $null }
        $j = "$v" | ConvertFrom-Json -ErrorAction Stop
        if (-not $j.PSObject.Properties['name'] -or -not "$($j.name)".Trim()) { return $null }
        [pscustomobject]@{ Name = [string]$j.name; Id = $(if ($j.PSObject.Properties['id'] -and $j.id) { [string]$j.id } else { '' })
                           Kind = $(if ($j.PSObject.Properties['kind'] -and $j.kind) { [string]$j.kind } else { '' })
                           Handle = $(if ($j.PSObject.Properties['handle'] -and $j.handle) { [string]$j.handle } else { '' })
                           TenantId = $(if ($j.PSObject.Properties['tenantId'] -and $j.tenantId) { [string]$j.tenantId } else { '' })
                           DisplayName = $(if ($j.PSObject.Properties['displayName'] -and $j.displayName) { [string]$j.displayName } else { '' })
                           ReadUtc = $(if ($j.PSObject.Properties['readUtc'] -and $j.readUtc) { ConvertTo-SIUpdateNowUtc $j.readUtc } else { '' }) }
    } catch { $null }
}

# =====================================================================================================================
#  The Pro database: the last good value
# =====================================================================================================================
function Get-SIInvardiaEnvironmentReadSql {
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    SELECT Value FROM cfg.InstallState WHERE Name = N'InvardiaEnvironment';
'@
}

function Get-SIInvardiaEnvironmentSaveSql {
    <# Upsert of the last GOOD value (only ever called with a good read). Answers ONE row: Saved. No table = 0. #>
    @'
SET NOCOUNT ON;
DECLARE @n int = 0;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'InvardiaEnvironment')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'heartbeat' WHERE Name = N'InvardiaEnvironment';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'InvardiaEnvironment', @Value, NULL, N'heartbeat');
    SET @n = @@ROWCOUNT;
    COMMIT;
END
SELECT @n AS Saved;
'@
}

function Read-SIInvardiaEnvironmentState {
    <# The kept value, or $null (none, no database, unreadable). Never throws. #>
    param([scriptblock]$Invoke)
    if (-not $Invoke) { return $null }
    try { ConvertFrom-SIInvardiaEnvironmentStateRow (& $Invoke (Get-SIInvardiaEnvironmentReadSql) @{} 'reader') } catch { $null }
}

function Get-SIInvardiaEnvironmentName {
    <# The environment name Invardia gave last (the kept value), '' when none is kept. Never throws. #>
    param([scriptblock]$Invoke)
    $s = Read-SIInvardiaEnvironmentState -Invoke $Invoke
    if ($s) { [string]$s.Name } else { '' }
}

# =====================================================================================================================
#  THE READ -- once per full heartbeat
# =====================================================================================================================
function Invoke-SIInvardiaEnvironmentRead {
    <#
        One read of the environment name. NEVER throws; returns @{ Status; Name; Line; Changed }. Status: skipped | read |
        unavailable (HTTP 404: the route is not live yet) | kept (any other failed read) | error. Name: the name this install shows from Invardia after the read (the kept one when the read failed; '' =
        none). Line: '' when a good read changed nothing. Seams (tests):
          -Context  Get-SITelemetryContext (Mode, Endpoint, AccessCode)
          -Invoke   the Pro database { param($Sql, $Params, $Mode) }
          -Http     { param($Uri, $InstallKey) } -> @{ Status; Body; Error } (default Invoke-SIUpdateNowHttp; a test session
                    without it never asks Invardia)
          -Now      the read time
    #>
    [CmdletBinding()]
    param($Context, [scriptblock]$Invoke, [scriptblock]$Http, $Now)
    $out = { param($s, $name, $line, [bool]$changed = $false) [pscustomobject]@{ Status = $s; Name = $name; Line = $line; Changed = $changed } }
    $kept = $null
    try {
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        if (-not $Context) { $Context = Get-SITelemetryContext }
        if (-not $Context -or [string]$Context.Mode -ne 'identified' -or -not "$($Context.AccessCode)".Trim()) { return (& $out 'skipped' '' '') }
        if (-not $Http) {
            if (Get-Module -Name Pester) { return (& $out 'skipped' '' '') }
            $Http = { param($Uri, $InstallKey) $h = [ordered]@{}; $h[$script:SIInvardiaEnv.Header] = $InstallKey; Invoke-SIUpdateNowHttp -Method 'GET' -Uri $Uri -Headers $h -TimeoutSec $script:SIInvardiaEnv.TimeoutSec }
        }
        $kept = Read-SIInvardiaEnvironmentState -Invoke $Invoke
        $keptName = if ($kept) { [string]$kept.Name } else { '' }
        $keptText = if ($keptName) { "'$keptName' stays" } else { 'none is kept yet' }
        $ans = $null
        try { $ans = & $Http (Get-SIInvardiaEnvironmentUri -Endpoint ([string]$Context.Endpoint)) ([string]$Context.AccessCode) }
        catch { $ans = [pscustomobject]@{ Status = 0; Body = ''; Error = $_.Exception.Message } }
        $code = if ($ans) { [int]$ans.Status } else { 0 }
        $env = $null
        if ($code -eq 200) { $env = ConvertFrom-SIInvardiaEnvironment -Body $ans.Body }
        if (-not $env) {
            # A FAILED READ NEVER BLANKS THE KEPT NAME
            $why = if ($code -eq 200) { 'the answer is not the agreed shape or names no environment' }
                   elseif ($code -eq 404) { 'Invardia does not answer this question yet (HTTP 404)' }
                   elseif ($code -gt 0) { 'HTTP {0}' -f $code }
                   else { 'no answer: {0}' -f $(if ($ans -and "$($ans.Error)".Trim()) { $(if (Get-Command -Name ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { ConvertTo-AitUplinkRedacted -Text ([string]$ans.Error) } else { 'the call failed' }) } else { 'unknown' }) }
            return (& $out $(if ($code -eq 404) { 'unavailable' } else { 'kept' }) $keptName ('environment name: Invardia''s name for this environment could not be read ({0}) -- the last known name {1}' -f $why, $keptText))
        }
        $changed = [bool](-not $kept -or $keptName -cne $env.Name -or [string]$kept.Id -ne [string]$env.Id -or [string]$kept.Kind -ne [string]$env.Kind -or
                          [string]$kept.Handle -cne [string]$env.Handle -or [string]$kept.TenantId -ne [string]$env.TenantId -or [string]$kept.DisplayName -cne [string]$env.DisplayName)
        $saved = $false
        if ($Invoke) {
            try {
                $rows = @(ConvertTo-SIHeartbeatSqlRows (& $Invoke (Get-SIInvardiaEnvironmentSaveSql) ([ordered]@{ Value = (New-SIInvardiaEnvironmentStateValue -Environment $env -ReadUtc $nowUtc) }) 'reader'))
                if ($rows.Count) { $c = Get-SIHeartbeatRowValue $rows[0] 'Saved'; if ($null -eq $c -and ($rows[0] -is [ValueType])) { $c = $rows[0] }; $saved = ($null -ne $c -and [int]$c -ge 1) }
            } catch { $saved = $false }
        }
        if (-not $saved) { return (& $out 'read' $env.Name ('environment name: Invardia names this environment ''{0}'', but it could not be kept in the SecurityInsight database -- it is read again with the next status report' -f $env.Name) $changed) }
        if (-not $changed) { return (& $out 'read' $env.Name '') }
        & $out 'read' $env.Name $(if ($keptName -and $keptName -cne $env.Name) { 'environment name: Invardia now names this environment ''{0}'' (was ''{1}'')' -f $env.Name, $keptName } else { 'environment name: Invardia names this environment ''{0}''' -f $env.Name }) $true
    } catch {
        & $out 'error' $(if ($kept) { [string]$kept.Name } else { '' }) ('environment name: not read this time ({0}) -- the last known name stays' -f $_.Exception.Message)
    }
}
