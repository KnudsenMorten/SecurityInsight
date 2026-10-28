<#
.SYNOPSIS
    Renders config\SecurityInsight.custom.ps1 from the Setup Wizard's collected state.

.DESCRIPTION
    Combines outputs from New-SISpn + Initialize-SIInfra (the SPN block + workspace /
    DCE / DCR / storage block) with optional sections the wizard's pages collected
    (SMTP, Azure OpenAI, Shodan, CMDB, per-engine JSON sink), and writes a complete
    SecurityInsight.custom.ps1 to disk.

    Idempotent. If the target file exists, backs it up to *.bak.<timestamp> before
    overwriting -- never silently destroys an operator's customizations.

    Storage: only the account name and resource group are written. Storage is reached
    with the signed-in identity (Storage Blob/Table/Queue Data Contributor roles).

.PARAMETER OutputPath
    Where to write the file. Default: <repo>\config\SecurityInsight.custom.ps1.

.PARAMETER Spn
    Output object from New-SISpn. Required.

.PARAMETER Infra
    Output object from Initialize-SIInfra. Required.

.PARAMETER Smtp
    Optional hashtable. Keys: Server, Port, UseSsl, User, Password, From, MailTo[],
    DetailedTo[], SummaryTo[]. Omit to skip the SMTP section entirely.

.PARAMETER OpenAi
    Optional hashtable. Keys: Endpoint, Deployment, ApiKey, ApiVersion, MaxTokens, MaxSpendUsd.

.PARAMETER Shodan
    Optional hashtable. Keys: ApiKey, ExtraTargets[].

.PARAMETER Cmdb
    Optional hashtable. Keys: Enabled, RefreshHours, CsvPath.

.PARAMETER EnableJsonSink
    Add 'JSON' to every SI_Sinks_<Engine> array. Default $false (LA + Excel only).

.PARAMETER DefenderWorkspaceResourceId
    Optional. ResourceId of a separate Sentinel/Defender workspace where Entra
    diagnostic logs land (read-only).

.OUTPUTS
    pscustomobject @{ Path; Bytes; Sections; Backup }

.NOTES
    Status: v2.2.105 -- ships with New-SISpn + Initialize-SIInfra + /api/apply.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]          [string]$OutputPath,
    [Parameter(Mandatory)] [object]$Spn,
    [Parameter(Mandatory)] [object]$Infra,
    [Parameter()]          [hashtable]$Smtp,
    [Parameter()]          [hashtable]$OpenAi,
    [Parameter()]          [hashtable]$Shodan,
    [Parameter()]          [hashtable]$Cmdb,
    [Parameter()]          [switch]$EnableJsonSink,
    [Parameter()]          [string]$DefenderWorkspaceResourceId,

    # Refuse to overwrite an existing custom.ps1 unless caller is explicit.
    # Backup-and-clobber was the v2.2.x default; in practice a container-flavour
    # bootstrap silently rewrote a live VM operator's customizations, leaving
    # only a *.bak.<ts> to find later. Default is now SAFE: bail with a
    # clear message + the backup path that WOULD have been written. Pass
    # -Force to keep the original (rewrite) behaviour.
    [Parameter()]          [switch]$Force,

    # #176: UPGRADE an existing file instead of refusing or regenerating it. Every value already in the file
    # stays exactly as it is; only settings it does not assign yet are appended (one marked, dated block),
    # after a backup. What re-running setup on an existing install should do.
    [Parameter()]          [switch]$Merge

    # v2.3 single-template: emits resolved values directly. v2.2 Bridged mode
    # (referenced $global:HighPriv_Modern_* from v1 Connect_Azure chain) is gone --
    # platform-tier customers (AutomateIT + Community-Multi) get the same Inline
    # output and the runtime KV pulls in section 11 use Connect-Platform's $global:Context.
)

$ErrorActionPreference = 'Stop'

if (-not $OutputPath) {
    # Resolve <SI repo root>\config\SecurityInsight.custom.ps1 by walking up from
    # this script's location.
    $cur = $PSScriptRoot
    while ($cur -and -not (Test-Path -LiteralPath (Join-Path $cur 'VERSION'))) {
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { $cur = $null; break }
        $cur = $parent
    }
    if (-not $cur) { throw 'Could not auto-resolve SI repo root. Pass -OutputPath explicitly.' }
    $OutputPath = Join-Path $cur 'config\SecurityInsight.custom.ps1'
}

# EVERY value written into the generated file goes through _Q. The file is PowerShell that every
# launcher dot-sources -- as SYSTEM on a scheduled host -- and values were pasted between single quotes
# unescaped: a ' in an SMTP password broke every launcher, and a value like  x'; <code>; '  became code.
# Inside a single-quoted literal the ONLY special characters are the quote characters, and PowerShell
# accepts four Unicode quotes as well as the ASCII one; each is doubled, which makes it literal.
function _Q([AllowNull()][object]$Value) {
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    foreach ($q in @([char]0x27, [char]0x2018, [char]0x2019, [char]0x201A, [char]0x201B)) {
        $s = $s.Replace([string]$q, [string]$q + [string]$q)
    }
    return "'" + $s + "'"
}

function _Step([string]$msg) { Write-Host "  [STEP] $msg" -ForegroundColor Cyan }
function _Ok  ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }

Write-Host ""
Write-Host "=== Write-SICustomConfig ===" -ForegroundColor Cyan
_Info "output : $OutputPath"
Write-Host ""

# ---------- Build sections ----------
$sb = New-Object System.Text.StringBuilder
$sectionsWritten = @()
$null = $sb.AppendLine("#Requires -Version 5.1")
$null = $sb.AppendLine("<#")
$null = $sb.AppendLine("    SecurityInsight customer config -- generated by Setup Wizard.")
$null = $sb.AppendLine("    Generated UTC: $((Get-Date).ToUniversalTime().ToString('u'))")
$null = $sb.AppendLine("    DO NOT commit this file. config\ is gitignored on purpose.")
$null = $sb.AppendLine("#>")
$null = $sb.AppendLine()

# ---- 1. SPN ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 1. SPN  --  identity SI uses for Graph + Az + LA Ingest")
$null = $sb.AppendLine("# ============================================================================")
# v2.3: emit resolved values directly. The Bridged variant
# (which referenced $global:HighPriv_Modern_*) is gone -- platform-tier
# customers now get their KV-sourced secrets via section 11 below
# using Connect-Platform's $global:Context.
# The sign-in, said explicitly (auth\SI-AuthMethod.ps1): every engine, the launchers and Bootstrap read this one setting.
$authMethodValue = switch ([string]$Spn.CredKind) { 'ManagedIdentity' { 'ManagedIdentity' } 'Cert' { 'Certificate' } default { 'Secret' } }
$null = $sb.AppendLine("`$global:SI_AuthMethod   = $(_Q $authMethodValue)   # ManagedIdentity (default) | Certificate | Secret")
if ([string]$Spn.CredKind -ne 'ManagedIdentity') { $null = $sb.AppendLine("`$global:SI_SPN_AppId    = $(_Q ($Spn.AppId))") }
$null = $sb.AppendLine("`$global:SI_SPN_TenantId = $(_Q ($Spn.TenantId))")
if ([string]$Spn.CredKind -ne 'ManagedIdentity' -or [string]$Spn.ObjectId) { $null = $sb.AppendLine("`$global:SI_SPN_ObjectId = $(_Q ($Spn.ObjectId))") }
switch ($Spn.CredKind) {
    'Secret' {
        if ($Spn.CredValue) {
            $null = $sb.AppendLine("`$global:SI_SPN_Secret   = $(_Q ($Spn.CredValue))")
        }
        if ($Spn.KvName) {
            $null = $sb.AppendLine("`$global:SI_KeyVaultName       = $(_Q ($Spn.KvName))")
            $null = $sb.AppendLine("`$global:SI_SPN_KvSecretName   = $(_Q ($Spn.KvSecretName))")
            $null = $sb.AppendLine("`$global:SpnKeyVaultName       = `$global:SI_KeyVaultName   # the name the az CLI sign-in reads")
            if (-not $Spn.CredValue) {
                # Names alone were emitted before, and nothing turned them into a secret -- every engine
                # then ran with no SPN credential. The secret stays in Key Vault; it is read into memory
                # each time this file loads.
                $null = $sb.AppendLine("# The SPN secret lives only in Key Vault -- read into memory on every load, never written here.")
                $null = $sb.AppendLine("if (-not `$global:SI_SPN_Secret) {")
                $null = $sb.AppendLine("    try {")
                $null = $sb.AppendLine("        . (Join-Path `$PSScriptRoot '..\auth\Get-SIKvSecret.ps1')")
                $null = $sb.AppendLine("        `$global:SI_SPN_Secret = Get-SIKvSecret -VaultName `$global:SI_KeyVaultName -SecretName `$global:SI_SPN_KvSecretName")
                $null = $sb.AppendLine("    } catch { Write-Warning (`"SI custom: the SPN secret could not be read from Key Vault: {0}`" -f `$_.Exception.Message) }")
                $null = $sb.AppendLine("}")
            }
        }
    }
    'Cert' {
        $null = $sb.AppendLine("`$global:SI_SPN_CertThumbprint = $(_Q ($Spn.CertThumbprint))")
        if ($Spn.KvName) {
            $null = $sb.AppendLine("`$global:SI_KeyVaultName     = $(_Q ($Spn.KvName))")
            # Where setup stored a copy of the certificate -- for recovery, not a setting (nothing reads it; #174).
            $null = $sb.AppendLine(("# SPN certificate also held in Key Vault as certificate: {0}" -f (($Spn.KvCertName -replace '[\r\n]', ' '))))
        }
    }
    'ManagedIdentity' {
        # Empty client id = the host's / the job's own identity (a Container Apps job is given SI_UAMI_CLIENTID by setup).
        $null = $sb.AppendLine("`$global:SI_ManagedIdentityClientId = $(_Q ($Spn.ManagedIdentityId))")
        $null = $sb.AppendLine("`$global:SI_SPN_UseManagedIdentity = `$true")
        $null = $sb.AppendLine("`$global:SI_SPN_ManagedIdentityClientId = $(_Q ($Spn.ManagedIdentityId))")
    }
}
$null = $sb.AppendLine()
$sectionsWritten += 'SPN'

# ---- 2. Infrastructure (workspace + DCE + DCR) ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 2. INFRASTRUCTURE  --  workspace / DCE / storage (created by setup; a run creates none)")
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("`$global:SI_Location                   = $(_Q ($Infra.Location))")
$null = $sb.AppendLine("`$global:SI_AzSubscriptionId           = $(_Q ($Infra.SubscriptionId))")
$null = $sb.AppendLine()
$null = $sb.AppendLine("`$global:SI_WorkspaceName              = $(_Q ($Infra.WorkspaceName))")
$null = $sb.AppendLine("`$global:SI_WorkspaceResourceGroup     = $(_Q ($Infra.ResourceGroupName))")
$null = $sb.AppendLine("`$global:SI_WorkspaceResourceId        = $(_Q ($Infra.WorkspaceResourceId))")
if ($DefenderWorkspaceResourceId) {
    $null = $sb.AppendLine("`$global:SI_DefenderWorkspaceResourceId = $(_Q $DefenderWorkspaceResourceId)")
}
$null = $sb.AppendLine()
$null = $sb.AppendLine("`$global:SI_DceName                    = $(_Q ($Infra.DceName))")
$null = $sb.AppendLine("`$global:SI_DceIngestionUri            = $(_Q ($Infra.DceIngestionUri))")
$null = $sb.AppendLine("`$global:SI_DceResourceGroup           = $(_Q ($Infra.ResourceGroupName))")
$null = $sb.AppendLine("`$global:SI_DcrResourceGroup           = $(_Q ($Infra.DcrResourceGroupName))")
$null = $sb.AppendLine()
$null = $sb.AppendLine("`$global:SI_TableNamePattern           = 'SI_{0}_Profile'")
$null = $sb.AppendLine("# v2.2.255 -- `$global:SI_DcrNamePattern dropped from wizard output. Every profiler")
$null = $sb.AppendLine("# engine has an explicit `$global:SI_<Engine>_DcrName override below, which always")
$null = $sb.AppendLine("# wins over the pattern -- emitting the pattern was dead code. Engine still has")
$null = $sb.AppendLine("# its own internal fallback ('dcr-si-{0}-profile' in Invoke-Output.ps1) for any")
$null = $sb.AppendLine("# engine not covered by an override.")
$null = $sb.AppendLine()
$null = $sb.AppendLine("# Per-engine DCR overrides (default names; edit if you collide with existing tables in the workspace)")
$null = $sb.AppendLine("`$global:SI_RiskAnalysis_DcrName_Detailed = 'dcr-si-risk-analysis-detailed'")
$null = $sb.AppendLine("`$global:SI_RiskAnalysis_DcrName_Summary  = 'dcr-si-risk-analysis-summary'")
$null = $sb.AppendLine("`$global:SI_RunHealth_DcrName             = 'dcr-si-run-health'")
$null = $sb.AppendLine("`$global:SI_SchemaCatalogDcr              = 'dcr-si-schema-catalog'")
$null = $sb.AppendLine("`$global:SI_AssetTagActivityDcr           = 'dcr-si-assettag-activity'")
$null = $sb.AppendLine("`$global:SI_Endpoint_DcrName              = 'dcr-si-endpoint-profile'")
$null = $sb.AppendLine("`$global:SI_Azure_DcrName                 = 'dcr-si-azure-profile'")
$null = $sb.AppendLine("`$global:SI_Identity_DcrName              = 'dcr-si-identity-profile'")
$null = $sb.AppendLine("`$global:SI_PublicIp_DcrName              = 'dcr-si-publicip-profile'")   # (was SI_Shodan_DcrName -- no longer read since 3.0.0)
$null = $sb.AppendLine()
$sectionsWritten += 'Infrastructure'

# ---- 3. Storage (the signed-in identity only) ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 3. STORAGE  --  reached with the signed-in identity, which needs Storage")
$null = $sb.AppendLine("#                  Blob/Table/Queue Data Contributor on the storage account")
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("`$global:SI_StorageAccount             = $(_Q ($Infra.StorageAccountName))")
$null = $sb.AppendLine("`$global:SI_StorageResourceGroup       = $(_Q ($Infra.StorageResourceGroupName))")
$null = $sb.AppendLine()
$sectionsWritten += 'Storage'

# ---- 4. Output sinks ----
$sinks = if ($EnableJsonSink) { "@('LA','Excel','JSON')" } else { "@('LA','Excel')" }
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 4. OUTPUT SINKS  --  per-engine output destinations")
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("`$global:SI_Sinks_Endpoint = $sinks")
$null = $sb.AppendLine("`$global:SI_Sinks_Identity = $sinks")
$null = $sb.AppendLine("`$global:SI_Sinks_Azure    = $sinks")
$null = $sb.AppendLine("`$global:SI_Sinks_PublicIp = $sinks")
# #830: the copy of the Risk Analysis report rows to Log Analytics is an optional output, off by default
$null = $sb.AppendLine("`$global:SendToLogAnalytics = `$false   # optional copy of the Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL) -- off by default; SecurityInsight reads its database")
$null = $sb.AppendLine()
$sectionsWritten += 'Sinks'

# ---- 5. SMTP (optional) ----
# Only emit the SMTP block when there's actually a server to send through. A
# hashtable with all-null fields can leak through when the wizard state still
# carries a stale smtp object the operator selected then turned off.
if ($Smtp -and $Smtp.Server) {
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("# 5. SMTP  --  email dispatch")
    $null = $sb.AppendLine("# ============================================================================")
    # v2.2.229 -- recipient-list serialization. The wizard frontend sometimes
    # delivers MailTo/DetailedTo/SummaryTo as arrays of hashtables (shape
    # @{ Email='foo@bar'; Name='Foo' }) instead of plain strings. The old
    # "'$_'" cast ToString()'d the hashtable to its type name and produced
    # `@('System.Collections.Hashtable',...)` in the customer file, breaking
    # mail dispatch. This helper coerces either shape to a clean email string.
    function _CfgEmailString {
        param([Parameter()]$Item)
        if ($null -eq $Item) { return $null }
        # A plain string FIRST. `-is [pscustomobject]` is `-is [psobject]`, which is TRUE for a pipeline-
        # wrapped string -- so every recipient typed as text fell into the object branch, found no Email
        # property and was dropped: MailTo / DetailedTo / SummaryTo were never written.
        $base = if ($Item -is [psobject]) { $Item.PSObject.BaseObject } else { $Item }
        if ($base -is [string]) {
            if ([string]::IsNullOrWhiteSpace($base) -or $base -eq 'System.Collections.Hashtable') { return $null }
            return $base.Trim()
        }
        $Item = $base
        if ($Item -is [hashtable] -or $Item -is [System.Collections.Specialized.OrderedDictionary]) {
            foreach ($k in 'Email','Address','Mail','Value','Recipient','Upn') {
                if ($Item.Contains($k) -and $Item[$k]) { return [string]$Item[$k] }
            }
            return $null
        }
        if ($Item -is [pscustomobject]) {
            foreach ($k in 'Email','Address','Mail','Value','Recipient','Upn') {
                $p = $Item.PSObject.Properties[$k]
                if ($p -and $p.Value) { return [string]$p.Value }
            }
            return $null
        }
        $s = [string]$Item
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        if ($s -eq 'System.Collections.Hashtable') { return $null }
        return $s
    }

    $null = $sb.AppendLine("`$global:SendMail        = `$true")
    if ($Smtp.MailTo) {
        $mailToList = @($Smtp.MailTo | ForEach-Object { _CfgEmailString $_ } | Where-Object { $_ })
        if ($mailToList.Count -gt 0) {
            $null = $sb.AppendLine("`$global:MailTo          = @($(($mailToList | ForEach-Object { _Q $_ }) -join ','))")
        }
    }
    if ($Smtp.Server)     { $null = $sb.AppendLine("`$global:SmtpServer      = $(_Q ($Smtp.Server))") }
    if ($Smtp.Port)       { $null = $sb.AppendLine("`$global:SmtpPort        = $([int]$Smtp.Port)") }
    if ($Smtp.User)       { $null = $sb.AppendLine("`$global:SMTPUser        = $(_Q ($Smtp.User))") }
    if ($Smtp.Password)   { $null = $sb.AppendLine("`$global:SMTPPassword    = $(_Q ($Smtp.Password))") }
    if ($Smtp.From)       { $null = $sb.AppendLine("`$global:SMTPFrom        = $(_Q ($Smtp.From))") }
    # v2.2.229 -- port 25 is plain SMTP / opportunistic STARTTLS by convention;
    # Send-MailMessage's -UseSsl flag is *implicit* TLS only and will fail the
    # handshake against a port-25 listener. Force UseSSL=$false on port 25
    # regardless of the wizard's UseSsl input. Operators who run a port-25
    # listener with implicit TLS (rare) can edit the file by hand.
    $portInt = if ($Smtp.Port) { [int]$Smtp.Port } else { 0 }
    $useSsl  = if ($null -ne $Smtp.UseSsl) { [bool]$Smtp.UseSsl } else { $true }
    if ($portInt -eq 25 -and $useSsl) {
        $null = $sb.AppendLine("# Port 25 + UseSSL=`$true is incompatible with Send-MailMessage's implicit-TLS;")
        $null = $sb.AppendLine("# auto-coerced to UseSSL=`$false. Switch to port 587 (STARTTLS) or 465 (implicit TLS) if you need encryption.")
        $useSsl = $false
    }
    $null = $sb.AppendLine("`$global:SMTP_UseSSL     = `$" + ($useSsl.ToString().ToLower()))
    if ($Smtp.DetailedTo) {
        $detList = @($Smtp.DetailedTo | ForEach-Object { _CfgEmailString $_ } | Where-Object { $_ })
        $list = ($detList | ForEach-Object { _Q $_ }) -join ','
        $null = $sb.AppendLine("`$global:RiskAnalysis_Detailed_SendMail = `$true")
        $null = $sb.AppendLine("`$global:RiskAnalysis_Detailed_To       = @($list)")
        $null = $sb.AppendLine("`$global:Mail_SecurityInsight_Detailed_SendMail = `$true")
        $null = $sb.AppendLine("`$global:Mail_SecurityInsight_Detailed_To       = @($list)")
    }
    if ($Smtp.SummaryTo) {
        $sumList = @($Smtp.SummaryTo | ForEach-Object { _CfgEmailString $_ } | Where-Object { $_ })
        $list = ($sumList | ForEach-Object { _Q $_ }) -join ','
        $null = $sb.AppendLine("`$global:RiskAnalysis_Summary_SendMail  = `$true")
        $null = $sb.AppendLine("`$global:RiskAnalysis_Summary_To        = @($list)")
        $null = $sb.AppendLine("`$global:Mail_SecurityInsight_Summary_SendMail = `$true")
        $null = $sb.AppendLine("`$global:Mail_SecurityInsight_Summary_To       = @($list)")
    }
    $null = $sb.AppendLine()
    $sectionsWritten += 'SMTP'
}

# ---- 6. Engine tuning (sensible defaults) ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 6. ENGINE TUNING  --  sensible defaults; override per tenant if needed")
$null = $sb.AppendLine("# ============================================================================")
foreach ($e in 'Endpoint','Identity','Azure','PublicIp') {
    $null = $sb.AppendLine("`$global:SI_AssetLimit_$e   = 0")
    $null = $sb.AppendLine("`$global:SI_ForceFullRun_$e = `$true")
}
$null = $sb.AppendLine("`$global:SI_ActiveStaleDays = 30")
$null = $sb.AppendLine("# Global force-full-run override (per-engine SI_ForceFullRun_<E> above isn't honored")
$null = $sb.AppendLine("# by every launcher's mode-resolver; this global one always wins). Flip to `$false")
$null = $sb.AppendLine("# once first runs are complete + cadence cache has populated.")
$null = $sb.AppendLine("`$global:SI_ForceFullRun = `$true")
$null = $sb.AppendLine()
$sectionsWritten += 'EngineTuning'

# ---- 7. RA defaults ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 7. RISK ANALYSIS  --  bucket / overwrite defaults")
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("`$global:RiskAnalysis_Summary_Override  = `$true")
$null = $sb.AppendLine("`$global:RiskAnalysis_Detailed_Override = `$false")
$null = $sb.AppendLine("`$global:AutoBucketCount = `$true")
$null = $sb.AppendLine("`$global:AutoBucketMax   = 1024")
$null = $sb.AppendLine("`$global:AutoBucketCache = `$true")
$null = $sb.AppendLine("`$global:OverwriteXlsx   = `$true")
$null = $sb.AppendLine()
$sectionsWritten += 'RA'

# ---- 8. Azure OpenAI (optional) ----
# Endpoint is required for any AI call; without it the section is meaningless.
if ($OpenAi -and $OpenAi.Endpoint) {
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("# 8. AZURE OPENAI  --  Build_Tier + RA -BuildSummaryByAI")
    $null = $sb.AppendLine("# ============================================================================")
    if ($OpenAi.Endpoint)   { $null = $sb.AppendLine("`$global:OpenAI_endpoint            = $(_Q ($OpenAi.Endpoint))") }
    if ($OpenAi.Deployment) { $null = $sb.AppendLine("`$global:OpenAI_deployment          = $(_Q ($OpenAi.Deployment))") }
    if ($OpenAi.ApiKey)     { $null = $sb.AppendLine("`$global:OpenAI_apiKey              = $(_Q ($OpenAi.ApiKey))") }
    if ($OpenAi.ApiVersion) { $null = $sb.AppendLine("`$global:OpenAI_apiVersion          = $(_Q ($OpenAi.ApiVersion))") } else { $null = $sb.AppendLine("`$global:OpenAI_apiVersion          = '2025-01-01-preview'") }
    if ($OpenAi.MaxTokens)  { $null = $sb.AppendLine("`$global:OpenAI_MaxTokensPerRequest = $([int]$OpenAi.MaxTokens)") } else { $null = $sb.AppendLine("`$global:OpenAI_MaxTokensPerRequest = 16384") }
    # The wizard sends MaxSpendPerRun; only MaxSpendUsd was read, so the operator's ceiling was replaced by 4.
    if (-not $OpenAi.MaxSpendUsd -and $OpenAi.MaxSpendPerRun) { $OpenAi.MaxSpendUsd = $OpenAi.MaxSpendPerRun }
    if ($OpenAi.MaxSpendUsd){ $null = $sb.AppendLine("`$global:MaxAiSpendPerRun           = $(([double]$OpenAi.MaxSpendUsd).ToString([Globalization.CultureInfo]::InvariantCulture))") } else { $null = $sb.AppendLine("`$global:MaxAiSpendPerRun           = 4") }
    $null = $sb.AppendLine("`$global:BuildSummaryByAI = `$true")
    $null = $sb.AppendLine()
    $sectionsWritten += 'OpenAI'
}

# ---- 9. Shodan (optional) ----
if ($Shodan -and $Shodan.ApiKey) {
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("# 9. SHODAN  --  PublicIP scanner")
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("`$global:SI_Shodan_ApiKey = $(_Q ($Shodan.ApiKey))")
    if ($Shodan.ExtraTargets) {
        $list = ($Shodan.ExtraTargets | ForEach-Object { _Q $_ }) -join ','
        $null = $sb.AppendLine("`$global:SI_PublicIP_ExtraTargets = @($list)")
    }
    $null = $sb.AppendLine()
    $sectionsWritten += 'Shodan'
}

# ---- 10. CMDB (optional) ----
if ($Cmdb -and $Cmdb.Enabled) {
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("# 10. CMDB PROVIDER  --  ServiceNow CMDB CSV")
    $null = $sb.AppendLine("# ============================================================================")
    $null = $sb.AppendLine("`$global:SI_EnableCmdbProvider       = `$true")
    $hours = if ($Cmdb.RefreshHours) { [int]$Cmdb.RefreshHours } else { 24 }
    $null = $sb.AppendLine("`$global:SI_CmdbRefreshIntervalHours = $hours")
    if ($Cmdb.CsvPath) { $null = $sb.AppendLine("`$global:SI_CmdbCsvPath              = $(_Q ($Cmdb.CsvPath))") }
    $null = $sb.AppendLine()
    $sectionsWritten += 'CMDB'
}

# ---- 11. KV pulls (always emitted; gated at runtime by $global:Context presence) ----
# Late-binding pulls of Shodan + OpenAI keys via Connect-Platform's PlatformContext.
# v2.3: single path -- $global:Context only. The v2.2.170 v1-fallback (elseif
# $global:KV_HighPriv_KeyVaultName) is gone. Community-Single deployments that
# never run Connect-Platform have $global:Context = $null and the if-block is a
# no-op (those users either pre-set the keys in the custom file or skip those
# integrations).
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# 11. KV PULLS  --  late-binding from the platform Key Vault")
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine("# Source: Connect-Platform's PlatformContext (Mode=Platform installs only).")
$null = $sb.AppendLine("if (`$global:Context) {")
$null = $sb.AppendLine("    # Soft-fail per secret -- a missing optional secret (e.g. OpenAI when AI is off, or Shodan when PublicIP is off) shouldn't break engine startup.")
$null = $sb.AppendLine("    if (-not `$global:SI_Shodan_ApiKey) { try { `$global:SI_Shodan_ApiKey = Get-PlatformSecret -Context `$global:Context -Name 'SI-Shodan-ApiKey' -AsPlainText -ErrorAction Stop } catch { Write-Verbose (`"SI custom: SI-Shodan-ApiKey not in KV -- skipping (`$(`$_.Exception.Message))`") } }")
$null = $sb.AppendLine("    if (-not `$global:OpenAI_apiKey)    { try { `$global:OpenAI_apiKey    = Get-PlatformSecret -Context `$global:Context -Name 'OpenAI-ApiKey'    -AsPlainText -ErrorAction Stop } catch { Write-Verbose (`"SI custom: OpenAI-ApiKey not in KV -- skipping (`$(`$_.Exception.Message))`") } }")
$null = $sb.AppendLine("} else {")
$null = $sb.AppendLine("    Write-Verbose ""SI custom: `$global:Context not set (no platform layer / Mode=Solution) -- skipping KV pulls""")
$null = $sb.AppendLine("}")
$null = $sb.AppendLine()
$sectionsWritten += 'KvPulls'

# ---- 12. Provenance footer ----
$null = $sb.AppendLine("# ============================================================================")
$null = $sb.AppendLine(("# Generated by Setup Wizard / Setup-SecurityInsight-Unattended (v2.3 single template) -- {0}" -f ((Get-Date).ToUniversalTime().ToString('u'))))
$null = $sb.AppendLine("# ============================================================================")

$content = $sb.ToString()

# ---------- Backup + write ----------
$backup = $null
if ((Test-Path -LiteralPath $OutputPath) -and $Merge -and -not $Force) {
    . (Join-Path $PSScriptRoot '..\..\_shared\SI-ConfigMerge.ps1')
    _Step "upgrade existing $OutputPath (keep every value; add only what is missing)"
    $merged = Update-SICustomConfigFile -Path $OutputPath -Generated $content
    if (@($merged.Added).Count) { _Ok ("added {0} setting(s): {1} (previous file kept as {2})" -f @($merged.Added).Count, (@($merged.Added) -join ', '), (Split-Path -Leaf $merged.Backup)) }
    else { _Ok 'nothing to add -- the existing file already has every setting' }
    return [pscustomobject]@{ Path = $OutputPath; Bytes = (Get-Item -LiteralPath $OutputPath).Length; Merged = $true; Added = @($merged.Added); Backup = $merged.Backup }
}
if (Test-Path -LiteralPath $OutputPath) {
    if (-not $Force) {
        # Guarded refusal -- the existing file may be a live operator's VM
        # config; silently backing it up + overwriting (the pre-v2.2.310 default)
        # is what wiped an internal-VM custom file during a container-flavour
        # bootstrap. Caller must pass -Force to acknowledge the rewrite.
        $wouldBackup = "$OutputPath.bak.{0:yyyyMMdd-HHmmss}" -f (Get-Date)
        throw ("Refusing to overwrite existing $OutputPath. Pass -Force to rewrite (a backup would be created at $wouldBackup). If this file is a live VM-flavour config that a container/sicont bootstrap is about to clobber, ABORT now and rerun the bootstrap against a different repo checkout or use -OutputPath to write somewhere else.")
    }
    $backup = "$OutputPath.bak.{0:yyyyMMdd-HHmmss}" -f (Get-Date)
    _Step "backup existing custom file -> $backup"
    Copy-Item -LiteralPath $OutputPath -Destination $backup -Force
    _Ok 'backup created'
}

# Make sure parent exists
$parentDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

_Step "write $OutputPath"
# UTF-8 WITH a BOM. Without one, Windows PowerShell 5.1 -- the VM launchers' runtime -- reads the file in
# the ANSI code page, so every non-ASCII value (an ae/oe/aa in a password, a display name) arrived corrupted.
[IO.File]::WriteAllText($OutputPath, $content, [Text.UTF8Encoding]::new($true))
$bytes = (Get-Item -LiteralPath $OutputPath).Length
_Ok "wrote $bytes bytes ($(($sectionsWritten -join ', ')))"

[pscustomobject]@{
    Path     = $OutputPath
    Bytes    = $bytes
    Sections = $sectionsWritten
    Backup   = $backup
}
