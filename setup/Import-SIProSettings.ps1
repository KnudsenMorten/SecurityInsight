<#
.SYNOPSIS
    SecurityInsight Pro -- move an installation's configuration from its files into the Pro settings database
    (the Community -> Pro importer).

.DESCRIPTION
    SETTINGS (cfg.Setting): config\SecurityInsight.custom.ps1 and every launcher\<engine>\LauncherConfig.custom.ps1 --
    every catalog setting set there as a plain value, Pro-edition settings included. A value set by code (a Key Vault
    pull, a condition) is NOT imported -- it is listed with the reason. A secret's value never enters the database: when
    the file pulls it from Key Vault by a literal secret name, that name is imported as the Key Vault reference;
    otherwise it is listed for you to set. A name the settings catalog does not know is listed, not dropped silently.

    DOCUMENTS (cfg.Document, Pro-1b): the Risk Analysis exclusion files (global and per report), the weightedRiskFactors
    of the risk-weights file, and every custom tier rule -- page-created or hand-written, in the tree or in the rules
    overlay (SI_EnrichmentDataRoot).

    CONFIGURATION ITEMS (cfg.ItemOverride, phase C) -- only what DIFFERS from the templates is stored:
      the custom Risk Analysis report catalog, the risk index, turned-off shipped rules, asset tagging (custom rules +
      config), the service model, schema overlays, asset / correlation decisions, per-report weights files and the
      risk-model sections of the weights file.
    CMDB OWNERSHIP (#251) is configuration, not a template: config\cmdb-source-ownership.custom.json merged over the shipped
    map (as the engine merges it) becomes the ONE configuration document cmdbownership/map.

    -Apply -CreateSchema is a SETUP path (#250): it creates the schema (cfg.TemplatePackStaged included), carries naming
    and CMDB ownership over to configuration, and installs the default templates as template pack 1.0
    (setup\Publish-SITemplates.ps1 -InstallDefault) before the import compares with them.
    CONNECTORS (cfg.Connector, phase E): the vulnerability close-loop's target from the SI_VulnSync_* settings becomes
    one connector row (sql or servicenow) with the same mode and arming -- ServiceNow credentials as Key Vault secret
    NAMES, never values. Written only when no row of that name exists or it differs.

    The templates compared against are the ones PUBLISHED in the database when it can be read (setup\Publish-SITemplates.ps1),
    else the ones this installation ships (then the risk index, which is edited in place, is not compared).

    Each item is validated exactly as the run will validate it; one that does not validate is listed with the reason and
    not imported. Nothing is written without -Apply. Each write is a cfg.ChangeLog entry.

    -RetireFiles (with -Apply): every file whose content was imported COMPLETELY is renamed to <name>.imported, so no
    loader reads it again -- shown in the plan first. A file is retired only when its family is served from the database
    (templates published for it, or a family without templates); shipped files and the settings .ps1 files are never
    renamed.

    The database comes from SI_ProSqlServer / SI_ProSqlDatabase and is reached as the engine SPN (certificate), like
    the run-time settings layer.

    NOTHING IS LOST SILENTLY (#275). Beyond the files above, the import also finds:
      * <Report>.exclude.json -- the name the shipped *.exclude.json.sample becomes -- read exactly as the engine reads it
        (<Report>.exclude.custom.json first);
      * the asset-tagging rules and config wherever the 2.2 launcher and engine find them (asset-tagging-rules\,
        SettingsPath from SecurityInsight.custom.ps1 / LauncherConfig.custom.ps1 / launcher.override.ps1, a renamed
        CustomYamlFile, the legacy names, <SettingsPath>\asset-tagging.config.json) -- the same resolution the run uses;
      * every launcher\<engine>\launcher.override.ps1: its plain catalog settings are imported, its code is listed;
      * the server-application catalog override (asset-profiling-enrichment\endpoint\server-applications.json);
      * exclusion files in config\, which nothing has ever read -- listed with where they belong.
    THE REPORT ends with "Not imported -- review": every item that was not imported, one line each ("not imported: <path>
    -- <reason>", "needs manual review: <file>:<line> -- <reason>"). The same report is written as JSON (-ReportPath,
    default OUTPUT\Import-SIProSettings.report.json under the solution).
    EXIT CODE: 0 = everything was imported; 2 = items need review (listed). A failure throws (exit code 1).

.EXAMPLE
    .\setup\Import-SIProSettings.ps1                               # show the plan
    .\setup\Import-SIProSettings.ps1 -Apply                        # write it
    .\setup\Import-SIProSettings.ps1 -Apply -RetireFiles           # write it, then retire the imported files
    .\setup\Import-SIProSettings.ps1 -ReportPath C:\temp\import.json; $LASTEXITCODE   # 0 = all imported, 2 = review the list

.LINK
    https://invardia.com/docs/si/scripts/Import-SIProSettings/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallPath,
    [switch]$Apply,
    [switch]$CreateSchema,
    [switch]$RetireFiles,
    # The Pro database and the engine identity. Defaults: the globals a loaded configuration sets. Passed explicitly when
    # importing into an empty database -- loading the full configuration would already try to read it.
    [string]$Server = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # The rules overlay to import tier rules from. Default: SI_EnrichmentDataRoot -- the loaded value, else the plain
    # value the solution's custom file sets.
    [string]$OverlayRoot,
    # Where the asset-tagging rules live. Default: where the asset-tagging launcher finds them (SettingsPath from the
    # configuration files, else its default folder -- engine\asset-tagging\AssetTagging.Resolve.ps1).
    [string]$AssetTaggingPath,
    # The JSON import report. Default: OUTPUT\Import-SIProSettings.report.json under the solution.
    [string]$ReportPath
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Import-SIProSettings' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false; $CreateSchema = [switch]$false; $RetireFiles = [switch]$false }   # -WhatIf = the plan: nothing is written, no file retired
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
if ($InstallPath) {
    $siRoot = @((Join-Path $InstallPath 'SOLUTIONS\SecurityInsight'), $InstallPath) | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'config') } | Select-Object -First 1
    if (-not $siRoot) { throw "no SecurityInsight installation under $InstallPath" }
}
if ($RetireFiles -and -not $Apply) { throw '-RetireFiles needs -Apply: files are retired only after their content is in the database' }
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSettings.ps1')

$catalog = @(Get-SISettingsCatalog -SIRoot $siRoot)
$plan = Get-SIProImportPlan -SIRoot $siRoot -Catalog $catalog
Write-Host ("[INFO] {0} setting(s) to import, {1} not imported" -f @($plan.Rows).Count, @($plan.Skipped).Count)
foreach ($r in $plan.Rows) {
    if ($r.KeyVaultSecretName) { Write-Host ("  import  {0,-12} {1} = Key Vault secret '{2}' (a reference -- the value stays in Key Vault)" -f $r.Scope, $r.Name, $r.KeyVaultSecretName) }
    else { Write-Host ("  import  {0,-12} {1} = {2}" -f $r.Scope, $r.Name, (ConvertTo-SIJsonText $r.Value)) }
}
foreach ($s in $plan.Skipped) { Write-Host ("  skip    {0,-12} {1} -- {2}" -f $s.Scope, $s.Name, $s.Reason) -ForegroundColor Yellow }
# #275 R4: every launcher.override.ps1 -- free PowerShell a Pro run never executes
foreach ($o in @($plan.Overrides)) {
    Write-Host ("[WARN] {0}: a Pro run does not run this file -- {1} setting(s) imported at {2}, {3} item(s) need review (listed at the end)" -f $o.Rel, $o.Imported, $o.Scope, $o.Review) -ForegroundColor Yellow
}

if (-not $OverlayRoot) {
    $OverlayRoot = [string]$global:SI_EnrichmentDataRoot
    if (-not $OverlayRoot) {
        $cfgText = (Read-SISettingsText -Path (Join-Path $siRoot 'config\SecurityInsight.custom.ps1')).Text
        $a = @(Get-SIPs1Assignments -Text $cfgText | Where-Object { $_.Name -eq 'SI_EnrichmentDataRoot' -and $_.TopLevel -and $_.Literal }) | Select-Object -Last 1
        if ($a) { $OverlayRoot = [string]$a.Value }
    }
}
if ($OverlayRoot -and -not (Test-Path -LiteralPath $OverlayRoot)) {
    Write-Host ("[WARN] the rules overlay {0} does not exist -- only the rules in the tree are planned" -f $OverlayRoot) -ForegroundColor Yellow
    $OverlayRoot = ''
}
$docPlan = Get-SIProDocumentImportPlan -SIRoot $siRoot -OverlayRoot $OverlayRoot
Write-Host ("[INFO] {0} document(s) to import, {1} not imported{2}" -f @($docPlan.Rows).Count, @($docPlan.Skipped).Count, $(if ($OverlayRoot) { " (rules overlay: $OverlayRoot)" } else { '' }))
foreach ($r in $docPlan.Rows) { Write-Host ("  import  {0,-12} {1}  <- {2}" -f $r.Kind, $r.Key, $r.Source) }
foreach ($s in $docPlan.Skipped) { Write-Host ("  skip    {0,-12} {1} -- {2}" -f 'document', $s.Name, $s.Reason) -ForegroundColor Yellow }
# #908: a rule file that is still a shipped sample (its SAMPLE / TEMPLATE header, or the sample unchanged) is never imported
$examples = @($docPlan.Skipped | Where-Object { [string]$_.Reason -match ': the shipped example -- ' })
if ($examples.Count) { Write-Host ("[WARN] {0} rule file(s) are the shipped EXAMPLE, not your rules -- NOT imported: {1}. Review each one (its example names, subnets and tiers), remove the '# SAMPLE / TEMPLATE' header line, then import again." -f $examples.Count, (($examples | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Yellow }
# #275 G10: exclusion files in config\ were never read -- one warning, naming where they belong (each is listed at the end)
$misplaced = @($docPlan.Skipped | Where-Object { $_.PSObject.Properties['Path'] -and [string]$_.Path -match '^config[\\/]' })
if ($misplaced.Count) { Write-Host ("[WARN] {0} exclusion file(s) in config\ have never been read (2.2 or 3.0) -- they belong in risk-analysis-detection\: {1}" -f $misplaced.Count, (($misplaced | ForEach-Object { $_.Path }) -join ', ')) -ForegroundColor Yellow }

# ---- configuration items: only what differs from the templates ----
$store = $null
if ($Server -and $Database) {
    try { $store = New-SIProSettingsStore -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint }
    catch { if ($Apply) { throw }; Write-Host ("[WARN] the Pro database cannot be reached from here ({0}) -- planning without it" -f $_.Exception.Message) -ForegroundColor Yellow }
}
# #250: -Apply -CreateSchema is a setup path: the schema (cfg.TemplatePackStaged included), the #251 carry-over and the
# default templates installed as template pack 1.0 -- BEFORE the import compares with the published templates.
if ($Apply -and $CreateSchema -and $store) {
    # the file is a series of guarded statements, run batch by batch on the blank lines that separate them -- through the
    # ONE apply every path uses (#352: setup, the internal build, the product updater), so its additive gate runs here too
    . (Join-Path $siRoot 'engine\pro-settings\SI-ProSchema.ps1')
    $applied = Invoke-SIProSchemaApply -SIRoot $siRoot -Invoke $store.Invoke -Names settings -Log { param($m) Write-Host $m }
    switch ($applied.Action) { 'applied' { } default { throw ("the cfg schema was not applied: {0}" -f $applied.Reason) } }
    Write-Host '[OK]   cfg schema present'
    $tplResult = & (Join-Path $siRoot 'setup\Publish-SITemplates.ps1') -InstallPath $siRoot -Store $store -InstallDefault -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
    if ($tplResult) { Write-Host ("[OK]   default templates: {0}" -f $tplResult.Reason) }
}
$templates = @(); $local = $true
if ($store) {
    try {
        $templates = @(Read-SIProTemplates -Store $store | ForEach-Object { [pscustomobject]$_ } | Where-Object { $null -eq $_.RetiredAt })
        if ($templates.Count) { $local = $false; Write-Host ("[INFO] comparing with the {0} template(s) published in {1}" -f $templates.Count, $store.Name) }
    } catch { Write-Host ("[WARN] the database's templates could not be read ({0}) -- comparing with this installation's shipped files" -f $_.Exception.Message) -ForegroundColor Yellow }
}
if ($local) { $templates = @((Get-SITemplateRows -SIRoot $siRoot).Rows); Write-Host '[INFO] comparing with the templates this installation ships (none published in the database)' }
# #275 R3: the asset-tagging files are found inside the plan exactly as the launcher and the engine find them
# (-AssetTaggingPath, when given, wins as the launcher's -SettingsPath switch does)
$cfgPlan = Get-SIProConfigImportPlan -SIRoot $siRoot -Templates $templates -OverlayRoot $OverlayRoot -AssetTaggingPath $AssetTaggingPath -LocalTemplates:$local
Write-Host ("[INFO] {0} configuration item(s) to import, {1} identical to the template (not stored), {2} not imported" -f @($cfgPlan.Rows).Count, @($cfgPlan.Same).Count, @($cfgPlan.Skipped).Count)
foreach ($r in $cfgPlan.Rows) { Write-Host ("  {0,-8} {1,-13} {2}  <- {3}" -f $r.State, $r.Kind, $r.Key, $r.Source) }
foreach ($s in $cfgPlan.Skipped) { Write-Host ("  skip    {0} -- {1}" -f $s.Name, $s.Reason) -ForegroundColor Yellow }
if (@($cfgPlan.Files | Where-Object { $_.Kind -eq 'assettagging' }).Count) { Write-Host ("[INFO] asset tagging read from: {0}" -f ((@($cfgPlan.Files | Where-Object { $_.Kind -eq 'assettagging' }) | ForEach-Object { $_.Rel }) -join ', ')) }

# ---- the vulnerability close-loop's target as a connector (cfg.Connector, phase E): only what differs ----
$connPlan = [pscustomobject]@{ Rows = @(); Skipped = @() }
$connScript = Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-Connector.ps1'
if (Test-Path -LiteralPath $connScript) {
    . $connScript
    $existingConnectors = @()
    if ($store) {
        try { $existingConnectors = @(Read-SIConnectorRows -Store $store) }
        catch { Write-Host ("[WARN] the connectors in the database could not be read ({0}) -- planning as if there were none" -f $_.Exception.Message) -ForegroundColor Yellow }
    }
    $connPlan = Get-SIConnectorImportPlan -SIRoot $siRoot -Existing $existingConnectors
    $connWrite = @($connPlan.Rows | Where-Object { $_.Action -ne 'same' })
    Write-Host ("[INFO] {0} connector(s) to import from the close-loop settings, {1} already the same in the database" -f $connWrite.Count, @($connPlan.Rows | Where-Object { $_.Action -eq 'same' }).Count)
    foreach ($r in $connWrite) {
        $d = $r.Definition
        Write-Host ("  {0,-8} connector {1} ({2}, mode {3}, create {4}, close {5}){6}" -f $r.Action, $d.Name, $d.Kind, $d.Mode, $d.AllowCreate, $d.AllowClose, $(if ($d.SecretRefsJson) { ' -- Key Vault secret NAMES: ' + $d.SecretRefsJson } else { '' }))
    }
    foreach ($s in $connPlan.Skipped) { Write-Host ("  skip    {0} -- {1}" -f $s.Name, $s.Reason) -ForegroundColor Yellow }
}

# ---- the files that would be retired ----
$retire = @()
if ($RetireFiles) {
    $served = @{}; foreach ($t in $templates) { $served[[string]$t.Kind] = $true }
    $untemplated = @('schemaoverlay', 'decision', 'weights', 'rule', 'cmdbownership', 'serverapps')
    $skippedText = (@($plan.Skipped) + @($docPlan.Skipped) + @($cfgPlan.Skipped) | ForEach-Object { [string]$_.Reason }) -join "`n"
    $docFiles = @($docPlan.Rows | ForEach-Object { $_.Source } | Select-Object -Unique)
    $cands = @(
        @($docFiles | ForEach-Object { [pscustomobject]@{ Rel = $_; Path = $(if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $siRoot $_ }); Kind = 'document' } })
        @($cfgPlan.Files | Where-Object { $_.Complete -and $_.Imported -gt 0 } | ForEach-Object { [pscustomobject]@{ Rel = $_.Rel; Path = $_.Path; Kind = $_.Kind } })
    )
    foreach ($c in $cands) {
        if ($c.Rel -match '(?i)(\.locked\.|riskscore\.index\.custom\.csv$|\.ps1$)') { continue }   # shipped files and settings files stay
        if ($skippedText.IndexOf($c.Rel, [StringComparison]::OrdinalIgnoreCase) -ge 0) { continue }    # not everything in it was imported
        if ($c.Kind -ne 'document' -and $untemplated -notcontains $c.Kind -and -not $served[$c.Kind]) { continue }   # its family still reads files
        if ($retire.Path -contains $c.Path) { continue }
        $retire += $c
    }
    Write-Host ("[INFO] {0} file(s) to retire (renamed to <name>.imported after the import)" -f $retire.Count)
    foreach ($c in $retire) { Write-Host ("  retire  {0}" -f $c.Rel) }
}
# ---- #275: the report's final section, "Not imported -- review", the JSON report and the exit code ----
$finish = {
    param([bool]$Applied)
    $rv = Get-SIProImportReview -Settings $plan -Documents $docPlan -Items $cfgPlan -Connectors $connPlan
    if (@($rv.Informational).Count) {
        Write-Host ("[INFO] {0} note(s) -- nothing lost:" -f @($rv.Informational).Count)
        foreach ($n in $rv.Informational) { Write-Host ('  ' + $n.Text) }
    }
    Write-Host ''
    Write-Host ("==== Not imported -- review ({0}) ====" -f @($rv.NotImported).Count)
    if (-not @($rv.NotImported).Count) { Write-Host '  nothing -- everything was imported' -ForegroundColor Green }
    foreach ($e in $rv.NotImported) { Write-Host ('  ' + $e.Text) -ForegroundColor Yellow }
    $json = ConvertTo-SIProImportReportJson -Review $rv -Settings $plan -Documents $docPlan -Items $cfgPlan -Connectors $connPlan -SIRoot $siRoot -Applied $Applied `
        -GeneratedAt ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture))
    $rp = if ($ReportPath) { $ReportPath } else { [IO.Path]::Combine($siRoot, 'OUTPUT', 'Import-SIProSettings.report.json') }
    if ($WhatIfPreference) { Write-Host ('[INFO] -WhatIf: the import report is not written ({0})' -f $rp) }
    else { try {
        $full = [IO.Path]::GetFullPath($rp)
        $d = [IO.Path]::GetDirectoryName($full)
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        [IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ("[INFO] import report: {0}" -f $full)
    } catch { Write-Host ("[WARN] the import report could not be written to {0}: {1}" -f $rp, $_.Exception.Message) -ForegroundColor Yellow } }
    Write-Host ("[INFO] exit code {0} -- {1}" -f $rv.ExitCode, $(if ($rv.ExitCode -eq 0) { 'everything was imported' } else { 'items need review (listed above)' }))
    $rv.ExitCode
}
if (-not $Apply) { Write-Host '[INFO] nothing written -- run with -Apply to write the import.'; $code = & $finish $false; exit $code }

if (-not $store) { throw 'nothing written: -Apply needs the Pro database (SI_ProSqlServer / SI_ProSqlDatabase, or -Server / -Database)' }
$by = '{0} (import)' -f (Get-SIProSessionActor)   # the session's own identity, never an input
# #260: the import is ONE event on the audit trail; every change row it writes carries the event's correlation id
$auditCid = [guid]::NewGuid().ToString('N')
$auditStore = $store
$store = [pscustomobject]@{ Name = $auditStore.Name; Invoke = (New-SIAuditInvoke -Invoke $auditStore.Invoke -CorrelationId $auditCid -ActorSource 'setup') }
$auditCounts = { [ordered]@{ settings = @($plan.Rows).Count; documents = @($docPlan.Rows).Count; items = @($cfgPlan.Rows).Count; connectors = $connDone; retiredFiles = @($retire).Count } }
$connDone = 0
trap {
    # (a trap covers the whole script: only a failure of the writing part below is the import's failed event)
    if ($auditCid -and $auditStore) { [void](Write-SIAuditEvent -Store $auditStore -Action 'settings.import.apply' -Actor $by -ActorSource 'setup' -Target $auditStore.Name -Reason 'Import-SIProSettings -Apply' `
        -Outcome 'error' -OutcomeText $_.Exception.Message -CorrelationId $auditCid -After (& $auditCounts)) }
    break
}
foreach ($r in $plan.Rows) {
    $srcText = if ($r.PSObject.Properties['Source'] -and $r.Source) { [string]$r.Source } else { 'the custom file' }
    if ($r.KeyVaultSecretName) { Set-SIProSetting -Store $store -Catalog $catalog -Name $r.Name -Scope $r.Scope -Action Set -KeyVaultSecretName $r.KeyVaultSecretName -ChangedBy $by -Reason ('imported from {0}, line {1} (Key Vault reference)' -f $srcText, $r.Line) }
    else { Set-SIProSetting -Store $store -Catalog $catalog -Name $r.Name -Scope $r.Scope -Action Set -Value $r.Value -ChangedBy $by -Reason ('imported from {0}, line {1}' -f $srcText, $r.Line) }
}
Write-Host ("[OK]   {0} setting(s) imported into {1}" -f @($plan.Rows).Count, $store.Name)
foreach ($r in $docPlan.Rows) {
    Set-SIProDocument -Store $store -Kind $r.Kind -Key $r.Key -Action Set -Body $r.Body -ChangedBy $by -Reason ('imported from {0}' -f $r.Source)
}
Write-Host ("[OK]   {0} document(s) imported into {1}" -f @($docPlan.Rows).Count, $store.Name)
$ctx = Get-SIProConfigContext -SIRoot $siRoot -Catalog $catalog
$ctx.Reports = @(@($ctx.Reports) + @($cfgPlan.Rows | Where-Object { $_.Kind -eq 'rareport' -and $_.Key -like 'report/*' } | ForEach-Object { $_.Key.Substring(7) }))
foreach ($r in $cfgPlan.Rows) {
    Set-SIProItem -Store $store -Kind $r.Kind -Key $r.Key -State $r.State -Body ([string]$r.Body) -Format $r.Format -BaseVersion $r.BaseVersion -BaseHash $r.BaseHash -ChangedBy $by -Reason ('imported from {0}' -f $r.Source) -Context $ctx
}
Write-Host ("[OK]   {0} configuration item(s) imported into {1}" -f @($cfgPlan.Rows).Count, $store.Name)
$connDone = 0
foreach ($r in @($connPlan.Rows | Where-Object { $_.Action -ne 'same' })) {
    Set-SIConnector -Store $store -Definition $r.Definition -Action Set -ChangedBy $by -Reason 'imported from the close-loop settings (SI_VulnSync_*)'
    $connDone++
}
Write-Host ("[OK]   {0} connector(s) imported into {1}" -f $connDone, $store.Name)
# #275 R2: a v2.2 CMDB.csv into the Pro CMDB, once (AlreadyImported when the guided install's pro-cmdb step did it).
# Never stops the import: a migration problem is reported and the review section below still prints.
$cmdbMigration = $null
try {
    # the CMDB migration is part of the paid CMDB (the Pro package carries it); a copy without it has nothing to migrate
    if ($auditStore -and $auditStore.Invoke -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Import-SICmdbCsv.ps1'))) {
        $cmdbMigration = & (Join-Path $PSScriptRoot 'Import-SICmdbCsv.ps1') -InstallPath $siRoot -Invoke $auditStore.Invoke -Apply -NoThrow
    }
} catch {
    Write-Host ("[WARN] the v2.2 CMDB.csv could not be migrated into the Pro CMDB: {0} -- run setup\Import-SICmdbCsv.ps1 -Apply" -f $_.Exception.Message) -ForegroundColor Yellow
}
foreach ($c in $retire) {
    $to = $c.Path + '.imported'
    if (Test-Path -LiteralPath $to) { $to = '{0}.{1}.imported' -f $c.Path, (Get-Date).ToString('yyyyMMdd-HHmmss') }
    Move-Item -LiteralPath $c.Path -Destination $to
    Write-Host ("[OK]   retired {0} -> {1}" -f $c.Rel, (Split-Path -Leaf $to))
}
[void](Write-SIAuditEvent -Store $auditStore -Action 'settings.import.apply' -Actor $by -ActorSource 'setup' -Target $auditStore.Name -Reason 'Import-SIProSettings -Apply' `
    -CorrelationId $auditCid -After (& $auditCounts))
$code = & $finish $true
exit $code
} finally { Stop-SIScriptRun -Run $siRun }
