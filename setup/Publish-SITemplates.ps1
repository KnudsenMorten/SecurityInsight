<#
.SYNOPSIS
    SecurityInsight Pro -- publish configuration TEMPLATES into the Pro settings database: this release's own, a
    template pack the vendor released, or a previous version (roll back).

.DESCRIPTION
    In Pro the shipped *.locked files are replaced by templates (REQUIREMENTS §9.3.3 phase C): one cfg.Template row per
    item. Templates hold only VENDOR-DEVELOPED content (#251). Built from the shipped files of THIS installation:
      rareport      risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml        (reports and report templates)
      riskindex     risk-analysis-detection\riskscore.index.locked.csv              (one row per item)
      rule          asset-profiling-enrichment\<engine>\**\*.locked.yaml             (every shipped tier rule)
      assettagging  asset-profiling-enrichment\endpoint\AssetTagging.locked.yaml     (one tagging rule per item)
      servicemodel  config\service-model.locked.json
    The profile schemas are not templates: they are the engines' data contract, shipped with the code. The names of
    tables / DCRs / DCE / workspace are SETTINGS, and the CMDB ownership map is the customer's CONFIGURATION (#251).

    THE SHIPPED TEMPLATES ARE TEMPLATE PACK 1.0 (#250), "Default templates 1.0" (engine\pro-settings\
    shipped-template-pack.json) -- like the old .locked files: they arrive with the install and are in force at once; the
    customer's own changes live beside them. Template pack versions are their own series (1.0, 1.1, ...), not the code
    version. A FULL publish of the shipped templates with -Apply (-InstallDefault = -Apply -CreateSchema, what setup and
    the update hook run) also:
      * carries naming and CMDB ownership over to configuration (#251, Invoke-SIProConfigurationMigration: naming
        overrides -> cfg.Setting rows 1:1, the ownership map -> the configuration document cmdbownership/map, the former
        template rows retired -- nothing removed);
      * stages the shipped templates as template pack 1.0 (cfg.TemplatePackStaged), so the web app lists it;
      * installs it (fresh install), ADOPTS it (templates already there with the same content -> recorded as installed),
        or records the install as "customised, based on 1.0" (other content: kept, and 1.0 is offered on the Template
        releases page) -- and records the installed pack (cfg.InstallState TemplatePack / TemplatePackStatus).
      A newer pack already installed (from the update ring) is never taken back to the shipped one.

    THE SPLIT INSTALL (#405, operator decision 2026-10-06 -- customers never import template packs by hand). Every shipped
    template is one of three classes (config\template-classification.locked.json):
      fix        our own queries / logic the engines rely on: installed WITH THE CODE, always, never held
      default    customer business logic (tier rules, risk index, service model, asset tagging): SecurityInsight's default is
                 installed with the code; a customer's edit is an override beside it and is never changed -- Template
                 conformance shows "SecurityInsight's default changed" with compare / keep yours / take ours
      microsoft  a new Microsoft data surface: a MICROSOFT CONTENT PACK between releases (its own series, 1.3, 1.4, ...),
                 ring by ring, installed AUTOMATICALLY by the updater once the install runs the pack's MinCodeVersion --
                 unless "Hold" (SI_InvardiaUpdate_HoldMicrosoftContent, default off) is on, or the customer
                 rolled back from it (-RollbackToVersion <v> -Class microsoft): then it waits on Template releases with Install.
                 Owner decision 2026-10-11 ("Automatic"): a pack that carries MORE than Microsoft content (SecurityInsight's
                 own templates) installs automatically the same way -- a customer's edit is an override, never written. A
                 pack without MinCodeVersion waits for the code it was built by (Get-SIProTemplatePackDecision).
    It is on when the shipped pack's ClassificationReviewed is true; false keeps the old behaviour below (every change
    waits for a review). A full shipped publish in split mode records what is installed per class: cfg.InstallState
    TemplateCode (the code release), TemplatePack (the Microsoft content -- a NEWER pack in force is kept, never taken
    back), TemplateMode. -InstallCurrent (RING 1, internal): every shipped template installed directly, no gate
    (TemplateDirect); the shipped pack it put in force is recorded as the installed pack (TemplatePack, as-released), so
    the staged pack of that version reads installed -- a NEWER pack in force is kept, as on a code roll.

    THREE SOURCES (#235, template versions released per ring):
      (default)            the templates shipped with this installation
      -PackPath / -FromStaged
                           a TEMPLATE PACK (si-templates-<packVersion>.json) the vendor released -- a file (checked against
                           its .sha256), or one staged in cfg.TemplatePackStaged by the updater (checked against the
                           SHA-256 it was staged with). Every item is checked: its body matches its hash, its content hash
                           is what this code computes, and it validates here.
      -RollbackToVersion   the items as they were at that pack / release version, from cfg.TemplateRevision
    -Method publishes only those DETECTION METHODS (e.g. AssetProfileByIPSubnet, endpoint/AssetProfileByIPSubnet,
    riskanalysis/Endpoint); an item of another method is neither written nor retired.

    Shows the plan by default (insert / update / same / retire per item). -Apply writes it, each item with a
    cfg.ChangeLog entry. A customer's overrides (cfg.ItemOverride) are never read or changed: publishing a new release
    keeps every override, and an override made against older template CONTENT reads "upgrade available".
    An item this release no longer ships is RETIRED (RetiredAt), never removed.

    A template that does not validate is never published; with any such template -Apply refuses (a release with an
    invalid shipped file is a defect to fix, not to half-publish).

    THE FINGERPRINT GATE (adopted from PIM4EntraPS). The templates in force are fingerprinted by CONTENT (comments,
    key order, `_*` keys and descriptions do not count). The install records the fingerprint it last published
    (cfg.InstallState 'TemplateFingerprint'). When this publish would put a DIFFERENT fingerprint in force, -Apply writes
    nothing unless -AcceptTemplateChange is given -- the plan lists what changes. -AcceptFingerprint narrows the
    acceptance to exactly the fingerprint the plan showed (the updater uses it, so an acceptance is never a standing
    blank cheque). A publish that changes only comments or descriptions needs no acceptance.
    From a pack, a roll-back or a -Method selection, -AcceptFingerprint names the SELECTION fingerprint (what is
    accepted: the selected methods' items and retirements, the plan prints it) and any other is refused; and a selection
    that changes an item the customer overrides or switched off is never written without an acceptance.
    The fingerprint is recorded ONLY after the written templates are read back and verified: every body matches its
    hash, every row carries its content hash, and the set in force is exactly the planned one. A pack / roll-back release
    is recorded then too (cfg.ChangeLog 'template-release'; a whole pack also as cfg.InstallState 'TemplatePack').

    -Stage puts the pack (or, without one, the templates shipped with this installation) in cfg.TemplatePackStaged, where
    the web app's Template releases page offers it. It writes nothing else.

    Callable from setup, from the container updater after a new release is synced, and as the Container Apps job
    caj-si-templates the web app starts after an Admin accepted a release:
        & .\setup\Publish-SITemplates.ps1 -Apply -Server <sql> -Database <db> [-AcceptTemplateChange]
    The database is reached as the engine identity (certificate, or the managed identity in a container), like the
    run-time settings layer; it needs write access to the cfg schema.

.EXAMPLE
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -InstallDefault   # what setup runs: schema, carry-over, pack 1.0
    .\setup\Publish-SITemplates.ps1                           # what would be published (no database needed)
    .\setup\Publish-SITemplates.ps1 -Server s -Database d     # the plan against the database's templates
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -Apply -CreateSchema
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -Apply -AcceptTemplateChange   # after reviewing the plan
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -PackPath .\si-templates-3.0.1.202610031200.json -Method AssetProfileByIPSubnet
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -FromStaged 3.0.1.202610031200 -Apply -AcceptFingerprint <selection fingerprint>
    .\setup\Publish-SITemplates.ps1 -Server s -Database d -RollbackToVersion 3.0.0 -Method riskanalysis/Endpoint

.LINK
    https://invardia.com/docs/si/scripts/Publish-SITemplates/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallPath,
    [switch]$Apply,
    [switch]$CreateSchema,
    # What every setup / update path runs (#250): -Apply -CreateSchema of the shipped templates -- the schema, the #251
    # carry-over, and the default templates installed (or adopted) as template pack 1.0.
    [switch]$InstallDefault,
    # The templates in force may change (the plan listed what changes). Without it a moved fingerprint writes nothing.
    [switch]$AcceptTemplateChange,
    # Accept only this fingerprint (at least its first 12 characters) -- what the plan printed.
    [string]$AcceptFingerprint,
    [string]$Server = [string]$global:SI_ProSqlServer,
    [string]$Database = [string]$global:SI_ProSqlDatabase,
    [string]$AppId = [string]$global:SI_SPN_AppId,
    [string]$TenantId = [string]$global:SI_SPN_TenantId,
    [string]$CertThumbprint = [string]$global:SI_SPN_CertThumbprint,
    # Publish only these kinds (default: all). Retiring is limited to the same kinds.
    [ValidateSet('rareport', 'riskindex', 'rule', 'assettagging', 'servicemodel')]
    [string[]]$Families,
    # The version to stamp (default: the shipped template pack's version, engine\pro-settings\shipped-template-pack.json).
    [string]$Version,
    # A template pack file (si-templates-<packVersion>.json); its .sha256 beside it is checked when present.
    [string]$PackPath,
    # The pack's SHA-256 (overrides the .sha256 file).
    [string]$PackSha256,
    # A pack staged in cfg.TemplatePackStaged, by version.
    [string]$FromStaged,
    # Republish the items as they were at this pack / release version (cfg.TemplateRevision).
    [string]$RollbackToVersion,
    # Only these detection methods ('<method>' or '<engine>/<method>'; '*' = all).
    [string[]]$Method,
    # Put the pack (or the shipped templates) in cfg.TemplatePackStaged for the web app.
    [switch]$Stage,
    [ValidateSet('feed', 'shipped', 'file')][string]$StageOrigin,
    [string]$StageRing,
    # A job run: a publish that is blocked FAILS (the web app shows the job as failed) instead of ending as a plan.
    [switch]$StrictJob,
    # Who accepted this release in the web app (recorded in the release's reason; the actor stays the session).
    [string]$RequestedBy,
    # The database, already open (New-SIProSettingsStore -Invoke ...): the container updater's token, or a test's fake.
    $Store,
    # Return the outcome as an object (the updater reads it).
    [switch]$PassThru,
    # #405: RING 1 (internal) -- every template shipped with this code installed DIRECTLY: no pack number, no gate, no
    # pack recorded as a release (the r1 deploy passes it; setup\Invoke-SIContainerUpdate.ps1 -InstallTemplatesDirect).
    [switch]$InstallCurrent,
    # #405: with -RollbackToVersion, only the items of these classes (the one-click roll back of Microsoft content).
    [ValidateSet('fix', 'default', 'microsoft')][string[]]$Class,
    # Test seam: $true / $false instead of the shipped pack's ClassificationReviewed flag ($null = the flag decides).
    $ClassificationReviewed = $null
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Publish-SITemplates' -Quiet:([bool]$PSBoundParameters.ContainsKey('Store'))
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
if ($InstallPath) {
    $siRoot = @((Join-Path $InstallPath 'SOLUTIONS\SecurityInsight'), $InstallPath) | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'config') } | Select-Object -First 1
    if (-not $siRoot) { throw "no SecurityInsight installation under $InstallPath" }
}
. (Join-Path $siRoot 'engine\pro-settings\SI-ProSettings.ps1')
. (Join-Path $siRoot 'engine\pro-settings\SI-TemplatePacks.ps1')

if (@($PackPath, $FromStaged, $RollbackToVersion | Where-Object { $_ }).Count -gt 1) { throw 'give ONE source: -PackPath, -FromStaged or -RollbackToVersion' }
if ($InstallDefault) {
    if ($PackPath -or $FromStaged -or $RollbackToVersion -or $Families -or $Method) { throw '-InstallDefault installs the shipped templates as a whole -- it takes no -PackPath, -FromStaged, -RollbackToVersion, -Families or -Method' }
    $Apply = [switch]$true; $CreateSchema = [switch]$true
}
if ($InstallCurrent) {
    if ($PackPath -or $FromStaged -or $RollbackToVersion -or $Families -or $Method -or $InstallDefault) { throw '-InstallCurrent installs every shipped template directly -- it takes no -PackPath, -FromStaged, -RollbackToVersion, -Families, -Method or -InstallDefault' }
    $Apply = [switch]$true; $CreateSchema = [switch]$true
}
# -WhatIf = the plan, also for -InstallDefault / -InstallCurrent / -Stage: nothing is written to the Pro database
if ($WhatIfPreference) { $Apply = [switch]$false; $CreateSchema = [switch]$false; $Stage = [switch]$false }
if ($Class -and -not $RollbackToVersion) { throw '-Class selects the items of a roll back (e.g. -RollbackToVersion 1.3 -Class microsoft)' }
$source = if ($PackPath -or $FromStaged) { 'pack' } elseif ($RollbackToVersion) { 'rollback' } else { 'shipped' }
$selective = ($source -ne 'shipped') -or [bool]$Method
# #250: a publish of EVERY shipped template is the default-templates path -- the carry-over, pack 1.0, the installed pack
$fullShipped = ($source -eq 'shipped') -and -not $Families -and -not $Method
$shippedInfo = Get-SIProShippedPackInfo -SIRoot $siRoot
# #405 (operator decision 2026-10-06): THE SPLIT INSTALL -- every shipped template is fix | default | microsoft
# (config\template-classification.locked.json). It runs when the vendor marked that classification as reviewed (the
# shipped pack's ClassificationReviewed): the code's fix + default templates are installed with the code, never held (a
# customer's edit is an override beside them and is never changed); a Microsoft content pack is installed automatically
# unless the install holds Microsoft content. Not reviewed = the old behaviour: every change waits for a review.
$classification = Get-SIProTemplateClassification -SIRoot $siRoot
$reviewed = if ($null -ne $ClassificationReviewed) { [bool]$ClassificationReviewed } else { [bool]$shippedInfo.ClassificationReviewed }
$split = $reviewed -and [bool]$classification.Present
$codeVersion = Get-SIProShippedVersion -SIRoot $siRoot
# the shipped templates, installed with the code (split) or directly (ring 1)
$splitShipped = $fullShipped -and ($split -or $InstallCurrent)

$result = [ordered]@{ Mode = 'plan'; Source = $source; Version = ''; PackVersion = ''; Fingerprint = ''; Baseline = ''; Recorded = ''; Moved = $false; Initial = $false
    Allowed = $false; Changes = @(); Written = 0; Verified = $false; Reason = ''; SelectionFingerprint = ''; Methods = @(); Selected = @(); Affected = 0; Staged = ''
    PackName = ''; Decision = ''; InstalledPack = ''; PackStatus = ''; Migration = $null
    Split = [bool]$split; Auto = $false; CodeVersion = $codeVersion; KeptMicrosoft = $false; Direct = [bool]$InstallCurrent; Class = @($Class | Where-Object { $_ }) }
$finish = {
    param($mode, $reason)
    $result.Mode = $mode; $result.Reason = $reason
    # #260: a publish that wrote, or that was blocked, is on the audit trail (a plan writes nothing and is not recorded)
    if ($Store -and $mode -in 'applied', 'blocked' -and -not $WhatIfPreference -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
        # #302 (AUDIT-1.1): a release an Admin accepted in the web app names the Admin (the job's start carries who it was,
        # SI_AUDIT_CID); the request's own name (SI_TEMPLATES_REQUESTED_BY) is the fallback when the start carried none
        $tplAttr = $null
        if ($global:SI_UseManagedIdentity -and [string]$RequestedBy -and -not (Get-SIJobAttribution -Invoke $Store.Invoke)) {
            $tplAttr = [pscustomobject]@{ Actor = [string]$RequestedBy; ApprovedBy = ''; CorrelationId = ''; Via = 'request' }
        }
        [void](Write-SIAuditEvent -Store $Store -Action 'template.pack.publish' -Actor (Get-SIAuditActor) -ActorSource $(if ($global:SI_UseManagedIdentity) { 'job' } else { 'setup' }) -Attribution $tplAttr `
            -Target ('template pack ' + [string]$result.Version) -Reason ([string]$reason) -Outcome $(if ($mode -eq 'applied') { 'ok' } else { 'refused' }) `
            -OutcomeText $(if ($mode -eq 'blocked') { [string]$reason } else { $null }) `
            -After ([ordered]@{ version = [string]$result.Version; written = $result.Written; fingerprint = [string]$result.Fingerprint; verified = [bool]$result.Verified; requestedBy = [string]$RequestedBy }))
    }
    if ($StrictJob -and $mode -eq 'blocked') { throw ('nothing written -- {0}' -f $reason) }
    if ($PassThru) { [pscustomobject]$result }
}

if (-not $Store -and $Server -and $Database) {
    try { $Store = New-SIProSettingsStore -Server $Server -Database $Database -AppId $AppId -TenantId $TenantId -CertThumbprint $CertThumbprint }
    catch { if ($Apply -or $FromStaged -or $RollbackToVersion -or $Stage) { throw }; Write-Host ("[WARN] the Pro database cannot be reached from here ({0}) -- planning without it" -f $_.Exception.Message) -ForegroundColor Yellow }
}
if ($Apply -and -not $Store) { throw 'nothing written: -Apply needs the Pro database (SI_ProSqlServer / SI_ProSqlDatabase, or -Server / -Database)' }
if (($FromStaged -or $RollbackToVersion -or $Stage) -and -not $Store) { throw 'the Pro database is needed for -FromStaged, -RollbackToVersion and -Stage (SI_ProSqlServer / SI_ProSqlDatabase, or -Server / -Database)' }
if ($Apply -and $CreateSchema) {
    $ddl = [System.IO.File]::ReadAllText((Join-Path $siRoot 'sql\si-pro-settings.sql'))
    foreach ($batch in ($ddl -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() }) { & $Store.Invoke $batch @{} 'nonquery' }
    Write-Host '[OK]   cfg schema present'
}
# ---- #251: naming and CMDB ownership become configuration -- carried over 1:1 before anything else is planned ----------
if ($Apply -and $fullShipped -and $Store -and -not @(Test-SIProVersioningSchema -Store $Store).Count) {
    $mig = Invoke-SIProConfigurationMigration -Store $Store -SIRoot $siRoot
    $result.Migration = [pscustomobject]@{ Settings = $mig.Written.Settings; Map = $mig.Written.Map; Retired = $mig.Written.Retired; Kept = @($mig.Kept).Count; NotCarried = @($mig.NotCarried).Count; Refused = @($mig.Refused) }
    if (-not $mig.Empty) {
        Write-Host ("[OK]   names and CMDB ownership are configuration now: {0} name(s) carried over as settings, CMDB ownership map {1}, {2} former template row(s) kept as history" -f $mig.Written.Settings, $(if ($mig.Written.Map) { 'written (' + $mig.Map.From + ')' } else { 'unchanged' }), $mig.Written.Retired)
    }
    foreach ($k in @($mig.Kept)) { Write-Host ("[INFO] {0}: your setting ({1}) already decides this name -- kept" -f $k.Name, $k.Setting) }
    foreach ($k in @($mig.NotCarried)) { Write-Host ("[WARN] {0}: {1}" -f $k.Name, $k.Reason) -ForegroundColor Yellow }
    foreach ($k in @($mig.Refused)) { Write-Host ("[WARN] {0}" -f $k) -ForegroundColor Yellow }
}
# #405: how this code installs templates -- 'split' (fix + default with the code, Microsoft content automatic) or 'gated'
# (every change reviewed) -- recorded on every setup / update run, so the web app's pages say what the install does
if ($Apply -and $fullShipped -and $Store -and -not @(Test-SIProVersioningSchema -Store $Store).Count) {
    Set-SIProInstallStateValue -Store $Store -Name 'TemplateMode' -Value $(if ($split) { 'split' } else { 'gated' }) -Version $codeVersion
}
$existing = @(); $recorded = ''; $overrides = @(); $translated = $false
# #405: what the install recorded per class -- ring 1's direct install, the Microsoft content rolled back from, the hold
$installedBefore = ''; $installedStatusBefore = ''; $directState = ''; $declinedState = ''; $holdMs = $false
if ($Store) {
    try {
        $existing = @(Read-SIProTemplates -Store $Store)
        $rec = Read-SIProInstallState -Store $Store
        if ($rec) { $recorded = ([string](Get-SIProRowValue $rec 'Value')).Trim() }
        if ($selective) { $overrides = @(Read-SIProItemOverrides -Store $Store) }
        if ($split -or $InstallCurrent -or $source -eq 'pack') {
            $installedBefore = Read-SIProInstalledPack -Store $Store
            $installedStatusBefore = Read-SIProInstalledPackStatus -Store $Store
            $directState = Read-SIProInstallStateValue -Store $Store -Name 'TemplateDirect'
            $declinedState = Read-SIProInstallStateValue -Store $Store -Name 'TemplatePackDeclined'
            if ($source -eq 'pack') { $holdMs = Read-SIProHoldMicrosoftContent -Store $Store }
        }
    }
    catch { if ($Apply -or $source -eq 'rollback') { throw }; Write-Host ("[WARN] the database's templates could not be read ({0}) -- the plan assumes none" -f $_.Exception.Message) -ForegroundColor Yellow }
}
# #251: the template fingerprint counts template CONTENT only now (names and the CMDB ownership map are configuration). A
# fingerprint recorded under the old definition, for exactly the templates in force, is the same baseline -- not a change.
# The former template rows count as they stood when that fingerprint was recorded -- live -- also after the carry-over
# above retired them.
if ($recorded) {
    $curNow = Get-SIProTemplateSetFingerprint -Rows $existing
    $asRecorded = @($existing | ForEach-Object {
        if ((Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $_ 'Kind'))) -and $null -ne (Get-SIProRowValue $_ 'RetiredAt')) {
            [pscustomobject]@{ Kind = (Get-SIProRowValue $_ 'Kind'); ItemKey = (Get-SIProRowValue $_ 'ItemKey'); ContentHash = (Get-SIProRowValue $_ 'ContentHash'); BodyJson = (Get-SIProRowValue $_ 'BodyJson'); Format = (Get-SIProRowValue $_ 'Format'); RetiredAt = $null }
        } else { $_ } })
    if ($recorded -ne $curNow -and ($recorded -eq (Get-SIProTemplateSetFingerprint -Rows $existing -AllKinds) -or $recorded -eq (Get-SIProTemplateSetFingerprint -Rows $asRecorded -AllKinds))) { $recorded = $curNow; $translated = $true }
}

# ---- the candidate rows: shipped, a pack, or a roll-back ----------------------------------------------------------------
$packText = $null; $packSha = ''; $scope = $null; $refused = @()
switch ($source) {
    'shipped' {
        $built = Get-SITemplateRows -SIRoot $siRoot -Version $Version -Families $Families
        $rows = @($built.Rows); $refused = @($built.Refused); $result.Version = $built.Version
        $scope = [pscustomobject]@{ Full = (-not $Families); Kinds = @($(if ($Families) { $Families } else { Get-SIProTemplatedKinds })); Methods = @(); Items = @() }
        if ($built.Version -eq $shippedInfo.PackVersion) { $result.PackVersion = $built.Version; $result.PackName = $shippedInfo.Name }
        Write-Host ("[INFO] the templates shipped with this release -- {0}: {1} item(s)" -f $(if ($result.PackName) { $result.PackName } else { 'version ' + $built.Version }), $rows.Count)
    }
    'pack' {
        if ($PackPath) {
            if (-not (Test-Path -LiteralPath $PackPath)) { throw "no template pack at $PackPath" }
            $packText = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $PackPath).Path)
            $expect = $PackSha256
            $shaFile = "$PackPath.sha256"
            if (-not $expect -and (Test-Path -LiteralPath $shaFile)) { $expect = Read-SIProSha256Line -Text ([System.IO.File]::ReadAllText($shaFile)) -FileName (Split-Path -Leaf $PackPath) }
            if (-not $expect) { Write-Host '[WARN] no .sha256 beside the pack and no -PackSha256: only the items'' own hashes are checked' -ForegroundColor Yellow }
        } else {
            $st = Read-SIProStagedPackText -Store $Store -PackVersion $FromStaged
            $packText = $st.Text; $expect = $st.Sha256
        }
        $parsed = ConvertFrom-SIProTemplatePack -Text $packText -ExpectedSha256 $expect -Context (Get-SIProConfigContext -SIRoot $siRoot)
        $packSha = $parsed.Sha256
        $rows = @($parsed.Rows); $refused = @($parsed.Refused); $scope = Get-SIProPackScope $parsed.Pack
        $result.Version = [string]$parsed.Pack.PackVersion; $result.PackVersion = $result.Version
        Write-Host ("[INFO] template pack {0} (built by SecurityInsight {1}, {2}): {3} item(s), SHA-256 {4}" -f $parsed.Pack.PackVersion, $parsed.Pack.CodeVersion, $(if ($scope.Full) { 'full' } else { 'partial' }), $rows.Count, $packSha.Substring(0, 12))
    }
    'rollback' {
        if (-not (Test-SIProPackVersion $RollbackToVersion)) { throw "'$RollbackToVersion' is not a version" }
        $revisions = @(Read-SIProTemplateRevisions -Store $Store)
        $rows = @(Get-SIProRollbackRows -Templates $existing -Revisions $revisions -Version $RollbackToVersion -Class @($Class | Where-Object { $_ }) -Classification $classification)
        $scope = [pscustomobject]@{ Full = $true; Kinds = @(Get-SIProTemplatedKinds); Methods = @(); Items = @(); Classes = @($Class | Where-Object { $_ }) }
        $result.Version = $RollbackToVersion; $result.PackVersion = $RollbackToVersion
        Write-Host ("[INFO] roll back to {0}{1}: {2} item(s) found in the template revisions" -f $RollbackToVersion, $(if ($Class) { ' (' + (@($Class) -join ', ') + ' content only)' } else { '' }), $rows.Count)
    }
}
# ---- risk factor model v2: the customer's overrides keyed the pre-v2 way follow the new keys (CONVERGE-DEFAULTS) ---------
# A risk index override under a 2.2 key, a factor override with 'stage' and without the v2 fields, an override of a removed
# factor: translated through the shipped translation table, the customer's values kept (engine\pro-settings\
# SI-ProOverrideMigration.ps1). Every setup / update path runs a full shipped publish, so every install converges once.
if ($Apply -and $fullShipped -and $Store) {
    try {
        $ovm = Invoke-SIProOverrideMigration -Store $Store -SIRoot $siRoot -Templates (@($existing) + @($rows))
        $result['OverrideMigration'] = [pscustomobject]@{ Applied = @($ovm.Applied).Count; Refused = @($ovm.Refused).Count }
        foreach ($a in @($ovm.Applied)) { Write-Host ("[OK]   your override {0}/{1}: {2}" -f $a.Kind, $a.OldKey, $a.Reason) }
        foreach ($x in @($ovm.Refused)) { Write-Host ("[WARN] your override {0}/{1} was left as it was -- it does not validate after translation: {2}" -f $x.Action.Kind, $x.Action.OldKey, $x.Reason) -ForegroundColor Yellow }
    } catch { Write-Host ("[WARN] your overrides could not be checked for the risk factor model v2 ({0}) -- they are unchanged; the next update tries again" -f $_.Exception.Message) -ForegroundColor Yellow }
}
# #405 + owner decision 2026-10-11: what THIS code does with a template pack -- every pack installs automatically (also
# one with more than Microsoft content); it is held only by the customer's Hold or a roll back from it, waits for newer
# code, or is the one in force already
$msDecision = $null; $autoAccept = $false
if ($source -eq 'pack') {
    $inForce = if (Test-SIProInstalledPackIsPack $installedBefore $installedStatusBefore) { $installedBefore } else { '' }
    $msDecision = Get-SIProTemplatePackDecision -Split $split -Pack $parsed.Pack -CodeVersion $codeVersion -Hold $holdMs -Declined $declinedState -Direct ([bool]$directState) -Installed $inForce
    $result.Decision = $msDecision.Action; $result.Auto = [bool]$msDecision.Auto; $autoAccept = [bool]$msDecision.Auto
    Write-Host ("[INFO] {0}" -f $msDecision.Reason)
}
# #405: the shipped templates in split mode (and ring 1's direct install) are installed with the code -- never held. A
# NEWER Microsoft content pack already in force (from the update ring) is kept: the code's Microsoft items are left out,
# and nothing of that class is retired.
$keepMicrosoft = $false; $stageRows = $rows
if ($splitShipped) {
    $autoAccept = $true
    # (ring 1's direct install too: a newer pack in force is not taken back by the next deploy)
    if (($InstallCurrent -or -not $directState) -and (Test-SIProInstalledPackIsPack $installedBefore $installedStatusBefore) -and
        (Compare-SIProPackVersion $installedBefore $shippedInfo.PackVersion) -gt 0) { $keepMicrosoft = $true }
    if ($keepMicrosoft) { $rows = @($rows | Where-Object { (Get-SIProRowClass -Row $_ -Classification $classification) -ne 'microsoft' }) }
    $result.Decision = $(if ($InstallCurrent) { 'direct' } else { 'code' }); $result.Auto = $true; $result.KeptMicrosoft = $keepMicrosoft; $result.InstalledPack = $installedBefore
    Write-Host ("[INFO] {0}" -f $(if ($InstallCurrent -and $keepMicrosoft) { "ring 1: the fix and default templates of SecurityInsight $codeVersion are installed directly; the newer pack $installedBefore in force is kept" }
        elseif ($InstallCurrent) { "ring 1: every template shipped with SecurityInsight $codeVersion is installed directly (no gate) -- recorded as template pack $($shippedInfo.PackVersion)" }
        elseif ($keepMicrosoft) { "the fix and default templates of SecurityInsight $codeVersion are installed with the code; the newer Microsoft content $installedBefore in force is kept" }
        else { "the templates of SecurityInsight $codeVersion are installed with the code (fixes, defaults and Microsoft content $($shippedInfo.PackVersion)); your own changes are kept" }))
}
foreach ($g in @($rows | Group-Object Kind | Sort-Object Name)) { Write-Host ("  {0,-14} {1}" -f $g.Name, $g.Count) }
foreach ($r in @($refused)) { Write-Host ("  refused {0} -- {1}" -f $r.Name, $r.Reason) -ForegroundColor Red }

# ---- #250: the default templates -- install, adopt, or leave a newer / customised install as it is ---------------------
$decision = $null; $dbFp = Get-SIProTemplateSetFingerprint -Rows $existing
# (#405: in split mode -- and for ring 1's direct install -- the shipped templates are always installed with the code)
if ($fullShipped -and $Store -and -not $splitShipped) {
    $installedPack = ''; $installedStatus = ''
    try { $installedPack = Read-SIProInstalledPack -Store $Store; $installedStatus = Read-SIProInstalledPackStatus -Store $Store } catch { if ($Apply) { throw } }
    $live = @($existing | Where-Object { $null -eq (Get-SIProRowValue $_ 'RetiredAt') -and -not (Test-SIProFormerTemplateKind ([string](Get-SIProRowValue $_ 'Kind'))) })
    $decision = Get-SIProDefaultTemplateDecision -InstalledPack $installedPack -InstalledStatus $installedStatus -LiveCount $live.Count -InstalledFingerprint $dbFp `
        -ShippedVersion $shippedInfo.PackVersion -ShippedFingerprint (Get-SIProTemplateSetFingerprint -Rows $rows) -ShippedName $shippedInfo.Name
    $result.Decision = $decision.Action; $result.InstalledPack = $installedPack; $result.PackStatus = $installedStatus
    Write-Host ("[INFO] default templates: {0}" -f $decision.Reason)
    # the templates in force ARE the shipped pack: that is the baseline, whatever was recorded before
    if ($decision.Action -eq 'adopt') { $recorded = $dbFp }
}

# ---- the detection methods, and the selection ----------------------------------------------------------------------------
$diff = $null; $methods = @()
if ($selective) {
    $diff = Get-SIProTemplatePackDiff -Rows $rows -Existing $existing -Scope $scope -Overrides $overrides
    $known = [string[]]@($diff.Methods | ForEach-Object { $_.Id })
    $methods = @(Resolve-SIProMethodSelection -Selection @($Method) -Known $known)
    $selAll = (-not $Method) -or (@($Method) -contains '*')
    $selRows = if ($selAll) { $rows } else { @($rows | Where-Object { $methods -contains (Get-SIProRowMethodId $_) }) }
    $result.SelectionFingerprint = Get-SIProSelectionFingerprint -Diff $diff -Methods $(if ($selAll) { @() } else { $methods })
    $result.Methods = @($diff.Methods); $result.Selected = @($methods)
    $affected = @($diff.Items | Where-Object { $_.Affected -and ($selAll -or $methods -contains $_.MethodId) })
    $result.Affected = $affected.Count
    Write-Host ("[INFO] detection methods: {0} selected of {1}" -f $methods.Count, $known.Count)
    foreach ($m in @($diff.Methods | Where-Object { $selAll -or $methods -contains $_.Id })) {
        if ($m.Added + $m.Changed + $m.Retired -eq 0) { continue }
        Write-Host ("  {0,-60} new {1}, changed {2}, retired {3}{4}" -f $m.Id, $m.Added, $m.Changed, $m.Retired, $(if ($m.Affected) { ", YOUR OVERRIDES AFFECTED: $($m.Affected)" } else { '' }))
    }
    Write-Host ("[INFO] selection fingerprint (what an acceptance names): {0}" -f $result.SelectionFingerprint)
} else { $selRows = $rows; $selAll = $true }

# ---- stage it for the web app (cfg.TemplatePackStaged) -------------------------------------------------------------------
# A full apply of the shipped templates always stages them (#250): the web app lists the pack the install runs on.
if ($Stage -or ($Apply -and $fullShipped -and $Store)) {
    if (-not (Test-SIProTemplatePackSchema -Store $Store)) { Write-Host '[WARN] not staged: the Pro database has no cfg.TemplatePackStaged yet -- the next setup or update run (with -CreateSchema) adds it' -ForegroundColor Yellow }
    else {
        if ($source -eq 'rollback') { throw '-Stage stages a pack or the shipped templates, not a roll-back' }
        $origin = if ($StageOrigin) { $StageOrigin } elseif ($source -eq 'pack') { if ($FromStaged) { 'feed' } else { 'file' } } else { 'shipped' }
        $text = if ($packText) { $packText } else {
            # (#405: the shipped pack as shipped -- also when a newer Microsoft content pack in force is kept)
            # #416: built once per process for the same rows (Get-SIProPackTextFor)
            Get-SIProPackTextFor -Rows $stageRows -PackVersion $result.Version -CodeVersion (Get-SIProShippedVersion -SIRoot $siRoot) -Kind $(if ($Families) { $Families } else { $null }) -Name $result.PackName -Classification $classification
        }
        $result.Staged = Save-SIProTemplatePackStaged -Store $Store -Text $text -Origin $origin -Ring $StageRing
        if ($result.Staged -eq 'Conflict' -and $splitShipped) {
            Write-Host ("[INFO] {0} is already staged with other content; the templates shipped with SecurityInsight {1} are installed with the code" -f $(if ($result.PackName) { $result.PackName } else { $result.Version }), $codeVersion)
        } elseif ($result.Staged -eq 'Conflict') {
            if ($source -ne 'shipped') { throw ("a DIFFERENT template pack {0} is already staged on this install -- a published pack never changes" -f $result.Version) }
            # the shipped templates changed under an unchanged pack version: never applied under that name
            Write-Host ("[WARN] this release ships other template content as {0} than the {0} already on this install -- not staged, not applied (template changes arrive as a new pack)" -f $(if ($result.PackName) { $result.PackName } else { $result.Version })) -ForegroundColor Yellow
            if ($decision -and $decision.Publish -and $decision.Action -ne 'install') {
                $decision = [pscustomobject]@{ Action = 'shipped-differs'; Publish = $false; Record = $false; Status = $result.PackStatus; Reason = ('{0} is already on this install with other content -- the templates in force are kept' -f $result.Version) }
                $result.Decision = $decision.Action
            }
        } else {
            Write-Host ("[OK]   template pack {0} staged for the web app's Template releases page ({1})" -f $(if ($result.PackName) { $result.PackName } else { $result.Version }), $result.Staged)
        }
    }
}

# ---- #250: nothing to publish (customised, newer, or other content under the same version) -- record, and stop here -----
if ($decision -and -not $decision.Publish) {
    if ($Apply) {
        if ($decision.Record) {
            Set-SIProTemplateRelease -Store $Store -PackVersion $shippedInfo.PackVersion -Mode adopted -Whole $true -Status $decision.Status -Fingerprint $dbFp -Changed 0 -RequestedBy $RequestedBy
            Write-Host ("[OK]   recorded: {0} -- {1}" -f $shippedInfo.Name, $(if ($decision.Status -eq 'customised') { 'customised (your templates are kept)' } else { 'installed' }))
        }
        if ($translated) { Set-SIProTemplateFingerprint -Store $Store -Fingerprint $recorded -Version $result.Version -Reason 'the template fingerprint counts template content only (names and the CMDB ownership map are configuration)' }
    }
    $result.Fingerprint = $dbFp; $result.Recorded = $recorded; $result.Baseline = $recorded; $result.Allowed = $true; $result.Moved = $false
    if ($decision.Record -and $Apply) { $result.InstalledPack = $shippedInfo.PackVersion; $result.PackStatus = $decision.Status }
    return (& $finish $(if ($Apply) { 'applied' } else { 'plan' }) $decision.Reason)
}
if ($decision -and $decision.Record -and $Apply) {
    # adopt: the templates in force are the shipped pack -- recorded as installed, and that content is the baseline
    Set-SIProTemplateRelease -Store $Store -PackVersion $shippedInfo.PackVersion -Mode adopted -Whole $true -Status 'as-released' -Fingerprint $dbFp -Changed 0 -RequestedBy $RequestedBy
    Set-SIProTemplateFingerprint -Store $Store -Fingerprint $dbFp -Version $shippedInfo.PackVersion -Reason ('the templates in force are {0} -- recorded as installed' -f $shippedInfo.Name)
    Write-Host ("[OK]   recorded: {0} is installed (the templates in force are exactly its content)" -f $shippedInfo.Name)
}

$plan = @(Get-SITemplatePublishPlan -Rows @($selRows) -Existing $existing -Families $(if ($source -eq 'shipped') { $Families } else { @($scope.Kinds) }) -RefreshMissingContentHash)
if ($selective) { $plan = @(Get-SIProSelectionPlan -Plan $plan -Existing $existing -Scope $scope -Methods $(if ($selAll) { @() } else { $methods })) }
# #405: the newer Microsoft content in force is kept -- nothing of that class is retired by the code's templates
if ($keepMicrosoft) { $plan = @($plan | Where-Object { -not ($_.Action -eq 'retire' -and (Get-SIProTemplateClass -Kind ([string]$_.Kind) -ItemKey ([string]$_.ItemKey) -Classification $classification) -eq 'microsoft') }) }
$byAction = @{}; foreach ($p in $plan) { $byAction[$p.Action] = 1 + [int]$byAction[$p.Action] }
Write-Host ("[INFO] plan: {0} insert, {1} update, {2} unchanged, {3} retire, {4} revive{5}" -f [int]$byAction['insert'], [int]$byAction['update'], [int]$byAction['same'], [int]$byAction['retire'], [int]$byAction['revive'], $(if ($Store) { " (against $($Store.Name))" } else { ' (no database configured -- every item would be new)' }))
foreach ($p in @($plan | Where-Object { $_.Action -in 'update', 'retire', 'revive' })) { Write-Host ("  {0,-7} {1}/{2}" -f $p.Action, $p.Kind, $p.ItemKey) }
# #529 (3): the items that follow the template and move to new content -- each gets an "upgraded" entry in the change log
# when written (Invoke-SITemplatePublish), so an inherited change is never silent
$upgOverrides = $overrides
if (-not $selective -and $Store) { try { $upgOverrides = @(Read-SIProItemOverrides -Store $Store) } catch { $upgOverrides = @() } }
$upgrades = @(Get-SIProTemplateUpgrades -Existing $existing -Plan $plan -Overrides @($upgOverrides))
$result.Upgraded = $upgrades.Count
if ($upgrades.Count) {
    Write-Host ("[INFO] {0} item(s) you do not override follow the new shipped version (recorded as upgraded):" -f $upgrades.Count)
    foreach ($u in ($upgrades | Select-Object -First 50)) { Write-Host ("  upgraded {0}  {1} -> {2}" -f $u.Name, $(if ($u.FromVersion) { $u.FromVersion } else { '(none)' }), $u.ToVersion) }
    if ($upgrades.Count -gt 50) { Write-Host ("  ... and {0} more" -f ($upgrades.Count - 50)) }
}

# ---- the fingerprint gate: what the templates in force would SAY after this publish, against what the install recorded
$expectedSet = @(Get-SIProPlannedTemplateSet -Existing $existing -Plan $plan)
$expected = Get-SIProTemplateSetFingerprint -Rows $expectedSet
$current = Get-SIProTemplateSetFingerprint -Rows $existing
$changes = @(Get-SIProTemplateChanges -Existing $existing -Plan $plan)
$selRefusal = ''
if ($selective) {
    # an acceptance from a pack, a roll-back or a selection names the SELECTION fingerprint -- exactly what was reviewed
    $sel = $result.SelectionFingerprint
    $acceptedSel = $AcceptFingerprint -and $AcceptFingerprint.Length -ge 12 -and $sel -and $sel.StartsWith($AcceptFingerprint, [StringComparison]::OrdinalIgnoreCase)
    # #405: Microsoft content installed automatically is accepted by the decision itself (an override of yours stays beside it)
    $gate = Get-SIProTemplateGateDecision -Recorded $recorded -Current $current -Expected $expected -Accept:($AcceptTemplateChange -or $acceptedSel -or $autoAccept)
    $pending = @($diff.Items | Where-Object { $_.Change -ne 'unchanged' -and ($selAll -or $methods -contains $_.MethodId) }).Count
    if ($AcceptFingerprint -and -not $acceptedSel) {
        $selRefusal = 'the acceptance names selection fingerprint {0}, but this release would put {1} in force -- the pack, the selection or your templates changed since it was reviewed; review it again' -f $AcceptFingerprint.Substring(0, [Math]::Min(12, $AcceptFingerprint.Length)), $(if ($sel) { $sel.Substring(0, 12) } else { '(nothing)' })
    } elseif ($msDecision -and $msDecision.Action -eq 'wait-code') {
        # never installed by code older than the pack names -- not even by hand
        $selRefusal = $msDecision.Reason
    } elseif ($msDecision -and $msDecision.Action -eq 'installed' -and $pending -gt 0 -and -not ($AcceptTemplateChange -or $acceptedSel)) {
        # a pack older than the one in force is never put back automatically (a roll back is its own path)
        $selRefusal = $msDecision.Reason
    } elseif ($msDecision -and $msDecision.Action -eq 'hold' -and $pending -gt 0 -and -not ($AcceptTemplateChange -or $acceptedSel)) {
        $selRefusal = '{0} -- nothing is written without an Install (-AcceptFingerprint {1})' -f $msDecision.Reason, $(if ($sel) { $sel.Substring(0, 12) } else { '' })
    } elseif ($result.Affected -gt 0 -and -not ($AcceptTemplateChange -or $acceptedSel -or $autoAccept)) {
        $selRefusal = '{0} of your overridden or switched-off item(s) change in this release -- nothing is written without an acceptance (-AcceptFingerprint {1})' -f $result.Affected, $(if ($sel) { $sel.Substring(0, 12) } else { '' })
    }
} else {
    # #405: the code's own templates in split mode (and ring 1's direct install) are installed with the code, never held
    $gate = Get-SIProTemplateGateDecision -Recorded $recorded -Current $current -Expected $expected -Accept:($AcceptTemplateChange -or $autoAccept) -AcceptFingerprint $(if ($autoAccept) { '' } else { $AcceptFingerprint })
}
$result.Fingerprint = $expected; $result.Recorded = $recorded; $result.Baseline = $gate.Baseline; $result.Moved = $gate.Moved
$result.Initial = $gate.Initial; $result.Allowed = ($gate.Allowed -and -not $selRefusal); $result.Changes = $changes
Write-Host ("[INFO] template fingerprint after this publish: {0} -- {1}" -f $expected, $(if ($selRefusal) { $selRefusal } else { $gate.Reason }))
if ($changes.Count) {
    Write-Host ("[INFO] {0} item(s) change what they do:" -f $changes.Count)
    foreach ($c in ($changes | Select-Object -First 50)) { Write-Host ("  {0,-8} {1}" -f $c.Change, $c.Name) }
    if ($changes.Count -gt 50) { Write-Host ("  ... and {0} more" -f ($changes.Count - 50)) }
}
if (-not $Apply) { Write-Host '[INFO] nothing written -- run with -Apply to publish.'; return (& $finish 'plan' $(if ($selRefusal) { $selRefusal } else { $gate.Reason })) }
if (@($refused).Count) { throw ('nothing written: {0} shipped item(s) do not validate -- fix the release first' -f @($refused).Count) }
if ($selRefusal -or -not $gate.Allowed) {
    $why = if ($selRefusal) { $selRefusal } else { $gate.Reason }
    Write-Host ('[BLOCKED] nothing written: {0}' -f $why) -ForegroundColor Red
    $name = if ($selective) { $result.SelectionFingerprint } else { $expected }
    Write-Host ('          review the items above, then run again with -AcceptTemplateChange (or -AcceptFingerprint {0})' -f $name.Substring(0, [Math]::Min(12, $name.Length))) -ForegroundColor Red
    return (& $finish 'blocked' $why)
}
$missing = @(Test-SIProVersioningSchema -Store $Store)
if ($missing.Count) { throw ('nothing written: the Pro database lacks {0} -- run again with -CreateSchema' -f ($missing -join ', ')) }

$by = '{0} (publish {1})' -f (Get-SIProSessionActor), $result.Version
$n = Invoke-SITemplatePublish -Store $Store -Plan $plan -ChangedBy $by
$result.Written = $n
Write-Host ("[OK]   {0} template change(s) written to {1}; customer overrides untouched" -f $n, $Store.Name)

# ---- verify by reading back, and only then record the fingerprint on the install
$after = @(Read-SIProTemplates -Store $Store)
$bad = New-Object System.Collections.Generic.List[string]
foreach ($r in @($after | Where-Object { $null -eq (Get-SIProRowValue $_ 'RetiredAt') })) {
    $name = '{0}/{1}' -f (Get-SIProRowValue $r 'Kind'), (Get-SIProRowValue $r 'ItemKey')
    if ((Get-SIProTextHash ([string](Get-SIProRowValue $r 'BodyJson'))) -ne ([string](Get-SIProRowValue $r 'BodyHash')).Trim()) { $bad.Add("$name (body does not match its hash)") }
    elseif (-not ([string](Get-SIProRowValue $r 'ContentHash')).Trim()) { $bad.Add("$name (no content hash)") }
}
$readBack = Get-SIProTemplateSetFingerprint -Rows $after
if ($readBack -ne $expected) { $bad.Add(('the templates in force read back as fingerprint {0}, not the published {1}' -f $readBack, $expected)) }
if ($bad.Count) {
    throw ('the publish could not be verified -- the template fingerprint was NOT recorded, so the next publish is gated again: {0}' -f (($bad | Select-Object -First 10) -join '; '))
}
$result.Verified = $true
$why = if ($gate.Initial) { 'first publish (baseline)' } elseif ($gate.Moved) { 'template change accepted: ' + $changes.Count + ' item(s)' } else { 'templates unchanged' }
Set-SIProTemplateFingerprint -Store $Store -Fingerprint $expected -Version $result.Version -Reason $why
Write-Host ("[OK]   verified; template fingerprint {0} recorded on the install ({1})" -f $expected, $why)
if ($source -ne 'shipped') {
    # every method of the pack (or of the roll-back) released: the install now runs this pack -- what the updater compares
    # the ring's approval with, so the same pack is not offered again
    $whole = [bool]$selAll
    # #405: a Microsoft content pack nobody had to accept was installed automatically; an explicit acceptance is a release
    $relMode = if ($source -eq 'rollback') { 'rollback' } elseif ($autoAccept -and -not ($AcceptTemplateChange -or $AcceptFingerprint)) { 'auto' } else { 'release' }
    $relClasses = if ($source -eq 'rollback') { @($Class | Where-Object { $_ }) } elseif ($parsed.Pack.PSObject.Properties['Content'] -and [string]$parsed.Pack.Content) { @([string]$parsed.Pack.Content) } else { @() }
    Set-SIProTemplateRelease -Store $Store -PackVersion $result.Version -Mode $relMode -Methods $methods `
        -SelectionFingerprint $result.SelectionFingerprint -Fingerprint $expected -Whole $whole -Changed $changes.Count -RequestedBy $RequestedBy -Classes $relClasses
    Write-Host ("[OK]   {0} of template pack {1} recorded ({2})" -f $(switch ($relMode) { 'rollback' { 'roll back' } 'auto' { 'automatic install' } default { 'release' } }), $result.Version, $(if ($whole) { 'the whole pack' } else { "$($methods.Count) detection method(s)" }))
    if ($split -and $source -eq 'rollback' -and @($Class) -contains 'microsoft' -and $installedBefore -and (Compare-SIProPackVersion $installedBefore $RollbackToVersion) -gt 0) {
        # the one-click roll back of Microsoft content: the pack rolled back from is never installed automatically again
        Set-SIProInstallStateValue -Store $Store -Name 'TemplatePackDeclined' -Value $installedBefore -Version $RollbackToVersion
        Write-Host ("[OK]   Microsoft content {0} will not be installed automatically again (a newer pack will)" -f $installedBefore)
    } elseif ($split -and $source -eq 'pack' -and $declinedState -and (Compare-SIProPackVersion $result.Version $declinedState) -ge 0) {
        Set-SIProInstallStateValue -Store $Store -Name 'TemplatePackDeclined' -Value '' -Version $result.Version
    }
} elseif ($splitShipped) {
    # #405: what is installed per class -- the code release's fix + default templates (TemplateCode); its Microsoft content
    # unless a newer pack was kept (TemplatePack); ring 1's direct install (TemplateDirect; no pack recorded as a release)
    if ($InstallCurrent) {
        # owner decision 2026-10-11: the record follows what the direct deploy installed -- the shipped pack it put in force
        # is the installed pack (TemplatePack + TemplatePackStatus as-released), unless a newer pack in force was kept
        Set-SIProTemplateRelease -Store $Store -PackVersion $result.Version -Mode direct -Fingerprint $expected -Whole (-not $keepMicrosoft) -Changed $changes.Count -RequestedBy $RequestedBy -Status 'as-released' -CodeVersion $codeVersion
        if (-not $keepMicrosoft) { $result.InstalledPack = $result.Version; $result.PackStatus = 'as-released' }
        Set-SIProInstallStateValue -Store $Store -Name 'TemplateDirect' -Value $codeVersion -Version $codeVersion
    } else {
        Set-SIProTemplateRelease -Store $Store -PackVersion $result.Version -Mode code -Fingerprint $expected -Whole (-not $keepMicrosoft) -Changed $changes.Count -RequestedBy $RequestedBy -Status 'as-released' -CodeVersion $codeVersion
        if (-not $keepMicrosoft) { $result.InstalledPack = $result.Version; $result.PackStatus = 'as-released' }
    }
    Set-SIProInstallStateValue -Store $Store -Name 'TemplateCode' -Value $codeVersion -Version $codeVersion
    Write-Host ("[OK]   the templates of SecurityInsight {0} are installed{1}" -f $codeVersion, $(if ($InstallCurrent) { $(if ($keepMicrosoft) { " directly (ring 1; the newer pack $installedBefore kept)" } else { " directly (ring 1; template pack $($result.Version))" }) } elseif ($keepMicrosoft) { " (Microsoft content $installedBefore kept)" } else { " (Microsoft content $($result.Version))" }))
} elseif ($fullShipped) {
    # #250: the shipped templates in force ARE the shipped pack (1.0): the install records it, as released
    Set-SIProTemplateRelease -Store $Store -PackVersion $result.Version -Mode shipped -Fingerprint $expected -Whole $true -Changed $changes.Count -RequestedBy $RequestedBy -Status 'as-released'
    $result.InstalledPack = $result.Version; $result.PackStatus = 'as-released'
    Write-Host ("[OK]   {0} is installed" -f $(if ($result.PackName) { $result.PackName } else { 'template pack ' + $result.Version }))
}
& $finish 'applied' $gate.Reason
} finally { Stop-SIScriptRun -Run $siRun }
