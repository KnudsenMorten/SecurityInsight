#Requires -Version 5.1
<#
    SecurityInsight -- THE DATA-OUT CONTRACT (#914, owner 2026-10-27: "performance is not critical, but data trust is
    critical"). ONE contract for every data-out target: the ServiceNow push (the data-out connector, the only one), the
    hand-off database and the two SQL connectors. docs/DESIGN.md "One trusted contract for every data-out target".

      * every run sends the FULL current scoped state of an output, every row with u_action (new / update / close /
        reopen / held / out_of_scope), u_row_hash and u_si_batch_id;
      * ONE stable key per record (the CI key; the CI key + the finding for a vulnerable item);
      * the output scope applied when sending (#274: the 'cmdb-servicenow' asset scope for the CIs, the 'vuln-servicenow'
        finding scope for the vulnerable items) -- a record that leaves the scope gets one out_of_scope row, a vulnerable
        item never closes as fixed by a scope (#217 rule 4);
      * one set of state and close-reason values (the value maps servicenow_ci_state, open_closed, servicenow_close_reason);
      * the clear marker u_si_cleared, re-keying (u_si_replaces), the order rule (a vulnerable item's CI is delivered first),
        the contract version, the resync and the test batch.

    PURE except Read-* / Write-* (they go through the seams they are given). PowerShell 7; parses on 5.1. No modules.
    NO Set-StrictMode here -- it leaks into the caller's scope.
#>

# =====================================================================================================================
#  THE CONTRACT'S VERSION. Rule: ADD ONLY. Renaming or removing a column, or changing what a value means, needs a new
#  version (and the old one is kept for the targets that read it).
# =====================================================================================================================
$script:SIDataOutContractVersion = '1'
$script:SIDataOutContractActions = @('new', 'update', 'close', 'reopen', 'held', 'out_of_scope')
$script:SIDataOutContractModes = @('live', 'resync', 'test')
# the classes a record can be in (what SecurityInsight says the target has after a row is imported)
$script:SIDataOutContractClasses = @('none', 'live', 'closed', 'out_of_scope', 'gone')
# the hash a row's state gets when its batch did not complete (#912 convention: a value no row has)
$script:SIDataOutUndelivered = ('0' * 64)
# the outputs the contract governs, their grain, their scope destination, their state column and the tokens of the
# envelope columns (system tokens of the output map: filled by the writer, never part of u_row_hash)
$script:SIDataOutContractOutputs = [ordered]@{
    'servicenow-ci'              = @{ Grain = 'ci'; Scope = 'cmdb-servicenow'; Object = 'ci' }
    'servicenow-vulnerable-item' = @{ Grain = 'ci_finding'; Scope = 'vuln-servicenow'; Object = 'vulnerable_item' }
}
$script:SIDataOutEnvelopeTokens = [ordered]@{
    '$action' = 'u_action'; '$batch_id' = 'u_si_batch_id'; '$cleared' = 'u_si_cleared'; '$reason' = 'u_si_reason'; '$replaces' = 'u_si_replaces'
}
# THE CLEARABLE COLUMNS per output: an empty value in one of these, on a row that carries SecurityInsight's whole current
# record (every action but held), is listed in u_si_cleared -- the target clears it. Any other empty column is unknown.
$script:SIDataOutClearable = @{
    'servicenow-ci'              = @('u_fqdn', 'u_dns_domain', 'u_serial_number', 'u_mac_address', 'u_object_id', 'u_azure_resource_id', 'u_aad_device_id',
                                     'u_mde_device_id', 'u_entra_object_id', 'u_tier', 'u_tier_reason', 'u_criticality', 'u_exposed_internet', 'u_data_sensitivity',
                                     'u_si_asset_subtype')
    'servicenow-vulnerable-item' = @('u_cmdb_ci', 'u_severity', 'u_closed_at', 'u_close_reason', 'u_title', 'u_si_component', 'u_si_servicenow_subci', 'u_si_os_family',
                                     'u_si_patch_cycle')
}
# the fixed columns of a vulnerable item an out_of_scope row carries (the hand-off database's values, #279 decision 3)
$script:SIDataOutOutOfScopeState = 'Closed'
$script:SIDataOutOutOfScopeReason = 'Out of scope'

function Get-SIDataOutContractVersion { <# PURE. The contract version every batch carries (u_si_contract_version). #> $script:SIDataOutContractVersion }
function Get-SIDataOutContractActions { <# PURE. The u_action values, in the documented order. #> , @($script:SIDataOutContractActions) }
function Get-SIDataOutContractModes { <# PURE. The u_si_mode values. #> , @($script:SIDataOutContractModes) }
function Get-SIDataOutUndeliveredHash { <# PURE. The row hash of a state row whose batch did not complete. #> $script:SIDataOutUndelivered }

function Test-SIDataOutContractOutput {
    <# PURE. Is the output governed by the contract (the two ServiceNow outputs)? #>
    param([string]$Output)
    $script:SIDataOutContractOutputs.Contains([string]$Output)
}

function Get-SIDataOutContractSpec {
    <# PURE. The contract's facts of one output: @{ Grain; Scope; Object } ($null for an output outside the contract). #>
    param([string]$Output)
    if (-not $script:SIDataOutContractOutputs.Contains([string]$Output)) { return $null }
    [pscustomobject]$script:SIDataOutContractOutputs[[string]$Output]
}

function Get-SIDataOutEnvelopeTokens { <# PURE. System token -> the envelope column it fills. #> $script:SIDataOutEnvelopeTokens }

function Get-SIDataOutClearableColumns {
    <# PURE. The columns of an output whose empty value is a clear (u_si_cleared). #>
    param([Parameter(Mandatory)][string]$Output)
    if ($script:SIDataOutClearable.ContainsKey($Output)) { return , @($script:SIDataOutClearable[$Output]) }
    , @()
}

function Get-SIDataOutContractColumns {
    <#
        PURE. The contract columns of an output's map, in order (the envelope + the row hash + the source run): every one of
        them must be in the map AND in every schema definition (the parity test holds them to it).
    #>
    param([Parameter(Mandatory)][string]$Output)
    $base = @('u_row_hash', 'u_source_run')
    , @($base + @($script:SIDataOutEnvelopeTokens.Values))
}

# =====================================================================================================================
#  THE ACTION OF ONE RECORD
# =====================================================================================================================

function Get-SIDataOutRecordClass {
    <#
        PURE. What a record IS now, for the action table: 'live' (a CI that is active or not-seen; an open finding),
        'counting' (an open finding whose absence is being counted -- u_absent_runs > 0), 'closed' (a retired CI, a closed
        finding). -Item: the data-out item (si_lifecycle / si_finding_state, absent_runs).
    #>
    param([Parameter(Mandatory)][ValidateSet('ci', 'ci_finding')][string]$Grain, $Item)
    if ($Grain -eq 'ci') {
        $lc = ([string](Get-SIItemValue $Item 'si_lifecycle')).Trim().ToLowerInvariant()
        if ($lc -eq 'retired') { return 'closed' }
        return 'live'
    }
    $st = ([string](Get-SIItemValue $Item 'si_finding_state')).Trim().ToLowerInvariant()
    if ($st -eq 'closed') { return 'closed' }
    $ar = 0; [void][int]::TryParse([string](Get-SIItemValue $Item 'absent_runs'), [ref]$ar)
    if ($ar -gt 0) { return 'counting' }
    'live'
}

function Get-SIDataOutContractAction {
    <#
    .SYNOPSIS  PURE. THE ACTION TABLE (docs/DESIGN.md #914 section 3): what one record's row says, from what the record is
               NOW and the BASE -- what the target last received in a COMPLETE batch.
    .PARAMETER Now   live | counting | closed | out_of_scope | held | gone
    .PARAMETER Base  none | live | closed | out_of_scope | gone
    .PARAMETER Resync  a full resync: every base is treated as none for live / counting / closed records
    .OUTPUTS   @{ Action ('' = no row); Send (bool); Class (the class the target has after the row is imported) }
    #>
    param([Parameter(Mandatory)][ValidateSet('live', 'counting', 'closed', 'out_of_scope', 'held', 'gone')][string]$Now,
          [ValidateSet('none', 'live', 'closed', 'out_of_scope', 'gone')][string]$Base = 'none', [switch]$Resync)
    $b = $Base
    if ($Resync -and $Now -in 'live', 'counting', 'closed') { $b = 'none' }
    $r = { param($a, $c) [pscustomobject]@{ Action = $a; Send = [bool]$a; Class = $c } }
    switch ($Now) {
        'live' {
            switch ($b) { 'none' { return (& $r 'new' 'live') } 'live' { return (& $r 'update' 'live') } default { return (& $r 'reopen' 'live') } }
        }
        'counting' {
            # an open finding whose absence is counted: SecurityInsight neither confirms nor closes it -- held, never closed
            switch ($b) { 'none' { return (& $r 'new' 'live') } 'live' { return (& $r 'held' 'live') } default { return (& $r 'reopen' 'live') } }
        }
        'closed' { return (& $r 'close' 'closed') }
        'out_of_scope' {
            # once, from an open / active record; a record the target never had, or has closed, gets no row (#217 rule 4:
            # a scope never opens or closes anything as fixed)
            if ($b -eq 'live') { return (& $r 'out_of_scope' 'out_of_scope') }
            return (& $r '' $b)
        }
        'held' {
            # disabled, a report that could not complete, a CI not delivered yet: the target keeps what it has
            if ($b -in 'live', 'closed') { return (& $r 'held' $b) }
            return (& $r '' $b)
        }
        'gone' {
            # not in SecurityInsight's data any more: one held row (the target keeps the record as it is), then no row
            if ($b -in 'live', 'closed') { return (& $r 'held' 'gone') }
            return (& $r '' $b)
        }
    }
}

function Get-SIDataOutStateMeta {
    <#
        PURE. What a state row (cfg.DataOutItem: RowHash + RowJson) says for the action table: @{ Present; Delivered; Base
        (the class the target has: delivered = the row's own class, else the base it was sent over); Cells (the row as
        sent, column -> text, the meta left out) }. A row written before #914 (no meta) reads as delivered 'live', or
        'closed' when its state says so.
    #>
    param($Prev, [string]$Grain = 'ci')
    if ($null -eq $Prev) { return [pscustomobject]@{ Present = $false; Delivered = $false; Base = 'none'; Cells = [ordered]@{}; Class = 'none' } }
    $hash = [string](Get-SIItemValue $Prev 'Hash')
    $json = [string](Get-SIItemValue $Prev 'Json')
    $cells = [ordered]@{}; $meta = @{}
    if ($json) {
        try {
            $o = $json | ConvertFrom-Json
            foreach ($p in $o.PSObject.Properties) { if ($p.Name.StartsWith('__')) { $meta[$p.Name] = [string]$p.Value } else { $cells[$p.Name] = [string]$p.Value } }
        } catch { }
    }
    $delivered = ($hash -and $hash -ne $script:SIDataOutUndelivered)
    $cls = [string]$meta['__c']
    if (-not $cls) {
        # before #914: the row as sent says what the target has
        $cls = 'live'
        $sv = ''
        foreach ($n in 'u_state', 'u_si_state') { if ($cells.Contains($n) -and $cells[$n]) { $sv = ([string]$cells[$n]).ToLowerInvariant(); break } }
        if ($sv -in 'closed', 'retired') { $cls = 'closed' }
    }
    $base = $cls
    if (-not $delivered) { $base = [string]$meta['__base']; if (-not $base) { $base = 'none' } }
    if ($script:SIDataOutContractClasses -notcontains $base) { $base = 'none' }
    [pscustomobject]@{ Present = $true; Delivered = [bool]$delivered; Base = $base; Cells = $cells; Class = $cls }
}

function ConvertTo-SIDataOutStateJson {
    <# PURE. The row as sent + its meta (__c the class after import, __base the class it was sent over, __a the action) as the state row's JSON. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Cells, [Parameter(Mandatory)][string]$Class, [string]$Base = 'none', [string]$Action = '')
    $h = [ordered]@{}
    foreach ($k in $Cells.Keys) { if (-not ([string]$k).StartsWith('__')) { $h[[string]$k] = [string]$Cells[$k] } }
    $h['__c'] = $Class; $h['__base'] = $Base; $h['__a'] = $Action
    ConvertTo-Json -InputObject $h -Compress
}

# =====================================================================================================================
#  THE SCOPE (#274), applied when sending -- the same rule the web app's preview counts with
# =====================================================================================================================

function ConvertTo-SIDataOutAssetKind {
    <# PURE. An item's class -> the asset kind of the CMDB asset scope (endpoint, identity, azure, publicip). #>
    param([string]$Class)
    switch (([string]$Class).Trim().ToLowerInvariant()) {
        'device' { 'endpoint' } 'identity' { 'identity' } 'cloud_resource' { 'azure' } 'public_ip' { 'publicip' } default { '' }
    }
}

function Test-SIDataOutInScope {
    <#
        PURE. Does one item pass its output's scope? -Scope: Get-SIOutputScope's result ($null = everything passes).
        A CI: Test-SIOutputScopeAsset (its tier, its kind from si_class). A finding: Test-SIOutputScopeFinding (severity,
        tier, security domain, the report, and the filters on its si_* fields). Blank values pass, as everywhere.
    #>
    param([Parameter(Mandatory)][ValidateSet('ci', 'ci_finding')][string]$Grain, $Item, $Scope)
    if ($null -eq $Scope) { return $true }
    if ($Grain -eq 'ci') {
        return (Test-SIOutputScopeAsset -Scope $Scope -Tier (Get-SIItemValue $Item 'si_tier') -Kind (ConvertTo-SIDataOutAssetKind ([string](Get-SIItemValue $Item 'si_class'))))
    }
    $fields = @{}
    foreach ($f in @($Scope.Filters)) { if ($f) { $fields[$f.Field] = Get-SIItemValue $Item $f.Field } }
    $reports = @(Get-SIOutputScopeNames (Get-SIItemValue $Item 'si_report_name'))
    Test-SIOutputScopeFinding -Scope $Scope -Severity ([string](Get-SIItemValue $Item 'si_severity')) -Tier (Get-SIItemValue $Item 'si_tier') `
        -Domain ([string](Get-SIItemValue $Item 'si_security_domain')) -Reports $reports -Fields $fields
}

# =====================================================================================================================
#  ONE ROW OF THE CONTRACT
# =====================================================================================================================

function Get-SIDataOutClearedList {
    <# PURE. The clear marker of one row: the clearable columns of -Output that are empty in -Cells, comma separated. #>
    param([Parameter(Mandatory)][string]$Output, [Parameter(Mandatory)][System.Collections.IDictionary]$Cells)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($c in (Get-SIDataOutClearableColumns -Output $Output)) {
        if (-not $Cells.Contains($c)) { continue }
        $v = $Cells[$c]
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { $out.Add($c) }
    }
    $out -join ','
}

function Set-SIDataOutEnvelope {
    <#
        PURE (into -Row). The envelope of one row: u_action, u_si_batch_id, u_si_reason, u_si_replaces and the clear marker
        (on every action but held -- a held row is not SecurityInsight's current record, so nothing is cleared). An
        out_of_scope row of a vulnerable item is closed as 'Out of scope', never as fixed. -Row: an ordered dictionary (the
        mapped row, column -> value). Returns the row.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Row, [Parameter(Mandatory)][string]$Output, [Parameter(Mandatory)][string]$Action,
          [string]$BatchId = '', [string]$Reason = '', [string]$Replaces = '')
    if ($script:SIDataOutContractActions -notcontains $Action) { throw ("'{0}' is not a u_action ({1})" -f $Action, ($script:SIDataOutContractActions -join ', ')) }
    if ($Action -eq 'out_of_scope' -and $Output -eq 'servicenow-vulnerable-item') {
        $Row['u_state'] = $script:SIDataOutOutOfScopeState
        $Row['u_close_reason'] = $script:SIDataOutOutOfScopeReason
        if (-not $Reason) { $Reason = 'the output scope leaves the finding out -- closed as out of scope, not as fixed' }
    }
    if ($Action -eq 'out_of_scope' -and -not $Reason) { $Reason = 'the output scope leaves the record out -- SecurityInsight sends no more rows for it while it is out of scope' }
    $Row['u_action'] = $Action
    $Row['u_si_batch_id'] = $BatchId
    $Row['u_si_reason'] = $Reason
    $Row['u_si_replaces'] = $Replaces
    $Row['u_si_cleared'] = $(if ($Action -eq 'held') { '' } else { Get-SIDataOutClearedList -Output $Output -Cells $Row })
    $Row
}

function Get-SIDataOutRowHashText {
    <# PURE. The u_row_hash of a row: SHA-256 over its content columns (the envelope, the hash and the run columns are not content). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Row, [AllowEmptyCollection()][string[]]$Exclude = @())
    $skip = @('u_row_hash', 'u_source_run', 'u_run_time', 'u_changed_at') + @($script:SIDataOutEnvelopeTokens.Values) + @($Exclude)
    $parts = foreach ($k in $Row.Keys) {
        if ($skip -contains [string]$k) { continue }
        $v = $Row[$k]
        '{0}={1}' -f $k, $(if ($null -eq $v) { '' } elseif ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { [string]$v })
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join '|')))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

# =====================================================================================================================
#  THE COUNTS PER ACTION (the staging status end row, cfg.DataOutBatch)
# =====================================================================================================================

function New-SIDataOutActionCounts {
    <# PURE. An empty count per action (ordered). #>
    $h = [ordered]@{}; foreach ($a in $script:SIDataOutContractActions) { $h[$a] = 0L }; $h
}

function Add-SIDataOutActionCount {
    <# PURE (into -Counts). One more row of -Action. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Counts, [Parameter(Mandatory)][string]$Action, [long]$By = 1)
    if (-not $Counts.Contains($Action)) { $Counts[$Action] = 0L }
    $Counts[$Action] = [long]$Counts[$Action] + $By
}

# =====================================================================================================================
#  THE REQUESTS: a full resync or a test batch (SI_DataOut_ServiceNowRequest = '<resync|test>:<token>')
# =====================================================================================================================

function ConvertFrom-SIDataOutRequest {
    <# PURE. The request setting -> @{ Kind (resync|test|''); Token; Problem }. Empty = no request. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = ([string]$Value).Trim()
    if (-not $v) { return [pscustomobject]@{ Kind = ''; Token = ''; Problem = '' } }
    $m = [regex]::Match($v, '^(?i)(resync|test):([A-Za-z0-9._-]{1,80})$')
    if (-not $m.Success) { return [pscustomobject]@{ Kind = ''; Token = ''; Problem = ("SI_DataOut_ServiceNowRequest '{0}' is not '<resync|test>:<token>' -- ignored" -f $v) } }
    [pscustomobject]@{ Kind = $m.Groups[1].Value.ToLowerInvariant(); Token = $m.Groups[2].Value; Problem = '' }
}

function Get-SIDataOutRequestDoneSql {
    <# Whether a request token was already carried out (a complete batch of the output that recorded it). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL SELECT CAST(0 AS int) AS Done;
ELSE SELECT CASE WHEN EXISTS (SELECT 1 FROM cfg.DataOutBatch WHERE OutputId = @OutputId AND RequestToken = @Token AND State IN (N'complete')) THEN 1 ELSE 0 END AS Done;
'@
}

# =====================================================================================================================
#  THE SECURITYINSIGHT-SIDE RUN RECORD OF EACH BATCH (cfg.DataOutBatch, sql/si-pro-settings.sql)
# =====================================================================================================================

function Get-SIDataOutBatchWriteSql {
    <# One batch record, upserted by its id (the same id the staging status table carries). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL RETURN;
MERGE cfg.DataOutBatch AS t
USING (SELECT @BatchId AS BatchId) AS s ON t.BatchId = s.BatchId
WHEN MATCHED THEN UPDATE SET State = @State, FinishedAt = CASE WHEN @State = N'writing' THEN NULL ELSE SYSUTCDATETIME() END,
     PlannedRows = @PlannedRows, SentRows = @SentRows, FailedRows = @FailedRows, NewRows = @NewRows, UpdateRows = @UpdateRows, CloseRows = @CloseRows,
     ReopenRows = @ReopenRows, HeldRows = @HeldRows, OutOfScopeRows = @OutOfScopeRows, ImportSetIds = NULLIF(@ImportSetIds, N''), Reason = LEFT(NULLIF(@Reason, N''), 1000)
WHEN NOT MATCHED THEN INSERT (BatchId, OutputId, Connector, RunId, State, Mode, ContractVersion, TargetTable, StartedAt, RequestToken)
     VALUES (@BatchId, @OutputId, NULLIF(@Connector, N''), @RunId, @State, @Mode, @ContractVersion, NULLIF(@TargetTable, N''), SYSUTCDATETIME(), NULLIF(@RequestToken, N''));
'@
}

function Get-SIDataOutOpenBatchSql {
    <# The batches of an output still 'writing' that are not this run's -- a batch that never ended (#914 c). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL SELECT CAST(NULL AS nvarchar(160)) AS BatchId, CAST(NULL AS nvarchar(64)) AS RunId, CAST(NULL AS datetime2(3)) AS StartedAt, CAST(NULL AS nvarchar(16)) AS Mode, CAST(NULL AS nvarchar(80)) AS TargetTable WHERE 1 = 0;
ELSE SELECT BatchId, RunId, StartedAt, Mode, TargetTable FROM cfg.DataOutBatch WHERE OutputId = @OutputId AND State = N'writing' AND BatchId <> @BatchId ORDER BY StartedAt;
'@
}

function Get-SIDataOutEndStaleBatchSql {
    <# Ends one stale writing batch as failed, with the reason. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL RETURN;
UPDATE cfg.DataOutBatch SET State = N'failed', FinishedAt = SYSUTCDATETIME(), Reason = LEFT(@Reason, 1000) WHERE BatchId = @BatchId AND State = N'writing';
'@
}

function Get-SIDataOutFeedbackDueSql {
    <# The newest complete live / resync batch of an output whose import result is not read yet (or was still pending), at most 3 days old. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL SELECT CAST(NULL AS nvarchar(160)) AS BatchId, CAST(NULL AS nvarchar(max)) AS ImportSetIds, CAST(NULL AS bigint) AS SentRows WHERE 1 = 0;
ELSE SELECT TOP (1) BatchId, ImportSetIds, SentRows FROM cfg.DataOutBatch
     WHERE OutputId = @OutputId AND State = N'complete' AND Mode IN (N'live', N'resync') AND BatchId <> @BatchId
       AND (FeedbackAt IS NULL OR ISNULL(ImportPending, 0) > 0) AND FinishedAt > DATEADD(day, -3, SYSUTCDATETIME())
     ORDER BY FinishedAt DESC;
'@
}

function Get-SIDataOutFeedbackWriteSql {
    <# The import result of one batch, as SecurityInsight read it back. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('cfg.DataOutBatch') IS NULL RETURN;
UPDATE cfg.DataOutBatch SET FeedbackAt = SYSUTCDATETIME(), ImportInserted = @Inserted, ImportUpdated = @Updated, ImportIgnored = @Ignored, ImportSkipped = @Skipped,
       ImportErrors = @Errors, ImportPending = @Pending, FeedbackNote = LEFT(NULLIF(@Note, N''), 400)
WHERE BatchId = @BatchId;
'@
}

function New-SIDataOutBatchParams {
    <# PURE. The parameters of Get-SIDataOutBatchWriteSql for one batch. #>
    param([Parameter(Mandatory)][string]$BatchId, [Parameter(Mandatory)][string]$OutputId, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)][ValidateSet('writing', 'complete', 'failed', 'held')][string]$State, [string]$Mode = 'live', [string]$Connector = '', [string]$TargetTable = '',
          [string]$RequestToken = '', $Counts, [long]$Planned = 0, [long]$Sent = 0, [long]$Failed = 0, [AllowEmptyCollection()][object[]]$ImportSets = @(), [string]$Reason = '')
    $c = $Counts; if ($null -eq $c) { $c = New-SIDataOutActionCounts }
    $g = { param($n) if ($c.Contains($n)) { [long]$c[$n] } else { 0L } }
    [ordered]@{
        BatchId = $BatchId; OutputId = $OutputId; RunId = $RunId; State = $State; Mode = $Mode; ContractVersion = $script:SIDataOutContractVersion
        Connector = $Connector; TargetTable = $TargetTable; RequestToken = $RequestToken
        PlannedRows = $Planned; SentRows = $Sent; FailedRows = $Failed
        NewRows = (& $g 'new'); UpdateRows = (& $g 'update'); CloseRows = (& $g 'close'); ReopenRows = (& $g 'reopen'); HeldRows = (& $g 'held'); OutOfScopeRows = (& $g 'out_of_scope')
        ImportSetIds = ((@($ImportSets) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique) -join ','); Reason = $Reason
    }
}

# =====================================================================================================================
#  RE-KEYING (#914 f): sidata.AssetIdHistory's rekey / merge rows -- the previous key of a CI that has a new one
# =====================================================================================================================

function Get-SIDataOutReplacesSql {
    <# For a page of CI keys (@keys, a JSON array): the previous key each replaces (rekey / merge), newest first. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.AssetIdHistory') IS NULL SELECT CAST(NULL AS nvarchar(400)) AS CurrentId, CAST(NULL AS nvarchar(400)) AS PreviousId WHERE 1 = 0;
ELSE SELECT h.CurrentId, h.PreviousId FROM sidata.AssetIdHistory AS h
     JOIN OPENJSON(@keys) WITH (k nvarchar(400) '$') AS p ON p.k = h.CurrentId
     WHERE h.EventType IN (N'rekey', N'merge') AND h.PreviousId <> h.CurrentId
     ORDER BY h.DetectedAt DESC;
'@
}

function ConvertTo-SIDataOutReplacesMap {
    <# PURE. Rows (CurrentId, PreviousId) -> current key -> previous key (the newest event per key wins). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $m = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $cur = [string](Get-SIItemValue $r 'CurrentId'); $prev = [string](Get-SIItemValue $r 'PreviousId')
        if ($cur -and $prev -and -not $m.ContainsKey($cur)) { $m[$cur] = $prev }
    }
    $m
}

# =====================================================================================================================
#  THE IMPORT RESULT READ BACK (#914 b): ServiceNow's own result for the rows of one batch
# =====================================================================================================================

function Get-SISnowImportFeedbackPath {
    <# PURE. The aggregate request for the import set rows of -ImportSets (sys_ids from insertMultiple, or ISET numbers). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ImportSets)
    $ids = @($ImportSets | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Select-Object -Unique)
    $sys = @($ids | Where-Object { $_ -match '^[0-9a-fA-F]{32}$' })
    $num = @($ids | Where-Object { $_ -notmatch '^[0-9a-fA-F]{32}$' })
    $q = New-Object System.Collections.Generic.List[string]
    if ($sys.Count) { $q.Add('sys_import_setIN' + ($sys -join ',')) }
    if ($num.Count) { $q.Add('sys_import_set.numberIN' + ($num -join ',')) }
    if ($q.Count -eq 0) { return '' }
    '/api/now/stats/sys_import_set_row?sysparm_count=true&sysparm_group_by=sys_import_state&sysparm_query={0}' -f [uri]::EscapeDataString(($q -join '^NQ'))
}

function ConvertFrom-SISnowImportStats {
    <#
        PURE. The aggregate answer -> @{ Inserted; Updated; Ignored; Skipped; Errors; Pending; Other; Total }. A state the
        contract does not name is counted in Other (and in Total).
    #>
    param($Content)
    $c = [ordered]@{ Inserted = 0L; Updated = 0L; Ignored = 0L; Skipped = 0L; Errors = 0L; Pending = 0L; Other = 0L; Total = 0L }
    $res = @(); if ($Content -and $Content.PSObject.Properties['result']) { $res = @($Content.result) }
    foreach ($g in $res) {
        if ($null -eq $g) { continue }
        $n = 0L
        if ($g.PSObject.Properties['stats'] -and $g.stats -and $g.stats.PSObject.Properties['count']) { [void][long]::TryParse([string]$g.stats.count, [ref]$n) }
        $state = ''
        if ($g.PSObject.Properties['groupby_fields']) { foreach ($f in @($g.groupby_fields)) { if ($f -and [string]$f.field -eq 'sys_import_state') { $state = ([string]$f.value).ToLowerInvariant() } } }
        switch ($state) {
            'inserted' { $c.Inserted += $n } 'updated' { $c.Updated += $n } 'ignored' { $c.Ignored += $n } 'skipped' { $c.Skipped += $n }
            'error' { $c.Errors += $n } 'pending' { $c.Pending += $n } default { $c.Other += $n }
        }
        $c.Total += $n
    }
    [pscustomobject]$c
}

function Read-SISnowImportFeedback {
    <#
        ONE read-back of a batch's import result (Invoke-SISnowRequest; never throws): @{ Ok; Counts; Note }. The error rows
        that the standard IRE pattern reports as handled ('Row transform ignored by onBefore script' / 'Target record not
        found', #912 live note 2026-10-06) are not errors: up to 50 error rows are read and those are moved to Ignored. Not
        readable (no right on sys_import_set_row) = Ok false, Note says so -- a warning, never a failure.
    #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ImportSets, [scriptblock]$Sleeper)
    $path = Get-SISnowImportFeedbackPath -ImportSets $ImportSets
    if (-not $path) { return [pscustomobject]@{ Ok = $false; Counts = $null; Note = 'the batch names no import set -- nothing to read back' } }
    try {
        $r = Invoke-SISnowRequest -Connection $Connection -Method GET -Path $path -Sleeper $Sleeper
        if (-not $r.Ok) {
            $why = if ([int]$r.Status -in 401, 403) { 'the integration user may not read sys_import_set_row (the import result) -- give it read access to see the import result per batch' } else { [string]$r.Error }
            return [pscustomobject]@{ Ok = $false; Counts = $null; Note = $why }
        }
        $counts = ConvertFrom-SISnowImportStats -Content $r.Content
        if ($counts.Errors -gt 0) {
            $ids = @($ImportSets | Where-Object { $_ -match '^[0-9a-fA-F]{32}$' })
            if ($ids.Count) {
                $q = '/api/now/table/sys_import_set_row?sysparm_limit=50&sysparm_fields=sys_import_state,sys_import_state_comment&sysparm_query={0}' -f [uri]::EscapeDataString(('sys_import_setIN{0}^sys_import_state=error' -f ($ids -join ',')))
                $er = Invoke-SISnowRequest -Connection $Connection -Method GET -Path $q -Sleeper $Sleeper
                if ($er.Ok -and $er.Content -and $er.Content.PSObject.Properties['result']) {
                    $handled = @(@($er.Content.result) | Where-Object { $_ -and ([string]$_.sys_import_state_comment -match 'Row transform ignored|^Target record not found') }).Count
                    if ($handled -gt 0) { $counts.Errors -= $handled; $counts.Ignored += $handled }
                }
            }
        }
        [pscustomobject]@{ Ok = $true; Counts = $counts; Note = '' }
    } catch { [pscustomobject]@{ Ok = $false; Counts = $null; Note = $_.Exception.Message } }
}

function ConvertTo-SIDataOutWireValue {
    <#
        PURE. ONE DATE FORMAT for every column of every row (#914 decision 9): a date and time -- a [datetime], or text in ISO
        8601 -- is sent as UTC 'yyyy-MM-dd HH:mm:ss' (the format ServiceNow's import reads into a glide_date_time, the same as
        the staging status rows). Every other value is returned as it is.
    #>
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string] -and $Value -match '^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:\d\d)?$') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
            return $d.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    $Value
}