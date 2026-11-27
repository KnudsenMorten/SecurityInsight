#Requires -Version 5.1
<#
    OPENAI-CAP (owner 2026-11-21, Invardia relay): THE CLASSIFY STAGE ASKS AI ONLY ABOUT WHAT CHANGED, IN BATCHES, WITH
    ONLY THE FIELDS THE ANSWER NEEDS.
    Before: one request per asset on every run, each with the whole instruction block and the asset's WHOLE Metadata
    (raw Defender device data, up to 60,000 characters) -- 500-700 requests per run at the internal install.
    Now:
      (a) ANSWER CACHE -- each answer is kept under a hash of the deciding fields (Get-SIClassifyAiItem) and the instruction
          text; an asset whose deciding fields did not change since the last answer is NOT asked again (status
          'ai-cached'). The cache is the install's storage (sistaging, ai-answers/<engine>/<writer>.json: one blob per
          writer, merged on read); entries not used for 30 days are dropped.
      (b) BATCHES -- up to 25 assets per request (Get-SIClassifyBatchSize), one instruction block per request.
      (c) ONLY THE DECIDING FIELDS -- AssetId, Hint, Sources, the posture-rule labels (at most 20), the cross-engine
          signals (XENG_* / EG_*) and the asset's short plain facts (at most 40, each at most 200 characters); never raw
          Metadata, never a nested blob.
      (d) The instruction text says exactly that (Get-SIClassifyBatchInstruction).
    Pure helpers + the cache store; Invoke-SIClassify (stages/Invoke-Classify.ps1) wires them.
#>

function Get-SIClassifyBatchSize { 25 }
function Get-SIClassifyAnswerMaxAgeDays { 30 }

function Test-SIClassifyPlainValue {
    <# PURE. A value the model may see: a number, a bool, or a short single-line text (at most 200 characters). #>
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return $true }
    if ($Value -is [string]) { $s = $Value.Trim(); return ($s.Length -gt 0 -and $s.Length -le 200 -and $s -notmatch '[\r\n]' -and $s -notmatch '^\s*[\[{]') }
    if ($Value -is [datetime]) { return $true }
    $false
}

function Get-SIClassifyPlainMap {
    <# PURE. The plain values of a hashtable / object (Test-SIClassifyPlainValue), key-sorted, at most -Max, keys matching -Skip left out. #>
    param($Source, [int]$Max = 40, [string]$Skip = '(?i)raw|json|properties|blob|payload|cert|secret|key$')
    $out = [ordered]@{}
    if ($null -eq $Source) { return $out }
    $pairs = if ($Source -is [System.Collections.IDictionary]) { @($Source.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Source[$_] } }) }
             else { @($Source.PSObject.Properties | Where-Object { $_.MemberType -in 'NoteProperty', 'Property' } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Value = $_.Value } }) }
    foreach ($p in @($pairs | Sort-Object Name)) {
        if ($out.Count -ge $Max) { break }
        if ($Skip -and $p.Name -match $Skip) { continue }
        if (-not (Test-SIClassifyPlainValue $p.Value)) { continue }
        $v = $p.Value
        if ($v -is [datetime]) { $v = $v.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
        elseif ($v -is [string]) { $v = $v.Trim() }
        $out[$p.Name] = $v
    }
    $out
}

function Get-SIClassifyAiItem {
    <#
        PURE. The ONE item an asset contributes to a batch -- and the input its answer is cached under: AssetId, Hint,
        Sources, PostureHits (labels, at most 20), Signals (XENG_* of the enrichment and the metadata, EG_* of the metadata;
        XENG_ActiveSignals as its 10 heaviest {Path, Weight}), Facts (the other plain metadata values, at most 40) and, for
        Azure, Posture (AZ_Posture's plain values, at most 30) and Tags (at most 15). Never raw Metadata.
    #>
    param([Parameter(Mandatory)]$Record, [string]$Engine = 'endpoint')
    $md = $Record.Metadata; $en = $Record.Enrichment
    $hits = @(@($Record.PostureHits) | Where-Object { $_ } | ForEach-Object {
        $l = if ($_ -is [string]) { $_ } elseif ($_.Label) { [string]$_.Label } elseif ($_.ProofLabel) { [string]$_.ProofLabel } else { '' }
        if ($l) { $l }
    } | Sort-Object -Unique | Select-Object -First 20)
    $sig = [ordered]@{}
    foreach ($src in @($en, $md)) {
        if ($null -eq $src) { continue }
        $m = Get-SIClassifyPlainMap -Source $src -Max 60 -Skip ''
        foreach ($k in $m.Keys) { if ($k -match '^(XENG|EG)_' -and -not $sig.Contains($k)) { $sig[$k] = $m[$k] } }
    }
    $act = $null
    foreach ($src in @($en, $md)) { if ($null -ne $src -and -not $act) { try { $act = $src.XENG_ActiveSignals } catch { } } }
    if ($act) {
        $sig['XENG_ActiveSignals'] = @(@($act) | Where-Object { $_ } | Sort-Object { try { -[double]$_.Weight } catch { 0 } } | Select-Object -First 10 | ForEach-Object { [ordered]@{ Path = [string]$_.Path; Weight = $_.Weight } })
    }
    $facts = Get-SIClassifyPlainMap -Source $md -Max 40
    foreach ($k in @($facts.Keys)) { if ($k -match '^(XENG|EG)_') { $facts.Remove($k) } }
    $item = [ordered]@{ AssetId = [string]$Record.AssetId }
    if ($Record.Hint) { $item.Hint = if (Test-SIClassifyPlainValue $Record.Hint) { $Record.Hint } else { [string]($Record.Hint | ConvertTo-Json -Compress -Depth 3) } }
    if ($Record.Sources) { $item.Sources = @(@($Record.Sources) | ForEach-Object { [string]$_ } | Sort-Object -Unique) }
    if ($hits.Count) { $item.PostureHits = $hits }
    if ($sig.Count) { $item.Signals = $sig }
    if ($facts.Count) { $item.Facts = $facts }
    if ($Engine -eq 'azure' -and $md) {
        $pos = $null; $tags = $null
        try { $pos = $md.AZ_Posture } catch { }
        try { $tags = $md.AZ_Tags } catch { }
        if ($pos) { $p = Get-SIClassifyPlainMap -Source $pos -Max 30 -Skip ''; if ($p.Count) { $item.Posture = $p } }
        if ($tags) { $t = Get-SIClassifyPlainMap -Source $tags -Max 15 -Skip ''; if ($t.Count) { $item.Tags = $t } }
    }
    $item
}

function Get-SIClassifyItemHash {
    <# PURE. The cache key: SHA-256 of the engine, the instruction text and the item (compact JSON, keys in a fixed order). #>
    param([Parameter(Mandatory)]$Item, [string]$Engine = 'endpoint', [string]$Instruction = '')
    $text = '{0}|{1}|{2}' -f $Engine, $Instruction, ($Item | ConvertTo-Json -Compress -Depth 6)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Get-SIClassifyBatchInstruction {
    <# PURE. The batch envelope appended to the engine's instruction: what the request holds and the one answer shape. #>
    @'

THIS REQUEST: the user message is {"Items":[...]} -- one entry per asset, at most 25. Each entry holds ONLY:
  AssetId      the asset's id (copy it into your answer unchanged)
  Hint         a short hint from discovery, when there is one
  Sources      which collections saw the asset
  PostureHits  the names of the posture rules that matched (at most 20)
  Signals      the cross-engine and Defender signals (XENG_*, EG_*), when present
  Facts        the asset's short plain facts (name, OS, type, group, resource group, ...)
  Posture/Tags (Azure only) the security-relevant settings and the tags, when present
There is no raw device or resource data; decide from these fields only. A field that is not there is unknown, not false.
ANSWER: ONE JSON object {"Results":[...]} with exactly one entry per item, each {"AssetId", "SI_Tier", "SI_ServiceType",
"SI_ServiceName", "SI_Group", "SI_Tier_Proofs"} as described above.
'@
}

function ConvertFrom-SIClassifyBatchAnswer {
    <# PURE. The batch answer's Results as AssetId -> verdict (an entry without an AssetId, or one not asked for, is dropped). #>
    param($Answer, [string[]]$AssetIds)
    $map = @{}
    $want = @{}; foreach ($a in @($AssetIds)) { $want[[string]$a] = $true }
    foreach ($r in @($Answer.Results)) {
        if ($null -eq $r) { continue }
        $id = [string]$r.AssetId
        if (-not $id -or -not $want.ContainsKey($id) -or $map.ContainsKey($id)) { continue }
        $map[$id] = $r
    }
    $map
}

function New-SIClassifyAnswerStore {
    <#
        The answer cache over the install's storage (-Account, container sistaging): Read -Engine = every writer's blob of
        the engine merged (hash -> @{ v = verdict; at = last used }); Write -Engine -Map = this writer's blob. Mock / no
        account = an in-process store (empty on each new process).
    #>
    param([string]$Account, [string]$Container = 'sistaging', [string]$Writer = '')
    if (-not $Writer) {
        $h = [Environment]::GetEnvironmentVariable('CONTAINER_APP_REPLICA_NAME'); if (-not $h) { $h = [Environment]::MachineName }
        $Writer = (('{0}-{1}' -f $h, $PID) -replace '[^A-Za-z0-9_-]', '_')
    }
    $st = @{ Account = $Account; Container = $Container; Writer = $Writer; Mem = @{} }
    if (-not $Account -or -not (Get-Command -Name Get-SIBlobList -ErrorAction SilentlyContinue)) {
        return @{
            Read  = { param($Engine) if ($st.Mem.ContainsKey($Engine)) { $st.Mem[$Engine] } else { @{} } }.GetNewClosure()
            Write = { param($Engine, $Map) $st.Mem[$Engine] = $Map }.GetNewClosure()
        }
    }
    # the blob functions CAPTURED here and called through & $fn: a .GetNewClosure() block cannot see a function that was
    # dot-sourced into a script scope (engine\_shared\SI-AzRest.ps1), only global ones
    $listFn = Get-Command -Name Get-SIBlobList -CommandType Function -ErrorAction SilentlyContinue
    $getFn = Get-Command -Name Get-SIBlobContent -CommandType Function -ErrorAction SilentlyContinue
    $setFn = Get-Command -Name Set-SIBlobContent -CommandType Function -ErrorAction SilentlyContinue
    @{
        Read = {
            param($Engine)
            $all = @{}
            if (-not $listFn -or -not $getFn) { throw 'the AI answer cache cannot be read in this job (Get-SIBlobList / Get-SIBlobContent not loaded from engine\_shared\SI-AzRest.ps1)' }
            foreach ($b in @(& $listFn -Account $st.Account -Container $st.Container -Prefix ("ai-answers/{0}/" -f $Engine))) {
                $bytes = & $getFn -Account $st.Account -Container $st.Container -Blob $b.Name -AllowMissing
                if ($null -eq $bytes) { continue }
                $o = [Text.Encoding]::UTF8.GetString([byte[]]$bytes) | ConvertFrom-Json -AsHashtable
                foreach ($k in @($o.Keys)) {
                    $e = $o[$k]
                    if (-not $all.ContainsKey($k) -or [string]$e.at -gt [string]$all[$k].at) { $all[$k] = $e }
                }
            }
            $all
        }.GetNewClosure()
        Write = {
            param($Engine, $Map)
            $json = $Map | ConvertTo-Json -Compress -Depth 10
            if (-not $setFn) { throw 'the AI answer cache cannot be written in this job (Set-SIBlobContent not loaded from engine\_shared\SI-AzRest.ps1)' }
            $null = & $setFn -Account $st.Account -Container $st.Container -Blob ("ai-answers/{0}/{1}.json" -f $Engine, $st.Writer) -Bytes ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json'
        }.GetNewClosure()
    }
}

function Select-SIClassifyAnswersToKeep {
    <# PURE. The cache entries to write back: the ones used or made in this run, plus the others used in the last -MaxAgeDays. #>
    param([hashtable]$Read = @{}, [hashtable]$Used = @{}, [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxAgeDays = (Get-SIClassifyAnswerMaxAgeDays))
    $keep = @{}
    $cut = $NowUtc.AddDays(-$MaxAgeDays).ToString('o')
    foreach ($k in @($Read.Keys)) { if ([string]$Read[$k].at -ge $cut) { $keep[$k] = $Read[$k] } }
    foreach ($k in @($Used.Keys)) { $keep[$k] = $Used[$k] }
    $keep
}
