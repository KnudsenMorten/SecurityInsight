#Requires -Version 5.1
<#
    SecurityInsight -- THE CI KEY (#406 / #409, REQUIREMENTS 9.3.2 decision 5: "one CI key = the ledger's
    SI_CorrelationId, with SI_AssetId as a mapped identifier"; #468 / V3-DATA-MODEL §2.3 (4): ONE rule, no provisional key).

    ONE rule, used by EVERYTHING that keys a CI -- the ServiceNow / SQL CMDB hand-off, the vulnerability rows, the asset
    lifecycle AND the Pro data sync (sidata.Asset, Get-SIDataAssetKey calls Resolve-SICiKey) -- so the rows of one asset
    carry ONE key whatever channel or table carries them:
      * the CI rows (snowstage.HandoffCi / BatchCi, the Import Set CI push)            -> Build-SIHandoffRows
      * the vulnerability rows (vuln.VulnerabilityItem.CorrelationId, the vuln push)   -> the close-loop
      * the Pro database's CI key (sidata.Asset.AssetKey / KeySource)                  -> Get-SIDataAssetKey
    THE RULE: the identity ledger's SI_CorrelationId when the correlation map marks it 'ledger' (minted once, stored,
    durable), else the asset's own SI_AssetId. IdSource says which: ledger | asset.
    🔴 A PROVISIONAL id (SI_IdSource = derived-provisional: the ledger was not configured or not reachable) is NEVER a key.
    It is derived from the correlation group and MOVES when the group's membership changes -- a moving key duplicates CIs
    in ServiceNow. Until 2026-10-10 the hand-off accepted it while the data sync did not: two CI-key rules (#468). The
    asset's own id does not move; the v3 CI build (engine/data-model) builds no CI at all without a ledger (§2.3 (4):
    an unreachable ledger stops P2 instead of publishing moving keys).

    Before 2026-10-06 the vulnerability rows carried SI_AssetId and the CI rows the ledger key under the same column
    u_si_correlation_id: the vulnerability view's join to the CI hand-off never matched, the class hint fell back to
    the key's shape and ServiceNow could not resolve the CI from the vulnerability row (#409 mismatch a).

    PURE. PS 5.1 safe. No Set-StrictMode (it leaks into the caller's scope).
#>

function Resolve-SICiKey {
    <#
        PURE. THE rule, for one asset: -AssetId, the correlation map's -CorrelationId and -IdSource for it ->
        @{ Key; IdSource = ledger | asset }. Only an id the map marks 'ledger' is a key; anything else (derived-provisional,
        empty, unknown) keys the asset by its own id. An empty -AssetId with no ledger id answers Key ''.
    #>
    param([AllowNull()][AllowEmptyString()][string]$AssetId, [AllowNull()][AllowEmptyString()][string]$CorrelationId, [AllowNull()][AllowEmptyString()][string]$IdSource)
    $a = ([string]$AssetId).Trim()
    $c = ([string]$CorrelationId).Trim()
    $s = ([string]$IdSource).Trim().ToLowerInvariant()
    if ($c -and $s -eq 'ledger') { return [pscustomobject]@{ Key = $c; IdSource = 'ledger' } }
    # a row that carries a key with NO source marker and no asset id (a hand-built row, an old export) keeps the key it
    # names; a key marked provisional never does
    if (-not $a -and $c -and -not $s) { return [pscustomobject]@{ Key = $c; IdSource = 'asset' } }
    [pscustomobject]@{ Key = $a; IdSource = 'asset' }
}

function ConvertTo-SICiKeyMap {
    <#
        PURE. Correlation-map rows (SI_AssetId, SI_CorrelationId, SI_IdSource -- Get-SIV3ObjectMapKql) -> a case-insensitive
        hashtable lower(SI_AssetId) -> @{ Key; IdSource = ledger }. Only LEDGER ids enter the map (Resolve-SICiKey): a row
        without one maps nothing and the asset keeps its own id. -Map: an already-built @{ SI_AssetId = @{ SI_CorrelationId;
        SI_IdSource } } (Build-SIHandoffRows' shape) is accepted as well.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Map = $null)
    $out = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    $val = { param($r, [string]$n) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$n] } elseif ($r.PSObject.Properties[$n]) { [string]$r.$n } else { '' } }
    $add = {
        param([string]$aid, $entry)
        $a = ([string]$aid).Trim(); if (-not $a) { return }
        $k = Resolve-SICiKey -AssetId $a -CorrelationId (& $val $entry 'SI_CorrelationId') -IdSource (& $val $entry 'SI_IdSource')
        if ($k.IdSource -ne 'ledger') { return }
        $out[$a] = $k
    }
    if ($null -ne $Map) { foreach ($aid in @($Map.Keys)) { & $add ([string]$aid) $Map[$aid] } }
    foreach ($r in @($Rows)) { if ($null -ne $r) { & $add (& $val $r 'SI_AssetId') $r } }
    $out
}

function Get-SICiKey {
    <#
        PURE. The CI key of one asset: @{ Key; IdSource } -- the ledger id (ledger), else the asset id itself (asset).
        -KeyMap from ConvertTo-SICiKeyMap. An empty -AssetId answers Key ''.
    #>
    param([AllowEmptyString()][string]$AssetId, [hashtable]$KeyMap)
    $a = ([string]$AssetId).Trim()
    if (-not $a) { return [pscustomobject]@{ Key = ''; IdSource = 'asset' } }
    if ($null -ne $KeyMap -and $KeyMap.ContainsKey($a)) { $e = $KeyMap[$a]; return (Resolve-SICiKey -AssetId $a -CorrelationId ([string]$e.Key) -IdSource ([string]$e.IdSource)) }
    [pscustomobject]@{ Key = $a; IdSource = 'asset' }
}
