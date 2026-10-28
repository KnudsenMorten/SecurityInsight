#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  KQL fragment builders: device keys, asset-name safety, and the bucket / sub-bucket filters.
#
#  The small KQL generators the bucketing machinery composes: the hash%(T) bucket filter and the
#  hash%(T*K) sub-bucket filter that the adaptive cascade uses, plus the device-key and
#  asset-name-safety helpers they lean on.
#
#  New-BucketFilterKql and New-SubBucketFilterKql are covered by
#  tests/pester/SI-RiskAnalysis-QueryBuild.Tests.ps1, which resolves function names across the
#  engine folder (audit #16), so moving them needs no test change.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function New-DeviceKeyKql {
@"
| extend DeviceKey = coalesce(
    tostring(column_ifexists('AadDeviceId','')),
    tostring(column_ifexists('DeviceId','')),
    tostring(column_ifexists('MachineId','')),
    tostring(column_ifexists('SI_AssetName','')),
    tostring(column_ifexists('AssetName','')),
    tostring(column_ifexists('DeviceName','')),
    tostring(column_ifexists('Computer','')),
    tostring(column_ifexists('DnsName','')),
    tostring(column_ifexists('HostName','')),
    tostring(column_ifexists('FQDN','')),
    tostring(column_ifexists('Id','')),
    'unknown'
)
"@
}

function Ensure-QueryIsAssetNameSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Query
    )

    $safeDeviceKeyBlock = (New-DeviceKeyKql).TrimEnd()

    # Replace only DeviceKey assignments that reference AssetName (the common failure)
    # Example (your YAML):
    # | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, AssetName)
    $Query = $Query -replace '(?im)^\s*\|\s*extend\s+DeviceKey\s*=\s*iif\s*\(\s*isnotempty\s*\(\s*AadDeviceId\s*\)\s*,\s*AadDeviceId\s*,\s*AssetName\s*\)\s*$', $safeDeviceKeyBlock

    # Also cover minor formatting variations where AssetName is used on the DeviceKey line
    $Query = $Query -replace '(?im)^\s*\|\s*extend\s+DeviceKey\s*=.*\bAssetName\b.*$', $safeDeviceKeyBlock

    return $Query
}

function New-BucketFilterKql {
  param(
    [int]$BucketCount,
    [int]$BucketIndex,
    [string]$ReportName = ''
  )

  # v2.2.331 -- device-only bucket key for ALL reports (Summary AND Detailed).
  # Previously the *_Detailed branch used a composite `DeviceKey|FindingKey` to
  # split hot-device cartesian. But that key DOESN'T ALIGN with the CL-side
  # bucket key (CL has device-only EpJoinKey -- there's no finding info on the
  # CL row), so CL-bucketing was disabled for Detailed reports entirely
  # (Resolve-ProfileCLLetBlocks fell back to full-inline per bucket -> 413).
  # Device-only on both sides aligns by string equality, so CL-bucketing works
  # for Detailed too. Accepted trade-off: a 1M-asset tenant with ONE hot device
  # carrying 10K findings will get 10K rows in that device's bucket. At N=256
  # buckets that single bucket may approach AH's response cap, but the engine
  # already handles bucket-timeout via sub-bucketing (v2.2.277) so the worst
  # case stays bounded. Multi-tenant runs validated v2.2.328 distribution as
  # uniform once the CL-side bucket key matched EG's.
  #
  # v2.2.404 -- cross-domain EG-aligned re-key. When the active report declares
  # crossDomainBucketCoalesce with an EgNativeKey (e.g. NodeId), the EG-side bucket
  # filter MUST hash on that SAME EG-native column so its partition is identical to
  # the CL side (whose bucket key value equals the EG NodeId hex). The default
  # coalesce above leads with DeviceKey (= AssetName for these Attack_Paths reports),
  # which would hash a DIFFERENT value than the CL key -> misaligned buckets ->
  # lossy joins. Promoting the declared EG-native key(s) to the FRONT of the
  # coalesce makes the EG partition bound EG work on the join key itself (genuine
  # partition, not a cap) AND keep every per-bucket join match (lossless).
  $egNativeKeys = New-Object System.Collections.Generic.List[string]
  foreach ($_cdc in @($script:_CrossDomainBucketCoalesce)) {
      # AUDIT #56.3 -- @($null) yields a one-element array holding $null, and on PS 5.1
      # $null.PSObject.Properties[...] throws "Cannot index into a null array". The engine always
      # sets this to @() per report (Invoke-RiskAnalysis.ps1 ~:2141) so it never bites at run time,
      # but it made the function impossible to unit-test and would bite if load order ever changed.
      # Skipping nulls costs nothing and makes the partition property testable in isolation.
      if ($null -eq $_cdc) { continue }
      $_k = if ($_cdc -is [System.Collections.IDictionary]) { [string]$_cdc['EgNativeKey'] }
            elseif ($_cdc.PSObject.Properties['EgNativeKey']) { [string]$_cdc.EgNativeKey }
            else { '' }
      if (-not [string]::IsNullOrWhiteSpace($_k) -and -not $egNativeKeys.Contains($_k)) {
          [void]$egNativeKeys.Add($_k)
      }
  }
  $defaultKeyCols = @('DeviceKey','NodeId','DeviceNodeId','AadDeviceId','DeviceId','MachineId','Id','SourceNodeId','TargetNodeId')
  if ($egNativeKeys.Count -gt 0) {
      # EG-native declared keys first, then the standard fallbacks (de-duped).
      $ordered = New-Object System.Collections.Generic.List[string]
      foreach ($k in $egNativeKeys) { if (-not $ordered.Contains($k)) { [void]$ordered.Add($k) } }
      foreach ($k in $defaultKeyCols) { if (-not $ordered.Contains($k)) { [void]$ordered.Add($k) } }
      $keyCols = $ordered.ToArray()
  } else {
      $keyCols = $defaultKeyCols
  }
  $coalesceLines = ($keyCols | ForEach-Object { "    tostring(column_ifexists('$_',''))" }) -join ",`n"
@"
| extend __bucket_key = coalesce(
$coalesceLines
)
| where isnotempty(__bucket_key)
| extend __bucket = tolong(strcat("0x", substring(hash_sha256(__bucket_key), 0, 8))) % $BucketCount
| where __bucket == $BucketIndex
"@
}

function New-SubBucketFilterKql {
  # v2.2.277 -- emits a KQL filter for sub-bucket j of K within parent bucket N
  # at parent total T. Produces the same hash-modulo filter as New-BucketFilterKql
  # but at modulus T*K with index N + j*T. Math: a row in parent bucket N
  # satisfies hash%T == N, i.e. hash = T*q + N for some q. Then hash%(T*K) =
  # N + T*(q % K), so the K possible values are {N, N+T, N+2T, ..., N+(K-1)T}.
  # Picking sub-index j selects exactly 1/K of the parent-N rows. Lossless;
  # K sub-buckets together = the original parent bucket.
  param(
    [int]$ParentBucketCount,
    [int]$ParentBucketIndex,
    [int]$SubBucketCount,
    [int]$SubBucketIndex,
    [string]$ReportName = ''
  )
  $newCount = $ParentBucketCount * $SubBucketCount
  $newIndex = $ParentBucketIndex + ($SubBucketIndex * $ParentBucketCount)
  return (New-BucketFilterKql -BucketCount $newCount -BucketIndex $newIndex -ReportName $ReportName)
}

# THE SECOND KEY: the row itself. A slice is split by its bucket key (above) -- every row of ONE key value (one device, one
# identity) stays in the same slice however finely the key is split. When that one key value alone carries more rows than
# the worker can hold (a device with tens of thousands of findings at a large estate), the slice is split further by the
# hash of each answered ROW: the same hash-modulo math as the key split, on the whole row (pack_all), applied to the rows
# the query answers. Lossless: the RowCount parts together are exactly the slice's rows (a row lands in exactly one part).
# The 32-bit hash is the limit of both splits: a modulus is never above it.
$script:RASplitModulusLimit = [long]4294967296

function New-RowSplitFilterKql {
  <# PURE. The row filter of part -RowIndex of -RowCount (the hash of the whole answered row, modulo). #>
  param([long]$RowCount, [long]$RowIndex)
@"
| where (tolong(strcat("0x", substring(hash_sha256(tostring(pack_all())), 0, 8))) % $RowCount) == $RowIndex
"@
}

function Add-RARowSplitFilter {
  <# PURE. -Query (one slice's query) with the row filter of part -RowIndex of -RowCount after its last line; unchanged when
     -RowCount is 1 or less (no row split). A trailing ';' is dropped first so the filter applies to the query's answer. #>
  param([Parameter(Mandatory)][string]$Query, [long]$RowCount = 1, [long]$RowIndex = 0)
  if ($RowCount -le 1) { return $Query }
  $q = $Query.TrimEnd().TrimEnd(';').TrimEnd()
  return ($q + "`n" + (New-RowSplitFilterKql -RowCount $RowCount -RowIndex $RowIndex).TrimEnd())
}

function Get-RAMemorySplitNext {
  <#
    PURE. How a slice that did not fit in the worker's memory is split next -- recursively, until it fits; no depth cap,
    because a memory split always makes the next answer smaller:
      * by its bucket key (Kind 'key', modulus x -FanOut) while that can still split it, i.e. unless -SingleKey says its
        rows sat in ONE child of the last key split (the others empty: one key value carries them) or the key modulus
        would pass the hash's range;
      * then by the row (Kind 'row', the row modulus x -FanOut), down to one row per part;
      * Kind 'none' when even the row split is at the hash's range: the slice cannot be made smaller (its rows unknown).
    -KeyCount / -RowCount: the slice's current key modulus and row modulus (1 = no row split yet).
  #>
  param([long]$KeyCount, [long]$RowCount = 1, [int]$FanOut = 4, [switch]$SingleKey)
  if ($FanOut -lt 2) { $FanOut = 2 }
  $lim = [long]$script:RASplitModulusLimit; if ($lim -le 0) { $lim = [long]4294967296 }
  $keyMax = [long][Math]::Min($lim, [long][int]::MaxValue)
  if ($RowCount -le 1 -and -not $SingleKey -and ($KeyCount * $FanOut) -le $keyMax) { return [pscustomobject]@{ Kind = 'key'; KeyCount = ($KeyCount * $FanOut); RowCount = 1L } }
  $rc = [long][Math]::Max([long]1, [long]$RowCount)
  if (($rc * $FanOut) -le $lim) { return [pscustomobject]@{ Kind = 'row'; KeyCount = $KeyCount; RowCount = ($rc * $FanOut) } }
  [pscustomobject]@{ Kind = 'none'; KeyCount = $KeyCount; RowCount = $rc }
}
