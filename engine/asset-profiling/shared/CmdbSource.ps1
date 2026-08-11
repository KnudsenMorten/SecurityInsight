#Requires -Version 5.1
<#
.SYNOPSIS
    AUDIT #58.1/#58.2/#58.3 -- CMDB source precedence: exactly one active, richest wins, fails loud.

.DESCRIPTION
    Operator (2026-08-11): "keep a separate cmdb as part of the solution, if servicenow connector is
    enabled. then it wins over any generic cmdb.csv file. only one cmdb can be active. if no servicenow
    (or any future cmdb's) are active, then it must lookup in the generic cmdb.csv" -- plus "with
    fail-loud".

    Resolution is FIRST MATCH WINS over a declared, ordered catalog:

      1. servicenow    (Pro)   live CIs, business services, relationships
      2. (future rich CMDBs -- each gets an explicit declared order here)
      3. generic-csv   (Free)  asset-profiling-providers/generic-cmdb/CMDB.csv
      4. none                  cmdb* columns stay empty

.NOTES
    🔑 EXACTLY ONE ACTIVE -- SOURCES ARE NEVER MERGED. With two sources both able to populate
    cmdbName / cmdbCriticality / cmdbDataSensitivity, "why does this asset say Critical?" becomes
    unanswerable. That is #54's defect class -- the value is right and nobody can explain it -- and
    #54 cost this project real time.

    🔴 FAIL LOUD (#58.2). A SELECTED source that fails does NOT silently drop to the next one. Silent
    substitution hands the customer PLAUSIBLE BUT STALE data on a green run: an asset labelled
    'Standard' from a CSV last touched a year ago while the live CMDB says 'Critical'.
    WRONG-BUT-PLAUSIBLE IS WORSE THAN EMPTY, because empty is visible and wrong is not. This is
    exactly how #57 hid -- a valid query, a successful run, and data that quietly stopped reflecting
    reality.

    🔑 THE WINNER IS STAMPED INTO THE DATA (#58.3), not only into the log, as `CmdbSource`. "Where did
    this CMDB value come from?" must be answerable from the export, on a machine the analyst has.
    Same principle as #54 (SI_RuleMatches) and #53 (RiskFactor_*_Detailed): an answer you cannot
    explain is an answer nobody trusts.

    📌 SCOPE AS BUILT. Only `generic-csv` can be ACTIVE today. The ServiceNow slot is declared but
    permanently inactive: the rich ServiceNow CMDB is a Pro feature that DOES NOT EXIST, and
    connector-platform work is on operator hold (2026-08-08). The catalog is written with it present
    so the ordering is a data question when it does arrive, not a code change -- and so a
    misconfiguration that claims ServiceNow is available is REFUSED rather than half-honoured.

    PowerShell 5.1: hashtables only, no ternary, no null-conditional.
#>

# The declared catalog. Order IS the precedence -- lower Order wins.
# Keep this a pure data structure: resolution must be testable without a tenant.
function Get-SICmdbSourceCatalog {
    [CmdletBinding()]
    param()
    return @(
        @{ Id = 'servicenow';  Order = 1; Edition = 'Pro';  Implemented = $false
           Description = 'Live ServiceNow CMDB (CIs, business services, relationships)' },
        @{ Id = 'generic-csv'; Order = 3; Edition = 'Free'; Implemented = $true
           Description = 'Generic CMDB CSV maintained by the customer (any origin)' }
    )
}

function Resolve-SICmdbSource {
    <#
      PURE + SIDE-EFFECT FREE so precedence can be proven without a tenant, a CSV or a connector.

      -Available : hashtable of sourceId -> [bool], "this source is configured AND usable".
                   Caller decides availability (CSV present on disk, connector enabled+licensed, ...).

      Returns @{
        Source      = 'servicenow' | 'generic-csv' | 'none'
        Reason      = human-readable, goes straight into the run log
        Considered  = @(ids that were offered)
        Shadowed    = @(ids that were available but LOST to a higher-precedence source)
        Fatal       = $true when the configuration itself is refused (see below)
      }

      🔴 Fatal is returned, never thrown, so the CALLER decides how loud to be. A resolver that throws
      cannot be used by a test that wants to assert the refusal message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$Available,
        [Parameter()][array]$Catalog
    )

    if (-not $Catalog) { $Catalog = Get-SICmdbSourceCatalog }
    $ordered = @($Catalog | Sort-Object { [int]$_.Order })

    $considered = New-Object System.Collections.Generic.List[string]
    $live       = New-Object System.Collections.Generic.List[object]

    foreach ($src in $ordered) {
        $id = [string]$src.Id
        [void]$considered.Add($id)
        if (-not $Available.ContainsKey($id)) { continue }
        if (-not [bool]$Available[$id]) { continue }

        # 🔴 A source that is declared but NOT IMPLEMENTED must never be selected. Claiming it is
        # available is a configuration error, and honouring it would leave cmdb* silently empty while
        # the log said a rich CMDB had won -- the worst of both failure modes.
        if (-not [bool]$src.Implemented) {
            return @{
                Source     = 'none'
                Reason     = ("CMDB source '{0}' is declared available but is NOT IMPLEMENTED in this edition. Refusing to select it, and refusing to fall through to a lower-precedence source, because falling through would silently substitute different data for the one that was asked for (#58.2). Disable it or install the connector." -f $id)
                Considered = @($considered.ToArray())
                Shadowed   = @()
                Fatal      = $true
            }
        }
        [void]$live.Add($src)
    }

    if ($live.Count -eq 0) {
        return @{
            Source     = 'none'
            Reason     = 'no CMDB source is configured -- cmdb* columns stay empty'
            Considered = @($considered.ToArray())
            Shadowed   = @()
            Fatal      = $false
        }
    }

    $winner   = $live[0]
    $shadowed = @()
    if ($live.Count -gt 1) {
        $shadowed = @($live[1..($live.Count - 1)] | ForEach-Object { [string]$_.Id })
    }

    $reason = ("CMDB source '{0}' selected ({1}, {2})" -f $winner.Id, $winner.Edition, $winner.Description)
    if ($shadowed.Count -gt 0) {
        # NOT an error -- this is the designed outcome of "richest wins". It is reported because a
        # customer who maintains a CSV and then enables a live CMDB must be told their CSV stopped
        # being read, rather than discovering it from changed risk scores.
        $reason += ("; NOT merged with lower-precedence source(s): {0} -- exactly one CMDB is ever active" -f ($shadowed -join ', '))
    }

    return @{
        Source     = [string]$winner.Id
        Reason     = $reason
        Considered = @($considered.ToArray())
        Shadowed   = $shadowed
        Fatal      = $false
    }
}

function Get-SICmdbSourceAvailability {
    <#
      Turn the runtime configuration into the -Available map Resolve-SICmdbSource expects.
      Separated from resolution so the precedence rules stay testable without touching disk.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$SolutionRoot,
        [Parameter()][AllowNull()][object]$EnableCmdbProvider,
        [Parameter()][AllowNull()][object]$EnableServiceNowCmdb
    )

    $avail = @{}

    # generic-csv: enabled by the existing provider flag AND an actual CSV on disk. Requiring the
    # file means "enabled but the CSV was never delivered" resolves to none-with-a-reason instead of
    # selecting a source that cannot answer.
    $csvOk = $false
    if ([bool]$EnableCmdbProvider -and -not [string]::IsNullOrWhiteSpace($SolutionRoot)) {
        foreach ($rel in @('asset-profiling-providers\generic-cmdb\CMDB.csv',
                           'asset-profiling-providers\servicenow-cmdb\CMDB.csv')) {   # pre-v2.2.421 location
            if (Test-Path -LiteralPath (Join-Path $SolutionRoot $rel)) { $csvOk = $true; break }
        }
    }
    $avail['generic-csv'] = $csvOk
    $avail['servicenow']  = [bool]$EnableServiceNowCmdb

    return $avail
}
