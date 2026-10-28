#Requires -Version 5.1
<#
    SI #61.4 -- correlation-decisions.custom.yaml. THE OPERATOR'S ASSERTIONS ABOUT IDENTITY.

    WHAT THIS IS FOR. V3-ARCHITECTURE 2.3a's decision table ends with a row that has had no
    implementation:

        | an identifier moves to a different object | split/reassign -- report it, never apply silently |

    and 2.3a explains why it is deliberately not automatic: one run cannot distinguish "this object
    split" from "a source failed and half its anchors are missing", and guessing wrong RETIRES A LIVE
    CI, which is worse than a late one. The same reasoning covers the endpoint profiler's
    "N merge(s) refused on conflicting AadDeviceIds" -- correctly refused, and until now with no
    resolution path at all.

    An operator assertion is the right answer to something that cannot be inferred. This file is that
    assertion, and nothing here guesses: every kind states a fact the engine then applies.

        never-merge   these anchors are NOT one object, however they appear to join
        force-merge   these anchors ARE one object, even though nothing joins them
        pin-id        this object's SI_CorrelationId is fixed

    NO `expires`, AND THAT IS A DECISION, NOT AN OVERSIGHT. 61.1 splits operator input three ways and
    ties expiry to the meaning: an OVERRIDE is "the computed answer is WRONG -- use this instead", a
    correction rather than a deviation, and it carries no expiry; only exception and exemption, which
    say "the answer is RIGHT but treat this asset differently", must expire. All three kinds here are
    corrections of fact -- two machines are two machines whether or not a year has passed. An entry
    carrying `expires` is therefore REJECTED with that reason rather than ignored, because an operator
    who wrote an expiry and saw no complaint would believe a review date exists that does not.

    PROVENANCE IS MANDATORY (`by`, `at`) -- 61.5 rule 4. Without it an assertion that two machines are
    one is indistinguishable from the corrupt upstream record it was written to overrule.

    NOT IN asset-profiling-enrichment\. That tree is the DETECTION RULE tree and Get-SIRuleSet
    allow-lists `*.custom.yaml` throughout it, so a decisions file dropped there is picked up and
    parsed as a broken rule. Same trap, same home as asset-decisions: config\ and the overlay ROOT.

    SELF-CONTAINED. The correlation tree deliberately carries no dependency on asset-profiling -- see
    SI-CorrelationIngest.ps1's header on why the auth block is duplicated rather than shared. The date
    rule that would have been the one thing worth sharing is absent here by the decision above, so
    nothing is duplicated to achieve it.
#>

$script:SICorrelationDecisionFileName = 'correlation-decisions.custom.yaml'
$script:SICorrelationDecisionKinds    = @('never-merge', 'force-merge', 'pin-id')

function Get-SICorrelationDecisionSource {
    <#
        WHICH files should be read, and in what order. PURE -- every root is a parameter, so the
        precedence rule is provable without a tenant or an installed tree. Returns one row per
        candidate INCLUDING ones that do not exist, because "you configured this and it is not there"
        is the single most useful thing this function can say -- and it says it (Configured) only for
        the explicit file.

          explicit   -Path / $global:SI_CorrelationDecisionsPath   -- names a file outright
          overlay    <SI_EnrichmentDataRoot>\                      -- operator data outside the tree
          tree       <siRoot>\config\                              -- the in-place location

        The overlay path is the overlay ROOT, not <root>\shared\: Get-SIRuleSet scans <root>\<engine>\
        and <root>\shared\ recursively and nothing else, so the root is the one place under an overlay
        where a non-rule YAML is safe.

        EXPLICIT IS EXCLUSIVE; OVERLAY AND TREE ARE ADDITIVE. Someone who names a file means THAT file.

        [IO.Path]::Combine, NOT Join-Path: on PS 5.1 Join-Path RESOLVES the drive and throws
        DriveNotFoundException, so an overlay root on a mapped drive the scheduled task's account
        cannot see would kill the run from inside the function whose job is to report what is missing.
    #>
    param(
        [Parameter()][AllowEmptyString()][string]$ExplicitPath,
        [Parameter()][AllowEmptyString()][string]$OverlayRoot,
        [Parameter()][AllowEmptyString()][string]$SolutionRoot,
        [Parameter()][string]$FileName = $script:SICorrelationDecisionFileName
    )

    $out = New-Object System.Collections.Generic.List[object]

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        [void]$out.Add([pscustomobject]@{
            Path = $ExplicitPath; Source = 'explicit'; Configured = $true
            Exists = (Test-Path -LiteralPath $ExplicitPath)
        })
        return $out.ToArray()
    }

    if (-not [string]::IsNullOrWhiteSpace($OverlayRoot)) {
        $p = [System.IO.Path]::Combine($OverlayRoot, $FileName)
        # Configured=$false, like the in-tree path: the overlay ROOT is what someone named, not this FILE.
        # A root that holds no decisions file is the normal case (a SecurityInsight Pro run points the root
        # at its own run folder and writes the file there only when the database holds a decision), so only
        # a file a person named outright (-Path / SI_CorrelationDecisionsPath) is reported when it is missing.
        [void]$out.Add([pscustomobject]@{
            Path = $p; Source = 'overlay'; Configured = $false; Exists = (Test-Path -LiteralPath $p)
        })
    }

    if (-not [string]::IsNullOrWhiteSpace($SolutionRoot)) {
        $p = [System.IO.Path]::Combine($SolutionRoot, 'config', $FileName)
        # Configured=$false: the in-tree path is always CHECKED and never CONFIGURED, so its absence is
        # the normal case for the overwhelming majority of installs and must stay silent. Only a path
        # someone deliberately named earns a warning when it is missing.
        [void]$out.Add([pscustomobject]@{
            Path = $p; Source = 'tree'; Configured = $false; Exists = (Test-Path -LiteralPath $p)
        })
    }

    $out.ToArray()
}

function ConvertTo-SICorrelationAnchorKey {
    <#
        "AadDeviceId:1234-..." -> "aaddeviceid|1234-...", the same normalisation the ledger uses, so an
        operator writing an anchor by hand and the engine reading one from a row cannot disagree about
        spelling or case.

        SPLIT ON THE FIRST COLON ONLY. An ARM path is a legitimate identifier value and is full of
        colons and slashes; splitting on all of them would silently truncate every azure anchor to
        "/subscriptions" and quietly match the wrong object -- or nothing at all.

        Returns $null for anything unparseable. Callers REPORT that; they do not skip it silently.
    #>
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Anchor)

    if ([string]::IsNullOrWhiteSpace($Anchor)) { return $null }
    $i = $Anchor.IndexOf(':')
    if ($i -lt 1 -or $i -ge ($Anchor.Length - 1)) { return $null }
    $type  = $Anchor.Substring(0, $i).Trim()
    $value = $Anchor.Substring($i + 1).Trim()
    if ([string]::IsNullOrWhiteSpace($type) -or [string]::IsNullOrWhiteSpace($value)) { return $null }

    # Get-SICanonicalIdType lives in SI-CorrelationCore.ps1 and folds the type aliases. When this file
    # is loaded on its own (a test exercising the parser alone) fall back to the raw type rather than
    # throwing -- the normalisation is then still consistent, just not alias-folded.
    $canon = if (Get-Command -Name Get-SICanonicalIdType -ErrorAction SilentlyContinue) {
        Get-SICanonicalIdType -Type $type
    } else { $type }

    '{0}|{1}' -f ([string]$canon).ToLowerInvariant(), $value.ToLowerInvariant()
}

function Get-SICorrelationDecisionField {
    # Shape-tolerant field read: ConvertFrom-Yaml yields hashtables, tests hand in pscustomobjects.
    param([Parameter()][AllowNull()]$Entry, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Collections.IDictionary]) {
        foreach ($k in $Entry.Keys) { if ([string]$k -ieq $Name) { return $Entry[$k] } }
        return $null
    }
    $p = $Entry.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($p) { return $p.Value }
    $null
}

function Test-SICorrelationDecisionEntry {
    <#
        Is this entry usable? Returns Ok plus a Problem naming what is wrong and, where it helps, what
        to write instead.

        EVERY REFUSAL IS REPORTED BY THE CALLER. A correlation decision that is silently dropped is
        strictly worse than one that was never written: the operator has recorded a fact about their
        estate, believes the engine is acting on it, and the run says nothing. That is the exact shape
        #61 has already produced three times.
    #>
    param([Parameter()][AllowNull()]$Entry)

    $kindRaw = Get-SICorrelationDecisionField -Entry $Entry -Name 'kind'
    $kind    = ([string]$kindRaw).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($kind)) {
        return [pscustomobject]@{ Ok = $false; Kind = ''; Problem = "no 'kind' -- expected one of: $($script:SICorrelationDecisionKinds -join ', ')" }
    }
    if ($script:SICorrelationDecisionKinds -notcontains $kind) {
        return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "unknown kind '$kind' -- expected one of: $($script:SICorrelationDecisionKinds -join ', ')" }
    }

    # Provenance -- 61.5 rule 4. Mandatory, and checked before anything else about the payload, because
    # an unattributed assertion that two machines are one is exactly the corrupt record it overrules.
    foreach ($f in @('by', 'at')) {
        $v = Get-SICorrelationDecisionField -Entry $Entry -Name $f
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) {
            return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "missing '$f' -- provenance is mandatory on every correlation decision (61.5 rule 4)" }
        }
    }

    # See the header: these are corrections, and 61.1 gives corrections no expiry. Rejected rather than
    # ignored so nobody believes a review date exists.
    $exp = Get-SICorrelationDecisionField -Entry $Entry -Name 'expires'
    if ($null -ne $exp -and -not [string]::IsNullOrWhiteSpace([string]$exp)) {
        return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "'expires' is not valid on a correlation decision -- these are corrections of fact, not time-boxed deviations (61.1). Remove it, or delete the entry when it stops being true" }
    }

    $anchorsRaw = Get-SICorrelationDecisionField -Entry $Entry -Name 'anchors'
    $anchors    = @($anchorsRaw | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($anchors.Count -eq 0) {
        return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "no 'anchors' -- each must read '<IdentifierType>:<value>', e.g. 'AadDeviceId:1234-abcd'" }
    }

    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($a in $anchors) {
        $k = ConvertTo-SICorrelationAnchorKey -Anchor ([string]$a)
        if ($null -eq $k) {
            return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "anchor '$a' is not '<IdentifierType>:<value>' -- the type and the value are split on the FIRST colon, so an ARM path is fine, but a bare value is not" }
        }
        if (-not $keys.Contains($k)) { [void]$keys.Add($k) }
    }

    # never-merge and force-merge are both statements ABOUT A RELATIONSHIP, so one anchor cannot
    # express either. A single-anchor pair would be a no-op the operator reads as applied.
    if ($kind -in @('never-merge', 'force-merge') -and $keys.Count -lt 2) {
        return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "'$kind' needs at least TWO distinct anchors -- it states a relationship between objects, and one anchor states nothing" }
    }

    $pinned = $null
    if ($kind -eq 'pin-id') {
        if ($keys.Count -ne 1) {
            return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "'pin-id' takes exactly ONE anchor -- pinning several at once cannot say whether they are one object or several with one id. Use force-merge to assert they are one, then pin" }
        }
        $idRaw = Get-SICorrelationDecisionField -Entry $Entry -Name 'id'
        if ($null -eq $idRaw -or [string]::IsNullOrWhiteSpace([string]$idRaw)) {
            return [pscustomobject]@{ Ok = $false; Kind = $kind; Problem = "'pin-id' needs an 'id' -- the SI_CorrelationId this object must keep" }
        }
        $pinned = ([string]$idRaw).Trim()
    }

    [pscustomobject]@{ Ok = $true; Kind = $kind; Problem = $null; AnchorKeys = $keys.ToArray(); PinnedId = $pinned }
}

function Import-SICorrelationDecisions {
    <#
        Read the operator's correlation decisions, validate them ONCE, and report everything that will
        not apply. Returns a report; it does NOT assign any global -- the caller assigns, and only when
        a file was actually found, so a test or launcher that set the decisions by hand is never
        silently emptied by a run that simply has no file.

        ONLY VALID ENTRIES REACH THE PLAN. A rejected entry can never apply, so carrying it forward
        would re-do the same validation inside the grouping hot path and report the same mistake once
        per group. Validate here, once, where the message names the file the operator has to edit.
    #>
    param(
        [Parameter()][AllowEmptyString()][string]$Path,
        [Parameter()][AllowEmptyString()][string]$OverlayRoot,
        [Parameter()][AllowEmptyString()][string]$SolutionRoot
    )

    # Resolved HERE rather than in the parameter block so an explicit empty string from a caller still
    # means "not set" and cannot half-shadow the global.
    if ([string]::IsNullOrWhiteSpace($Path)        -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_CorrelationDecisionsPath)) { $Path        = [string]$global:SI_CorrelationDecisionsPath }
    if ([string]::IsNullOrWhiteSpace($OverlayRoot) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_EnrichmentDataRoot))       { $OverlayRoot = [string]$global:SI_EnrichmentDataRoot }
    if ([string]::IsNullOrWhiteSpace($SolutionRoot)) {
        # $PSScriptRoot = <si>\engine\asset-correlation\_shared -> three parents up = the solution root.
        $SolutionRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    }

    $decisions   = New-Object System.Collections.Generic.List[object]
    $rejected    = New-Object System.Collections.Generic.List[object]
    $parseFailed = New-Object System.Collections.Generic.List[object]
    $missing     = New-Object System.Collections.Generic.List[object]
    $read        = New-Object System.Collections.Generic.List[object]

    foreach ($c in (Get-SICorrelationDecisionSource -ExplicitPath $Path -OverlayRoot $OverlayRoot -SolutionRoot $SolutionRoot)) {
        if (-not $c.Exists) {
            # Configured but absent is NOT a silent no-op -- audit #29/#34's lesson. The run would look
            # clean while every decision the operator wrote is missing. "Configured" is a FILE someone
            # named; an overlay root with no decisions file in it is not a mistake (one verbose line,
            # and nothing is created).
            if ($c.Configured) { [void]$missing.Add($c) }
            elseif ($c.Source -eq 'overlay') { Write-Verbose ("correlation decisions: no file at the overlay root ({0}) -- none to load from there." -f $c.Path) }
            continue
        }

        $raw = $null
        try { $raw = Get-Content -LiteralPath $c.Path -Raw -Encoding UTF8 }
        catch {
            [void]$parseFailed.Add([pscustomobject]@{ Path = $c.Path; Source = $c.Source; Error = $_.Exception.Message })
            continue
        }
        if ([string]::IsNullOrWhiteSpace($raw)) { [void]$read.Add($c); continue }

        # SecurityInsight's own YAML reader (no powershell-yaml module).
        if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-Yaml.ps1')
        }

        $doc = $null
        try { $doc = ConvertFrom-SIYaml -Yaml $raw -SourceName $c.Path }
        catch {
            [void]$parseFailed.Add([pscustomobject]@{ Path = $c.Path; Source = $c.Source; Error = $_.Exception.Message })
            continue
        }
        [void]$read.Add($c)

        $idx = 0
        foreach ($e in @($doc)) {
            $idx++
            if ($null -eq $e) { continue }
            $v = Test-SICorrelationDecisionEntry -Entry $e
            if (-not $v.Ok) {
                [void]$rejected.Add([pscustomobject]@{ Path = $c.Path; Source = $c.Source; Index = $idx; Kind = $v.Kind; Problem = $v.Problem })
                continue
            }
            [void]$decisions.Add([pscustomobject]@{
                Kind       = $v.Kind
                AnchorKeys = $v.AnchorKeys
                PinnedId   = $v.PinnedId
                By         = [string](Get-SICorrelationDecisionField -Entry $e -Name 'by')
                At         = [string](Get-SICorrelationDecisionField -Entry $e -Name 'at')
                Reason     = [string](Get-SICorrelationDecisionField -Entry $e -Name 'reason')
                Path       = $c.Path
                Source     = $c.Source
                Index      = $idx
            })
        }
    }

    [pscustomobject]@{
        Decisions   = $decisions.ToArray()
        Rejected    = $rejected.ToArray()
        ParseFailed = $parseFailed.ToArray()
        Missing     = $missing.ToArray()
        FilesRead   = $read.ToArray()
    }
}

function Get-SICorrelationDecisionPlan {
    <#
        Turn validated decisions into the three lookups the grouping needs, and REFUSE contradictions
        rather than resolving them.

          Forbid    anchorKey -> set of anchorKeys it must not share an object with
          Force     list of anchorKey sets that must end up in one object
          Pinned    anchorKey -> SI_CorrelationId

        THE ONE CONTRADICTION THAT MATTERS: the same pair asserted both never-merge and force-merge.
        Applying either would honour one instruction and silently discard the other, and the operator
        cannot predict which. Both are dropped and the pair is reported -- fail closed, exactly as the
        schema gate refuses a wildcard approval rather than interpreting it.
    #>
    param([Parameter()][AllowEmptyCollection()][object[]]$Decisions)

    # ONE unordered pair -> ONE key, ordinally. Written out rather than as
    # `$a,$b = @($x,$y | Sort-Object)`: that destructuring collapses to a single element whenever the
    # pipeline yields one, leaving $b $null and the format string one argument short -- which is how
    # this function first failed. It is also culture-dependent, and a pair key that sorts differently
    # on a da-DK host would make the same contradiction detected on one machine and missed on another.
    $pairKey = {
        param([string]$x, [string]$y)
        if ([string]::CompareOrdinal($x, $y) -le 0) { '{0}##{1}' -f $x, $y } else { '{0}##{1}' -f $y, $x }
    }

    $forbid  = @{}
    $force   = New-Object System.Collections.Generic.List[object]
    $pinned  = @{}
    $conflicts = New-Object System.Collections.Generic.List[object]

    $never = @(@($Decisions) | Where-Object { $_ -and $_.Kind -eq 'never-merge' })
    $forceD = @(@($Decisions) | Where-Object { $_ -and $_.Kind -eq 'force-merge' })
    $pinD   = @(@($Decisions) | Where-Object { $_ -and $_.Kind -eq 'pin-id' })

    # Every unordered pair a never-merge entry forbids.
    $neverPairs = @{}
    foreach ($d in $never) {
        $keys = @($d.AnchorKeys)
        for ($i = 0; $i -lt $keys.Count; $i++) {
            for ($j = $i + 1; $j -lt $keys.Count; $j++) {
                $neverPairs[(& $pairKey $keys[$i] $keys[$j])] = $d
            }
        }
    }

    # A force-merge that contradicts a never-merge kills BOTH sides of that pair.
    $killed = @{}
    foreach ($d in $forceD) {
        $keys = @($d.AnchorKeys)
        for ($i = 0; $i -lt $keys.Count; $i++) {
            for ($j = $i + 1; $j -lt $keys.Count; $j++) {
                $pk = & $pairKey $keys[$i] $keys[$j]
                if ($neverPairs.ContainsKey($pk)) {
                    $killed[$pk] = $true
                    [void]$conflicts.Add([pscustomobject]@{
                        Problem = "the pair '$($keys[$i])' / '$($keys[$j])' is asserted BOTH never-merge and force-merge. Both are ignored; one of the two entries is wrong and the engine will not choose between them"
                        AnchorA = $keys[$i]; AnchorB = $keys[$j]
                    })
                }
            }
        }
    }

    foreach ($pk in $neverPairs.Keys) {
        if ($killed.ContainsKey($pk)) { continue }
        $halves = $pk -split '##', 2
        $a = $halves[0]; $b = $halves[1]
        if (-not $forbid.ContainsKey($a)) { $forbid[$a] = @{} }
        if (-not $forbid.ContainsKey($b)) { $forbid[$b] = @{} }
        $forbid[$a][$b] = $true
        $forbid[$b][$a] = $true
    }

    foreach ($d in $forceD) {
        $keys = @($d.AnchorKeys)
        $anyKilled = $false
        for ($i = 0; $i -lt $keys.Count; $i++) {
            for ($j = $i + 1; $j -lt $keys.Count; $j++) {
                if ($killed.ContainsKey((& $pairKey $keys[$i] $keys[$j]))) { $anyKilled = $true }
            }
        }
        if (-not $anyKilled) { [void]$force.Add([pscustomobject]@{ AnchorKeys = $keys; Decision = $d }) }
    }

    foreach ($d in $pinD) {
        $k = @($d.AnchorKeys)[0]
        if ($pinned.ContainsKey($k) -and $pinned[$k] -ne $d.PinnedId) {
            [void]$conflicts.Add([pscustomobject]@{
                Problem = "anchor '$k' is pinned to two different ids ('$($pinned[$k])' and '$($d.PinnedId)'). Both are ignored"
                AnchorA = $k; AnchorB = $null
            })
            $pinned.Remove($k)
            continue
        }
        if (-not $pinned.ContainsKey($k)) { $pinned[$k] = $d.PinnedId }
    }

    [pscustomobject]@{
        Forbid    = $forbid
        Force     = $force.ToArray()
        Pinned    = $pinned
        Conflicts = $conflicts.ToArray()
        IsEmpty   = (($forbid.Keys.Count -eq 0) -and ($force.Count -eq 0) -and ($pinned.Keys.Count -eq 0))
    }
}
