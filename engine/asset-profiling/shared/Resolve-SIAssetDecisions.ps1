#Requires -Version 5.1
<#
    SI #61 -- OPERATOR DECISIONS: override / exception / exemption.

    Machine tags currently do all three jobs at once, undated and unattributed. That is how one host
    ends up carrying both a tier0 and a tier2 tag with nothing to say which is authoritative, who set
    either, or whether either is still true. Three intentions wearing one mechanism.

      override   the computed answer is WRONG -- use this instead.   no expiry.        CHANGES the tier.
      exception  the answer is RIGHT, treat this asset differently.  expiry mandatory. does not.
      exemption  this asset is OUT OF SCOPE for SI.                  expiry mandatory. excluded.

    🔴 ONLY `override` TOUCHES THE TIER. Collapsing the other two into "just set the tier lower" is how
    an estate fills with fake T3s nobody can audit. SI already gets exemption structurally right --
    --Excluded--SI removes the asset VISIBLY, via the excluded-assets report, rather than disguising it
    as a low tier. What it lacked was expiry and attribution, not shape.

    PURE. The file loader is separate, so the decisions -- which is what can be wrong -- are provable
    without a file, a tenant or a YAML parser.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

$script:SIDecisionKinds = @('override','exception','exemption')

function Get-SIAssetDecisionField {
    <#
        ONE spelling for "read a field off a decision entry".

        An entry arrives as a YAML Hashtable from the loader, or as a PSCustomObject from a test or a
        caller that built it by hand. Both shapes are legal and both are used, so every reader needs the
        same two-branch lookup -- and this file previously carried that lookup three times, inline, in
        three slightly different forms. That is the "one fact, two spellings" trap in miniature: the day
        one of them gains a trim and the others do not, an entry validates and then fails to match.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Entry,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains($Name)) { return $Entry[$Name] }
        return $null
    }
    if ($Entry.PSObject.Properties[$Name]) { return $Entry.$Name }
    $null
}

function Get-SIAssetDecisionExpiry {
    <#
        THE reading of `expires` -- shared by the resolver below and by the loader.

        Why it is a function: the loader has to decide "is this entry already dead on arrival" and the
        resolver has to decide "has it lapsed for this asset", and those are the SAME question asked at
        two moments. Two implementations of one date rule is how a decision reports lapsed in the run
        summary and still applies to an asset, or the reverse -- and either way the operator is told
        something that is not true about their own estate.

        Returns Parsed=$false rather than throwing: an unreadable date is an operator typo to be
        REPORTED, not an exception that takes down a profile run.
    #>
    param([Parameter(Mandatory)][AllowNull()]$Entry)

    $raw = Get-SIAssetDecisionField -Entry $Entry -Name 'expires'
    if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) {
        return [pscustomobject]@{ HasExpiry = $false; Expiry = $null; Parsed = $true; Problem = $null }
    }

    # CURRENT CULTURE FIRST, INVARIANT SECOND -- and the order is the whole point.
    # Current-culture-first means nothing that parses today changes meaning: a da-DK operator who wrote
    # 30-11-2026 still gets 30 November. Invariant runs only for strings the current culture REFUSES, so
    # it can add readings (a US-style 11/30/2026 on a da-DK host) but can never silently re-interpret an
    # existing one. Doing it the other way round would move 03-04-2026 from 3 April to 4 March on this
    # machine -- an exemption quietly ending a month early, or a month late.
    $exp = [datetime]::MinValue
    if ([datetime]::TryParse([string]$raw, [ref]$exp)) {
        return [pscustomobject]@{ HasExpiry = $true; Expiry = $exp; Parsed = $true; Problem = $null }
    }
    if ([datetime]::TryParse([string]$raw, [System.Globalization.CultureInfo]::InvariantCulture,
                             [System.Globalization.DateTimeStyles]::None, [ref]$exp)) {
        return [pscustomobject]@{ HasExpiry = $true; Expiry = $exp; Parsed = $true; Problem = $null }
    }

    # NO BACKTICKS. See the note in Test-SIAssetDecision -- and this message is why it is repeated here:
    # the first version of this line read "unparseable `expires` value", and under pwsh 7 the backtick-e
    # is the ESCAPE character, so it emitted a raw ESC byte into the log and printed "unparseable xpires
    # value". The one message in this file that was supposed to explain a typo contained one.
    [pscustomobject]@{
        HasExpiry = $true; Expiry = $null; Parsed = $false
        Problem   = ("unparseable 'expires' value '{0}'" -f $raw)
    }
}

function Get-SIAssetDecisionKey {
    <#
        A stable identity for ONE decision entry.

        Needed because the resolver runs per ASSET and returns that asset's view, so a single wildcard
        entry (`LAB-*`) appears in the Lapsed list of every asset it matches. Summing those lists counts
        one operator mistake once per machine -- "47 rejected entries" for a file with one typo in it.
        Keying on what the operator actually wrote collapses it back to the truth.
    #>
    param([Parameter(Mandatory)][AllowNull()]$Entry)
    if ($null -eq $Entry) { return '<null>' }
    '{0}|{1}|{2}|{3}' -f (Get-SIAssetDecisionField -Entry $Entry -Name 'kind'),
                         (Get-SIAssetDecisionField -Entry $Entry -Name 'asset'),
                         (Get-SIAssetDecisionField -Entry $Entry -Name 'at'),
                         (Get-SIAssetDecisionField -Entry $Entry -Name 'expires')
}

function Test-SIAssetDecision {
    <#
        Is this entry usable? Returns the entry plus WHY NOT, never a bare boolean.

        🔒 FAIL CLOSED AND SAY SO. An entry that cannot be validated is REJECTED, not applied and not
        silently dropped. Silently dropping is the worse half: the operator believes an exemption is in
        force, the asset is being reported on anyway, and nothing anywhere says so. Every rejection
        carries the reason so it can be fixed rather than guessed at.
    #>
    param([Parameter(Mandatory)][AllowNull()]$Entry)

    $problems = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Entry) { return [pscustomobject]@{ Valid = $false; Problems = @('entry is null') } }

    $get = {
        param($o,$n)
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] } ; return $null }
        if ($o.PSObject.Properties[$n]) { return $o.$n }
        $null
    }

    $asset = [string](& $get $Entry 'asset')
    $kind  = ([string](& $get $Entry 'kind')).Trim().ToLowerInvariant()
    $by    = [string](& $get $Entry 'by')
    $at    = & $get $Entry 'at'
    $exp   = & $get $Entry 'expires'
    $tier  = & $get $Entry 'tier'

    # 🪤 NO BACKTICKS IN THESE MESSAGES. Inside a double-quoted PowerShell string a backtick is the
    # ESCAPE character, so "`tier`" renders as a literal TAB followed by "ier" -- which is exactly what
    # shipped in the first draft and what its own test caught. Field names are quoted with apostrophes
    # instead; the message is for a human reading a log, not for a markdown renderer.
    if ([string]::IsNullOrWhiteSpace($asset)) { [void]$problems.Add("no 'asset' selector") }
    if ($script:SIDecisionKinds -notcontains $kind) {
        [void]$problems.Add(("'kind' must be one of {0} (got '{1}')" -f ($script:SIDecisionKinds -join '/'), $kind))
    }

    # PROVENANCE IS MANDATORY ON EVERY KIND. Without who and when, an override IS the stale tag this
    # model exists to replace -- the same reasoning that makes the schema gate refuse unsigned approvals.
    if ([string]::IsNullOrWhiteSpace($by)) { [void]$problems.Add("no 'by' -- an unattributed decision cannot be audited") }
    if ($null -eq $at -or [string]::IsNullOrWhiteSpace([string]$at)) { [void]$problems.Add("no 'at' -- an undated decision cannot be aged") }

    switch ($kind) {
        'override' {
            # An override is a CORRECTION, not a deviation, so it does not expire -- and an expiry on
            # one is a sign someone meant `exception`. Refuse rather than guess which they meant.
            if ($null -ne $exp -and -not [string]::IsNullOrWhiteSpace([string]$exp)) {
                [void]$problems.Add("an 'override' must not carry 'expires' -- it is a correction, not a time-boxed deviation. Did you mean kind: exception?")
            }
            if ($null -eq $tier -or [string]::IsNullOrWhiteSpace([string]$tier)) {
                [void]$problems.Add("an 'override' must state a 'tier' -- otherwise it corrects nothing")
            } else {
                $t = -1; if (-not [int]::TryParse([string]$tier, [ref]$t) -or $t -lt 0 -or $t -gt 3) {
                    [void]$problems.Add(("'tier' must be 0-3 (got '{0}')" -f $tier))
                }
            }
        }
        { $_ -in 'exception','exemption' } {
            # MANDATORY. An exception without an end date is a permanent silent hole, which is the thing
            # the whole model is for.
            if ($null -eq $exp -or [string]::IsNullOrWhiteSpace([string]$exp)) {
                [void]$problems.Add(("a '{0}' must carry 'expires' -- an expiry nobody set is a permanent hole" -f $kind))
            }
            if ($null -ne $tier -and -not [string]::IsNullOrWhiteSpace([string]$tier)) {
                # Refusing this is the point of the whole model: it is how a scope decision gets
                # smuggled in as a tier change and becomes unauditable.
                [void]$problems.Add(("a '{0}' must NOT set 'tier' -- only an 'override' changes the tier" -f $kind))
            }
        }
    }

    [pscustomobject]@{ Valid = ($problems.Count -eq 0); Problems = $problems.ToArray(); Kind = $kind; Asset = $asset }
}

function Test-SIAssetSelectorMatch {
    <# Exact or wildcard (`LAB-*`), case-insensitive. FQDN and short name both match a short selector. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Selector,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Asset
    )
    if ([string]::IsNullOrWhiteSpace($Selector) -or [string]::IsNullOrWhiteSpace($Asset)) { return $false }
    $a = $Asset.Trim(); $s = $Selector.Trim()
    if ($a -like $s) { return $true }
    # A selector of SRV-01 should match SRV-01.contoso.local: operators write the name they know, and
    # which form reaches SI depends on which source won the merge -- not on their intent.
    $short = ($a -split '\.')[0]
    ($short -like $s)
}

function Resolve-SIAssetDecisions {
    <#
        Which decisions apply to this asset, right now.

        Returns the winning override (if any), the live exceptions, whether the asset is exempt, and --
        crucially -- everything that LAPSED or was REJECTED, so the run can report it.

        🔒 EXPIRY FAILS CLOSED (operator, 2026-08-13). A lapsed entry stops applying and the asset
        returns to normal treatment. Rejected: keep-applying-and-warn, because an expiry nobody enforces
        is decoration.
        ⚠️ The consequence is real and must be reported, not discovered: a lapse makes assets REAPPEAR in
        reports -- the v2.2.430 fewer-assets surprise in reverse.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][object[]]$Decisions,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Asset,
        [Parameter()][datetime]$Now = ([datetime]'2000-01-01')
    )

    $applicable = New-Object System.Collections.Generic.List[object]
    $lapsed     = New-Object System.Collections.Generic.List[object]
    $rejected   = New-Object System.Collections.Generic.List[object]

    foreach ($d in @($Decisions)) {
        if ($null -eq $d) { continue }
        $v = Test-SIAssetDecision -Entry $d
        if (-not $v.Valid) {
            [void]$rejected.Add([pscustomobject]@{ Entry = $d; Problems = $v.Problems })
            continue
        }
        $sel = if ($d -is [System.Collections.IDictionary]) { [string]$d['asset'] } else { [string]$d.asset }
        if (-not (Test-SIAssetSelectorMatch -Selector $sel -Asset $Asset)) { continue }

        $ex = Get-SIAssetDecisionExpiry -Entry $d
        if (-not $ex.Parsed) {
            [void]$rejected.Add([pscustomobject]@{ Entry = $d; Problems = @($ex.Problem) })
            continue
        }
        if ($ex.HasExpiry -and $Now -gt $ex.Expiry) {
            [void]$lapsed.Add([pscustomobject]@{ Entry = $d; Expired = $ex.Expiry })
            continue
        }
        [void]$applicable.Add($d)
    }

    $kindOf = { param($x) ([string]$(if ($x -is [System.Collections.IDictionary]) { $x['kind'] } else { $x.kind })).Trim().ToLowerInvariant() }
    $selOf  = { param($x) [string]$(if ($x -is [System.Collections.IDictionary]) { $x['asset'] } else { $x.asset }) }
    $atOf   = { param($x) $(if ($x -is [System.Collections.IDictionary]) { $x['at'] } else { $x.at }) }

    # MOST SPECIFIC WINS, then most recent. An exact name beats a wildcard because the operator who
    # typed the whole name meant that host; among equals the later decision supersedes the earlier,
    # which is the only reading that lets someone correct themselves without deleting history.
    $pickBest = {
        param($candidates)
        $c = @($candidates)
        if ($c.Count -le 1) { return @($c)[0] }
        $exact = @($c | Where-Object { (& $selOf $_) -notmatch '[\*\?]' })
        if ($exact.Count -gt 0) { $c = $exact }
        $best = $null; $bestAt = [datetime]::MinValue
        foreach ($x in $c) {
            $d0 = [datetime]::MinValue
            [void][datetime]::TryParse([string](& $atOf $x), [ref]$d0)
            if ($null -eq $best -or $d0 -gt $bestAt) { $best = $x; $bestAt = $d0 }
        }
        $best
    }

    $overrides  = @($applicable | Where-Object { (& $kindOf $_) -eq 'override'  })
    $exemptions = @($applicable | Where-Object { (& $kindOf $_) -eq 'exemption' })
    $exceptions = @($applicable | Where-Object { (& $kindOf $_) -eq 'exception' })

    [pscustomobject]@{
        Asset      = $Asset
        Override   = if ($overrides.Count  -gt 0) { & $pickBest $overrides }  else { $null }
        Exemption  = if ($exemptions.Count -gt 0) { & $pickBest $exemptions } else { $null }
        Exceptions = @($exceptions)                 # ALL of them: they are per-control and do not compete
        IsExempt   = ($exemptions.Count -gt 0)
        Lapsed     = $lapsed.ToArray()
        Rejected   = $rejected.ToArray()
    }
}

function Get-SIAssetDecisionReport {
    <#
        What the run must SAY about operator decisions, every run.

        A decision that silently stops applying is the same silent-loss class as everything else here:
        the operator believes an exemption is in force and the asset is being reported on anyway. So
        lapsed and rejected entries are counted for the run summary, not left to be discovered.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resolutions)
    $r = @($Resolutions | Where-Object { $null -ne $_ })

    # ASSET counts and ENTRY counts are different questions, and this function answers both -- so the
    # two must not be computed the same way.
    #
    # 🔴 The first version summed the per-asset Lapsed/Rejected lists, and that is wrong by a factor of
    # the estate. The resolver is called ONCE PER ASSET with the WHOLE decisions list, and it validates
    # every entry each time -- so one malformed line in the file lands in all 56 resolutions and was
    # reported as "56 rejected entries". The operator goes looking for 56 mistakes in a file with one.
    # Worse in the direction that matters: a number that large reads as a broken file rather than a
    # typo, which is exactly the kind of report people learn to ignore.
    $lapsedKeys   = New-Object 'System.Collections.Generic.HashSet[string]'
    $rejectedKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($res in $r) {
        foreach ($l in @($res.Lapsed))   { if ($l) { [void]$lapsedKeys.Add(  (Get-SIAssetDecisionKey -Entry $l.Entry)) } }
        foreach ($x in @($res.Rejected)) { if ($x) { [void]$rejectedKeys.Add((Get-SIAssetDecisionKey -Entry $x.Entry)) } }
    }

    [pscustomobject]@{
        AssetsWithOverride  = @($r | Where-Object { $_.Override  }).Count
        AssetsExempt        = @($r | Where-Object { $_.IsExempt  }).Count
        AssetsWithException = @($r | Where-Object { @($_.Exceptions).Count -gt 0 }).Count
        LapsedEntries       = $lapsedKeys.Count
        RejectedEntries     = $rejectedKeys.Count
    }
}
