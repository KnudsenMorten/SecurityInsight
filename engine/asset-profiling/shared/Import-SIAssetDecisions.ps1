#Requires -Version 5.1
<#
    SI #61 -- THE LOADER. `Resolve-SIAssetDecisions.ps1` DECIDES; this file FINDS THE FILE.

    🔴 WHY THIS EXISTS, AND WHY ITS ABSENCE WAS INVISIBLE.
    Everything else in #61 shipped correct and green: the resolver (31 tests), the row-builder wiring
    (5 tests), the SI_TierBeforeOverride / SI_TierOverrideBy columns, the schema declaration. And the
    whole feature was INERT, because nothing anywhere populated `$global:SI_AssetDecisions`. An operator
    who wrote `asset-decisions.custom.yaml` got no effect and -- the half that makes it dangerous rather
    than merely broken -- NO ERROR. They would believe an exemption was in force while the asset was
    reported on all along.
    🔑 Every test still passed, because the tests exercised the resolver and the wiring: the two ends of
    a path whose MIDDLE did not exist. That is the fourth instance of this codebase's
    declared-but-never-wired defect, after AssetName, AssetId and the tier aggregator -- and the first
    one caught by reading the handoff rather than by a customer.

    🔒 FAIL LOUD, NEVER SILENTLY EMPTY. The one outcome this file must never produce is "no decisions
    loaded" that looks identical to "no decisions written". A configured-but-missing path, an
    unparseable file and a malformed entry are each REPORTED BY NAME, because every one of them means
    the operator believes something is in force that is not.
    "Configured" means a FILE a person named (-Path / SI_AssetDecisionsPath). An overlay root that holds
    no decisions file, like an install tree that holds none, is the normal case and stays silent.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# The resolver carries Test-SIAssetDecision / Get-SIAssetDecisionExpiry / Get-SIAssetDecisionField, and
# validation must be THE SAME code the run itself applies. A loader with its own opinion of "valid"
# would accept an entry the resolver later refuses -- reporting a decision in force that never applies.
if (-not (Get-Command -Name Test-SIAssetDecision -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'Resolve-SIAssetDecisions.ps1')
}

$script:SIAssetDecisionFileName = 'asset-decisions.custom.yaml'

function Get-SIAssetDecisionSource {
    <#
        WHICH files should be read, and in what order.

        PURE -- every root is a parameter, so the precedence rule is provable without a tenant, an
        installed tree or a config file. Returns one row per candidate, including ones that do not
        exist, because "you configured this and it is not there" is the single most useful thing this
        function can say -- and it says it (Configured) only for the explicit file.

        Precedence:
          explicit   -Path / $global:SI_AssetDecisionsPath   -- names a file outright
          overlay    <SI_EnrichmentDataRoot>\...             -- operator data outside the code tree
          tree       <siRoot>\config\...                     -- the in-place location

        🔴 NEITHER LOCATION IS INSIDE asset-profiling-enrichment\, AND THAT IS NOT A STYLE CHOICE.
        That tree is the DETECTION RULE tree, and Get-SIRuleSet allow-lists exactly `*.locked.yaml` and
        `*.custom.yaml` anywhere under <engine>\ and shared\. A file called
        `asset-decisions.custom.yaml` sitting there matches the allow-list, so the rule loader picks it
        up and parses a decisions document as a broken detection rule. The first draft of this loader
        put it there; the schema-compliance guard caught it because the shipped SAMPLE then had to be a
        valid rule and was not. Decisions are CONFIGURATION, so they live in config\ with the rest of
        the customer-owned, install-once, never-published files.
        📌 The overlay path is the overlay ROOT for the same reason: Get-SIRuleSet scans
        <root>\<engine>\ and <root>\shared\ recursively, and nothing else -- so the root itself is the
        one place under an overlay that a non-rule YAML is safe.

        🔑 EXPLICIT IS EXCLUSIVE; OVERLAY AND TREE ARE ADDITIVE. Someone who names a file means THAT
        file, and silently also reading two others would be a surprise. But overlay and tree are two
        places the same kind of operator data legitimately lives, so both are read and the RESOLVER
        arbitrates any collision by its documented rule -- most specific selector, then most recent
        `at`. That is a stated rule the operator can predict, where "whichever folder I checked first
        wins" is not.
    #>
    param(
        [Parameter()][AllowEmptyString()][string]$ExplicitPath,
        [Parameter()][AllowEmptyString()][string]$OverlayRoot,
        [Parameter()][AllowEmptyString()][string]$SolutionRoot,
        [Parameter()][string]$FileName = $script:SIAssetDecisionFileName
    )

    $out = New-Object System.Collections.Generic.List[object]

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        [void]$out.Add([pscustomobject]@{
            Path = $ExplicitPath; Source = 'explicit'; Configured = $true
            Exists = (Test-Path -LiteralPath $ExplicitPath)
        })
        return $out.ToArray()      # exclusive -- see the note above
    }

    if (-not [string]::IsNullOrWhiteSpace($OverlayRoot)) {
        # Overlay ROOT, never <root>\shared\ -- see the note above: shared\ is scanned by the rule
        # loader, and a decisions file there is read as a detection rule.
        #
        # 🪤 [IO.Path]::Combine, NOT Join-Path. On PS 5.1 Join-Path RESOLVES the drive and throws
        # DriveNotFoundException, so an SI_EnrichmentDataRoot pointing at a mapped drive the scheduled
        # task's account cannot see kills the run from inside the very function whose job is to report
        # what is missing. Combine is pure string work and never touches the filesystem.
        # (Test-Path below stays safe either way: it returns $false on a bad drive rather than throwing.)
        $p = [System.IO.Path]::Combine($OverlayRoot, $FileName)
        # Configured=$false, like the in-tree path: the overlay ROOT is what someone named, not this FILE.
        # A root that simply holds no decisions file is the normal case -- a SecurityInsight Pro run points
        # the root at its own run folder and writes the file there only when the database holds a decision,
        # so "configured (overlay) but does not exist" was said on every run of an install with none.
        # Only a file a person named outright (-Path / SI_AssetDecisionsPath) is reported when it is missing.
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

function Import-SIAssetDecisions {
    <#
        Read the operator's decisions, validate them ONCE, and report everything that will not apply.

        Returns a report; it does NOT assign $global:SI_AssetDecisions. The caller assigns, and only
        when a file was actually found -- so a test or a launcher that set the global by hand is never
        silently emptied by a run that simply has no file.

        🔒 ONLY VALID ENTRIES REACH THE GLOBAL. A rejected entry can never apply (the resolver refuses
        it too), so carrying it into the per-asset hot path would re-do the same validation once per
        machine and report the same mistake once per machine. Validate here, once, where the message is
        actionable and where it names the file the operator has to edit.
    #>
    param(
        [Parameter()][AllowEmptyString()][string]$Path,
        [Parameter()][AllowEmptyString()][string]$OverlayRoot,
        [Parameter()][AllowEmptyString()][string]$SolutionRoot,
        [Parameter()][datetime]$Now = ([datetime]::UtcNow)
    )

    # Defaults come from config, resolved HERE rather than in the parameter block so an explicit empty
    # string from a caller still means "not set" and cannot half-shadow the global.
    if ([string]::IsNullOrWhiteSpace($Path)        -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_AssetDecisionsPath)) { $Path        = [string]$global:SI_AssetDecisionsPath }
    if ([string]::IsNullOrWhiteSpace($OverlayRoot) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_EnrichmentDataRoot)) { $OverlayRoot = [string]$global:SI_EnrichmentDataRoot }
    if ([string]::IsNullOrWhiteSpace($SolutionRoot)) {
        # $PSScriptRoot = <si>\engine\asset-profiling\shared -> three parents up = the solution root.
        $SolutionRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    }

    $decisions   = New-Object System.Collections.Generic.List[object]
    $rejected    = New-Object System.Collections.Generic.List[object]
    $lapsed      = New-Object System.Collections.Generic.List[object]
    $parseFailed = New-Object System.Collections.Generic.List[object]
    $missing     = New-Object System.Collections.Generic.List[object]
    $read        = New-Object System.Collections.Generic.List[object]

    $candidates = Get-SIAssetDecisionSource -ExplicitPath $Path -OverlayRoot $OverlayRoot -SolutionRoot $SolutionRoot

    foreach ($c in $candidates) {
        if (-not $c.Exists) {
            # Configured but absent is NOT a silent no-op -- audit #29/#34's lesson, and the same shape
            # as Get-SIRuleSet's missing-overlay warning: the run would look clean while every decision
            # the operator wrote is missing. "Configured" is a FILE someone named; an overlay root with
            # no decisions file in it is not a mistake (one verbose line, and nothing is created).
            if ($c.Configured) { [void]$missing.Add($c) }
            elseif ($c.Source -eq 'overlay') { Write-Verbose ("operator decisions: no file at the overlay root ({0}) -- none to load from there." -f $c.Path) }
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

        # 🪤 SHAPE NORMALISATION, AND THE ORDER OF THESE BRANCHES MATTERS.
        # A YAML list comes back from powershell-yaml as List[object] (verified, PS 5.1) -- NOT an
        # array -- so [array] must be tested BEFORE IList, because Object[] satisfies IList and has no
        # .ToArray(). A file holding a single mapping parses to one Hashtable and is accepted as one
        # entry: writing one decision without a leading dash is a reasonable thing to do, and the
        # validator below will say so if it is actually malformed rather than merely unlisted.
        $entries = @()
        if     ($null -eq $doc)                                  { $entries = @() }
        elseif ($doc -is [System.Collections.IDictionary])       { $entries = @($doc) }
        elseif ($doc -is [array])                                { $entries = $doc }
        elseif ($doc -is [System.Collections.IList])             { $entries = $doc.ToArray() }
        else                                                     { $entries = @($doc) }

        foreach ($e in $entries) {
            if ($null -eq $e) { continue }

            $v = Test-SIAssetDecision -Entry $e
            if (-not $v.Valid) {
                [void]$rejected.Add([pscustomobject]@{ Entry = $e; Problems = $v.Problems; Source = $c.Path })
                continue
            }

            # Expiry read through the SAME function the resolver uses -- see its comment. An entry that
            # is already expired at load is dead for every asset, so saying so once here is both
            # cheaper and clearer than discovering it per machine.
            $ex = Get-SIAssetDecisionExpiry -Entry $e
            if (-not $ex.Parsed) {
                [void]$rejected.Add([pscustomobject]@{ Entry = $e; Problems = @($ex.Problem); Source = $c.Path })
                continue
            }
            if ($ex.HasExpiry -and $Now -gt $ex.Expiry) {
                [void]$lapsed.Add([pscustomobject]@{ Entry = $e; Expired = $ex.Expiry; Source = $c.Path })
                # STILL CARRIED. The resolver re-checks expiry per asset and fails closed there, so
                # passing it through changes no outcome -- and dropping it here would mean a decision
                # that lapses DURING a long run behaves differently from one that lapsed before it
                # started. One rule, applied in one place.
            }

            [void]$decisions.Add($e)
        }
    }

    $kindOf = { param($x) ([string](Get-SIAssetDecisionField -Entry $x -Name 'kind')).Trim().ToLowerInvariant() }

    [pscustomobject]@{
        Decisions    = $decisions.ToArray()
        Sources      = $read.ToArray()
        Missing      = $missing.ToArray()
        ParseFailed  = $parseFailed.ToArray()
        Rejected     = $rejected.ToArray()
        Lapsed       = $lapsed.ToArray()
        Loaded       = $decisions.Count
        Overrides    = @($decisions | Where-Object { (& $kindOf $_) -eq 'override'  }).Count
        Exceptions   = @($decisions | Where-Object { (& $kindOf $_) -eq 'exception' }).Count
        Exemptions   = @($decisions | Where-Object { (& $kindOf $_) -eq 'exemption' }).Count
    }
}

function Write-SIAssetDecisionLoadReport {
    <#
        What the RUN says about the decisions file, every run.

        🔒 Silence only when there is genuinely nothing to say -- no file anywhere, which is the normal
        case. Anything else prints, because every other state means a gap between what the operator
        believes and what the engine will do.
        ⚠️ Lapsed entries are the customer-visible one: a lapse makes assets REAPPEAR in reports, the
        v2.2.430 fewer-assets surprise in reverse. Reported by name so it is an explanation rather than
        a discovery.
    #>
    param(
        [Parameter(Mandatory)]$Report,
        [Parameter()][scriptblock]$Info = { param($m) Write-Host "  $m" },
        [Parameter()][scriptblock]$Warn = { param($m) Write-Warning $m }
    )

    foreach ($m in @($Report.Missing)) {
        & $Warn ("operator decisions: '{0}' is configured ({1}) but does not exist. NO decisions were loaded from it -- overrides, exceptions and exemptions in that file are NOT in force. Fix the path or clear the setting." -f $m.Path, $m.Source)
    }
    foreach ($p in @($Report.ParseFailed)) {
        & $Warn ("operator decisions: FAILED to read '{0}' ({1}). Every decision in that file is NOT in force." -f $p.Path, $p.Error)
    }

    if (@($Report.Sources).Count -eq 0 -and @($Report.Missing).Count -eq 0 -and @($Report.ParseFailed).Count -eq 0) {
        return   # no file, nothing configured, nothing to say
    }

    foreach ($s in @($Report.Sources)) {
        & $Info ("operator decisions: read {0} [{1}]" -f $s.Path, $s.Source)
    }
    & $Info ("operator decisions: {0} in force -- {1} override, {2} exception, {3} exemption" -f `
             $Report.Loaded, $Report.Overrides, $Report.Exceptions, $Report.Exemptions)

    foreach ($l in @($Report.Lapsed)) {
        & $Warn ("operator decisions: LAPSED -- '{0}' ({1}) expired {2:yyyy-MM-dd} and no longer applies; the asset returns to normal treatment and will REAPPEAR in reports." -f `
                 (Get-SIAssetDecisionField -Entry $l.Entry -Name 'asset'),
                 (Get-SIAssetDecisionField -Entry $l.Entry -Name 'kind'), $l.Expired)
    }
    foreach ($x in @($Report.Rejected)) {
        & $Warn ("operator decisions: REJECTED -- '{0}' ({1}) is NOT in force: {2}" -f `
                 (Get-SIAssetDecisionField -Entry $x.Entry -Name 'asset'),
                 (Get-SIAssetDecisionField -Entry $x.Entry -Name 'kind'),
                 (@($x.Problems) -join '; '))
    }
}
