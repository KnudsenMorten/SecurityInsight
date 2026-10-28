#Requires -Version 5.1
<#
    AI SUMMARY MODE -- the pure decision half of "do the Summary and Detailed
    reports show the same numbers?"

    WHY THIS IS ITS OWN FILE. The logic used to live inline in Invoke-RiskAnalysis.ps1,
    where the only way to test it is to match its source text -- and a source match
    proves a line is WRITTEN, never that it RESOLVES or that it decides correctly.
    Everything here is pure: no globals, no disk, no network, no clock of its own
    (the caller passes the time in). Every branch is reachable from a unit test.

    THE PROBLEM, stated once so nobody re-derives it:

    Summary counts distinct ASSETS. Detailed counts individual ASSET FINDINGS -- one
    asset can carry many. The same estate therefore yields different totals and
    percentages in the two reports, permanently and correctly. Customers whose
    management receives BOTH reports kept asking why the figures disagree, so the
    engine was made to freeze one report's snapshot and have the other adopt it
    ('Consistent'). Customers whose management receives ONE report are better served
    by each report telling the truth about its own grain ('PerReport').

    🔴 WHY THERE IS A LEADER INSTEAD OF A "FIRST RUN WINS" RULE.

    The original design said the first report of a cycle wins. Two attempts to
    implement that failed, and the second failure is the instructive one:

      1. ROLLING AGE (the shipped behaviour until 2026-09-07). Reuse was gated only
         on the snapshot being younger than $SI_AISummary_MaxAgeHours; CollectionTime
         was written into the payload but never read for any decision. So the owner
         was not "whoever ran first" but "whoever first crossed the 24h line", which
         with a daily cadence and a couple of hours between the jobs DRIFTS and then
         parks on Detailed -- putting Detailed's much larger figures in BOTH mails.
         That is the defect a customer reported.

      2. UTC-DAY KEY (considered, rejected same day). Keying the cycle on the UTC date
         fixes the drift but breaks on any schedule that straddles midnight UTC --
         "Summary late evening, Detailed early morning" is an ordinary arrangement,
         not an edge case, and a long run can straddle it by itself. Operator:
         "you can easily have situations where summary and detailed run on different
         utc time."

      Anchoring to the DATA rather than the clock was examined too: RA reads the
      profile tables with `arg_max(CollectionTime, *) by PrimaryEntityId`, which is
      PER ENTITY, so there is no single snapshot timestamp to key on and producing
      one costs an extra Log Analytics query.

    So the cycle is not knowable from a clock, and asking "which cycle is this?" is
    the wrong question. The right one is "who is the source of truth?" -- which needs
    no clock at all:

        I am the leader      -> ALWAYS build my own figures. I adopt from nobody.
        I am not the leader  -> adopt the leader's snapshot when one exists within
                                the backstop; otherwise build my own.

    This is order-independent, timezone-independent and date-independent, and it has
    the property the complaint actually needs: the follower's figures can never
    appear in the leader's mail.

    ⚠️ It reverses v2.2.345, which removed a "Summary is authority" asymmetry in
    favour of first-run-wins. First-run-wins is what proved unimplementable without a
    clock. The leader is configurable so a customer whose management reads the
    Detailed report can invert it.
#>

Set-StrictMode -Off

function Resolve-RAAISummaryMode {
    <#
    .SYNOPSIS
        PURE. Map a customer's $global:SI_AISummary_Mode string to a canonical mode.

    .DESCRIPTION
        Returns 'Consistent' or 'PerReport', plus whether the input was recognised so
        the caller can warn once, and the edition whose default applied.

        🔒 THE DEFAULT DEPENDS ON THE EDITION (operator, 2026-10-05). An explicitly set
        value always wins, in both editions; only an UNSET (or unrecognised) value takes
        the edition's default:

          Community -> 'Consistent'. It is what every install did before this setting
                       existed. This engine reaches ~6,000 community installs with no
                       review step; changing their default would silently move the
                       headline score an executive sees.
          Pro       -> 'PerReport'. Pro has the web app, where Summary and Detailed are
                       one click apart -- each report showing its own figures (Summary
                       counts distinct assets, Detailed counts individual findings) reads
                       better there than one report carrying the other's numbers.

        An -Edition other than 'Pro' (including none) is Community: not knowing the
        edition must never move a Community install off its default.

        🪤 AN UNRECOGNISED VALUE FALLS BACK, IT DOES NOT THROW. This is customer config
        read by an unattended scheduled job. A typo must cost a warning line, not a
        customer's nightly report.

        'FirstCome' and 'Actual' are accepted as aliases -- the words the two
        behaviours were described in before they had a setting.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][string]$Value,
        [Parameter()][AllowNull()][string]$Edition
    )

    $ed = if ("$Edition".Trim() -ieq 'Pro') { 'Pro' } else { 'Community' }
    $default = Get-RAAISummaryDefaultMode -Edition $ed
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [pscustomobject]@{ Mode = $default; Recognised = $true; Supplied = $false; Edition = $ed }
    }
    switch -Regex ($Value.Trim()) {
        '^(?i)(consistent|firstcome|first-come)$' {
            return [pscustomobject]@{ Mode = 'Consistent'; Recognised = $true; Supplied = $true; Edition = $ed }
        }
        '^(?i)(perreport|per-report|actual)$' {
            return [pscustomobject]@{ Mode = 'PerReport';  Recognised = $true; Supplied = $true; Edition = $ed }
        }
        default {
            # an unrecognised value gets what an unset one gets: the edition's default
            return [pscustomobject]@{ Mode = $default; Recognised = $false; Supplied = $true; Edition = $ed }
        }
    }
}

function Get-RAAISummaryDefaultMode {
    <#
    .SYNOPSIS
        PURE. The agreement mode an install gets when SI_AISummary_Mode is not set:
        'PerReport' for Pro, 'Consistent' for anything else (Community, unknown).
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Edition)
    if ("$Edition".Trim() -ieq 'Pro') { return 'PerReport' }
    return 'Consistent'
}

function Get-RAAISummaryEdition {
    <#
    .SYNOPSIS
        PURE. Which edition's default applies to this run: 'Pro' when the run took its
        settings from the SecurityInsight Pro settings database, else 'Community'.

    .DESCRIPTION
        The caller passes $global:SI_ProSettingsVersion. Only the Pro settings layer
        (Invoke-SIProSettingsLayer) sets it, and only after reading the database
        successfully -- a Pro run that cannot read it stops before Risk Analysis starts.
        So a non-empty version means exactly "this is a Pro run", with no licence call
        and no network; a Community install never carries it.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$ProSettingsVersion)
    if ([string]::IsNullOrWhiteSpace($ProSettingsVersion)) { return 'Community' }
    return 'Pro'
}

function Test-RAAISummaryUseCachedKpi {
    <#
    .SYNOPSIS
        PURE. May this run replace its own Risk Score KPI with a cached (adopted) one?

    .DESCRIPTION
        Only in Consistent mode, and only when the cached snapshot carries a score. In
        PerReport each report shows its OWN KPI: a snapshot left in memory must never
        put the leading report's score in this report's mail or executive view.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][string]$Mode,
        [Parameter()][AllowNull()][object]$CachedKpi
    )
    if ($Mode -eq 'PerReport') { return $false }
    if ($null -eq $CachedKpi) { return $false }
    $p = $CachedKpi.PSObject.Properties['GlobalScore']
    if (-not $p -or $null -eq $p.Value) { return $false }
    return $true
}

function Get-RAReportGrainLabel {
    <#
    .SYNOPSIS
        PURE. A clean, customer-facing word for a report template.

    .DESCRIPTION
        Templates are internal identifiers that vary by install --
        'RiskAnalysis_Summary_Bucket' on the engine default, 'RiskAnalysis_Summary' on
        the community launcher, and anything at all if a customer overrides
        $global:ReportTemplate. The leader comparison must not depend on that string
        matching exactly, so both sides are reduced to a GRAIN first.

        Returns 'Summary' or 'Detailed', or $null when the template cannot be
        classified -- the caller then falls back rather than guessing.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$ReportTemplate)

    if ([string]::IsNullOrWhiteSpace($ReportTemplate)) { return $null }
    # Detailed is tested FIRST: a template named '..._Detailed_Summary_Bucket' is a
    # Detailed report, and testing Summary first would mislabel it.
    if ($ReportTemplate -match '(?i)detail') { return 'Detailed' }
    if ($ReportTemplate -match '(?i)summar') { return 'Summary'  }
    return $null
}

function Resolve-RAAISummaryLeader {
    <#
    .SYNOPSIS
        PURE. Which report grain is the source of truth in 'Consistent' mode.

    .DESCRIPTION
        Default 'Detailed' (#636, owner 2026-10-19: "i prefer to switch so detailed becomes
        the engine default and summary is optional"): the Summary step is off by default, so
        the Detailed report is the one that runs -- a leader that never runs would leave the
        follower waiting for a snapshot that never comes. An install that switched the
        Summary step on and whose management reads the Summary report sets 'Summary' and the
        relationship inverts cleanly -- nothing else in the design changes.

        Unrecognised values fall back to 'Detailed' with Recognised=$false, same
        contract as the mode resolver and for the same reason.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [pscustomobject]@{ Leader = 'Detailed'; Recognised = $true; Supplied = $false }
    }
    switch -Regex ($Value.Trim()) {
        '^(?i)summar(y|ies)?$' { return [pscustomobject]@{ Leader = 'Summary';  Recognised = $true; Supplied = $true } }
        '^(?i)detail(ed)?$'    { return [pscustomobject]@{ Leader = 'Detailed'; Recognised = $true; Supplied = $true } }
        default                { return [pscustomobject]@{ Leader = 'Detailed'; Recognised = $false; Supplied = $true } }
    }
}

function Test-RAAISummaryShouldAdopt {
    <#
    .SYNOPSIS
        PURE. Should THIS run adopt the cached snapshot, or build its own?

    .DESCRIPTION
        The whole decision, in one place, called by every site in the engine that asks
        it. When those sites each carried their own copy of the test they disagreed:
        the read path would correctly decline a snapshot and the race guard a few
        hundred lines later would adopt the very same one.

        Rules, in order:

          1. PerReport         -> never adopt. Each report shows its own figures.
          2. No snapshot       -> nothing to adopt.
          3. I am the leader   -> never adopt. The leader is the source of truth, so it
                                  always rebuilds; this is what stops the follower's
                                  figures ever reaching the leader's mail.
          4. Snapshot is not
             the leader's      -> do not adopt. A snapshot left by the follower (from a
                                  cycle where the leader did not run) must not be
                                  promoted into the leader's role.
          5. Older than the
             backstop          -> do not adopt. Stops a snapshot from a host that was
                                  offline for a week being carried into today's mail.
          6. Otherwise         -> ADOPT.

        Note there is NO cycle key and NO date arithmetic. That is the point: the
        pairing survives any schedule, any timezone and any run duration.

    .OUTPUTS
        { Adopt; Reason }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Consistent','PerReport')][string]$Mode,
        [Parameter(Mandatory)][string]$LeaderGrain,
        [Parameter()][AllowNull()][string]$MyGrain,
        [Parameter()][AllowNull()][string]$SnapshotGrain,
        [Parameter()][AllowNull()][object]$GeneratedAtUtc,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [Parameter(Mandatory)][int]$MaxAgeHours,
        [Parameter()][switch]$HasSnapshot
    )

    if ($Mode -eq 'PerReport') {
        return [pscustomobject]@{ Adopt = $false; Reason = 'PerReport mode -- this report always shows its own figures' }
    }
    if (-not $HasSnapshot) {
        return [pscustomobject]@{ Adopt = $false; Reason = 'no snapshot available' }
    }
    if ($MyGrain -and $MyGrain -eq $LeaderGrain) {
        return [pscustomobject]@{ Adopt = $false; Reason = ("this run is the leader ({0}) -- the leader always builds its own figures" -f $LeaderGrain) }
    }
    if ($SnapshotGrain -and $SnapshotGrain -ne $LeaderGrain) {
        return [pscustomobject]@{ Adopt = $false; Reason = ("the snapshot was written by {0}, which is not the leader ({1}) -- not adopting it" -f $SnapshotGrain, $LeaderGrain) }
    }
    if ($null -eq $GeneratedAtUtc) {
        return [pscustomobject]@{ Adopt = $false; Reason = 'snapshot has no usable timestamp' }
    }
    $ageHours = ($NowUtc.ToUniversalTime() - ([datetime]$GeneratedAtUtc).ToUniversalTime()).TotalHours
    if ($ageHours -gt $MaxAgeHours) {
        return [pscustomobject]@{ Adopt = $false; Reason = ("the leader's snapshot is {0:N1}h old, over the {1}h backstop" -f $ageHours, $MaxAgeHours) }
    }
    return [pscustomobject]@{ Adopt = $true; Reason = ("adopting the leader's ({0}) snapshot, {1:N1}h old" -f $LeaderGrain, $ageHours) }
}
