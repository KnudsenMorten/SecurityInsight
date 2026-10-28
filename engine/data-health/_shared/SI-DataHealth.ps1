#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE DATA HEALTH MODEL (CR2, REQUIREMENTS #656; framework DOCS/REQUIREMENTS.md §12.11d).
    SecurityInsight ONLY (owner 2026-10-14: "it is solely for si"): nothing here is shared with or aligned to another product.

    Every day SecurityInsight checks its OWN data, read-only, as its engine identity:
      (a) COLLECTIONS  per source 10% of the source's records (at least 50, all when fewer), picked at random every day,
                       read from the source and looked up in the newest collection: present + key fields;
      (b) RISK ANALYSIS 10% of the in-scope assets (at least 50, random) re-asked from Defender for Endpoint and compared
                       with the stored findings, per report.
    A source / report is ANOMALOUS when what does not match is MORE than its margin: max(minimum, floor(sampled x percent)).
    What does not match because the SOURCE changed after the collection (a CVE fixed since, a CVE published since, a field
    the source changed since) is DRIFT (#747): counted and said separately, never against the margin.
    The install is Healthy or Unhealthy: Healthy -> Unhealthy after THREE anomalous cycles in a row, Unhealthy -> Healthy
    after ONE good cycle. A cycle that could not check every source (and found nothing anomalous) changes nothing.
    While Unhealthy every data-out channel is HELD (plan only, nothing written outside); a SuperAdmin may let ONE channel
    through with a reason, until the install is Healthy again.

    This file is PURE: the catalog, the sample, the comparisons, the verdicts, the state step, the hold decision and the
    health record for Invardia (counts only -- never a name, id, UPN, host or value). The reads are in
    ..\Invoke-SIDataHealth.ps1, the run behind seams in SI-DataHealthRun.ps1, the database in SI-DataHealthStore.ps1.
    PowerShell 5.1 and 7: no ?. / ??, no ternary.
#>

# The approved defaults (owner 2026-10-14, "defaults approved as proposed, editable by an Admin"): margin percent per source,
# at least 5 records. The sample: 10 % of the records, at least 50, all when fewer (the design's rule, not a cap).
$script:SIDataHealth = @{
    SamplePercent   = 10
    SampleMinimum   = 50
    MarginMinimum   = 5
    # a record of the newest collection carries that collection's time; a record older than the newest collection by more
    # than this was NOT in it (runs are daily; shards and engines of one run land within minutes of each other)
    PresentToleranceHours = 6
    UnhealthyAfter  = 3
    MaxSources      = 50
    MaxReports      = 200
    MaxWireBytes    = 32768
    Product         = 'securityinsight'
}

function Get-SIDataHealthSourceCatalog {
    <#
        PURE. The sources of check (a), in order. Id = the wire id; Provider / RecordType = where the newest collection keeps
        the records (sidata.CiRecord, RecordKey '<provider>:<source id lower-cased>'); Fields = the key fields compared:
        Source = the name in the source read, Stored = the SI field in the record (DocJson), Kind = lower | bool | number.
        A source value that is empty is not compared (nothing to compare with). ByRecordType: the value a record of that
        record type IS when it does not carry the field -- an Azure public IP address is a public_ip record (same key as
        an Azure resource), and the azure mapping writes si_azure_resource_type on azure_resource records only; a type the
        record does carry is compared as it is, so a public IP stored as something else still differs.
    #>
    @(
        [pscustomobject]@{ Id = 'entra-users';     Label = 'Entra users';                         Provider = 'entra'; RecordType = 'user';              MarginPercent = 1; Setting = 'SI_DataHealth_Margin_EntraUsers'
                           Fields = @(@{ Source = 'userPrincipalName'; Stored = 'si_upn'; Kind = 'lower' }, @{ Source = 'accountEnabled'; Stored = 'si_account_enabled'; Kind = 'bool' }) }
        [pscustomobject]@{ Id = 'entra-apps';      Label = 'Entra apps and service principals'    ; Provider = 'entra'; RecordType = 'service_principal'; MarginPercent = 1; Setting = 'SI_DataHealth_Margin_EntraApps'
                           Fields = @(@{ Source = 'appId'; Stored = 'entra_app_id'; Kind = 'lower' }, @{ Source = 'accountEnabled'; Stored = 'si_account_enabled'; Kind = 'bool' }) }
        [pscustomobject]@{ Id = 'devices';         Label = 'Defender devices';                    Provider = 'mde';   RecordType = 'device';            MarginPercent = 2; Setting = 'SI_DataHealth_Margin_Devices'
                           Fields = @(@{ Source = 'aadDeviceId'; Stored = 'entra_device_id'; Kind = 'lower' }) }
        [pscustomobject]@{ Id = 'azure';           Label = 'Azure resources';                     Provider = 'azure'; RecordType = 'azure_resource';    MarginPercent = 3; Setting = 'SI_DataHealth_Margin_Azure'
                           Fields = @(@{ Source = 'type'; Stored = 'si_azure_resource_type'; Kind = 'lower'; ByRecordType = @{ public_ip = 'microsoft.network/publicipaddresses' } }, @{ Source = 'location'; Stored = 'si_azure_location'; Kind = 'lower' }) }
        [pscustomobject]@{ Id = 'mdc';             Label = 'Defender for Cloud recommendations';  Provider = 'mdc';   RecordType = 'azure_resource';    MarginPercent = 5; Setting = 'SI_DataHealth_Margin_DefenderForCloud'
                           Fields = @(@{ Source = 'unhealthy'; Stored = 'si_mdc_unhealthy_count'; Kind = 'number' }) }
        [pscustomobject]@{ Id = 'vulnerabilities'; Label = 'Vulnerabilities';                     Provider = '';      RecordType = '';                  MarginPercent = 5; Setting = 'SI_DataHealth_Margin_Vulnerabilities'
                           Fields = @() }
    )
}

function Get-SIDataHealthReportMargin {
    <# PURE. The default margin of check (b), every Risk Analysis report: 3 %. #>
    [pscustomobject]@{ Percent = 3; Setting = 'SI_DataHealth_Margin_RiskAnalysis' }
}

function ConvertTo-SIDataHealthPercent {
    <# PURE. A setting's value as a percent 0..100, or $null when it is not a number in that range. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $d = 0.0
    if (-not [double]::TryParse(("$Value".Trim() -replace ',', '.'), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ($d -lt 0 -or $d -gt 100) { return $null }
    $d
}

function Get-SIDataHealthMargins {
    <#
        PURE over -Globals (a name -> value dictionary; default: the run's globals). The margin in force per source id and
        for the reports ('risk-analysis'): @{ <id> = @{ Percent; Minimum } }. An Admin's value replaces the default; a value
        that is not a percent is ignored (the default stays, said by the caller). SI_DataHealth_MarginMinimum = the least
        number of records a margin allows (default 5).
    #>
    param([System.Collections.IDictionary]$Globals)
    $get = { param($n) if ($Globals) { if ($Globals.Contains($n)) { $Globals[$n] } else { $null } } else { Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue } }
    $min = $script:SIDataHealth.MarginMinimum
    $mv = & $get 'SI_DataHealth_MarginMinimum'
    if ($null -ne $mv -and "$mv" -match '^\s*\d+\s*$') { $min = [int]"$mv" }
    $out = @{}
    foreach ($s in (Get-SIDataHealthSourceCatalog)) {
        $p = ConvertTo-SIDataHealthPercent (& $get $s.Setting); if ($null -eq $p) { $p = [double]$s.MarginPercent }
        $out[$s.Id] = [pscustomobject]@{ Percent = $p; Minimum = $min }
    }
    $rm = Get-SIDataHealthReportMargin
    $p = ConvertTo-SIDataHealthPercent (& $get $rm.Setting); if ($null -eq $p) { $p = [double]$rm.Percent }
    $out['risk-analysis'] = [pscustomobject]@{ Percent = $p; Minimum = $min }
    $out
}

function Get-SIDataHealthSampleSize {
    <# PURE. How many of -Count records are checked: all when 50 or fewer, else 10 % rounded up, at least 50. #>
    param([Parameter(Mandatory)][long]$Count, [int]$Percent = $script:SIDataHealth.SamplePercent, [int]$Minimum = $script:SIDataHealth.SampleMinimum)
    if ($Count -le 0) { return 0 }
    if ($Count -le $Minimum) { return [int]$Count }
    [int][Math]::Max($Minimum, [Math]::Ceiling($Count * $Percent / 100.0))
}

function Select-SIDataHealthSample {
    <#
        PURE but for the random numbers. -Size items of -Items, picked at random (a partial Fisher-Yates shuffle) -- a
        different pick every day (owner: "randomize this so it is not the same objects every time"). -Seed makes it
        repeatable (tests).
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [Parameter(Mandatory)][int]$Size, [AllowNull()]$Seed)
    $a = @($Items | Where-Object { $null -ne $_ })
    if ($Size -le 0) { return }
    if ($Size -ge $a.Count) { return $a }
    $rnd = if ($null -ne $Seed) { New-Object System.Random ([int]$Seed) } else { New-Object System.Random }
    for ($i = 0; $i -lt $Size; $i++) {
        $j = $rnd.Next($i, $a.Count)
        $t = $a[$i]; $a[$i] = $a[$j]; $a[$j] = $t
    }
    $a[0..($Size - 1)]
}

function Get-SIDataHealthAllowed {
    <# PURE. How many of -Sampled may differ: max(minimum, floor(sampled x percent / 100)). #>
    param([long]$Sampled, [Parameter(Mandatory)]$Margin)
    [long][Math]::Max([double]$Margin.Minimum, [Math]::Floor($Sampled * [double]$Margin.Percent / 100.0))
}

function ConvertTo-SIDataHealthValue {
    <# PURE. A key field's value as compared: lower | bool | number; '' = empty (not compared). #>
    param([AllowNull()]$Value, [string]$Kind = 'lower')
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) { $Value = @($Value)[0]; if ($null -eq $Value) { return '' } }
    $s = "$Value".Trim()
    if ($s -eq '') { return '' }
    switch ($Kind) {
        'bool' {
            if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
            if ($s -match '^(?i)(true|1|yes)$') { return 'true' }
            if ($s -match '^(?i)(false|0|no)$') { return 'false' }
            return $s.ToLowerInvariant()
        }
        'number' {
            $d = 0.0
            if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d.ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
            return $s
        }
        default { return $s.ToLowerInvariant() }
    }
}

function Get-SIDataHealthItem {
    <# PURE. A value of a row whatever the row is (dictionary / object); $null when absent. #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] } else { return $null } }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function ConvertTo-SIDataHealthUtc {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    # a time from SQL has no kind: it IS UTC (every time SecurityInsight stores is UTC), never local
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function Get-SIDataHealthEligible {
    <#
        PURE. The source's records that the newest collection can be asked about: a record the source says was CREATED
        after the newest collection (-NewestCollection) is not expected in it yet and is left out (not a miss).
        -Rows: @{ Key; Name; Created; Values }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowNull()]$NewestCollection)
    $nc = ConvertTo-SIDataHealthUtc $NewestCollection
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not "$(Get-SIDataHealthItem $r 'Key')".Trim()) { continue }
        $c = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $r 'Created')
        if ($nc -and $c -and $c -gt $nc) { continue }
        $r
    }
}

function Compare-SIDataHealthSource {
    <#
        PURE. Check (a) for ONE source: the sampled source rows (-Sampled: @{ Key; Name; Values }) looked up in the newest
        collection (-Stored: record key -> @{ CollectionTime; RecordType; Values } -- keys compared without case). A record is FOUND when
        it is there and was in the newest collection (its collection time within PresentToleranceHours of -NewestCollection);
        a found record's key fields that differ from the source make one FIELD MISMATCH (one per record).
        DRIFT (#747): a field mismatch of a record the SOURCE says it changed AFTER the record was collected (the row's
        Modified -- e.g. a Defender for Cloud assessment's status change -- later than the record's collection time) is
        explained by time, not a defect: it stays counted in FieldMismatches and is ALSO counted in Drift, which the verdict
        takes off (Get-SIDataHealthDiffer). A row without Modified is never drift. A missing record is never drift.
        Returns @{ Sampled; Found; Missing; FieldMismatches; Drift; Problems = @(@{ Key; Name; Problem }) } -- the problems
        are for the install's own Data health page; they never leave the install.
    #>
    param([Parameter(Mandatory)]$Source, [AllowEmptyCollection()][object[]]$Sampled = @(), [System.Collections.IDictionary]$Stored = @{},
          [AllowNull()]$NewestCollection)
    $nc = ConvertTo-SIDataHealthUtc $NewestCollection
    $tol = $script:SIDataHealth.PresentToleranceHours
    $lookup = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in @($Stored.Keys)) { $lookup[[string]$k] = $Stored[$k] }
    $found = 0L; $missing = 0L; $mism = 0L; $n = 0L; $drift = 0L
    $problems = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Sampled)) {
        if ($null -eq $r) { continue }
        $n++
        $key = [string](Get-SIDataHealthItem $r 'Key'); $name = [string](Get-SIDataHealthItem $r 'Name')
        $st = $null
        if (-not $lookup.TryGetValue($key, [ref]$st) -or $null -eq $st) {
            $missing++; $problems.Add([pscustomobject]@{ Key = $key; Name = $name; Problem = 'not in the newest collection' }); continue
        }
        $ct = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $st 'CollectionTime')
        if ($nc -and $ct -and $ct -lt $nc.AddHours(-$tol)) {
            $missing++; $problems.Add([pscustomobject]@{ Key = $key; Name = $name; Problem = ('not in the newest collection (last collected {0:yyyy-MM-dd HH:mm} UTC)' -f $ct) }); continue
        }
        $found++
        $sv = Get-SIDataHealthItem $r 'Values'; $tv = Get-SIDataHealthItem $st 'Values'
        $diff = New-Object System.Collections.Generic.List[string]
        foreach ($f in @($Source.Fields)) {
            $a = ConvertTo-SIDataHealthValue (Get-SIDataHealthItem $sv ([string]$f.Source)) ([string]$f.Kind)
            if ($a -eq '') { continue }
            $b = ConvertTo-SIDataHealthValue (Get-SIDataHealthItem $tv ([string]$f.Stored)) ([string]$f.Kind)
            if ($b -eq '' -and $f.ByRecordType) {
                $rt = [string](Get-SIDataHealthItem $st 'RecordType')
                if ($rt -and $f.ByRecordType.Contains($rt)) { $b = ConvertTo-SIDataHealthValue $f.ByRecordType[$rt] ([string]$f.Kind) }
            }
            if ($a -ne $b) { $diff.Add([string]$f.Source) }
        }
        if ($diff.Count) {
            $mism++
            # changed in the source after this record was collected (its own collection time, else the newest collection's)
            $mod = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $r 'Modified')
            $at = $ct; if ($null -eq $at) { $at = $nc }
            if ($mod -and $at -and $mod -gt $at) {
                $drift++
                $problems.Add([pscustomobject]@{ Key = $key; Name = $name; Problem = ('differs from the source: {0} -- changed in the source {1:yyyy-MM-dd HH:mm} UTC, after the collection (drift)' -f ($diff -join ', '), $mod) })
            } else {
                $problems.Add([pscustomobject]@{ Key = $key; Name = $name; Problem = ('differs from the source: ' + ($diff -join ', ')) })
            }
        }
    }
    [pscustomobject]@{ Sampled = $n; Found = $found; Missing = $missing; FieldMismatches = $mism; Drift = $drift; Problems = $problems.ToArray() }
}

function Compare-SIDataHealthVulnerabilities {
    <#
        PURE. Check (b), and the 'vulnerabilities' source of check (a), from ONE re-ask of Defender for the sampled assets.
          -Assets    the sampled in-scope assets: @{ MdeId; Name }
          -Defender  MdeId (lower) -> the CVE ids Defender reports for the machine now; $null for a machine whose read failed
                     (it is left out, counted in NotRead)
          -Stored    the stored CVE findings of the newest complete collection for those assets: @{ MdeId; Report; Cve }
        Per asset: the 'vulnerabilities' source counts Defender's CVEs (sampled) and how many SI holds in ANY report (found).
        Per report, over the assets that report holds rows for: matched = its CVEs Defender still reports; extra = its CVEs
        Defender no longer reports; missing = Defender's CVEs of the asset the report does not hold.
        DRIFT (#747) -- a difference explained by a change in Defender AFTER the stored collection, counted in Drift on top of
        Missing / Extra (the verdict takes it off, Get-SIDataHealthDiffer; the columns keep their meaning):
          * every EXTRA: the stored collection holds the CVE and Defender no longer reports it for the machine -- the machine
            was patched (or the CVE otherwise resolved) since the collection. Defender's machine read reports only what is
            open NOW and carries no fixed-on time, so the stored finding itself (it was in the collection) is the proof that
            the change came after the collection;
          * a MISSING CVE Defender published after the collection (-CollectionTime; the Defender item's Published) -- it did
            not exist when the collection was made.
        A missing CVE that existed at the collection's time (published before it, or no publication date) stays a real
        miss: SecurityInsight never holds fewer findings than the source.
        Returns @{ Source = @{ Sampled; Found; Missing; Drift }; Reports = @(@{ Report; Sampled; Matched; Missing; Extra;
        Drift; FixedSince; NewSince }); Assets; NotRead; Problems }.
    #>
    param([AllowEmptyCollection()][object[]]$Assets = @(), [System.Collections.IDictionary]$Defender = @{}, [AllowEmptyCollection()][object[]]$Stored = @(),
          # CR2: { param([string]$Report, [string]$Cve, $LastModified) } -> would THAT report keep this CVE? (the report's own
          # exclusions: excluded CVEs, the CVE minimum age -- Test-RAInScopeFinding). Not given = every CVE is expected.
          [scriptblock]$InScope,
          # #747: the stored collection's time (sidata.Collection.CollectionTime); not given = no missing CVE is drift
          [AllowNull()]$CollectionTime)
    $collAt = ConvertTo-SIDataHealthUtc $CollectionTime
    $byAsset = @{}
    foreach ($s in @($Stored)) {
        if ($null -eq $s) { continue }
        $m = ([string](Get-SIDataHealthItem $s 'MdeId')).ToLowerInvariant(); $cve = ([string](Get-SIDataHealthItem $s 'Cve')).Trim().ToUpperInvariant()
        $rep = [string](Get-SIDataHealthItem $s 'Report')
        if (-not $m -or -not $cve) { continue }
        if (-not $byAsset.ContainsKey($m)) { $byAsset[$m] = @{} }
        if (-not $byAsset[$m].ContainsKey($rep)) { $byAsset[$m][$rep] = New-Object 'System.Collections.Generic.HashSet[string]' }
        [void]$byAsset[$m][$rep].Add($cve)
    }
    $src = @{ Sampled = 0L; Found = 0L; Missing = 0L; Drift = 0L }
    $reports = [ordered]@{}
    $problems = New-Object System.Collections.Generic.List[object]
    $notRead = 0; $assetsChecked = 0
    foreach ($a in @($Assets)) {
        if ($null -eq $a) { continue }
        $m = ([string](Get-SIDataHealthItem $a 'MdeId')).ToLowerInvariant(); $name = [string](Get-SIDataHealthItem $a 'Name')
        if (-not $m) { continue }
        if (-not $Defender.Contains($m) -or $null -eq $Defender[$m]) { $notRead++; continue }
        $assetsChecked++
        $dset = New-Object 'System.Collections.Generic.HashSet[string]'
        $dmod = @{}
        $dnew = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in @($Defender[$m])) {
            # a CVE id, or @{ Cve; LastModified; Published } (LastModified: the date the report's minimum age is judged by;
            # Published: when Defender published the CVE -- after the collection = it did not exist then)
            $cv = ''; $lm = $null; $pb = $null
            if ($c -is [string]) { $cv = $c } else { $cv = [string](Get-SIDataHealthItem $c 'Cve'); $lm = Get-SIDataHealthItem $c 'LastModified'; $pb = Get-SIDataHealthItem $c 'Published' }
            $cv = $cv.Trim().ToUpperInvariant()
            if ($cv) {
                [void]$dset.Add($cv); $dmod[$cv] = $lm
                $pu = ConvertTo-SIDataHealthUtc $pb
                if ($collAt -and $pu -and $pu -gt $collAt) { [void]$dnew.Add($cv) }
            }
        }
        $keep = { param($rep, $cve) if (-not $InScope) { return $true }; try { [bool](& $InScope $rep $cve $dmod[$cve]) } catch { $true } }
        $mine = @{}; if ($byAsset.ContainsKey($m)) { $mine = $byAsset[$m] }
        $all = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($rep in @($mine.Keys)) { foreach ($c in $mine[$rep]) { [void]$all.Add($c) } }
        # the 'vulnerabilities' source: Defender's CVEs of the device that at least ONE of its reports would keep
        $expected = @(foreach ($c in $dset) { if ($all.Contains($c)) { $c; continue }; foreach ($rep in @($mine.Keys)) { if (& $keep $rep $c) { $c; break } } })
        if ($mine.Count -eq 0) { $expected = @($dset) }
        $src.Sampled += $expected.Count
        $f = 0; $fd = 0; foreach ($c in $expected) { if ($all.Contains($c)) { $f++ } elseif ($dnew.Contains($c)) { $fd++ } }
        $src.Found += $f; $src.Missing += ($expected.Count - $f); $src.Drift += $fd
        $realMiss = $expected.Count - $f - $fd
        if ($realMiss -gt 0) { $problems.Add([pscustomobject]@{ Key = $m; Name = $name; Problem = ('{0} vulnerability(ies) Defender reports are not in any report' -f $realMiss) }) }
        if ($fd -gt 0) { $problems.Add([pscustomobject]@{ Key = $m; Name = $name; Problem = ('{0} vulnerability(ies) Defender published after the collection are not in any report yet (drift)' -f $fd) }) }
        foreach ($rep in @($mine.Keys)) {
            if (-not $reports.Contains($rep)) { $reports[$rep] = @{ Report = $rep; Sampled = 0L; Matched = 0L; Missing = 0L; Extra = 0L; Drift = 0L; FixedSince = 0L; NewSince = 0L } }
            $r = $reports[$rep]; $set = $mine[$rep]
            $mt = 0; $ex = 0; foreach ($c in $set) { if ($dset.Contains($c)) { $mt++ } else { $ex++ } }
            # missing: what Defender reports that THIS report would keep (its own exclusions applied) and does not hold
            $mi = 0; $md = 0; foreach ($c in $dset) { if (-not $set.Contains($c) -and (& $keep $rep $c)) { $mi++; if ($dnew.Contains($c)) { $md++ } } }
            $r.Matched += $mt; $r.Extra += $ex; $r.Missing += $mi; $r.Sampled += ($mt + $ex + $mi)
            # drift: every extra (fixed since the collection) + the missing CVEs published after it
            $r.FixedSince += $ex; $r.NewSince += $md; $r.Drift += ($ex + $md)
            if ($ex -gt 0) { $problems.Add([pscustomobject]@{ Key = $m; Name = $name; Problem = ('{0}: {1} vulnerability(ies) Defender no longer reports -- fixed since the collection (drift)' -f $rep, $ex) }) }
            if ($md -gt 0) { $problems.Add([pscustomobject]@{ Key = $m; Name = $name; Problem = ('{0}: {1} vulnerability(ies) Defender published after the collection (drift)' -f $rep, $md) }) }
        }
    }
    [pscustomobject]@{
        Source   = [pscustomobject]$src
        Reports  = @($reports.Values | ForEach-Object { [pscustomobject]$_ })
        Assets   = $assetsChecked
        NotRead  = $notRead
        Problems = $problems.ToArray()
    }
}

function Get-SIDataHealthVerdict {
    <#
        PURE. One source's or report's verdict: ok | anomalous | not-checked. -Differ = what did not match (missing + field
        mismatches for a source; missing + extra for a report -- less the drift, Get-SIDataHealthDiffer). Nothing sampled while the newest collection HOLDS records of
        the source (-StoredCount > 0) is anomalous: the source answered empty while SecurityInsight holds its records.
    #>
    param([long]$Sampled, [long]$Differ, [Parameter(Mandatory)]$Margin, [long]$StoredCount = 0, [switch]$NotChecked)
    if ($NotChecked) { return 'not-checked' }
    if ($Sampled -le 0) { if ($StoredCount -gt 0) { return 'anomalous' } else { return 'ok' } }
    if ($Differ -gt (Get-SIDataHealthAllowed -Sampled $Sampled -Margin $Margin)) { return 'anomalous' }
    'ok'
}

function Get-SIDataHealthDiffer {
    <#
        PURE (#747). What counts against the margin: the differences (missing + field mismatches / extra) less the DRIFT --
        the part of them explained by a change in the source after the collection. Drift is a subset of the differences; it
        is never more than them and never below 0. The margin, the sample and the threshold are unchanged.
    #>
    param([long]$Missing, [long]$Mismatches, [long]$Drift = 0)
    $all = [long]$Missing + [long]$Mismatches
    $d = [long][Math]::Min([Math]::Max(0L, [long]$Drift), $all)
    $all - $d
}

function Format-SIDataHealthDriftText {
    <#
        PURE (#747). The drift in words for the verdict's reason -- '' when there is none. A report: "N fixed since the
        collection -- drift" (and "M published after the collection -- drift"); a source: "N changed in the source after the
        collection -- drift".
    #>
    param([long]$Drift = 0, [long]$FixedSince = -1, [long]$NewSince = 0, [string]$Kind = 'report')
    if ($Drift -le 0) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Kind -eq 'report') {
        if ($FixedSince -lt 0) { $FixedSince = $Drift - $NewSince }
        if ($FixedSince -gt 0) { $parts.Add(('{0} fixed since the collection -- drift' -f $FixedSince)) }
        if ($NewSince -gt 0) { $parts.Add(('{0} published after the collection -- drift' -f $NewSince)) }
    } elseif ($NewSince -gt 0) {
        $parts.Add(('{0} published after the collection -- drift' -f $NewSince))
    } else {
        $parts.Add(('{0} changed in the source after the collection -- drift' -f $Drift))
    }
    ($parts.ToArray() -join '; ')
}

function Get-SIDataHealthCycleVerdict {
    <#
        PURE. The cycle from its source and report results (each with a Verdict ok | anomalous | not-checked | not-used):
        Anomalous = any anomalous; Complete = none not-checked (a source that could not be READ). 'not-used' (a source this
        install holds no collection of, a part of the check that is not set up) counts neither way. Nothing checked at all =
        not complete.
    #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    # 'not-used' = a source this install does not collect / the check is not set up for: neither good nor missing
    $all = @($Results | Where-Object { $_ -and [string]$_.Verdict -ne 'not-used' })
    [pscustomobject]@{
        Anomalous  = [bool](@($all | Where-Object { [string]$_.Verdict -eq 'anomalous' }).Count -gt 0)
        Complete   = [bool]($all.Count -gt 0 -and @($all | Where-Object { [string]$_.Verdict -eq 'not-checked' }).Count -eq 0)
        NotChecked = @($all | Where-Object { [string]$_.Verdict -eq 'not-checked' }).Count
    }
}

function Step-SIDataHealthState {
    <#
        PURE. The install's state after one cycle. -Previous: @{ State; Since; ConsecutiveAnomalous } ($null = the first
        cycle: an install starts Healthy). -Cycle: Get-SIDataHealthCycleVerdict.
          anomalous cycle          ConsecutiveAnomalous + 1; Healthy -> Unhealthy at the third in a row
          good cycle (complete)    ConsecutiveAnomalous = 0; Unhealthy -> Healthy
          incomplete, no anomaly   nothing changes (a source that could not be read proves nothing either way)
        Returns @{ State; Since; ConsecutiveAnomalous; Changed; From }.
    #>
    param([AllowNull()]$Previous, [Parameter(Mandatory)]$Cycle, [datetime]$NowUtc = [datetime]::UtcNow, [int]$UnhealthyAfter = $script:SIDataHealth.UnhealthyAfter)
    $now = $NowUtc.ToUniversalTime()
    $state = 'Healthy'; $since = $now; $consec = 0
    if ($Previous) {
        $ps = [string](Get-SIDataHealthItem $Previous 'State'); if ($ps -in 'Healthy', 'Unhealthy') { $state = $ps }
        $pst = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $Previous 'Since'); if ($pst) { $since = $pst }
        $pc = Get-SIDataHealthItem $Previous 'ConsecutiveAnomalous'; if ($null -ne $pc -and "$pc" -match '^\d+$') { $consec = [int]"$pc" }
    }
    $from = $state
    if ($Cycle.Anomalous) {
        $consec++
        if ($state -eq 'Healthy' -and $consec -ge $UnhealthyAfter) { $state = 'Unhealthy'; $since = $now }
    } elseif ($Cycle.Complete) {
        $consec = 0
        if ($state -eq 'Unhealthy') { $state = 'Healthy'; $since = $now }
    }
    [pscustomobject]@{ State = $state; Since = $since; ConsecutiveAnomalous = $consec; Changed = [bool]($state -ne $from); From = $from }
}

function Get-SIDataHealthActiveOverrides {
    <#
        PURE. The SuperAdmin overrides that let a channel through NOW: not cleared, and made during the current Unhealthy
        period (on or after -State.Since) -- an override lasts until the install is Healthy again, never into a later period.
        -Overrides: rows @{ Channel; By; Role; Reason; SinceUtc; ClearedAt }.
    #>
    param([AllowNull()]$State, [AllowEmptyCollection()][object[]]$Overrides = @())
    if ($null -eq $State -or [string](Get-SIDataHealthItem $State 'State') -ne 'Unhealthy') { return }
    $since = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $State 'Since')
    foreach ($o in @($Overrides)) {
        if ($null -eq $o) { continue }
        $cl = Get-SIDataHealthItem $o 'ClearedAt'; if ($null -ne $cl -and "$cl" -ne '') { continue }
        $at = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $o 'SinceUtc')
        if ($since -and $at -and $at -lt $since.AddSeconds(-1)) { continue }
        if (-not "$(Get-SIDataHealthItem $o 'Channel')".Trim()) { continue }
        $o
    }
}

function Test-SIDataHealthChannelHeld {
    <#
        PURE. Is data-out channel -Channel (a connector name) held? Held = the install is Unhealthy and no active SuperAdmin
        override names the channel (without case). Returns @{ Held; Overridden; State; Since; Reason }.
    #>
    param([AllowNull()]$State, [AllowEmptyCollection()][object[]]$Overrides = @(), [Parameter(Mandatory)][string]$Channel)
    $st = [string](Get-SIDataHealthItem $State 'State')
    $since = ConvertTo-SIDataHealthUtc (Get-SIDataHealthItem $State 'Since')
    if ($st -ne 'Unhealthy') { return [pscustomobject]@{ Held = $false; Overridden = $false; State = $(if ($st) { $st } else { 'Unknown' }); Since = $since; Reason = '' } }
    $ov = @(Get-SIDataHealthActiveOverrides -State $State -Overrides $Overrides | Where-Object { [string]::Equals(([string]$_.Channel).Trim(), $Channel.Trim(), [StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
    if ($ov) {
        return [pscustomobject]@{ Held = $false; Overridden = $true; State = $st; Since = $since
            Reason = ('let through by {0} ({1}): {2}' -f [string]$ov.By, [string]$(if ($ov.Role) { $ov.Role } else { 'SuperAdmin' }), [string]$ov.Reason) }
    }
    [pscustomobject]@{ Held = $true; Overridden = $false; State = $st; Since = $since
        Reason = ('the data health check has found SecurityInsight''s data Unhealthy since {0:yyyy-MM-dd HH:mm} UTC -- nothing is sent from {1} until the data is Healthy again, or a SuperAdmin lets this channel through on Configuration > Connectors > Data-health hold' -f $since, $Channel) }
}

function ConvertTo-SIDataHealthIso {
    param($Value)
    $u = ConvertTo-SIDataHealthUtc $Value
    if ($null -eq $u) { return $null }
    $u.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function New-SIDataHealthWire {
    <#
        PURE. The uplink record kind 'health' (framework §12.11d) -- COUNTS ONLY: no name, id, UPN, host or value of the
        customer's objects; the report key is SecurityInsight's own report name. An IDENTIFIED install only (-Context.Mode
        identified): $null for an anonymous one (a health verdict says whose install it is). At most 50 sources and 200
        reports; over 32 KB the reports are cut to fit and 'truncated' says so.
          -Sources / -Reports  the cycle's results (Name, Sampled, Found|Matched, Missing, FieldMismatches|Extra, Margin, Verdict)
          -State               Step-SIDataHealthState;  -Cycle  @{ Id; StartedUtc; FinishedUtc; Anomalous; Complete }
          -Overrides           the active overrides (Get-SIDataHealthActiveOverrides)
        A source / report that could not be checked is not in the lists (the wire knows ok | anomalous only); the cycle
        carries 'complete' and 'notChecked' (extra fields; Invardia ignores what it does not know).
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$State, [Parameter(Mandatory)]$Cycle,
          [AllowEmptyCollection()][object[]]$Sources = @(), [AllowEmptyCollection()][object[]]$Reports = @(),
          [AllowEmptyCollection()][object[]]$Overrides = @(), [bool]$DataOutHeld, $NowUtc = [datetime]::UtcNow)
    if ([string]$Context.Mode -ne 'identified') { return $null }
    $w = $script:SIDataHealth
    $num = { param($v) $x = 0L; if ($null -ne $v -and [long]::TryParse([string]$v, [ref]$x) -and $x -ge 0) { $x } else { 0L } }
    $mg = { param($m) [ordered]@{ percent = [double]$m.Percent; minimum = [int]$m.Minimum } }
    $src = @(@($Sources) | Where-Object { $_ -and [string]$_.Verdict -in 'ok', 'anomalous' } | Select-Object -First $w.MaxSources | ForEach-Object {
        [ordered]@{ source = [string]$_.Name; sampled = (& $num $_.Sampled); found = (& $num $_.Found); missing = (& $num $_.Missing)
                    fieldMismatches = (& $num $_.FieldMismatches); drift = (& $num $(if ($_.PSObject.Properties['Drift']) { $_.Drift } else { 0 })); margin = (& $mg $_.Margin); verdict = [string]$_.Verdict } })
    # drift (#747): the part of missing + mismatches / extra explained by a change in the source after the collection (a
    # count; an extra field Invardia ignores until it reads it)
    $rep = @(@($Reports) | Where-Object { $_ -and [string]$_.Verdict -in 'ok', 'anomalous' } | Select-Object -First $w.MaxReports | ForEach-Object {
        [ordered]@{ report = [string]$_.Name; sampled = (& $num $_.Sampled); matched = (& $num $_.Found); missing = (& $num $_.Missing)
                    extra = (& $num $_.FieldMismatches); drift = (& $num $(if ($_.PSObject.Properties['Drift']) { $_.Drift } else { 0 })); margin = (& $mg $_.Margin); verdict = [string]$_.Verdict } })
    $nc = @(@($Sources) + @($Reports) | Where-Object { $_ -and [string]$_.Verdict -eq 'not-checked' }).Count
    $r = [ordered]@{
        schema = 2; kind = 'health'; product = $w.Product; version = [string]$Context.Version
    }
    if ("$($Context.InstallId)".Trim()) { $r.installId = [string]$Context.InstallId }
    if ("$($Context.TenantId)".Trim()) { $r.tenantId = [string]$Context.TenantId }
    $r.sentUtc = ConvertTo-SIDataHealthIso $NowUtc
    $r.state = [string]$State.State
    $r.since = ConvertTo-SIDataHealthIso $State.Since
    $r.cycle = [ordered]@{ id = [string]$Cycle.Id; startedUtc = (ConvertTo-SIDataHealthIso $Cycle.StartedUtc); finishedUtc = (ConvertTo-SIDataHealthIso $Cycle.FinishedUtc)
                           anomalous = [bool]$Cycle.Anomalous; consecutiveAnomalous = [int]$State.ConsecutiveAnomalous; complete = [bool]$Cycle.Complete; notChecked = [int]$nc }
    $r.sources = $src
    $r.reports = $rep
    $r.dataOut = [ordered]@{ held = [bool]$DataOutHeld
        overrides = @(@($Overrides) | Where-Object { $_ } | ForEach-Object {
            # the channel is SecurityInsight's connector name (the customer's name for a database connector is shortened
            # to its kind -- a name can say whose system it is)
            [ordered]@{ channel = (ConvertTo-SIDataHealthWireChannel ([string]$_.Channel)); byRole = $(if ("$($_.Role)".Trim()) { [string]$_.Role } else { 'SuperAdmin' })
                        sinceUtc = (ConvertTo-SIDataHealthIso $_.SinceUtc); reason = (ConvertTo-SIDataHealthWireReason ([string]$_.Reason)) } }) }
    # the size limit: cut reports (then sources) until the record fits, and say so
    $json = ConvertTo-Json -InputObject $r -Depth 8 -Compress
    while ([Text.Encoding]::UTF8.GetByteCount($json) -gt $w.MaxWireBytes -and (@($r.reports).Count -gt 0 -or @($r.sources).Count -gt 0)) {
        if (@($r.reports).Count -gt 0) { $r.reports = @($r.reports | Select-Object -First ([Math]::Max(0, @($r.reports).Count - 10))) }
        else { $r.sources = @($r.sources | Select-Object -First ([Math]::Max(0, @($r.sources).Count - 5))) }
        $r.truncated = $true
        $json = ConvertTo-Json -InputObject $r -Depth 8 -Compress
    }
    [pscustomobject]$r
}

function ConvertTo-SIDataHealthWireChannel {
    <# PURE. A channel name as it may leave the install: SecurityInsight's own connector names as they are; anything else
       (a name the customer gave a connector) becomes 'connector'. #>
    param([AllowNull()][AllowEmptyString()][string]$Channel)
    $c = "$Channel".Trim().ToLowerInvariant()
    if ($c -in (Get-SIDataHealthKnownChannels)) { return $c }
    'connector'
}

function ConvertTo-SIDataHealthWireReason {
    <# PURE. An override's reason on the wire: no reason text leaves the install (it may name people or systems) -- only
       whether one was given. #>
    param([AllowNull()][AllowEmptyString()][string]$Reason)
    if ("$Reason".Trim()) { 'given' } else { '' }
}

function Get-SIDataHealthKnownChannels {
    <# PURE. SecurityInsight's own data-out channel names (connectors whose name SecurityInsight gives). #>
    @('servicenow-cmdb', 'cmdb-sql', 'asset-tagging', 'servicenow', 'sql', 'rest', 'asset-vulnerabilities',
      'data-out-excel-ci', 'data-out-excel-findings-detailed', 'data-out-excel-findings-summary', 'data-out-excel-records',
      'data-out-servicenow-ci', 'data-out-servicenow-vulnerable-item')
}

function Test-SIDataHealthSendEnabled {
    <#
        PURE. Does the health record go to Invardia? framework §12.22: a new uplink kind is used only after Invardia confirmed
        it through one ring 0 call, and has a switch that turns it off without a release. SI_Telemetry_SendHealth (or the
        environment variable SI_TELEMETRY_SENDHEALTH). ON by default since Invardia's intake for 'health' is live (accepted since
        2026-10-15, confirmed 2026-10-18 for CR2): an install sends unless the setting or the variable turns it off.
    #>
    param([AllowNull()]$Value = $global:SI_Telemetry_SendHealth, [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_TELEMETRY_SENDHEALTH)
    foreach ($v in @($Value, $EnvValue)) {
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { return $v }
        $s = ([string]$v).Trim().Trim('$').ToLowerInvariant()
        if (-not $s) { continue }
        return ($s -in @('true', '1', 'on', 'yes', 'enabled'))
    }
    $true
}

function Get-SIDataHealthSendSkipReason {
    <#
        PURE. Why the health record for Invardia is NOT sent this time, as ONE plain line -- or '' when it is sent (an
        identified context, the switch on, telemetry on, not a dry run). A step that does not happen says so: a record that
        silently stayed home was the first live run's finding (2026-10-15). -Context: Get-SITelemetryContext (its Mode and
        AnonymousReason); -ContextError: why the context could not be built.
    #>
    param([bool]$SendEnabled, [bool]$TelemetryEnabled = $true, [switch]$DryRun, [AllowNull()]$Context, [AllowNull()][AllowEmptyString()][string]$ContextError)
    $p = 'The health record for Invardia is not sent: '
    if ($DryRun) { return $p + 'this is a dry run.' }
    if (-not $SendEnabled) { return $p + 'it is switched off (SI_Telemetry_SendHealth).' }
    if (-not $TelemetryEnabled) { return $p + 'telemetry to Invardia is switched off for this install (SI_Telemetry_Enabled).' }
    if ("$ContextError".Trim()) { return $p + ('what this install reports as could not be read ({0}).' -f "$ContextError".Trim()) }
    if ($null -eq $Context) { return $p + 'what this install reports as could not be read.' }
    if ([string]$Context.Mode -ne 'identified') {
        $why = ''; if ($Context.PSObject.Properties['AnonymousReason']) { $why = "$($Context.AnonymousReason)".Trim() }
        return $p + ('this install reports to Invardia without its identity (anonymously), and only an identified install sends one{0}.' -f $(if ($why) { ' -- ' + $why } else { '' }))
    }
    ''
}

function Format-SIDataHealthCoverage {
    <#
        PURE. What the cycle could NOT check, for the line next to the state -- '' when every source and report it uses was
        checked, else e.g. '4 of 6 sources not checked'. A source not used here ('not-used') is not counted either way. The
        state stays what the state rule says (Step-SIDataHealthState); this only makes sure a Healthy that rests on part of
        the sources never reads as a bare Healthy.
    #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    $used = @(@($Results) | Where-Object { $_ -and [string]$_.Verdict -ne 'not-used' })
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($k in @(@('source', 'source', 'sources'), @('report', 'report', 'reports'))) {
        $all = @($used | Where-Object { [string]$_.Kind -eq $k[0] })
        $nc = @($all | Where-Object { [string]$_.Verdict -eq 'not-checked' })
        if ($nc.Count) { $parts.Add(('{0} of {1} {2} not checked' -f $nc.Count, $all.Count, $(if ($all.Count -eq 1) { $k[1] } else { $k[2] }))) }
    }
    ($parts.ToArray() -join ', ')
}

function Test-SIDataHealthEnabled {
    <# PURE. Is the daily check on? SI_DataHealth_Enabled, default ON (it only reads). #>
    param([AllowNull()]$Value = $global:SI_DataHealth_Enabled)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim().Trim('$').ToLowerInvariant()
    if (-not $s) { return $true }
    -not ($s -in @('false', '0', 'off', 'no', 'disabled'))
}
