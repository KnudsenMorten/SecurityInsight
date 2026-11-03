#Requires -Version 5.1
<#
    SecurityInsight -- THE INSTALL'S LASTING ID ON ITS CALLS TO INVARDIA (Invardia S16, agreed 2026-11-01; the same contract
    PIM 3.0.14 runs).

    THE ID. One per install: the Key Vault secret SI-InstallId -- the GUID the licence request (SI-LicenceRequest.ps1)
    created ONCE, at the install's first knock, kept next to the licence and sent as the knock body's installId on every knock
    since. It is what Invardia already knows the install by. An update, a restart or a new container never replaces it (it
    lives in the install's Key Vault, not in the image or on a disk; a reinstall that keeps the vault keeps the id). It is
    CREATED ONCE when missing -- by the licence knock and (Invardia 2026-11-01) by the uplink heartbeat job -- with the same
    code (Resolve-SIInvardiaInstallId: a GUID, written, read back), and never rewritten. Every other caller only READS it.
    No id stored / not readable / not a GUID = NO header and NO field -- never an empty, a placeholder or a made-up value
    (a wrong id would lock the install key at Invardia).

    NOT the anonymous telemetry id (Get-SITelemetryInstallId: <state>\install-id, or derived from the storage account in a
    container). That one identifies nothing but "the same Community install as last time"; the two are never joined.

    WHERE IT GOES:
      header X-Invardia-Install-Id (lower-case GUID) on the manifest pull (SI-InvardiaUpdate.ps1 Request-SIInvardiaManifest)
                                     and the licence knock (SI-LicenceRequest.ps1, POST /api/licence-requests);
      field  InstallId on every IDENTIFIED uplink record -- heartbeat, run, guard (SI-TelemetrySend.ps1,
                                     SI-Guard.ps1, SI-GuardHeal.ps1; the health record's own installId, SI-DataHealth.ps1);
      never on the setup report (Kind setup), an anonymous record, the key claim, the licence pull, the install-run tracking
      or the update-now signal.

    PURE helpers, no network. PS 5.1 and 7.
#>

# The names are LITERALS inside each function (no $script: state): these functions are loaded by one script and called from
# another's scope (an engine's own script, the updater), where a file-level variable would be empty.

function ConvertTo-SIInvardiaInstallId {
    <# PURE. A GUID (any case, trimmed) -> its lower-case 8-4-4-4-12 text; anything else ($null, '', '-', not a GUID) -> ''. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $t = "$Value".Trim().ToLowerInvariant()
    if ($t -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $t }
    return ''
}

function Select-SIInvardiaFirstInstallId {
    <#
        PURE. FIRST WRITE WINS (Invardia 2026-11-01): from the versions of SI-InstallId (-Versions: objects with Value, Enabled,
        Created, Version), the OLDEST ENABLED version that holds a GUID is the install's id -- whichever side wrote it. Order:
        Created ascending, then the version id (ordinal) so two versions made in the same second are ordered the same way by
        every reader. Returns @{ First (the id, lower-cased, '' = none); Newest (the newest enabled version's value as stored);
        Count (enabled versions) }.
    #>
    param([AllowNull()][object[]]$Versions)
    # a seam that hands back its list as ONE object (a List, an array in an array) is read as its items
    $flat = foreach ($x in @($Versions)) { if ($x -is [System.Collections.IEnumerable] -and $x -isnot [string] -and $x -isnot [System.Collections.IDictionary]) { foreach ($y in $x) { $y } } else { $x } }
    $en = @(@($flat) | Where-Object { $null -ne $_ -and -not ($_.PSObject.Properties['Enabled'] -and $_.Enabled -eq $false) })
    $key = { param($x) $c = $x.Created; if ($c -is [datetime]) { $c.ToUniversalTime().Ticks } elseif ($null -ne $c -and "$c" -match '^\d+$') { [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds([double]"$c").Ticks } else { [long]::MaxValue } }
    $sorted = @($en | Sort-Object -Property @{ Expression = { & $key $_ } }, @{ Expression = { [string]$_.Version } })
    $first = ''
    foreach ($x in $sorted) { $g = ConvertTo-SIInvardiaInstallId $x.Value; if ($g) { $first = $g; break } }
    [pscustomobject]@{ First = $first; Newest = $(if ($sorted.Count) { [string]$sorted[-1].Value } else { $null }); Count = $sorted.Count }
}

function Get-SIInvardiaKvInstallIdVersions {
    <#
        The versions of a Key Vault secret over REST (engine\_shared\SI-AzRest.ps1, the run's own sign-in): GET
        /secrets/<name>/versions (every page), then each enabled version's value (at most 50, oldest first, plus the newest).
        Returns @(@{ Value; Enabled; Created; Version }); none (404) = @(). THROWS when the vault cannot be read -- a caller
        never takes an unreadable vault for an empty one.
    #>
    param([Parameter(Mandatory)][string]$VaultName, [string]$Name = 'SI-InstallId')
    $uri = 'https://{0}.vault.azure.net/secrets/{1}/versions?api-version=7.4&maxresults=25' -f $VaultName, [uri]::EscapeDataString($Name)
    $items = New-Object System.Collections.Generic.List[object]
    $pages = 0
    while ($uri -and $pages -lt 20) {
        $pages++
        $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -What ("the versions of Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
        if (-not $r) { break }
        $j = $r.Content | ConvertFrom-Json
        foreach ($v in @($j.value)) { if ($v) { $items.Add($v) } }
        $uri = if ($j.PSObject.Properties['nextLink'] -and "$($j.nextLink)" -match '^https://') { [string]$j.nextLink } else { $null }
    }
    $rows = @($items | ForEach-Object {
        $ver = ([string]$_.id).TrimEnd('/').Split('/')[-1]
        [pscustomobject]@{ Value = $null; Enabled = -not ($_.attributes -and $_.attributes.enabled -eq $false); Created = $(if ($_.attributes) { $_.attributes.created } else { $null }); Version = $ver }
    } | Where-Object { $_.Enabled })
    $order = @($rows | Sort-Object -Property @{ Expression = { if ("$($_.Created)" -match '^\d+$') { [double]"$($_.Created)" } else { [double]::MaxValue } } }, @{ Expression = { [string]$_.Version } })
    $want = @($order | Select-Object -First 50) + @($order | Select-Object -Last 1)
    $seen = @{}
    foreach ($x in $want) {
        if ($seen.ContainsKey([string]$x.Version)) { continue }; $seen[[string]$x.Version] = $true
        # only the versions that can decide: the 50 oldest (the first GUID is among them) and the newest (the converge check)
        $raw = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name -Version $x.Version
        if ($raw) { $x.Value = [string]$raw.value }
    }
    # one object per version (an empty vault returns nothing): callers wrap the call in @()
    return $order
}

function Get-SIInvardiaInstallId {
    <#
        This install's lasting id, READ ONLY. With -ReadVersions { param($Name) } (the versions of SI-InstallId): the OLDEST
        enabled version holding a GUID (first write wins); when the versions cannot be read, the current value through
        -ReadSecret { param($Name) }. A GUID comes back lower-cased; none / not a GUID / the read failed -> ''. Never creates
        it, never throws.
    #>
    param([scriptblock]$ReadSecret, [scriptblock]$ReadVersions)
    if ($ReadVersions) {
        try { $p = Select-SIInvardiaFirstInstallId -Versions @(& $ReadVersions 'SI-InstallId'); if ($p.First -or $p.Count) { return $p.First } } catch { }
    }
    if (-not $ReadSecret) { return '' }
    $v = $null
    try { $v = & $ReadSecret 'SI-InstallId' } catch { return '' }
    return (ConvertTo-SIInvardiaInstallId $v)
}

function Resolve-SIInvardiaInstallId {
    <#
        Invardia 2026-11-01 (S16, answer 2): the lasting id, CREATED ONCE when it is missing -- by the licence knock and by the
        uplink (heartbeat) job, with the same code and format: [guid]::NewGuid().ToString(), written to SI-InstallId.
          * FIRST WRITE WINS (-ReadVersions): the id is the OLDEST enabled version of SI-InstallId that holds a GUID
            (Select-SIInvardiaFirstInstallId), whichever side wrote it. A side that just wrote reads back the same way, so
            when the knock and the uplink create at once both send the first value. When a later version holds ANOTHER GUID
            (the losing write of such a race), the first value is written once more as the current version, so a plain read
            (the engines' status reports) gives the same id -- the id itself never changes. One version (every install
            before a race) behaves exactly as a plain read.
          * without -ReadVersions, or when the versions cannot be read: the current value (-ReadSecret), as before;
          * a stored GUID is KEPT (returned lower-cased) -- never replaced by another id;
          * a stored value that is not a GUID is left as it is and '' comes back, unless -ReplaceNotGuid (the knock's rule
            since #239: its body needs a GUID);
          * the vault cannot be read or written -> '' (no id this time), never a throw.
        -ReadSecret { param($Name) } / -WriteSecret { param($Name, $Value) } / -ReadVersions { param($Name) } -> @(@{ Value;
        Enabled; Created; Version }).
    #>
    param([scriptblock]$ReadSecret, [scriptblock]$WriteSecret, [scriptblock]$ReadVersions, [switch]$ReplaceNotGuid)
    if ($ReadVersions) {
        $pick = { Select-SIInvardiaFirstInstallId -Versions @(& $ReadVersions 'SI-InstallId') }
        $p = $null
        try { $p = & $pick } catch { $p = $null }
        if ($null -ne $p) {
            $converge = {
                param($sel)
                $nw = ConvertTo-SIInvardiaInstallId $sel.Newest
                if ($WriteSecret -and $sel.First -and $nw -and $nw -ne $sel.First) { try { $null = & $WriteSecret 'SI-InstallId' $sel.First } catch { } }
            }
            if ($p.First) { & $converge $p; return $p.First }
            if ($null -ne $p.Newest -and "$($p.Newest)".Trim() -and -not $ReplaceNotGuid) { return '' }
            if (-not $WriteSecret) { return '' }
            $new = [guid]::NewGuid().ToString()
            try { $null = & $WriteSecret 'SI-InstallId' $new } catch { return '' }
            try { $p = & $pick } catch { return '' }
            if ($p.First) { & $converge $p }
            return [string]$p.First
        }
        # the versions could not be read: the plain read below (as before)
    }
    if (-not $ReadSecret) { return '' }
    $v = $null
    try { $v = & $ReadSecret 'SI-InstallId' } catch { return '' }
    $have = ConvertTo-SIInvardiaInstallId $v
    if ($have) { return $have }
    if ($null -ne $v -and "$v".Trim() -and -not $ReplaceNotGuid) { return '' }
    if (-not $WriteSecret) { return '' }
    $new = [guid]::NewGuid().ToString()
    try { $null = & $WriteSecret 'SI-InstallId' $new } catch { return '' }
    $back = $null
    try { $back = & $ReadSecret 'SI-InstallId' } catch { return '' }
    return (ConvertTo-SIInvardiaInstallId $back)
}
function Add-SIInvardiaInstallIdHeader {
    <# PURE. -Headers with X-Invardia-Install-Id = -InstallId added when it is a GUID (lower-case); unchanged otherwise. #>
    param([AllowNull()][System.Collections.IDictionary]$Headers, [AllowNull()][AllowEmptyString()][string]$InstallId = '')
    $h = if ($null -ne $Headers) { $Headers } else { @{} }
    $iid = ConvertTo-SIInvardiaInstallId $InstallId
    if ($iid) { $h['X-Invardia-Install-Id'] = $iid }
    return $h
}

function Add-SIUplinkInstallId {
    <#
        PURE (sets one field). An IDENTIFIED uplink record with -FieldName (default InstallId, the name PIM 3.0.14 sends) =
        -InstallId, lower-cased. Unchanged when the id is not a GUID, when the record is a setup report (Kind / kind 'setup'),
        or when it is $null. The caller decides identified vs anonymous: an anonymous record is never passed here.
    #>
    param([AllowNull()][object]$Record, [AllowNull()][AllowEmptyString()][string]$InstallId = '', [string]$FieldName = 'InstallId')
    if ($null -eq $Record) { return $Record }
    $iid = ConvertTo-SIInvardiaInstallId $InstallId
    if (-not $iid) { return $Record }
    if ($Record -is [System.Collections.IDictionary]) {
        foreach ($k in 'Kind', 'kind') { if ($Record.Contains($k) -and "$($Record[$k])" -eq 'setup') { return $Record } }
        $Record[$FieldName] = $iid
        return $Record
    }
    $kp = $Record.PSObject.Properties['Kind']
    if ($kp -and "$($kp.Value)" -eq 'setup') { return $Record }
    $Record | Add-Member -NotePropertyName $FieldName -NotePropertyValue $iid -Force
    return $Record
}
