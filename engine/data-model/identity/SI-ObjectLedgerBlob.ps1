#Requires -Version 5.1
<#
    SI v3 -- THE IDENTITY LEDGER, BACKED BY BLOB STORAGE INSTEAD OF SQL.

    🔑 WHY THIS EXISTS. The ledger is what turns a correlation id from `derived-provisional` into
    `ledger` -- minted once per real-world object and remembered -- and until it has one, EVERY id in
    the estate moves when correlation group membership changes. `Send-SIObjectMapRows`' own header
    records the measurement: adding one member moved a group from `exposuregraphnodeid:aaa` to
    `exposuregraphnodeid:000`, and departures are routine (one source timing out removed 51 assets from
    a snapshot on an ordinary day). A CI created from an id like that is duplicated on the next change.

    🔴 SO "NO LEDGER" IS NOT A COSMETIC GAP -- IT IS WHAT BLOCKS CMDB SCENARIO 2 ENTIRELY.
    The only store was Azure SQL, which drags in SCHEMA-1: `needsSchema: true` means migrations would
    run unattended on ~30 customers, and that is a decision nobody has taken. So the ledger was
    unreachable in practice and creation could never be safe.

    ✅ THE OBSERVATION THAT REMOVES THE BLOCKER: the ledger is not relational. It is one map,
    `identifier -> (correlation id, first seen)`, read WHOLE once per run and written once per run.
    `Get-SIObjectLedger`'s own docblock already says so -- *"read whole rather than queried per anchor
    ... one round trip against a table of this shape beats thousands"*. A store that can hold one
    document and swap it atomically satisfies the entire contract, and EVERY SI install already has
    one: the storage account the profilers stage through.

    🔒 WHAT THIS DOES NOT CHANGE. The SQL provider stays, unchanged and preferred when configured --
    a customer who has already stood one up keeps it, and its transaction is a stronger guarantee than
    an ETag. This is the option for everyone else, and it makes durable ids the DEFAULT rather than a
    provisioning project.

    ⚠️ CONCURRENCY IS REAL EVEN THOUGH CORRELATION IS SCHEDULED. Two runs overlapping (a manual run
    during the nightly one) would otherwise last-write-wins, and a lost merge is the exact state the
    SQL version spends a transaction to prevent -- anchors re-pointed at a survivor while the
    superseded record is missing means the connector never learns old -> new and ORPHANS a CI. So the
    write is ETag-conditional and a conflict FAILS LOUDLY rather than clobbering.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

$script:SILedgerBlobContainer = 'siledger'
$script:SILedgerBlobName      = 'object-identity.json'

function Get-SIObjectLedgerBlobStore {
    <#
        The blob store descriptor, or $null when no storage account is configured.

        $null is NOT an error -- it is "this install has no ledger", which stays a supported state.
        The ids are then honestly marked `derived-provisional` and the connector refuses to create,
        which is the behaviour that was always intended.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$AccountName = [string]$global:SI_StorageAccount,
        [Parameter()][string]$ContainerName,
        [Parameter()][object]$Context
    )
    if ([string]::IsNullOrWhiteSpace($AccountName) -and $null -eq $Context) { return $null }
    if ([string]::IsNullOrWhiteSpace($ContainerName)) {
        $ContainerName = if ($global:SI_LedgerContainer) { [string]$global:SI_LedgerContainer } else { $script:SILedgerBlobContainer }
    }

    if ($null -eq $Context) {
        # 🔒 The run's identity only -- SI has no account-key access to storage, and the ledger holds
        # the identity of every asset in the estate.
        $Context = New-SIStorageContext -AccountName $AccountName
    }

    [pscustomobject]@{
        Kind          = 'blob'
        Context       = $Context
        ContainerName = $ContainerName
        BlobName      = $(if ($global:SI_LedgerBlobName) { [string]$global:SI_LedgerBlobName } else { $script:SILedgerBlobName })
    }
}

function Set-SIObjectLedgerStoreSuperseded {
    <#
        Carry the document's EXISTING supersessions on the store, where Save-SIObjectLedgerToBlob merges
        them (#132). The read only ever loaded `Entries`, so every save rewrote `Superseded` with just this
        run's old->new pairs and ERASED the rest -- and a lost supersession is exactly what the save's own
        comment says orphans a CI permanently. The provider hands the SAME store object to read and save,
        so attaching it here is all the wiring the save already expected.
    #>
    param([Parameter(Mandatory)]$Store, $Doc)
    $sup = @()
    if ($null -ne $Doc -and $Doc.PSObject.Properties['Superseded'] -and $null -ne $Doc.Superseded) {
        $sup = @($Doc.Superseded | Where-Object { $null -ne $_ })
    }
    Add-Member -InputObject $Store -NotePropertyName 'Superseded' -NotePropertyValue $sup -Force
}

function Get-SIObjectLedgerFromBlob {
    <#
        The whole ledger as the hashtable Resolve-SIObjectIdentity expects:
        "type|value" -> @{ CorrelationId; FirstSeen }.

        Returns an EMPTY ledger plus a $null ETag on first ever run -- which is correct and is how the
        first run mints every id. It must not be an error: "the ledger does not exist yet" and "the
        ledger could not be read" are different facts, and only the second may stop a run.

        🪤 A READ FAILURE IS NOT AN EMPTY LEDGER, AND CONFLATING THEM IS CATASTROPHIC. An empty ledger
        makes the next run mint NEW ids for every object in the estate, so every existing CI silently
        loses its binding and the connector proposes creating the whole estate again. So a genuine
        read error throws; only a genuinely absent blob returns empty.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Store)

    $ledger = @{}
    $result = [pscustomobject]@{ Ledger = $ledger; ETag = $null; Existed = $false }
    if ($null -eq $Store) { return $result }

    if ($Store.Context -and $Store.Context.Mode -eq 'Mock') {
        $blobs = $Store.Context.MockState.Blobs
        if ($blobs.ContainsKey($Store.ContainerName) -and $blobs[$Store.ContainerName].ContainsKey($Store.BlobName)) {
            $json = [System.Text.Encoding]::UTF8.GetString($blobs[$Store.ContainerName][$Store.BlobName])
            $result.Existed = $true
            $result.ETag = 'mock-etag'
            $doc = $json | ConvertFrom-Json
            foreach ($e in @($doc.Entries)) {
                $k = '{0}|{1}' -f ([string]$e.Type).ToLowerInvariant(), ([string]$e.Value).ToLowerInvariant()
                $ledger[$k] = @{ CorrelationId = [string]$e.CorrelationId; FirstSeen = [datetime]$e.FirstSeen }
            }
            Set-SIObjectLedgerStoreSuperseded -Store $Store -Doc $doc
        }
        return $result
    }

    $blob = $null
    try {
        $blob = Get-SIAzStorageBlob -Container $Store.ContainerName -Blob $Store.BlobName -Context $Store.Context.AzContext -ErrorAction Stop
    } catch {
        # Distinguish "not there yet" from "cannot read". Only the first is a normal first run.
        $msg = [string]$_.Exception.Message
        if ($msg -match 'does not exist|NotFound|ResourceNotFound|BlobNotFound|ContainerNotFound') { return $result }
        throw ("ledger(blob): could not read {0}/{1} -- {2}. Refusing to treat this as an EMPTY ledger: that would re-mint an id for every object in the estate and orphan every CI already bound." -f `
            $Store.ContainerName, $Store.BlobName, $msg)
    }

    $result.Existed = $true
    $result.ETag = [string]$blob.ICloudBlob.Properties.ETag

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-ledger-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    try {
        $null = Get-SIAzStorageBlobContent -Container $Store.ContainerName -Blob $Store.BlobName `
                    -Context $Store.Context.AzContext -Destination $tmp -Force -ErrorAction Stop
        $json = Get-Content -LiteralPath $tmp -Raw -Encoding UTF8
        if (-not [string]::IsNullOrWhiteSpace($json)) {
            $doc = $json | ConvertFrom-Json -ErrorAction Stop
            foreach ($e in @($doc.Entries)) {
                if ($null -eq $e) { continue }
                $k = '{0}|{1}' -f ([string]$e.Type).ToLowerInvariant(), ([string]$e.Value).ToLowerInvariant()
                $ledger[$k] = @{ CorrelationId = [string]$e.CorrelationId; FirstSeen = [datetime]$e.FirstSeen }
            }
            Set-SIObjectLedgerStoreSuperseded -Store $Store -Doc $doc
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    $result
}

function Save-SIObjectLedgerToBlob {
    <#
        Persist one run's decisions: new anchors, and any merge supersessions.

        🔒 READ-MODIFY-WRITE UNDER AN ETAG, WHICH IS THIS STORE'S VERSION OF THE SQL TRANSACTION.
        The whole document is swapped in one PUT, so a half-written merge is not representable -- the
        blob is either the old document or the new one. What the ETag adds is the case a single PUT
        cannot cover: another run having written in between. That is refused rather than overwritten,
        because silently discarding the other run's merges recreates exactly the orphaned-CI state the
        atomicity exists to prevent.

        Anchors are UPSERTed by (type, value) -- an anchor already present under the same id is the
        normal case on every run after the first and must be a no-op, not a duplicate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Store,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Decisions,
        [Parameter()][AllowEmptyCollection()][object[]]$Superseded,
        [Parameter()][datetime]$Now = ([datetime]::UtcNow),
        # The ETag read at the start of this run. Passing it is what makes the write conditional.
        [Parameter()][AllowNull()][string]$IfMatchETag,
        # The ledger as read at the start of the run, so this function does not re-read and widen the
        # window between check and write.
        [Parameter()][hashtable]$CurrentLedger = @{}
    )

    if ($null -eq $Store) { return [pscustomobject]@{ AnchorsWritten = 0; SupersededWritten = 0; Skipped = $true } }

    # ---- merge the run's decisions into the map we read ----
    $entries = @{}
    foreach ($k in @($CurrentLedger.Keys)) {
        $v = $CurrentLedger[$k]
        $parts = $k -split '\|', 2
        $entries[$k] = [pscustomobject]@{
            Type = $parts[0]; Value = $(if ($parts.Count -gt 1) { $parts[1] } else { '' })
            CorrelationId = [string]$v.CorrelationId; FirstSeen = [datetime]$v.FirstSeen; LastSeen = $Now
        }
    }

    $written = 0
    foreach ($d in @($Decisions)) {
        if ($null -eq $d -or [string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) { continue }
        foreach ($n in @($d.NewIdentifiers)) {
            if ($null -eq $n) { continue }
            $ty = [string]$n.Type; $va = [string]$n.Value
            if ([string]::IsNullOrWhiteSpace($ty) -or [string]::IsNullOrWhiteSpace($va)) { continue }
            $k = '{0}|{1}' -f $ty.ToLowerInvariant(), $va.ToLowerInvariant()
            if ($entries.ContainsKey($k)) {
                # 🔑 FirstSeen IS NEVER MOVED. It is the evidence of when this object was first known,
                # and re-stamping it on every run would erase the only thing that makes the ledger a
                # history rather than a cache.
                $entries[$k].CorrelationId = [string]$n.CorrelationId
                $entries[$k].LastSeen      = $Now
            } else {
                $entries[$k] = [pscustomobject]@{
                    Type = $ty; Value = $va; CorrelationId = [string]$n.CorrelationId
                    FirstSeen = $Now; LastSeen = $Now
                }
            }
            $written++
        }
    }

    # Supersessions are APPENDED and never rewritten -- old -> new is how a connector re-points a CI
    # whose object was merged into another, and losing it orphans that CI permanently.
    $sup = New-Object System.Collections.ArrayList
    $existingSup = @{}
    if ($Store.PSObject.Properties['Superseded'] -and $Store.Superseded) {
        foreach ($s in @($Store.Superseded)) { if ($s) { $existingSup[[string]$s.OldId] = $true; [void]$sup.Add($s) } }
    }
    $supWritten = 0
    foreach ($s in @($Superseded)) {
        if ($null -eq $s) { continue }
        $old = [string]$s.OldId
        if ([string]::IsNullOrWhiteSpace($old) -or $existingSup.ContainsKey($old)) { continue }
        [void]$sup.Add([pscustomobject]@{ OldId = $old; NewId = [string]$s.NewId; SupersededAt = $Now
                                          Reason = 'merge: anchors resolved to two ids' })
        $existingSup[$old] = $true
        $supWritten++
    }

    $doc = [pscustomobject]@{
        SchemaVersion = 1
        WrittenUtc    = $Now
        Entries       = @($entries.Values)
        Superseded    = @($sup.ToArray())
    }
    $json = ConvertTo-Json -InputObject $doc -Depth 6

    if ($Store.Context -and $Store.Context.Mode -eq 'Mock') {
        if (-not $Store.Context.MockState.Blobs.ContainsKey($Store.ContainerName)) {
            $Store.Context.MockState.Blobs[$Store.ContainerName] = @{}
        }
        $Store.Context.MockState.Blobs[$Store.ContainerName][$Store.BlobName] = [System.Text.Encoding]::UTF8.GetBytes($json)
        return [pscustomobject]@{ AnchorsWritten = $written; SupersededWritten = $supWritten; Entries = @($entries.Values).Count }
    }

    $existing = Get-SIAzStorageContainer -Name $Store.ContainerName -Context $Store.Context.AzContext -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-SIAzStorageContainer -Name $Store.ContainerName -Context $Store.Context.AzContext -Permission Off | Out-Null
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-ledger-out-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    try {
        Set-Content -LiteralPath $tmp -Value $json -Encoding UTF8
        $params = @{
            File      = $tmp
            Container = $Store.ContainerName
            Blob      = $Store.BlobName
            Context   = $Store.Context.AzContext
            Force     = $true
            ErrorAction = 'Stop'
        }
        # 🔴 THE CONDITIONAL WRITE. Without -IfMatchETag two overlapping runs last-write-wins and one
        # run's merges vanish silently.
        if (-not [string]::IsNullOrWhiteSpace($IfMatchETag)) {
            # Az.Storage's AccessCondition + UploadFromFile (Module), or a PUT with If-Match (Rest).
            Set-SIAzStorageBlobContentIfMatch -File $tmp -Container $Store.ContainerName -Blob $Store.BlobName -Context $Store.Context.AzContext -IfMatchETag $IfMatchETag
        } else {
            $null = Set-SIAzStorageBlobContent @params
        }
    } catch {
        $msg = [string]$_.Exception.Message
        if ($msg -match 'ConditionNotMet|412|condition specified using HTTP conditional header') {
            throw ("ledger(blob): another run wrote the ledger while this one was working, so this run's decisions were NOT saved. Nothing was overwritten -- re-run correlation. (Overwriting would discard the other run's merges and orphan any CI they re-pointed.)")
        }
        throw
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    [pscustomobject]@{ AnchorsWritten = $written; SupersededWritten = $supWritten; Entries = @($entries.Values).Count }
}
