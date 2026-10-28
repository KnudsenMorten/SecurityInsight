#Requires -Version 5.1
<#
    SI v3 -- WHICH LEDGER STORE, chosen in one place.

    The ledger's CONTRACT is two operations: read the whole map, write one run's decisions. Two stores
    satisfy it -- Azure SQL (`SI-ObjectLedgerStore.ps1`) and blob (`SI-ObjectLedgerBlob.ps1`) -- and
    the correlation engine should not know which it got.

    🔒 PRECEDENCE, AND IT IS NOT ARBITRARY:
      1. SQL, when SI_LedgerSqlServer + SI_LedgerDatabase are set. A customer who has stood one up
         keeps it, and its TRANSACTION is a stronger guarantee than an ETag.
      2. BLOB, when a storage account is configured -- which every SI install already has, because the
         profilers stage through it. This is what makes a durable id the DEFAULT.
      3. NONE. Still supported, still honest: ids are marked `derived-provisional` and the CMDB
         connector refuses to create from them.

    🪤 THE ONE THING THIS MUST NOT DO IS SILENTLY FALL BACK. If SQL is CONFIGURED and unreachable,
    dropping to blob would split the ledger across two stores -- ids minted in one are unknown to the
    other, so the next run re-mints them and every CI bound to the old id is orphaned. That is worse
    than not writing at all. A configured store that fails is an ERROR, never a fallback.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

function Get-SIObjectLedgerProvider {
    <#
        Returns @{ Kind = 'sql' | 'blob'; Connection|Store; Description } or $null.

        Never throws for "not configured" -- that is a supported state. It DOES throw when a store is
        configured and cannot be opened, for the reason in the header.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$SqlServer   = [string]$global:SI_LedgerSqlServer,
        [Parameter()][string]$SqlDatabase = [string]$global:SI_LedgerDatabase,
        [Parameter()][string]$StorageAccount = [string]$global:SI_StorageAccount,
        # Test seam: an already-built storage context (including a Mock one).
        [Parameter()][object]$StorageContext
    )

    if (-not [string]::IsNullOrWhiteSpace($SqlServer) -and -not [string]::IsNullOrWhiteSpace($SqlDatabase)) {
        $conn = Get-SIObjectLedgerConnection -Server $SqlServer -Database $SqlDatabase
        if ($null -eq $conn) { return $null }
        return [pscustomobject]@{ Kind = 'sql'; Connection = $conn; Store = $null
            Description = ("Azure SQL {0}/{1}" -f $SqlServer, $SqlDatabase) }
    }

    if (-not [string]::IsNullOrWhiteSpace($StorageAccount) -or $null -ne $StorageContext) {
        $store = Get-SIObjectLedgerBlobStore -AccountName $StorageAccount -Context $StorageContext
        if ($null -eq $store) { return $null }
        return [pscustomobject]@{ Kind = 'blob'; Connection = $null; Store = $store
            Description = ("blob {0}/{1}" -f $store.ContainerName, $store.BlobName) }
    }

    $null
}

function Read-SIObjectLedger {
    <#
        The whole ledger, plus whatever the store needs to write it back safely.

        Returns @{ Ledger; ETag; Existed }. `ETag` is $null for SQL, which does not need one -- its
        write is a transaction. The shape is shared so the caller has no branch.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Provider)

    if ($null -eq $Provider) { return [pscustomobject]@{ Ledger = @{}; ETag = $null; Existed = $false } }
    switch ($Provider.Kind) {
        'sql'  { return [pscustomobject]@{ Ledger = (Get-SIObjectLedger -Connection $Provider.Connection); ETag = $null; Existed = $true } }
        'blob' { return (Get-SIObjectLedgerFromBlob -Store $Provider.Store) }
    }
    [pscustomobject]@{ Ledger = @{}; ETag = $null; Existed = $false }
}

function Write-SIObjectLedger {
    <#
        Persist one run's decisions through whichever store is configured.

        🔒 `-CurrentLedger` and `-IfMatchETag` come from the SAME read that produced the decisions.
        Re-reading here would widen the window between check and write, which is the whole thing the
        ETag exists to close.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Provider,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Decisions,
        [Parameter()][AllowEmptyCollection()][object[]]$Superseded,
        [Parameter()][datetime]$Now = ([datetime]::UtcNow),
        [Parameter()][AllowNull()][string]$IfMatchETag,
        [Parameter()][hashtable]$CurrentLedger = @{}
    )

    if ($null -eq $Provider) { return [pscustomobject]@{ AnchorsWritten = 0; SupersededWritten = 0; Skipped = $true } }
    switch ($Provider.Kind) {
        'sql' {
            return (Save-SIObjectLedger -Connection $Provider.Connection -Decisions $Decisions -Superseded $Superseded -Now $Now)
        }
        'blob' {
            return (Save-SIObjectLedgerToBlob -Store $Provider.Store -Decisions $Decisions -Superseded $Superseded `
                        -Now $Now -IfMatchETag $IfMatchETag -CurrentLedger $CurrentLedger)
        }
    }
    [pscustomobject]@{ AnchorsWritten = 0; SupersededWritten = 0; Skipped = $true }
}

function Close-SIObjectLedgerProvider {
    <# SQL holds an open connection; blob holds nothing. Symmetric close so the caller has no branch. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Provider)
    if ($null -eq $Provider) { return }
    if ($Provider.Kind -eq 'sql' -and $Provider.Connection) {
        try { $Provider.Connection.Close() } catch { }
        try { $Provider.Connection.Dispose() } catch { }
    }
}
