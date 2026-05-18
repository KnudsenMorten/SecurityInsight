#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- shared storage context.

    One Azure Storage account holds all v2.2 transient state:
      * Table Storage  -- fingerprint cache
      * Blob Storage   -- stage payload staging (JSONL shards)
      * Queue Storage  -- worker coordination

    The context is created once per orchestrator run and threaded through
    every stage. Real-Azure mode uses Az.Storage; Mock mode keeps everything
    in-memory hashtables so unit tests can run without credentials.
#>

function New-SIStorageContext {
    [CmdletBinding(DefaultParameterSetName = 'KeyAuth')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'KeyAuth')]
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [string]$AccountName,

        [Parameter(Mandatory, ParameterSetName = 'KeyAuth')]
        [string]$AccountKey,

        # OAuth mode: blob/queue use Az.Storage's -UseConnectedAccount;
        # table uses bearer-token REST. Caller is responsible for having
        # called Connect-AzAccount (-Identity / -ServicePrincipal / interactive)
        # with a principal that has Storage Blob/Table/Queue Data Contributor
        # on the account.
        [Parameter(Mandatory, ParameterSetName = 'OAuth')]
        [switch]$UseOAuth,

        [Parameter(Mandatory, ParameterSetName = 'Mock')]
        [switch]$Mock
    )

    if ($PSCmdlet.ParameterSetName -eq 'Mock') {
        return [pscustomobject]@{
            Mode        = 'Mock'
            AccountName = '<mock>'
            AccountKey  = $null
            AzContext   = $null
            MockState   = @{
                Tables = @{}        # tableName -> @{ "<pk>|<rk>" = entity }
                Blobs  = @{}        # containerName -> @{ blobName = bytes }
                Queues = @{}        # queueName -> [System.Collections.ArrayList]
            }
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'OAuth') {
        $azCtx = New-AzStorageContext -StorageAccountName $AccountName -UseConnectedAccount
        return [pscustomobject]@{
            Mode        = 'OAuth'
            AccountName = $AccountName
            AccountKey  = $null
            AzContext   = $azCtx
            MockState   = $null
        }
    }

    $azCtx = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
    [pscustomobject]@{
        Mode        = 'KeyAuth'
        AccountName = $AccountName
        AccountKey  = $AccountKey
        AzContext   = $azCtx
        MockState   = $null
    }
}

function Get-SITableAuthorizationHeader {
    <#
        Returns the Authorization header value for an Azure Table REST call.
        Takes the request URL directly so the canonicalized resource is
        derived from [Uri].AbsolutePath -- this guarantees we sign exactly
        what .NET will put on the wire.
        SharedKeyLite for Table service: StringToSign = Date + "\n" + CanonicalizedResource
        Query string is excluded from canon (per spec), which AbsolutePath gives us for free.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Date,
        [Parameter(Mandatory)][string]$Url
    )
    if ($Context.Mode -eq 'OAuth') {
        $tok = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/'
        $tokStr = if ($tok.Token -is [System.Security.SecureString]) {
            [System.Net.NetworkCredential]::new('', $tok.Token).Password
        } else { $tok.Token }
        return ('Bearer ' + $tokStr)
    }
    $uri = [Uri]$Url
    $canon = '/{0}{1}' -f $Context.AccountName, $uri.AbsolutePath
    $stringToSign = ($Date + "`n" + $canon)
    $sig = Get-SISharedKeySignature -AccountName $Context.AccountName -AccountKey $Context.AccountKey -StringToSign $stringToSign
    return ('SharedKeyLite {0}:{1}' -f $Context.AccountName, $sig)
}

function Get-SISharedKeySignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][string]$AccountKey,
        [Parameter(Mandatory)][string]$StringToSign
    )

    $keyBytes  = [Convert]::FromBase64String($AccountKey)
    $hmac      = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $keyBytes
        $sigBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($StringToSign))
        return [Convert]::ToBase64String($sigBytes)
    }
    finally {
        $hmac.Dispose()
    }
}

function ConvertTo-SIRfc1123Date {
    param([datetime]$When = [datetime]::UtcNow)
    $when.ToUniversalTime().ToString('R')
}

# Azure Table key constraints: cannot contain / \ # ? control chars (0x00-0x1F,
# 0x7F-0x9F). We also strip apostrophe ('), double-quote ("), space, +, and %
# even though Table accepts them in keys -- our REST URL form
#   /Tbl(PartitionKey='pk',RowKey='rk')
# uses ' as the OData literal delimiter, so a raw ' inside the key terminates
# the literal early and the server returns 400 Bad Request. Space/+ break URL
# parsing (space->+, + ambiguous), and % invalidates URL-encoded sequences.
# Hit in the wild on Identity engine when ENTRA_Department / OU contained
# names like "Tom's Team" or "Borns Center" (Danish o-stroke).
# The mapping is deterministic, lowercase, and human-debuggable in Storage Explorer.
function ConvertTo-SISafeKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)
    return ($Key -replace '[/\\#?''"+% \u0000-\u001f\u007f-\u009f]', '_').ToLowerInvariant()
}

