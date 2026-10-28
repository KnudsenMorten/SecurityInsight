#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- shared storage context.

    One Azure Storage account holds all v2.2 transient state:
      * Table Storage  -- fingerprint cache
      * Blob Storage   -- stage payload staging (JSONL shards)
      * Queue Storage  -- worker coordination

    The context is created once per orchestrator run and threaded through
    every stage. Real-Azure mode reaches the account over REST with the run's
    identity; Mock mode keeps everything in in-memory hashtables so unit tests
    can run without credentials.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function New-SIStorageContext {
    <#
        The storage account is reached ONLY with the run's signed-in identity (OAuth bearer
        token): the managed identity in a container; the app identity (certificate or secret)
        or a managed identity on a VM. That identity holds the Storage Blob / Queue / Table Data
        Contributor roles on the account. There is no account-key mode.
        -UseOAuth is accepted for call sites that still pass it; it changes nothing.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Identity')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Identity')]
        [string]$AccountName,

        [Parameter(ParameterSetName = 'Identity')]
        [switch]$UseOAuth,

        [Parameter(Mandatory, ParameterSetName = 'Mock')]
        [switch]$Mock
    )

    if ($PSCmdlet.ParameterSetName -eq 'Mock') {
        return [pscustomobject]@{
            Mode        = 'Mock'
            AccountName = '<mock>'
            AzContext   = $null
            MockState   = @{
                Tables = @{}        # tableName -> @{ "<pk>|<rk>" = entity }
                Blobs  = @{}        # containerName -> @{ blobName = bytes }
                Queues = @{}        # queueName -> [System.Collections.ArrayList]
            }
        }
    }

    $azCtx = New-SIAzStorageContext -StorageAccountName $AccountName -UseConnectedAccount
    return [pscustomobject]@{
        Mode        = 'OAuth'
        AccountName = $AccountName
        AzContext   = $azCtx
        MockState   = $null
    }
}

function Get-SITableAuthorizationHeader {
    <#
        Returns the Authorization header value for an Azure Table REST call: a bearer token for
        https://storage.azure.com/ issued to the run's identity. -Date / -Url stay so call sites
        do not change; the token does not depend on them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$Date,
        [Parameter(Mandatory)][string]$Url
    )
    $tok = Get-SIAzAccessToken -ResourceUrl 'https://storage.azure.com/'
    $tokStr = if ($tok.Token -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $tok.Token).Password
    } else { $tok.Token }
    return ('Bearer ' + $tokStr)
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
    # First-line sanitization: replace the chars Azure Tables outright forbids
    # in PK/RK (slash/backslash/hash/question/quotes/plus/percent/space/control).
    $sanitized = ($Key -replace '[/\\#?''"+% \u0000-\u001f\u007f-\u009f]', '_').ToLowerInvariant()
    # v2.2.371 -- belt-and-braces: Azure Tables docs say PK accepts most Unicode,
    # but in practice non-ASCII chars (Danish a-ring, o-slash, ae etc.) and very
    # long keys have returned `InvalidInput` (HTTP 400) on PUT. Customer log
    # showed two ScheduledQueryRule assets with Danish chars in the name failing
    # Set-SIFingerprintRecord. When the sanitized key contains ANY non-ASCII
    # char or exceeds a safe length budget, fall back to SHA256 -- the
    # 64-hex-char key is always valid PK/RK material, and the deterministic
    # hash means Get and Set produce the same key on every run. The original
    # AssetId is preserved as `original_asset_id` row property for debugging.
    if ($sanitized -match '[^\x00-\x7f]' -or $sanitized.Length -gt 512) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
            return 'h_' + ([BitConverter]::ToString($bytes) -replace '-','').ToLowerInvariant()
        } finally { $sha.Dispose() }
    }
    return $sanitized
}

