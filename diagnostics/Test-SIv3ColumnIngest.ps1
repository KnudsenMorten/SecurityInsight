<#
    INGEST-1 probe -- is a newly declared column actually reaching Log Analytics yet?
    See V3-ARCHITECTURE.md §6b. Posts ONE sentinel row and nothing else.

    WHY THIS EXISTS RATHER THAN "just run the engine again": an engine run takes ~4 minutes, rebuilds
    every row, and answers the same question this answers in about five seconds. Three engine runs on
    2026-08-12 all returned 0% -- re-running is not the test.

    It deliberately bypasses EVERYTHING SI does: no row builder, no schema, no AzLogDcrIngestPS, no
    name resolution. It posts a hand-built row straight at the DCE FQDN and DCR immutableId that ARM
    says are bound to each other. So the result cannot be blamed on SI code.
      - sentinel lands WITH values  -> ingest is healthy; re-run the engine and merge.
      - sentinel lands with EMPTY   -> the table/DCR pair still is not ingesting the new columns.
                                       Everything on our side is already proven correct: open an
                                       Azure support case rather than changing code.

    🪤 Name resolution is NOT safe here: three DCEs are named 'dce-securityinsight' across two
    subscriptions and a stale 'dcr-si-endpoint' in <sub-platform> writes to this same workspace. Resolving
    by name returned the wrong DCE and a 403. Hence hard resource ids below -- re-verify them from ARM
    if the infra is ever rebuilt (the DCE suffix changes when a DCE is recreated).

    Read-only apart from the single sentinel row it writes, which is findable by PrimaryEntityId.
#>
[CmdletBinding()]
param(
    # Vary this per attempt so successive probes are distinguishable in the table.
    [string] $Marker = ('SENTINEL-{0}' -f (Get-Date -Format 'HHmmss')),

    # Non-secret identifiers (client id / cert thumbprint / tenant id). The private key stays in
    # LocalMachine\My and never leaves the machine.
    [string] $TenantId = '<tenant-id>',
    [string] $ClientId = '<engine-spn-client-id>',
    [string] $Thumbprint = '78E4197442BF1414A33F7F9471038ED97DB67F71',

    # Verified from ARM, NOT resolved by name -- see the trap note above.
    [string] $DceFqdn = 'https://dce-securityinsight-vy7f.westeurope-1.ingest.monitor.azure.com',
    [string] $DcrImmutableId = 'dcr-fa402ed739074b6fa16b12a3b0334065',
    [string] $Stream = 'Custom-SI_Endpoint_Profile_CL'
)
$ErrorActionPreference = 'Stop'

$tenantId = $TenantId
$clientId = $ClientId
$thumb    = $Thumbprint
$dceFqdn  = $DceFqdn
$dcrImmut = $DcrImmutableId
$stream   = $Stream

$cert = Get-Item "Cert:\LocalMachine\My\$thumb"

# Client-credentials with a client assertion (JWT signed by the cert) -- audience monitor.azure.com.
Add-Type -AssemblyName System.Security
function ConvertTo-B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }

$now  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$hdr  = @{ alg='RS256'; typ='JWT'; x5t=(ConvertTo-B64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
$aud  = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$pl   = @{ aud=$aud; iss=$clientId; sub=$clientId; jti=[guid]::NewGuid().ToString(); nbf=$now; exp=($now+600) } | ConvertTo-Json -Compress
$unsigned = (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($hdr))) + '.' + (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($pl)))
$rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$sig  = ConvertTo-B64Url ($rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))
$assertion = "$unsigned.$sig"

$tok = Invoke-RestMethod -Method Post -Uri $aud -Body @{
    client_id             = $clientId
    scope                 = 'https://monitor.azure.com/.default'
    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    client_assertion      = $assertion
    grant_type            = 'client_credentials'
}
Write-Host 'token acquired for https://monitor.azure.com'

$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
# PrimaryEntityId is the CONTROL: it is a pre-existing string column on the same row. If it lands and
# the other two do not, the row reached the table and only the new columns were dropped.
$body = ConvertTo-Json -Depth 10 -Compress -InputObject @(@{
    TimeGenerated       = $stamp
    CollectionTime      = $stamp
    PrimaryEntityId     = "$Marker-PK"
    SI_AssetId          = "$Marker-SI"
    ExposureGraphNodeId = "$Marker-EG"
})
Write-Host "body: $body"

$uri = "$dceFqdn/dataCollectionRules/$dcrImmut/streams/$stream" + '?api-version=2023-01-01'
Write-Host "POST $uri"
$resp = Invoke-WebRequest -UseBasicParsing -Uri $uri -Method Post -Body $body `
            -Headers @{ Authorization = "Bearer $($tok.access_token)"; 'Content-Type' = 'application/json' }
Write-Host ("HTTP {0}   (204 = accepted; it says nothing about which columns survive)" -f $resp.StatusCode)
Write-Host ''
Write-Host 'Now read it back -- ingestion lags a minute or two:'
Write-Host ("  SI_Endpoint_Profile_CL | where PrimaryEntityId == '{0}-PK' | project PrimaryEntityId, SI_AssetId, ExposureGraphNodeId" -f $Marker)
Write-Host ''
Write-Host 'VERDICT: all three populated -> ingest healthy, re-run the engine and merge.'
Write-Host '         only PrimaryEntityId populated -> INGEST-1 still open (V3-ARCHITECTURE.md §6b).'
