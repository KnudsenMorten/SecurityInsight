<#
    A FAKE AZURE FOR THE HEARTBEAT'S OWN THREAD (tests\pester\SIv3-PartLease.Tests.ps1).

    The heartbeat that renews a worker's hold on its part runs in a SECOND RUNSPACE, which starts empty and loads only the
    files the product gives it (Get-SIWorkItemLeaseBeatLibraries). A Pester Mock does not reach into another runspace, so
    this file is loaded there LAST, after the product's files, and replaces the two things that would leave the machine:
      * the identity endpoint -- $global:SI_InstallTokenProvider, the product's own hook in Get-SIManagedIdentityToken
        ("while it is set, the token comes from it and no identity endpoint is called"). The hook lives INSIDE the
        managed-identity sign-in, so a runspace that did not load auth\SI-ManagedIdentity.ps1 still fails exactly as the
        container did on 2026-10-13.
      * the HTTP seam Invoke-SIAzRestHttp -- every request is written as one line to the file named by the environment
        variable SI_TEST_PARTLEASE_LOG, and answered as the storage queue answers an Update Message: 204 with a new
        x-ms-popreceipt.
#>
$global:SI_InstallTokenProvider = { param($Resource) 'identity-token' }
$script:SIPartLeaseFakeCalls = 0
function Invoke-SIAzRestHttp {
    param([string]$Method, [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 300, [switch]$AsBytes)
    $script:SIPartLeaseFakeCalls++
    $log = [Environment]::GetEnvironmentVariable('SI_TEST_PARTLEASE_LOG')
    if ($log) { [IO.File]::AppendAllText($log, ('{0} {1} | {2} | {3}{4}' -f $Method, $Uri, [string]$Headers['Authorization'], [string]$Body, [Environment]::NewLine)) }
    [pscustomobject]@{ StatusCode = 204; Content = ''; Bytes = $null; Headers = @{ 'x-ms-popreceipt' = ('receipt-{0}' -f $script:SIPartLeaseFakeCalls) }; RetryAfter = $null }
}
