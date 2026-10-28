function Test-PlatformConnectivity {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [int]$TimeoutSeconds = 5,

        [switch]$PassThru
    )

    $targets = [System.Collections.Generic.List[pscustomobject]]::new()

    $targets.Add([pscustomobject]@{ Name = 'Microsoft Graph'; Host = 'graph.microsoft.com';          Port = 443 })
    $targets.Add([pscustomobject]@{ Name = 'Azure Mgmt';      Host = 'management.azure.com';        Port = 443 })

    if ($Context.Tenant.KeyVaultName) {
        $targets.Add([pscustomobject]@{ Name = 'Key Vault'; Host = "$($Context.Tenant.KeyVaultName).vault.azure.net"; Port = 443 })
    }
    if ($Context.Tenant.StorageAccountName) {
        $targets.Add([pscustomobject]@{ Name = 'Storage (table)'; Host = "$($Context.Tenant.StorageAccountName).table.core.windows.net"; Port = 443 })
    }
    if ($Context.Tenant.SmtpServer) {
        $targets.Add([pscustomobject]@{ Name = 'SMTP'; Host = $Context.Tenant.SmtpServer; Port = 587 })
    }

    if ($Context.Capabilities.OnPremAD -and $env:USERDNSDOMAIN) {
        $targets.Add([pscustomobject]@{ Name = 'Domain controller (LDAP)'; Host = $env:USERDNSDOMAIN; Port = 389 })
    }

    $results = foreach ($t in $targets) {
        $ok = $false
        $errMsg = $null
        $client = $null
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $connect = $client.ConnectAsync($t.Host, $t.Port)
            if ($connect.Wait([timespan]::FromSeconds($TimeoutSeconds))) {
                $ok = $client.Connected
                if (-not $ok) { $errMsg = 'not connected after wait' }
            } else {
                $errMsg = "timeout after ${TimeoutSeconds}s"
            }
        }
        catch {
            $errMsg = $_.Exception.Message
        }
        finally {
            if ($client) { $client.Dispose() }
        }

        [pscustomobject]@{
            Name  = $t.Name
            Host  = $t.Host
            Port  = $t.Port
            Ok    = $ok
            Error = $errMsg
        }
    }

    Write-PlatformLog -Context $Context -Event 'platform.connectivity' -Message 'Connectivity check complete' -Data @{
        total  = @($results).Count
        failed = @($results | Where-Object { -not $_.Ok }).Count
        targets = $results
    }

    if ($PassThru) { return $results }
    $results
}
