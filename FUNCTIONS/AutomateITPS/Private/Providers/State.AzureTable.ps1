function Get-PlatformStateAzureTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$Key
    )

    $endpoint = Get-AzureTableEntityUri -Context $Context -ScriptName $ScriptName -Key $Key
    $headers  = Get-AzureTableHeaders -Context $Context

    try {
        $resp = Invoke-RestMethod -Method GET -Uri $endpoint -Headers $headers -ErrorAction Stop
    }
    catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -eq 404) { return $null }
        throw "Get-PlatformStateAzureTable: $($_.Exception.Message)"
    }

    if ($null -eq $resp -or -not ($resp.PSObject.Properties.Name -contains 'Value')) { return $null }

    $raw = $resp.Value
    if ([string]::IsNullOrEmpty($raw)) { return $raw }
    try { return ($raw | ConvertFrom-Json -ErrorAction Stop) } catch { return $raw }
}

function Set-PlatformStateAzureTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][AllowNull()]$Value
    )

    $serialized = if ($Value -is [string]) { $Value } else { ($Value | ConvertTo-Json -Depth 20 -Compress) }

    $endpoint = Get-AzureTableEntityUri -Context $Context -ScriptName $ScriptName -Key $Key
    $headers  = Get-AzureTableHeaders -Context $Context
    $headers['Content-Type'] = 'application/json'
    $headers['If-Match']     = '*'

    $pk = Get-AzureTablePartitionKey -Context $Context
    $body = @{
        PartitionKey = $pk
        RowKey       = $Key
        Value        = $serialized
        UpdatedUtc   = [datetime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod -Method PUT -Uri $endpoint -Headers $headers -Body $body -ErrorAction Stop | Out-Null
        return
    }
    catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($status -ne 404) { throw "Set-PlatformStateAzureTable: $($_.Exception.Message)" }
    }

    New-AzureTable -Context $Context -ScriptName $ScriptName
    Invoke-RestMethod -Method PUT -Uri $endpoint -Headers $headers -Body $body -ErrorAction Stop | Out-Null
}

function New-AzureTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$ScriptName
    )
    $account = $Context.Tenant.StorageAccountName
    $table   = ConvertTo-AzureTableName -Name $ScriptName
    $url     = "https://$account.table.core.windows.net/Tables"
    $headers = Get-AzureTableHeaders -Context $Context
    $headers['Content-Type'] = 'application/json'
    $body = @{ TableName = $table } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Method POST -Uri $url -Headers $headers -Body $body -ErrorAction Stop | Out-Null
    }
    catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($status -ne 409) { throw "New-AzureTable: $($_.Exception.Message)" }
    }
}

function Get-AzureTableEntityUri {
    [CmdletBinding()]
    param($Context, $ScriptName, $Key)
    $account = $Context.Tenant.StorageAccountName
    if (-not $account) { throw "Tenant.StorageAccountName not set on context. Pass -StorageAccountName to New-PlatformContext." }
    $table = ConvertTo-AzureTableName -Name $ScriptName
    $pk    = Get-AzureTablePartitionKey -Context $Context
    $rk    = [Uri]::EscapeDataString($Key)
    $pkEsc = [Uri]::EscapeDataString($pk)
    "https://$account.table.core.windows.net/$table(PartitionKey='$pkEsc',RowKey='$rk')"
}

function Get-AzureTablePartitionKey {
    [CmdletBinding()]
    param($Context)
    if ($Context.Tenant.Id) { return $Context.Tenant.Id }
    'default'
}

function ConvertTo-AzureTableName {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Name)
    $safe = ($Name -replace '[^a-zA-Z0-9]','').ToLower()
    if ($safe.Length -eq 0) { $safe = 'state' }
    if ($safe -notmatch '^[a-z]') { $safe = 'x' + $safe }
    if ($safe.Length -gt 63) { $safe = $safe.Substring(0, 63) }
    if ($safe.Length -lt 3)  { $safe = ($safe + 'xxx').Substring(0, 3) }
    $safe
}

function Get-AzureTableHeaders {
    [CmdletBinding()]
    param($Context)
    $token = Get-AutomateITAzureToken -Context $Context -ResourceUrl 'https://storage.azure.com/'
    @{
        Authorization   = "Bearer $token"
        'x-ms-version'  = '2020-12-06'
        'x-ms-date'     = [datetime]::UtcNow.ToString('R')
        Accept          = 'application/json;odata=nometadata'
    }
}
