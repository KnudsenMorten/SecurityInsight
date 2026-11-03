#Requires -Version 5.1
<#
    SECURITYINSIGHT -- WHERE A CREDENTIAL MAY GO. PURE checks, each returning '' (allowed) or the reason in plain words.
    The engine uses them where it sends a token, a key or the install's own credential; a value one of them refuses is left
    out of the run and said (a warning), never the end of the run. The web app checks the same rules when a person saves a
    setting (pro-management/src/SI.Management.Web/Settings/OutboundHostPolicy.cs).

      Test-SIAzureSqlHost            the SQL server the engine sends its Azure SQL access token to: an Azure SQL host
      Test-SITelemetryEndpointHost   the uplink the install key goes to: https, invardia.com or a subdomain of it
      Test-SIHttpsSameOrigin         a connector's request or next page: https, the same host and port as its own base address
      Test-SISqlDatabaseName         a database name, never a connection-string fragment
      New-SISqlConnectionString      the Azure SQL connection string, built (never formatted) from the server and database

    Strict-mode safe; PS 5.1 and 7.
#>

function Get-SIAzureSqlHostSuffixes { @('.database.windows.net', '.database.usgovcloudapi.net', '.database.chinacloudapi.cn', '.database.cloudapi.de') }

function Get-SISqlServerHostName {
    <# PURE. 'tcp:<host>,<port>' / '<host>,<port>' / '<host>' -> '<host>' (lower case). #>
    param([AllowEmptyString()][string]$Server = '')
    $h = "$Server".Trim()
    if ($h.StartsWith('tcp:', [StringComparison]::OrdinalIgnoreCase)) { $h = $h.Substring(4) }
    $c = $h.IndexOf(','); if ($c -ge 0) { $h = $h.Substring(0, $c) }
    $h.Trim().ToLowerInvariant()
}

function Test-SIAzureSqlHost {
    <# PURE. '' = -Server is an Azure SQL server (public or sovereign cloud) the engine's SQL access token may go to. #>
    param([AllowEmptyString()][string]$Server = '')
    $h = Get-SISqlServerHostName -Server $Server
    if (-not $h) { return 'no SQL server is named' }
    if ($h -notmatch '^[a-z0-9.-]+$') { return ("'{0}' is not a SQL server name" -f "$Server".Trim()) }
    foreach ($s in (Get-SIAzureSqlHostSuffixes)) { if ($h.EndsWith($s) -and $h.Length -gt $s.Length) { return '' } }
    ("'{0}' is not an Azure SQL server (<name>.database.windows.net)" -f $h)
}

function Test-SISqlDatabaseName {
    <# PURE. '' = -Database is a database name (1-128 characters, no ; = quote bracket brace or control character). #>
    param([AllowEmptyString()][string]$Database = '')
    $d = "$Database".Trim()
    if (-not $d) { return 'no database is named' }
    if ($d.Length -gt 128 -or $d -match '[;=''"\[\]{}\x00-\x1f]') { return ("'{0}' is not a database name" -f $d) }
    ''
}

function New-SISqlConnectionString {
    <#
        PURE. The connection string for an Azure SQL database with an Entra token: built with SqlConnectionStringBuilder, so a
        server or database value is always ONE value (a ';' in it can never add a keyword). Encrypted, the certificate checked.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [int]$ConnectTimeoutSec = 30)
    $csb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $csb['Data Source'] = ('tcp:{0},1433' -f (Get-SISqlServerHostName -Server $Server))
    $csb['Initial Catalog'] = "$Database".Trim()
    $csb['Encrypt'] = $true; $csb['TrustServerCertificate'] = $false; $csb['Connect Timeout'] = $ConnectTimeoutSec
    $csb.ConnectionString
}

function Test-SITelemetryEndpointHost {
    <# PURE. '' = -Endpoint is Invardia's own https address (invardia.com or a subdomain) -- the only place the install key goes. #>
    param([AllowEmptyString()][string]$Endpoint = '')
    $e = "$Endpoint".Trim()
    if (-not $e) { return 'no endpoint is set' }
    $u = $null
    if (-not [Uri]::TryCreate($e, [UriKind]::Absolute, [ref]$u)) { return ("'{0}' is not an address" -f $e) }
    if ($u.Scheme -ne 'https') { return ("'{0}' is not https" -f $e) }
    if ($u.UserInfo) { return ("'{0}' carries a user name" -f $u.Host) }
    $h = $u.Host.ToLowerInvariant()
    if ($h -eq 'invardia.com' -or $h.EndsWith('.invardia.com')) { return '' }
    ("'{0}' is not an Invardia address" -f $u.Host)
}

function Test-SIHttpsSameOrigin {
    <# PURE. '' = -Url is https with the same host and port as -BaseUrl (which must be https itself). #>
    param([AllowEmptyString()][string]$Url = '', [AllowEmptyString()][string]$BaseUrl = '')
    $b = $null; $u = $null
    if (-not [Uri]::TryCreate("$BaseUrl".Trim(), [UriKind]::Absolute, [ref]$b) -or $b.Scheme -ne 'https') { return 'the connector''s base address is not an https address' }
    if (-not [Uri]::TryCreate("$Url".Trim(), [UriKind]::Absolute, [ref]$u)) { return ("'{0}' is not an address" -f $Url) }
    if ($u.Scheme -ne 'https') { return ("'{0}' is not https" -f $u.GetLeftPart([UriPartial]::Authority)) }
    if ($u.UserInfo) { return ("'{0}' carries a user name" -f $u.Host) }
    if (-not [string]::Equals($u.Host, $b.Host, [StringComparison]::OrdinalIgnoreCase) -or $u.Port -ne $b.Port) {
        return ("'{0}' is not the connector's own host ({1})" -f $u.Authority, $b.Authority)
    }
    ''
}
