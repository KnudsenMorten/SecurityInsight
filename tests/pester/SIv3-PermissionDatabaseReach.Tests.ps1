#Requires -Version 7.0
<#
    THE PERMISSION SELF-CHECK TELLS "THE DATABASE COULD NOT BE REACHED" FROM "NO DATABASE USER".

    Why (owner 2026-10-12, the first customer install): Get Started > Permissions said "Pro database: sign-in (a database
    user for this identity) is missing ... run the guided install again" although the database user existed. The real
    cause was the database server's firewall: it refused the job before any sign-in (SQL error 40615), and its text
    ("Cannot open server ... requested by the login. Client with IP address ... is not allowed to access the server") was
    read as a refused sign-in. A person who follows the wrong fix loses an hour and the real fault stays.

    Held here: the pure classifier (Get-SIPermissionDatabaseFailure, engine/_shared/SI-PermissionCheck.ps1), the item and
    the fix Test-SIPermissionDatabaseRoles gives for each cause, and that the run-health record's PermissionGaps carries
    it. The settings layer's half (it records the firewall refusal with its text, and asset tagging's record names the
    firewall) is in SIv3-PermissionCheckPro.Tests.ps1. Offline: no database, no Azure.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-PermissionCheck.ps1')
    # the texts SqlClient gives, as PowerShell wraps them
    $script:Firewall = 'Exception calling "Open" with "0" argument(s): "Cannot open server ''sql-si-example'' requested by the login. Client with IP address ''20.1.2.3'' is not allowed to access the server.  To enable access, use the Azure Management Portal or run sp_set_firewall_rule on the master database to create a firewall rule for this IP address or address range.  It may take up to five minutes for this change to take effect."'
    $script:LoginFailed = 'Exception calling "Open" with "0" argument(s): "Login failed for user ''<token-identified principal>''."'
    $script:Timeout = 'Exception calling "Open" with "0" argument(s): "Connection Timeout Expired.  The timeout period elapsed during the post-login phase."'
    $script:Fix = 'As the SQL server''s Entra admin, give the identity a user in the Pro database'
}

Describe 'why a sign-in to the Pro database failed' {
    It 'a firewall refusal is "firewall" although its text says "requested by the login"' {
        Get-SIPermissionDatabaseFailure -Message $script:Firewall | Should -Be 'firewall'
        Get-SIPermissionDatabaseFailure -Message 'SqlException (0x80131904): Error Number:40615,State:1,Class:14' | Should -Be 'firewall'
        Get-SIPermissionDatabaseFailure -Message 'Connection was denied since Deny Public Network Access is set to Yes' | Should -Be 'firewall'
        Get-SIPermissionDatabaseFailure -Message 'Cannot open server "x" requested by the login. Client is not allowed to access the server because of a virtual network rule (40914).' | Should -Be 'firewall'
    }
    It 'a server that does not answer is "unreachable"' {
        Get-SIPermissionDatabaseFailure -Message $script:Timeout | Should -Be 'unreachable'
        Get-SIPermissionDatabaseFailure -Message 'A network-related or instance-specific error occurred while establishing a connection to SQL Server.' | Should -Be 'unreachable'
        Get-SIPermissionDatabaseFailure -Message 'No such host is known.' | Should -Be 'unreachable'
        Get-SIPermissionDatabaseFailure -Message "Database 'sqldb-si' on server 'sql-si' is not currently available." | Should -Be 'unreachable'
    }
    It 'only a sign-in refused by a database that answered is "no-user"' {
        Get-SIPermissionDatabaseFailure -Message $script:LoginFailed | Should -Be 'no-user'
        Get-SIPermissionDatabaseFailure -Message 'Login failed for user ''NT AUTHORITY\ANONYMOUS LOGON''. (18456)' | Should -Be 'no-user'
        Get-SIPermissionDatabaseFailure -Message 'Cannot open database "sqldb-si" requested by the login. The login failed.' | Should -Be 'no-user'
    }
    It 'anything else, and no text at all, is "unknown" -- and it never throws' {
        Get-SIPermissionDatabaseFailure -Message 'The SELECT permission was denied on the object' | Should -Be 'unknown'
        Get-SIPermissionDatabaseFailure -Message '' | Should -Be 'unknown'
        Get-SIPermissionDatabaseFailure -Message $null | Should -Be 'unknown'
    }
}

Describe 'what the check says for each cause' {
    It 'the firewall: ONE item that names the firewall, with the firewall''s fix -- never "a database user is missing"' {
        $r = @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader', 'db_datawriter') -Access @{ SignIn = 'failed'; Roles = $null; Error = $script:Firewall } -Fix $script:Fix)
        $r.Count | Should -Be 1
        $r[0].Area | Should -Be 'Pro database'
        $r[0].State | Should -Be 'missing'
        $r[0].Item | Should -Be 'connection (the database could not be reached: its firewall refused this job)'
        $r[0].Item | Should -Not -Match 'database user'
        $r[0].Fix | Should -Match 'firewall'
        $r[0].Fix | Should -Match 'The database user is not the problem'
        $r[0].Fix | Should -Not -Be $script:Fix
    }
    It 'a server that did not answer: ONE item that says so' {
        $r = @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access @{ SignIn = 'failed'; Error = $script:Timeout } -Fix $script:Fix)
        $r.Count | Should -Be 1
        $r[0].Item | Should -Be 'connection (the database could not be reached: it did not answer)'
        $r[0].Fix | Should -Not -Be $script:Fix
    }
    It 'a refused sign-in on a database that answered: the database user, with the catalog''s fix' {
        $r = @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access @{ SignIn = 'failed'; Error = $script:LoginFailed } -Fix $script:Fix)
        $r.Count | Should -Be 1
        $r[0].Item | Should -Be 'sign-in (a database user for this identity)'
        $r[0].Fix | Should -Be $script:Fix
    }
    It 'a failed sign-in with no text, or an object instead of a hashtable, is read the same way' {
        @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access @{ SignIn = 'failed' } -Fix $script:Fix)[0].Item | Should -Be 'sign-in (a database user for this identity)'
        @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access ([pscustomobject]@{ SignIn = 'failed'; Error = $script:Firewall }) -Fix $script:Fix)[0].Item | Should -Match 'firewall refused this job'
    }
    It 'the run-health record carries the firewall item to Get Started' {
        $check = [pscustomobject]@{ Engine = 'flow'; Identity = 'cccccccc-0000-0000-0000-000000000001'; IdentityKey = 'collection'; Label = 'SecurityInsight''s collection identity'
            Checks = @('database'); DatabaseRoles = @('db_datareader', 'db_datawriter'); DatabaseFix = $script:Fix; Checked = @(); Error = ''; CheckedAt = [datetime]::UtcNow }
        $done = Complete-SIPermissionCheck -Check $check -Globals @{ SI_ProSqlServer = 'sql-x'; SI_ProSqlDatabase = 'sqldb-si' } -DatabaseAccess @{ SignIn = 'failed'; Roles = $null; Error = $script:Firewall }
        $o = ConvertTo-SIPermissionGapsJson -Check $done | ConvertFrom-Json
        $o.missing | Should -Be 1
        @($o.items).Count | Should -Be 1
        $o.items[0].area | Should -Be 'Pro database'
        $o.items[0].item | Should -Match 'its firewall refused this job'
        $o.items[0].fix | Should -Match 'firewall'
    }
}

Describe 'the check itself never opens a database' {
    It 'the classifier and the item are worked out from the recorded text alone' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-PermissionCheck.ps1'))
        $src | Should -Not -Match '(?i)SqlConnection|Invoke-Sqlcmd|Import-Module'
        $src | Should -Match 'function Get-SIPermissionDatabaseFailure'
    }
}
