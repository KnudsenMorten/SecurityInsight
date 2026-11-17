#Requires -Version 5.1
<#
    WHERE EACH SOFTWARE COPY IS (REQUIREMENTS #1219 + #1277, one lane; owner 2026-11-16).

    Defender's software evidence (DeviceTvmSoftwareEvidenceBeta) as SecurityInsight data: every path, every drive, the
    registry too, no cap; per path its install kind and the application it lies in; the optional path / install-kind /
    version conditions of the hasSoftwareInstalled rules; the evidence fields on the device and on every finding of the
    software. What is proven here:
      * the READ: one query per page of devices (paging), every path (no cap), the evidence table read WITHOUT a fuzzy union;
        a missing / refused / empty table = UNKNOWN for the run (said, never "no evidence"); a failed page = its devices
        UNKNOWN, the other pages kept; the device states and rows reach the database writer; the record part is added
      * PATH -> INSTALL KIND / APPLICATION on many real-shaped Windows and Linux paths (D:\home\users\x\wordpress,
        WindowsApps, Common Files, the driver store, /opt, /home, /var/www ...); the inventory match (name + version),
        the folder fallback, a tie or several versions never guessed; bundled only in ANOTHER product's folder
      * THE RULE CONDITIONS: a detection without them answers EXACTLY as before (every shipped hasSoftwareInstalled
        detection against a legacy copy of the handler); installKinds drops a data-folder WordPress; unknown evidence falls
        back to the name match and is counted; the CI rule reads the profiler's hits and falls back without them
      * the FINDING fields: device + vendor + product + version; the count of rows never changes; unknown stays empty
      * the DATA MODEL: the catalog fields, the device mapping, the finding row columns; NO shipped rule carries a condition
        (owner 2026-11-16: no generic path rules -- per-server exceptions, SIv3-SoftwareException.Tests.ps1)
      * the SCHEMA: additive; ONLY THE NEWEST RUN is kept -- on a real SQL Server: a device read again is replaced (never
        doubled), an unknown device keeps no row (never an older run's paths), a write cut before its last chunk is never
        shown, read per device / CI / the view, retention of devices no run reads any more
    PS 5.1 / 7. SQL part on the test runner's SQL Server (skipped without SI_TEST_LOCALSQL). Nothing is sent anywhere.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SoftwareEvidence.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderSoftwareEvidence.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleEval.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SoftwareEvidence.ps1')
    function Write-SIInfo { param($m) }
    $script:SavedRoot = $global:SI_EnrichmentDataRoot
    if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }

    $script:D1 = '0c8545c566aa838508be174878084b0c7a9cfd4e'
    $script:D2 = '1d9656d677bb949619cf285989195c1d8badfe5f'
    $script:D3 = '2e9767e788cc050720d0396090206d2e9cbeef60'

    # THE HANDLER AS IT WAS (before #1219), verbatim -- the parity reference for every detection without the new conditions
    function script:Test-LegacyHasSoftwareInstalled {
        param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)]$Args)
        $patterns = @($Args.tvmSoftwareNames)
        if (-not $patterns -or $patterns.Count -eq 0) { return $false }
        $devId = [string](Get-SIAssetField -Asset $Asset -Name 'MDE_DeviceId')
        if (-not $devId) { $devId = [string](Get-SIAssetField -Asset $Asset -Name 'PrimaryEntityId') }
        if (-not $devId) { return $false }
        $idx = if (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue) { $script:SIRuleIndexes.tvmSoftware } else { $null }
        if (-not $idx) { return $false }
        $pairs = $idx[$devId.ToLower()]
        if (-not $pairs) { return $false }
        foreach ($pair in $pairs) {
            foreach ($p in $patterns) {
                $glob = ([string]$p).ToLower()
                if ($pair -like $glob -or $pair -like ('*/' + $glob)) { return $true }
            }
        }
        return $false
    }
    # THE CI CONDITION AS IT WAS (before #1219) for hasSoftwareInstalled
    function script:Get-LegacyCiSoftwareCondition($Spec) {
        $pats = New-Object System.Collections.Generic.List[string]
        foreach ($p in @(Get-SIItemValue $Spec 'tvmSoftwareNames')) { if ($p) { $pats.Add(([string]$p).ToLowerInvariant()); $pats.Add('*/' + ([string]$p).ToLowerInvariant()) } }
        return [ordered]@{ field = 'si_installed_software'; op = 'like'; value = $pats.ToArray() }
    }
    function script:Ev([string]$Vendor, [string]$Name, [string]$Version, [string[]]$Disk = @(), [string[]]$Reg = @(), [string]$Seen = '2026-11-15T03:00:00Z') {
        [pscustomobject]@{ SoftwareVendor = $Vendor; SoftwareName = $Name; SoftwareVersion = $Version; DiskPaths = @($Disk); RegistryPaths = @($Reg); LastSeenTime = $Seen }
    }
    function script:Inv([string]$Vendor, [string]$Name, [string]$Version) { @{ Vendor = $Vendor; Name = $Name; Version = $Version } }
}

AfterAll {
    if ($null -ne $script:SavedRoot) { $global:SI_EnrichmentDataRoot = $script:SavedRoot }
}

Describe 'path -> install kind, drive and product folder (Windows)' {
    It '<p> -> <k> / <d> / <a>' -TestCases @(
        @{ p = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'; k = 'installed'; d = 'C:'; a = 'Adobe Acrobat DC' }
        @{ p = 'C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe'; k = 'installed'; d = 'C:'; a = 'Adobe ARM' }
        @{ p = 'C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\OpenConsole.exe'; k = 'installed'; d = 'C:'; a = 'Microsoft.WindowsTerminal' }
        @{ p = 'C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_0123456789abcdef\igdumdim64.dll'; k = 'installed'; d = 'C:'; a = 'iigd_dch.inf_amd64' }
        @{ p = 'C:\Windows\System32\curl.exe'; k = 'installed'; d = 'C:'; a = 'Microsoft Windows' }
        @{ p = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll'; k = 'installed'; d = 'C:'; a = 'Microsoft.NET' }
        @{ p = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe'; k = 'installed'; d = 'C:'; a = 'Microsoft Windows Defender' }
        @{ p = 'C:\Program Files\7-Zip\7z.dll'; k = 'installed'; d = 'C:'; a = '7-Zip' }
        @{ p = 'C:\Program Files\Python311\DLLs\libssl-3.dll'; k = 'installed'; d = 'C:'; a = 'Python311' }
        @{ p = 'C:\Program Files\Microsoft SQL Server\150\Shared\sqlbrowser.exe'; k = 'installed'; d = 'C:'; a = 'Microsoft SQL Server' }
        @{ p = 'D:\Program Files\Contoso\Agent\bin\agent.exe'; k = 'installed'; d = 'D:'; a = 'Contoso Agent' }
        @{ p = 'D:\home\users\x\wordpress\wp-includes\version.php'; k = 'data-folder'; d = 'D:'; a = '' }
        @{ p = 'E:\Shares\Finance\tools\tool.exe'; k = 'data-folder'; d = 'E:'; a = '' }
        @{ p = 'D:\Backup\old-site\wordpress\index.php'; k = 'data-folder'; d = 'D:'; a = '' }
        @{ p = '\\fs01\apps\tool\tool.exe'; k = 'data-folder'; d = '\\fs01\apps'; a = '' }
        @{ p = 'C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\resources\app\node.dll'; k = 'user-profile'; d = 'C:'; a = 'Microsoft VS Code' }
        @{ p = 'C:\Users\bob\Downloads\wordpress\wp-includes\version.php'; k = 'user-profile'; d = 'C:'; a = '' }
        @{ p = 'C:\Users\Public\Documents\x.dll'; k = 'unknown'; d = 'C:'; a = '' }
        @{ p = 'C:\xampp\php\php.exe'; k = 'unknown'; d = 'C:'; a = '' }
        @{ p = 'C:\inetpub\wwwroot\wordpress\wp-includes\version.php'; k = 'installed'; d = 'C:'; a = 'wordpress' }
        @{ p = 'D:\xampp\htdocs\wordpress\index.php'; k = 'installed'; d = 'D:'; a = 'wordpress' }
        @{ p = 'D:\Websites\intranet\wp-includes\version.php'; k = 'installed'; d = 'D:'; a = 'intranet' }
    ) {
        $i = ConvertTo-SIEvidencePathInfo -Path $p
        $i.PathType | Should -Be 'disk'
        $i.InstallKind | Should -Be $k
        [string]$i.Drive | Should -Be $d
        [string]$i.Folder | Should -Be $a
    }
    It 'a registry path: registry-only, no drive, no folder' {
        foreach ($p in 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{11111111-2222-3333-4444-555555555555}', 'HKLM\SOFTWARE\WOW6432Node\Notepad++') {
            $i = ConvertTo-SIEvidencePathInfo -Path $p
            ($i.PathType, $i.InstallKind) | Should -Be @('registry', 'registry-only')
            $i.Drive | Should -BeNullOrEmpty; $i.Folder | Should -BeNullOrEmpty
        }
    }
}

Describe 'path -> install kind and product folder (Linux / macOS)' {
    It '<p> -> <k> / <a>' -TestCases @(
        @{ p = '/opt/microsoft/msedge/libffmpeg.so'; k = 'installed'; a = 'microsoft msedge' }
        @{ p = '/opt/splunkforwarder/lib/libssl.so.1.0.0'; k = 'installed'; a = 'splunkforwarder' }
        @{ p = '/usr/lib/x86_64-linux-gnu/libssl.so.3'; k = 'installed'; a = '' }
        @{ p = '/usr/bin/openssl'; k = 'installed'; a = '' }
        @{ p = '/usr/share/code/resources/app/node_modules.asar'; k = 'installed'; a = 'code' }
        @{ p = '/usr/lib/jvm/java-17-openjdk-amd64/lib/libjava.so'; k = 'installed'; a = 'java-17-openjdk-amd64' }
        @{ p = '/usr/local/nginx/sbin/nginx'; k = 'installed'; a = 'nginx' }
        @{ p = '/snap/firefox/4793/usr/lib/firefox/libssl3.so'; k = 'installed'; a = 'firefox' }
        @{ p = '/var/www/html/wordpress/wp-includes/version.php'; k = 'installed'; a = 'wordpress' }
        @{ p = '/srv/www/shop/index.php'; k = 'installed'; a = 'shop' }
        @{ p = '/home/bob/wordpress/wp-includes/version.php'; k = 'user-profile'; a = '' }
        @{ p = '/home/bob/.local/share/JetBrains/bin/x.so'; k = 'user-profile'; a = 'JetBrains' }
        @{ p = '/root/.cache/pip/x.so'; k = 'user-profile'; a = '' }
        @{ p = '/srv/data/backup/wordpress/index.php'; k = 'data-folder'; a = '' }
        @{ p = '/mnt/share/tools/libssl.so'; k = 'data-folder'; a = '' }
        @{ p = '/tmp/x/y.so'; k = 'unknown'; a = '' }
        @{ p = '/var/lib/docker/overlay2/abc/diff/usr/lib/libssl.so.3'; k = 'unknown'; a = '' }
        @{ p = '/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework/Electron Framework'; k = 'installed'; a = 'Slack' }
        @{ p = '/Users/carol/Library/Application Support/x.dylib'; k = 'user-profile'; a = '' }
    ) {
        $i = ConvertTo-SIEvidencePathInfo -Path $p
        $i.InstallKind | Should -Be $k
        [string]$i.Folder | Should -Be $a
        $i.Drive | Should -BeNullOrEmpty
    }
}

Describe 'the application: the device''s own inventory first, the folder name otherwise; bundled only in ANOTHER product''s folder' {
    BeforeAll {
        $script:Inventory = @(
            (Inv 'adobe' 'acrobat_dc' '23.008.20470'), (Inv 'python' 'python' '3.11.4'), (Inv 'openssl' 'openssl' '3.0.13'), (Inv 'openssl' 'openssl' '3.1.4'),
            (Inv 'microsoft' 'visual_studio_code' '1.95.1'), (Inv 'wordpress' 'wordpress' '6.4.2'), (Inv 'notepad++' 'notepad++' '8.6'))
        $script:Rows = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $script:D1.ToUpperInvariant() -Inventory $script:Inventory -Evidence @(
            (Ev 'OpenSSL' 'OpenSSL' '3.0.13' -Disk @('C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll'))
            (Ev 'openssl' 'openssl' '3.1.4' -Disk @('C:\Program Files\Python311\DLLs\libssl-3.dll', 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe', 'D:\Tools\Contoso\Agent\libssl.dll'))
            (Ev 'openssl' 'openssl' '3.1.4' -Disk @('c:\program files\python311\dlls\libssl-3.dll') -Seen '2026-11-16T01:00:00Z')
            (Ev 'electron' 'electron' '30.0.1' -Disk @('C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\resources\app\electron.dll'))
            (Ev 'curl' 'curl' '8.4.0' -Disk @('C:\Windows\System32\curl.exe'))
            (Ev 'wordpress' 'wordpress' '6.4.2' -Disk @('D:\home\users\x\wordpress\wp-includes\version.php'))
            (Ev 'notepad++' 'notepad++' '8.6' -Reg @('HKEY_LOCAL_MACHINE\SOFTWARE\Notepad++'))
            (Ev 'igor_pavlov' '7-zip' '23.01' -Disk @('C:\Program Files\7-Zip\7z.dll') -Reg @('HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip'))
        ))
        function script:RowOf([string]$Product, [string]$Version, [string]$Like) { @($script:Rows | Where-Object { $_.Product -eq $Product -and $_.Version -eq $Version -and $_.FullPath -like $Like })[0] }
    }
    It 'every path is a row (no cap), duplicates merged (case), the newest LastSeen kept, the device id lower-case' {
        @($script:Rows).Count | Should -Be 10 -Because '1 + 3 openssl copies'' paths (the duplicate merged) + electron + curl + wordpress + notepad++ (registry) + 7-zip (disk + registry)'
        @($script:Rows | Where-Object { $_.FullPath -like '*python311*' }).Count | Should -Be 1
        (RowOf 'openssl' '3.1.4' '*Python311*').LastSeen | Should -Be ([datetime]::SpecifyKind([datetime]'2026-11-16T01:00:00', 'Utc'))
        @($script:Rows | ForEach-Object DeviceId | Sort-Object -Unique) | Should -Be @($script:D1)
        (@($script:Rows | ForEach-Object Vendor) -ccontains 'OpenSSL') | Should -BeFalse -Because 'vendor and product are lower-case, as Defender''s inventory has them'
    }
    It 'openssl inside Acrobat: bundled, the application from the inventory (vendor, name, version)' {
        $r = RowOf 'openssl' '3.0.13' '*Acrobat*'
        ($r.InstallKind, $r.Application, $r.ApplicationVendor, $r.ApplicationVersion, $r.ApplicationSource) | Should -Be @('bundled', 'acrobat_dc', 'adobe', '23.008.20470', 'inventory')
        Format-SIEvidenceApplication $r | Should -Be 'adobe/acrobat_dc 23.008.20470'
    }
    It 'openssl inside Python: bundled by python 3.11.4; in its OWN folder: installed (never bundled by itself), its version not guessed (two on the device)' {
        $py = RowOf 'openssl' '3.1.4' '*Python311*'
        ($py.InstallKind, $py.Application, $py.ApplicationVersion) | Should -Be @('bundled', 'python', '3.11.4')
        $own = RowOf 'openssl' '3.1.4' '*OpenSSL-Win64*'
        $own.InstallKind | Should -Be 'installed'
        ($own.Application, $own.ApplicationSource) | Should -Be @('openssl', 'inventory')
        $own.ApplicationVersion | Should -BeNullOrEmpty -Because 'openssl has two versions on the device -- which copy owns the folder is not known'
    }
    It 'unmatched in the inventory: the folder name, said as such; a data drive library is still bundled' {
        $r = RowOf 'openssl' '3.1.4' 'D:\Tools*'
        ($r.InstallKind, $r.Application, $r.ApplicationSource) | Should -Be @('data-folder', $null, $null) -Because 'D:\Tools names no product folder -- unknown, never guessed'
        $e = RowOf 'electron' '30.0.1' '*'
        ($e.InstallKind, $e.Application, $e.ApplicationSource) | Should -Be @('bundled', 'Microsoft VS Code', 'folder') -Because 'visual_studio_code''s words are not all in "Microsoft VS Code"'
        $c = RowOf 'curl' '8.4.0' '*'
        ($c.InstallKind, $c.Application, $c.ApplicationSource) | Should -Be @('bundled', 'Microsoft Windows', 'folder') -Because 'the fix comes with Windows'
    }
    It 'a server application found in a data folder stays data-folder (it is no library)' {
        $w = RowOf 'wordpress' '6.4.2' '*'
        ($w.InstallKind, $w.Drive, $w.Application) | Should -Be @('data-folder', 'D:', $null)
    }
    It 'registry: registry-only when the copy has no disk path; unknown beside a disk path' {
        (RowOf 'notepad++' '8.6' 'HKEY*').InstallKind | Should -Be 'registry-only'
        (RowOf '7-zip' '23.01' 'HKEY*').InstallKind | Should -Be 'unknown'
        (RowOf '7-zip' '23.01' 'C:*').InstallKind | Should -Be 'installed'
    }
    It 'a tie between two products is never guessed' {
        $inv = @((Inv 'contoso' 'agent' '1.0'), (Inv 'fabrikam' 'agent' '2.0'))
        $a = Resolve-SIEvidenceApplication -Folder 'Shared Agent' -Inventory $inv
        ($a.Name, $a.Source) | Should -Be @('Shared Agent', 'folder')
        $b = Resolve-SIEvidenceApplication -Folder 'Contoso Agent' -Inventory $inv
        ($b.Name, $b.Vendor, $b.Version, $b.Source) | Should -Be @('agent', 'contoso', '1.0', 'inventory') -Because 'the vendor word decides'
        (Resolve-SIEvidenceApplication -Folder 'DC' -Inventory @(Inv 'adobe' 'acrobat_dc' '1')).Source | Should -Be 'folder'
        (Resolve-SIEvidenceApplication -Folder '' -Inventory $inv).Source | Should -BeNullOrEmpty
    }
    It 'the compact form for the rules carries every copy (evidence and inventory-only); the record part lists paths, kinds, bundled-by' {
        $c = ConvertTo-SISoftwareEvidenceDevice -Rows $script:Rows -Inventory $script:Inventory
        $c.State | Should -Be 'read'
        $ssl = @($c.Items | Where-Object { $_.p -eq 'openssl/openssl' -and $_.v -eq '3.1.4' })[0]
        @($ssl.paths).Count | Should -Be 3
        $acro = @($c.Items | Where-Object { $_.p -eq 'adobe/acrobat_dc' })[0]
        @($acro.paths).Count | Should -Be 0 -Because 'an inventory product without evidence: its evidence is unknown'
        $part = ConvertTo-SISoftwareEvidencePart -Rows $script:Rows
        @($part.Paths) | Should -Contain 'openssl/openssl 3.0.13 | bundled | C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll'
        @($part.Kinds) | Should -Contain 'wordpress/wordpress|data-folder'
        @($part.BundledBy) | Should -Contain 'openssl/openssl 3.0.13 | adobe/acrobat_dc 23.008.20470'
        ConvertTo-SISoftwareEvidencePart -Rows @() | Should -BeNullOrEmpty -Because 'no rows = no part (unknown, never "none")'
    }
    It 'the record part (the CI field si_software_evidence_paths) carries the FULL path, a user name included (owner 2026-11-17)' {
        $rows = @(
            [pscustomobject]@{ Vendor = 'electron'; Product = 'electron'; Version = '30.0.1'; InstallKind = 'user-profile'; FullPath = 'C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\resources\app\electron.dll' }
            [pscustomobject]@{ Vendor = 'x'; Product = 'x'; Version = '1'; InstallKind = 'user-profile'; FullPath = '/home/bob/.local/lib/x.so' }
            [pscustomobject]@{ Vendor = 'y'; Product = 'y'; Version = '2'; InstallKind = 'unknown'; FullPath = 'C:\Users\Public\Documents\y.dll' }
        )
        $part = ConvertTo-SISoftwareEvidencePart -Rows $rows
        @($part.Paths) | Should -Contain 'electron/electron 30.0.1 | user-profile | C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\resources\app\electron.dll'
        @($part.Paths) | Should -Contain 'x/x 1 | user-profile | /home/bob/.local/lib/x.so'
        @($part.Paths) | Should -Contain 'y/y 2 | unknown | C:\Users\Public\Documents\y.dll'
        (@($part.Paths) -join "`n") | Should -Not -Match '<user>' -Because 'nothing is hidden: the path is the evidence an Admin fine-tunes a detection with'
    }
}

Describe 'the evidence read (advanced hunting): paging, no cap, a missing table is unknown' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine endpoint -Clear }
    It 'the query: every path as Defender has it (no slice, no take), the evidence table WITHOUT a fuzzy union, checked ids only' {
        $q = Get-SIDefenderSoftwareEvidenceKql -DeviceIds @($script:D1, $script:D2.ToUpperInvariant(), $script:D1)
        $q | Should -Match ('let _ids = dynamic\(\["{0}","{1}"\]\);' -f $script:D1, $script:D2)
        $q | Should -Match 'let _ev = DeviceTvmSoftwareEvidenceBeta\r?\n'
        $q | Should -Not -Match 'isfuzzy=true \(datatable\([^)]*\)\[\]\), \(DeviceTvmSoftwareEvidenceBeta\)' -Because 'a tenant without the table must answer an error (unknown), not "none"'
        $q | Should -Not -Match 'array_slice|\| take |make_set\(|make_list\(' -Because 'no cap: every path'
        foreach ($c in 'DiskPaths', 'RegistryPaths', 'LastSeenTime') { $q | Should -Match ('column_ifexists\("{0}"' -f $c) }
        $q | Should -Match 'union isfuzzy=true \(datatable\([^)]*\)\[\]\), \(DeviceTvmSoftwareInventory\)'
        $q | Should -Not -Match '//'
        Get-SIDefenderSoftwareEvidenceKql -DeviceIds @('"]); DeviceInfo | take 1 //', 'nope') | Should -Be ''
    }
    It 'one query per PAGE of devices; rows, device states and the record part; a device with no row is read (nothing found)' {
        $asked = New-Object System.Collections.Generic.List[string]
        $writes = New-Object System.Collections.Generic.List[object]
        $sql = { param($s, $p, $m) if ($s -match 'INSERT sidata\.SoftwareEvidence') { $writes.Add($p); @([pscustomobject]@{ Written = @(ConvertFrom-Json $p.rows).Count }) } else { @([pscustomobject]@{ Removed = 0 }) } }
        $query = {
            param($kql)
            $asked.Add($kql)
            if ($kql -match 'take 1') { return @([pscustomobject]@{ DeviceId = $script:D1 }) }
            $out = @()
            if ($kql -match $script:D1) {
                $out += [pscustomobject]@{ DeviceId = $script:D1; Kind = 'e'; SoftwareVendor = 'wordpress'; SoftwareName = 'wordpress'; SoftwareVersion = '6.4.2'
                    DiskPaths = '["D:\\home\\users\\x\\wordpress\\wp-includes\\version.php","C:\\inetpub\\wwwroot\\site\\wp-includes\\version.php"]'; RegistryPaths = '[]'; LastSeenTime = '2026-11-15T03:00:00Z' }
                $out += [pscustomobject]@{ DeviceId = $script:D1; Kind = 'i'; SoftwareVendor = 'wordpress'; SoftwareName = 'wordpress'; SoftwareVersion = '6.4.2' }
            }
            $out
        }
        $r = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1, $script:D2, $script:D3) -Query $query -Invoke $sql -PageDevices 1 -CollectionTime ([datetime]'2026-11-16T03:00:00Z')
        $r.State | Should -Be 'read'
        $r.Pages | Should -Be 3 -Because 'one query per page of devices'
        @($asked | Where-Object { $_ -match 'DeviceTvmSoftwareEvidenceBeta\r?\n' }).Count | Should -Be 3
        $r.Rows | Should -Be 2
        $r.ByDevice[$script:D1].State | Should -Be 'read'
        $r.ByDevice[$script:D2].State | Should -Be 'read' -Because 'its page was read: nothing found, which is not unknown'
        @($r.ByDevice[$script:D2].Items).Count | Should -Be 0
        $dev = @($writes | ForEach-Object { @(ConvertFrom-Json $_.devices) }) | Sort-Object DeviceId
        @($dev | ForEach-Object { '{0}={1}' -f $_.DeviceId, $_.State }) | Should -Be @("$($script:D1)=read", "$($script:D2)=read", "$($script:D3)=read")
        $rec = $global:SIRecordCaptureState.Records[('mde|device|{0}' -f $script:D1)]
        $part = ConvertFrom-Json ([string]$rec.Parts['softwareEvidence'].SIJson)
        @($part.Paths).Count | Should -Be 2
        @($part.Kinds) | Should -Be @('wordpress/wordpress|data-folder', 'wordpress/wordpress|installed')
    }
    It 'a missing table (refused read) is UNKNOWN for every device, said, and no page is asked' {
        $asked = @{ N = 0 }
        $r = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1, $script:D2) -NoStore -Query { param($kql) $asked.N++; throw "'take' operator: Failed to resolve table or column expression named 'DeviceTvmSoftwareEvidenceBeta'" }
        $r.State | Should -Be 'unknown'
        $r.Reason | Should -Match 'could not be read'
        $r.ByDevice.Count | Should -Be 0
        $asked.N | Should -Be 1 -Because 'the table is probed once; no page is asked'
        Format-SIDefenderSoftwareEvidenceLine -Result $r | Should -Match 'UNKNOWN this run \(not "no evidence"\)'
    }
    It 'an EMPTY table is unknown too (no evidence data is no proof of no path)' {
        $r = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1) -NoStore -Query { param($kql) @() }
        ($r.State, $r.ByDevice.Count) | Should -Be @('unknown', 0)
        $r.Reason | Should -Match 'holds no rows'
    }
    It 'a failed page: its devices UNKNOWN (stored as such), the other pages kept; the database missing the table is said' {
        $writes = New-Object System.Collections.Generic.List[object]
        $sql = { param($s, $p, $m) if ($s -match 'INSERT sidata\.SoftwareEvidence') { $writes.Add($p); @([pscustomobject]@{ Written = 0 }) } else { @([pscustomobject]@{ Removed = 0 }) } }
        $query = { param($kql) if ($kql -match 'take 1') { return @([pscustomobject]@{ DeviceId = 'x' }) }; if ($kql -match $script:D2) { throw 'Service unavailable (503)' }; @() }
        $r = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1, $script:D2) -Query $query -Invoke $sql -PageDevices 1 3>$null
        $r.State | Should -Be 'read'
        $r.Failed | Should -Be 1
        $r.ByDevice.ContainsKey($script:D2) | Should -BeFalse
        $r.ByDevice[$script:D1].State | Should -Be 'read'
        @($writes | ForEach-Object { @(ConvertFrom-Json $_.devices) } | Where-Object DeviceId -eq $script:D2)[0].State | Should -Be 'unknown'
        $r.Reason | Should -Match 'not read'
        $miss = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1) -Query $query -Invoke { param($s, $p, $m) @([pscustomobject]@{ Written = -1 }) }
        $miss.StoreNote | Should -Match 'not updated yet'
    }
}

Describe 'the rule conditions (hasSoftwareInstalled): absent = EXACTLY as before; installKinds; the fallback' {
    BeforeAll {
        $script:SIRuleIndexes = @{ tvmSoftware = @{
            $script:D1 = @('wordpress/wordpress', 'microsoft/sql_server_2019', 'apache/tomcat')
            $script:D2 = @('wordpress/wordpress')
            $script:D3 = @('microsoft/word', 'atlassian/confluence_server', 'fortinet/forticlient') }; softwareRuleHits = @{}; softwareRuleFallbacks = @{} }
        $script:Rules = @(Get-SIRuleSet -Engine endpoint 3>$null | ForEach-Object { $_ })
        $script:SwSpecs = New-Object System.Collections.Generic.List[object]
        foreach ($r in $script:Rules) { foreach ($d in @($r.Detections)) { foreach ($s in @(@($d.Detect.any) + @($d.Detect.all) | Where-Object { $_ })) { if ([string]$s.kind -eq 'hasSoftwareInstalled') { $script:SwSpecs.Add([pscustomobject]@{ Rule = $r.Id; Spec = $s }) } } } }
        function script:ArgsOf($Spec, [string]$RuleId) {
            $h = @{}; if ($Spec -is [System.Collections.IDictionary]) { foreach ($k in $Spec.Keys) { if ($k -ne 'kind') { $h[$k] = $Spec[$k] } } } else { foreach ($p in $Spec.PSObject.Properties) { if ($p.Name -ne 'kind') { $h[$p.Name] = $p.Value } } }
            $h['__ruleId'] = $RuleId; $h
        }
        $script:WpSpec = @{ tvmSoftwareNames = @('wordpress*'); installKinds = @('installed'); __ruleId = 'WordpressWordpress' }
        function script:Asset([string]$Dev, $Evidence) { $m = @{ MDE_DeviceId = $Dev }; if ($null -ne $Evidence) { $m['SoftwareEvidence'] = $Evidence }; [pscustomobject]@{ Name = 'srv'; Metadata = $m } }
        function script:EvOf([string]$Product, [string]$Version, [object[]]$Paths) { [ordered]@{ State = 'read'; Items = @([ordered]@{ p = $Product; v = $Version; paths = @($Paths) }) } }
    }
    It 'the shipped rules carry hasSoftwareInstalled detections (control: the parity below cannot pass by finding none)' {
        $script:SwSpecs.Count | Should -BeGreaterThan 400
    }
    It 'EVERY shipped detection WITHOUT the new conditions answers exactly as the old handler, on every device' {
        $assets = @((Asset $script:D1 $null), (Asset $script:D2 (EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = 'D:\home\x\wp'; k = 'data-folder' }))), (Asset $script:D3 $null), (Asset 'nodevice' $null))
        $n = 0
        foreach ($x in $script:SwSpecs) {
            if (Test-SISoftwareSpecHasConditions -Spec $x.Spec) { continue }
            $a = ArgsOf $x.Spec $x.Rule
            foreach ($as in $assets) {
                $n++
                (Test-SIKind_hasSoftwareInstalled -Asset $as -Args $a) | Should -Be (Test-LegacyHasSoftwareInstalled -Asset $as -Args $a) -Because "$($x.Rule) on $($as.Metadata.MDE_DeviceId)"
            }
        }
        $n | Should -BeGreaterThan 1600
        $script:SIRuleIndexes.softwareRuleHits.Count | Should -Be 0 -Because 'a detection without conditions never touches the evidence'
    }
    It 'NO shipped detection carries a path / install-kind / version condition (owner 2026-11-16: no generic path rules -- per-server exceptions instead)' {
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($r in @(Get-SIRuleSet -Engine endpoint 3>$null | ForEach-Object { $_ })) { foreach ($d in @($r.Detections)) { foreach ($s in @(@($d.Detect.any) + @($d.Detect.all) | Where-Object { $_ })) {
            if ([string]$s.kind -ne 'hasSoftwareInstalled' -or -not (Test-SISoftwareSpecHasConditions -Spec $s)) { continue }
            if (-not $ids.Contains([string]$r.Id)) { $ids.Add([string]$r.Id) }
        } } }
        $ids | Should -BeNullOrEmpty
        # and no shipped rule file names one (the custom samples included)
        $named = @(Get-ChildItem -Path (Join-Path $script:SIRoot 'asset-profiling-enrichment') -Recurse -Filter *.yaml | Select-String -Pattern '^\s*(installKinds|pathPatterns|notPathPatterns|versionRange)\s*:' | ForEach-Object { '{0}:{1}' -f $_.Filename, $_.LineNumber })
        $named | Should -BeNullOrEmpty
    }
    It 'installKinds drops a WordPress found ONLY in a data folder; an installed copy keeps it' {
        $data = Asset $script:D2 (EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = 'D:\home\users\x\wordpress\wp-includes\version.php'; k = 'data-folder' }))
        Test-SIKind_hasSoftwareInstalled -Asset $data -Args $script:WpSpec | Should -BeFalse
        Test-LegacyHasSoftwareInstalled -Asset $data -Args $script:WpSpec | Should -BeTrue -Because 'before, the data-folder copy tiered the server'
        $both = Asset $script:D2 (EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = 'D:\home\users\x\wordpress\index.php'; k = 'data-folder' }, [ordered]@{ t = 'disk'; f = '/var/www/html/wordpress/index.php'; k = 'installed' }))
        Test-SIKind_hasSoftwareInstalled -Asset $both -Args $script:WpSpec | Should -BeTrue
        $script:SIRuleIndexes.softwareRuleHits[$script:D2] | Should -Contain (Get-SISoftwareSpecKey -RuleId 'WordpressWordpress' -Spec $script:WpSpec)
        $script:SIRuleIndexes.softwareRuleHits[$script:D2] | Should -Contain '-'
    }
    It 'THE FALLBACK: unknown evidence, an inventory-only copy, an unknown kind -> matched by name as before, and counted' {
        $script:SIRuleIndexes.softwareRuleFallbacks = @{}
        Test-SIKind_hasSoftwareInstalled -Asset (Asset $script:D2 $null) -Args $script:WpSpec | Should -BeTrue
        $script:SIRuleIndexes.softwareRuleFallbacks[$script:D2] | Should -Be 'evidence-unknown'
        Test-SIKind_hasSoftwareInstalled -Asset (Asset $script:D2 ([ordered]@{ State = 'unknown'; Items = @() })) -Args $script:WpSpec | Should -BeTrue
        Test-SIKind_hasSoftwareInstalled -Asset (Asset $script:D2 (EvOf 'wordpress/wordpress' '6.4.2' @())) -Args $script:WpSpec | Should -BeTrue
        $script:SIRuleIndexes.softwareRuleFallbacks[$script:D2] | Should -Be 'no-evidence-path'
        Test-SIKind_hasSoftwareInstalled -Asset (Asset $script:D2 (EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = 'C:\wpsite\wordpress\index.php'; k = 'unknown' }))) -Args $script:WpSpec | Should -BeTrue
        $script:SIRuleIndexes.softwareRuleFallbacks[$script:D2] | Should -Be 'unknown-kind'
        # the name never matched: still false, exactly as before
        Test-SIKind_hasSoftwareInstalled -Asset (Asset $script:D3 $null) -Args $script:WpSpec | Should -BeFalse
    }
    It 'pathPatterns / notPathPatterns / versionRange (a JSON round trip of the evidence is read too)' {
        $ev = EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = '/var/www/backup/wordpress/index.php'; k = 'installed' })
        $evJ = ConvertFrom-Json (ConvertTo-Json -InputObject $ev -Depth 6)
        (Test-SISoftwareSpecConditions -Spec @{ notPathPatterns = @('(?i)/backup/') } -Evidence $evJ -Patterns @('wordpress*')).Match | Should -BeFalse
        (Test-SISoftwareSpecConditions -Spec @{ pathPatterns = @('^/var/www/') } -Evidence $evJ -Patterns @('wordpress*')).Match | Should -BeTrue
        (Test-SISoftwareSpecConditions -Spec @{ pathPatterns = @('^C:\\') } -Evidence $evJ -Patterns @('wordpress*')).Match | Should -BeFalse
        (Test-SISoftwareSpecConditions -Spec @{ versionRange = '>=6.0 <6.4.3' } -Evidence $evJ -Patterns @('wordpress*')).Match | Should -BeTrue
        (Test-SISoftwareSpecConditions -Spec @{ versionRange = '>=6.5' } -Evidence $evJ -Patterns @('wordpress*')).Match | Should -BeFalse
        $odd = Test-SISoftwareSpecConditions -Spec @{ versionRange = '>=6.5' } -Evidence (EvOf 'wordpress/wordpress' '6.x-beta' @()) -Patterns @('wordpress*')
        ($odd.Match, $odd.Fallback) | Should -Be @($true, $true) -Because 'a version that cannot be compared is never decided against'
        Test-SIEvVersionRange -Version '2.17.1' -Range '<2.17' | Should -BeFalse
        Test-SIEvVersionRange -Version '2.16.0' -Range '>=2.0, <2.17' | Should -BeTrue
        Test-SIEvVersionRange -Version '1.0' -Range 'abc' | Should -BeNullOrEmpty
    }
    It 'a copy with disk paths is decided by its disk paths (its registry rows are no evidence of where it is)' {
        $ev = EvOf 'wordpress/wordpress' '6.4.2' @([ordered]@{ t = 'disk'; f = 'D:\data\wp\index.php'; k = 'data-folder' }, [ordered]@{ t = 'registry'; f = 'HKLM\SOFTWARE\WP'; k = 'unknown' })
        (Test-SISoftwareSpecConditions -Spec $script:WpSpec -Evidence $ev -Patterns @('wordpress*')).Match | Should -BeFalse
    }
}

Describe 'the CI rule of a conditioned detection reads the profiler''s hits; without them it matches by name as before' {
    It 'a detection WITHOUT conditions converts exactly as before (every shipped one)' {
        $rules = @(Get-SIRuleSet -Engine endpoint 3>$null | ForEach-Object { $_ })
        $n = 0
        foreach ($r in $rules) { foreach ($d in @($r.Detections)) { foreach ($s in @(@($d.Detect.any) + @($d.Detect.all) | Where-Object { $_ })) {
            if ([string]$s.kind -ne 'hasSoftwareInstalled' -or (Test-SISoftwareSpecHasConditions -Spec $s)) { continue }
            $n++
            (ConvertTo-Json -InputObject (ConvertTo-SICiKindCondition -Spec $s -RuleId ([string]$r.Id)) -Depth 6 -Compress) | Should -Be (ConvertTo-Json -InputObject (Get-LegacyCiSoftwareCondition $s) -Depth 6 -Compress)
        } } }
        $n | Should -BeGreaterThan 400
    }
    It 'conditioned: matched when the profiler recorded its key; not when it evaluated and did not; by name when it never evaluated' {
        $spec = [pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('wordpress*'); installKinds = @('installed') }
        $c = ConvertTo-SICiKindCondition -Spec $spec -RuleId 'WordpressWordpress'
        $key = Get-SISoftwareSpecKey -RuleId 'WordpressWordpress' -Spec $spec
        $key | Should -Match '^WordpressWordpress#[0-9a-f]{12}$'
        Test-SICondition $c @{ si_installed_software = @('wordpress/wordpress'); si_software_rule_hits = @('-', $key) } | Should -BeTrue
        Test-SICondition $c @{ si_installed_software = @('wordpress/wordpress'); si_software_rule_hits = @('-') } | Should -BeFalse -Because 'evaluated against known evidence and excluded'
        Test-SICondition $c @{ si_installed_software = @('wordpress/wordpress') } | Should -BeTrue -Because 'not evaluated (no evidence field): by name as before'
        Test-SICondition $c @{ si_installed_software = @('microsoft/word') } | Should -BeFalse
        Get-SISoftwareSpecKey -RuleId 'WordpressWordpress' -Spec @{ tvmSoftwareNames = @('WORDPRESS*'); installKinds = @('Installed') } | Should -Be $key -Because 'both sides compute the same key'
        Get-SISoftwareSpecKey -RuleId 'WordpressWordpress' -Spec @{ tvmSoftwareNames = @('wordpress*'); installKinds = @('installed', 'registry-only') } | Should -Not -Be $key
    }
    It 'every shipped detection still converts (none unconverted)' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
        $conv = ConvertTo-SICiRules -RuleSet @(Get-SICiRuleSetAll)
        (@($conv.Unconverted) -join "`n") | Should -BeNullOrEmpty
    }
}

Describe 'the finding fields: device + vendor + product + version, the count unchanged, unknown stays empty' {
    BeforeAll {
        $script:EvRows = @(
            [pscustomobject]@{ DeviceId = $script:D1; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.13'; FullPath = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll'; InstallKind = 'bundled'; Application = 'acrobat_dc'; ApplicationVendor = 'adobe'; ApplicationVersion = '23.008'; ApplicationSource = 'inventory' }
            [pscustomobject]@{ DeviceId = $script:D1; Vendor = 'openssl'; Product = 'openssl'; Version = '3.0.13'; FullPath = 'C:\Program Files\Contoso\Agent\libssl.dll'; InstallKind = 'bundled'; Application = 'Contoso Agent'; ApplicationSource = 'folder' }
            [pscustomobject]@{ DeviceId = $script:D1; Vendor = 'openssl'; Product = 'openssl'; Version = '3.5.7'; FullPath = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'; InstallKind = 'installed'; Application = 'openssl'; ApplicationSource = 'inventory' }
        )
    }
    It 'every path of the copy, its kinds and the applications; the row count is the source''s' {
        $rows = @(
            [pscustomobject]@{ ConfigurationId = 'CVE-2024-1'; MdeDeviceId = $script:D1.ToUpperInvariant(); SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl'; SI_AffectedVersion = '3.0.13'; si_affected_path = 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll' }
            [pscustomobject]@{ ConfigurationId = 'CVE-2024-2'; MdeDeviceId = $script:D1; SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl'; SI_AffectedVersion = '3.0.13;3.5.7' }
            [pscustomobject]@{ ConfigurationId = 'CVE-2024-3'; MdeDeviceId = $script:D2; SI_AffectedVendor = 'openssl'; SI_AffectedProduct = 'openssl'; SI_AffectedVersion = '3.0.13' }
            @{ ConfigurationId = 'scid-1'; MdeDeviceId = $script:D1 }
        )
        $out = Add-RASoftwareEvidence -Rows $rows -Read { param($ids) $script:Asked = @($ids); $script:EvRows }
        @($out).Count | Should -Be 4
        @($script:Asked | Sort-Object) | Should -Be @($script:D1, $script:D2) -Because 'only the bucket''s devices are read'
        $out[0].si_evidence_paths | Should -Be 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll;C:\Program Files\Contoso\Agent\libssl.dll'
        $out[0].si_install_kind | Should -Be 'bundled'
        $out[0].si_bundled_by | Should -Be 'Contoso Agent;adobe/acrobat_dc 23.008' -Because 'distinct, in ordinal order'
        $out[0].si_affected_path | Should -Be 'C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll' -Because 'the report''s own field is left as it is'
        $out[1].si_install_kind | Should -Be 'bundled;installed'
        @($out[1].si_evidence_paths -split ';').Count | Should -Be 3
        $out[2].PSObject.Properties['si_evidence_paths'] | Should -BeNullOrEmpty -Because 'no stored evidence for the copy: unknown, left empty'
        $out[3].Contains('si_evidence_paths') | Should -BeFalse
    }
    It 'a failed read is said once and changes no row; no database = the rows unchanged' {
        $global:RA_SoftwareEvidenceSaid = $false
        $said = New-Object System.Collections.Generic.List[string]
        $rows = @([pscustomobject]@{ MdeDeviceId = $script:D1; SI_AffectedProduct = 'openssl'; SI_AffectedVendor = 'openssl'; SI_AffectedVersion = '3.0.13' })
        $o1 = Add-RASoftwareEvidence -Rows $rows -Read { throw 'timeout' } -Log { param($m) $said.Add($m) }
        $o2 = Add-RASoftwareEvidence -Rows $rows -Read { throw 'timeout' } -Log { param($m) $said.Add($m) }
        $said.Count | Should -Be 1
        $said[0] | Should -Match 'complete without it'
        $o1[0].PSObject.Properties['si_evidence_paths'] | Should -BeNullOrEmpty
        (Add-RASoftwareEvidence -Rows $rows)[0].PSObject.Properties['si_evidence_paths'] | Should -BeNullOrEmpty
    }
}

Describe 'the data model: catalog, device mapping, finding row columns' {
    BeforeAll { $script:Model = Get-SIDataModel; $script:Cat = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\field-catalog.locked.json') | ConvertFrom-Json }
    It 'the catalog carries the device and finding fields, the Pro copy is identical' {
        $names = @($script:Cat.fields | ForEach-Object name)
        foreach ($n in 'si_software_evidence_paths', 'si_software_install_kind', 'si_software_bundled_by', 'si_software_rule_hits', 'si_evidence_paths', 'si_install_kind', 'si_bundled_by') { $names | Should -Contain $n }
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Core\ProData\DataModel\field-catalog.locked.json')) | Should -Be ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\field-catalog.locked.json')))
        $ft = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\finding-texts.locked.json') | ConvertFrom-Json
        foreach ($n in 'si_evidence_paths', 'si_install_kind', 'si_bundled_by') { @($ft.rowColumns.$n) | Should -Be @($n) }
    }
    It 'the device record maps the evidence part and the rule hits onto its SI fields' {
        $null = Reset-SIRecordCapture -Engine endpoint -Clear
        Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $script:D1 -Part 'machine' -Object ([pscustomobject]@{ id = $script:D1; computerDnsName = 'web1.contoso.test' })
        Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $script:D1 -Part 'softwareEvidence' -Object ([pscustomobject]@{ Paths = @('wordpress/wordpress 6.4.2 | data-folder | D:\home\x\wp\index.php'); Kinds = @('wordpress/wordpress|data-folder'); BundledBy = @() })
        $global:SIRuleIndexesForRecords = @{ tvmSoftware = @{}; softwareRuleHits = @{ $script:D1 = @('-', 'WordpressWordpress#0123456789ab') } }
        try { Add-SIRecordPartsFromRuleIndexes } finally { $global:SIRuleIndexesForRecords = $null }
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        $r = @($res.Rows | Where-Object mde_device_id -eq $script:D1)[0]
        @($r.si_software_evidence_paths) | Should -Be @('wordpress/wordpress 6.4.2 | data-folder | D:\home\x\wp\index.php')
        @($r.si_software_install_kind) | Should -Be @('wordpress/wordpress|data-folder')
        @($r.si_software_rule_hits) | Should -Be @('-', 'WordpressWordpress#0123456789ab')
    }
}

Describe 'the schema: additive, and on a real SQL Server' {
    It 'the data schema stays additive and carries the two tables (one row per device: only the newest run), their indexes and the view' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
        $add = Test-SISchemaIsAdditive -Sql $s
        @($add.Findings | ForEach-Object { '{0}: {1}' -f $_.Line, $_.Why }) | Should -BeNullOrEmpty
        $add.IsAdditive | Should -BeTrue
        foreach ($x in 'CREATE TABLE sidata.SoftwareEvidence (', 'CREATE TABLE sidata.SoftwareEvidenceDevice (', 'CX_SoftwareEvidence_Device ON sidata.SoftwareEvidence (DeviceId)',
                       'IX_SoftwareEvidence_Software ON sidata.SoftwareEvidence (Vendor, Product, Version)', 'CONSTRAINT PK_SoftwareEvidenceDevice PRIMARY KEY CLUSTERED (DeviceId)',
                       "CHECK (State IN ('read', 'unknown', 'writing'))", 'CREATE VIEW sidata.vSoftwareEvidence', "JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = e.DeviceId AND s.State = N''read''") { $s | Should -Match ([regex]::Escape($x)) }
    }
    It 'the write is one transaction per chunk: the old rows go and the state turns writing in the first, read in the last; an unknown device keeps no row' {
        $w = Get-SISoftwareEvidenceWriteSql
        $w | Should -Match 'SET XACT_ABORT ON;'
        $w | Should -Match 'BEGIN TRAN;'
        $w | Should -Match 'COMMIT;'
        $w | Should -Match "IF @first = 1\s+BEGIN\s+DELETE e FROM sidata\.SoftwareEvidence e JOIN @d d ON d\.DeviceId = e\.DeviceId;"
        $w | Should -Not -Match 'e\.CollectionTime = @t AND @first' -Because 'the old rows go whatever run wrote them -- only the newest run is kept'
        $w | Should -Match "CASE WHEN State = N'read' THEN N'writing' ELSE N'unknown' END"
        $w | Should -Match "IF @last = 1\s+UPDATE s SET State = N'read'"
        # the readers take rows of READ devices only
        Get-SISoftwareEvidenceReadSql | Should -Match "s\.State = N'read'"
        # the chunks: first / last flags as the rows go
        $calls = New-Object System.Collections.Generic.List[object]
        $null = Write-SISoftwareEvidence -Invoke { param($s, $p, $m) $calls.Add($p); @([pscustomobject]@{ Written = 1 }) } -CollectionTime ([datetime]'2026-11-16T03:00:00Z') -Devices @(@{ DeviceId = $script:D1; State = 'read'; Rows = 5 }) -Rows @(1..5 | ForEach-Object { [pscustomobject]@{ DeviceId = $script:D1; FullPath = "C:\p$_"; Vendor = 'v'; Product = 'p'; Version = '1'; PathType = 'disk'; InstallKind = 'installed' } }) -ChunkRows 2
        @($calls | ForEach-Object { '{0}{1}' -f $_.first, $_.last }) | Should -Be @('10', '00', '01')
        $calls.Clear()
        $null = Write-SISoftwareEvidence -Invoke { param($s, $p, $m) $calls.Add($p); @([pscustomobject]@{ Written = 0 }) } -CollectionTime ([datetime]'2026-11-16T03:00:00Z') -Devices @(@{ DeviceId = $script:D1; State = 'unknown'; Rows = 0 }) -Rows @()
        @($calls | ForEach-Object { '{0}{1}' -f $_.first, $_.last }) | Should -Be @('11')
    }
    It 'a missing / empty evidence table marks every device of the run UNKNOWN in the database (its earlier paths go)' {
        $writes = New-Object System.Collections.Generic.List[object]
        $sql = { param($s, $p, $m) if ($s -match 'INSERT sidata\.SoftwareEvidence') { $writes.Add($p); @([pscustomobject]@{ Written = 0 }) } else { @([pscustomobject]@{ Removed = 0 }) } }
        $r = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1, $script:D2) -Invoke $sql -Query { param($kql) throw "Failed to resolve table or column expression named 'DeviceTvmSoftwareEvidenceBeta'" }
        $r.State | Should -Be 'unknown'
        $dev = @($writes | ForEach-Object { @(ConvertFrom-Json $_.devices) }) | Sort-Object DeviceId
        @($dev | ForEach-Object { '{0}={1}' -f $_.DeviceId, $_.State }) | Should -Be @("$($script:D1)=unknown", "$($script:D2)=unknown")
        $writes.Clear()
        $null = Read-SIDefenderSoftwareEvidence -DeviceIds @($script:D1) -Invoke $sql -Query { param($kql) @() }
        @($writes | ForEach-Object { @(ConvertFrom-Json $_.devices) } | ForEach-Object State) | Should -Be @('unknown')
    }
    Context 'real SQL Server' {
        BeforeAll {
            function script:New-LocalInvoke([string]$Db) {
                $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
                {
                    param([string]$sql, $p, [string]$mode)
                    $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                    try {
                        $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                        if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                        if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                        if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                        $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                        while ($r.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add([pscustomobject]$h) }
                        $r.Close(); return , $rows.ToArray()
                    } finally { $cn.Close() }
                }.GetNewClosure()
            }
        }
        It 'ONLY THE NEWEST RUN: a device read again is replaced (never doubled), an unknown device keeps nothing, a write cut before its last chunk is never shown; read per device / CI / view; retention by staleness' -Skip:(-not $script:LocalSql) {
            $db = 'siev_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $master = New-LocalInvoke 'master'
            [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
            try {
                $inv = New-LocalInvoke $db
                $schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
                [void](& $inv $schema @{} 'nonquery'); [void](& $inv $schema @{} 'nonquery')
                $t1 = [datetime]::SpecifyKind([datetime]'2026-11-14T03:00:00', 'Utc'); $t2 = $t1.AddDays(1); $t3 = $t2.AddDays(1)
                $rowsD1 = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $script:D1 -Inventory @((Inv 'adobe' 'acrobat_dc' '23.0')) -Evidence @(
                    (Ev 'openssl' 'openssl' '3.0.13' -Disk @('C:\Program Files\Adobe\Acrobat DC\Acrobat\libcrypto-3-x64.dll', ('D:\' + ('deep\' * 400) + 'libssl.dll')) -Reg @('HKLM\SOFTWARE\OpenSSL'))))
                $rowsD2 = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $script:D2 -Evidence @((Ev 'wordpress' 'wordpress' '6.4.2' -Disk @('D:\home\users\x\wordpress\index.php'))))
                # run 1: both read (in chunks of 2 rows: 4 rows = 2 transactions)
                (Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t1 -Devices @(@{ DeviceId = $script:D1; State = 'read'; Rows = $rowsD1.Count }, @{ DeviceId = $script:D2; State = 'read'; Rows = 1 }) -Rows (@($rowsD1) + @($rowsD2)) -ChunkRows 2).Written | Should -Be 4
                [int](& $inv 'SELECT MAX(LEN(FullPath)) FROM sidata.SoftwareEvidence' @{} 'scalar') | Should -BeGreaterThan 2000 -Because 'a long path is kept whole'
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D1, $script:D2)).Count | Should -Be 4
                # run 2: D1 read (a new path), D2 UNKNOWN -> D1 has ONLY run 2's rows, D2 has NONE (never run 1's paths as current)
                $rowsD1b = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $script:D1 -Evidence @((Ev 'openssl' 'openssl' '3.5.7' -Disk @('C:\Program Files\OpenSSL-Win64\bin\openssl.exe'))))
                (Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t2 -Devices @(@{ DeviceId = $script:D1; State = 'read'; Rows = 1 }, @{ DeviceId = $script:D2; State = 'unknown'; Rows = 0 }) -Rows $rowsD1b).Written | Should -Be 1
                # the same page written again (a part re-run): replaced, never doubled
                (Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t2 -Devices @(@{ DeviceId = $script:D1; State = 'read'; Rows = 1 }, @{ DeviceId = $script:D2; State = 'unknown'; Rows = 0 }) -Rows $rowsD1b).Written | Should -Be 1
                [int](& $inv 'SELECT COUNT(*) FROM sidata.SoftwareEvidence' @{} 'scalar') | Should -Be 1 -Because 'only the newest run is kept: run 1''s rows of BOTH devices are gone'
                [int](& $inv 'SELECT COUNT(DISTINCT CollectionTime) FROM sidata.SoftwareEvidence' @{} 'scalar') | Should -Be 1
                $now = @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D1, $script:D2))
                @($now | ForEach-Object Version | Sort-Object -Unique) | Should -Be @('3.5.7')
                @($now | Where-Object DeviceId -eq $script:D2).Count | Should -Be 0 -Because 'unknown this run: no paths, and never the older ones'
                [string](& $inv 'SELECT State FROM sidata.SoftwareEvidenceDevice WHERE DeviceId = @d' @{ d = $script:D2 } 'scalar') | Should -Be 'unknown'
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D1) -CollectionTime $t2).Count | Should -Be 1
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D1) -CollectionTime $t1).Count | Should -Be 0
                # run 3: D2 read again, but the write is CUT after its first chunk (the last chunk never ran): nothing shown for it
                $rowsD2c = @(ConvertTo-SISoftwareEvidenceRows -DeviceId $script:D2 -Evidence @((Ev 'wordpress' 'wordpress' '6.5.0' -Disk @('C:\inetpub\wwwroot\wp\index.php', 'C:\inetpub\wwwroot\wp\wp-load.php'))))
                $rj = ConvertTo-Json -InputObject @($rowsD2c[0] | ForEach-Object { [ordered]@{ DeviceId = $_.DeviceId; Vendor = $_.Vendor; Product = $_.Product; Version = $_.Version; PathType = $_.PathType; FullPath = $_.FullPath; InstallKind = $_.InstallKind } }) -Compress
                if (-not $rj.StartsWith('[')) { $rj = '[' + $rj + ']' }
                $dj = ConvertTo-Json -InputObject @([ordered]@{ DeviceId = $script:D2; State = 'read'; Rows = 2 }) -Compress; if (-not $dj.StartsWith('[')) { $dj = '[' + $dj + ']' }
                [void](& $inv (Get-SISoftwareEvidenceWriteSql) @{ ct = $t3.ToString('yyyy-MM-ddTHH:mm:ss.fff'); devices = $dj; rows = $rj; first = 1; last = 0 } 'rows')
                [string](& $inv 'SELECT State FROM sidata.SoftwareEvidenceDevice WHERE DeviceId = @d' @{ d = $script:D2 } 'scalar') | Should -Be 'writing'
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D2)).Count | Should -Be 0 -Because 'a device is shown whole or not at all'
                [int](& $inv 'SELECT COUNT(*) FROM sidata.vSoftwareEvidence WHERE DeviceId = @d' @{ d = $script:D2 } 'scalar') | Should -Be 0
                # the next run writes it whole -> shown
                (Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t3 -Devices @(@{ DeviceId = $script:D2; State = 'read'; Rows = 2 }) -Rows $rowsD2c -ChunkRows 1).Written | Should -Be 2
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D2)).Count | Should -Be 2
                # a device read with nothing found: no rows, state read (never its older paths)
                $null = Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t3 -Devices @(@{ DeviceId = $script:D1; State = 'read'; Rows = 0 }) -Rows @()
                @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D1)).Count | Should -Be 0
                [string](& $inv 'SELECT State FROM sidata.SoftwareEvidenceDevice WHERE DeviceId = @d' @{ d = $script:D1 } 'scalar') | Should -Be 'read'
                # a CI through CiLink, and the view
                [void](& $inv "INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary) VALUES (N'CI-1', N'mde', N'device', @d, 1)" @{ d = $script:D2 } 'nonquery')
                @(Get-SISoftwareEvidence -Invoke $inv -CiId 'CI-1').Count | Should -Be 2
                [string](& $inv 'SELECT TOP 1 CiId FROM sidata.vSoftwareEvidence WHERE DeviceId = @d' @{ d = $script:D2 } 'scalar') | Should -Be 'CI-1'
                # the finding join reads the stored evidence
                $ix = New-SIFindingEvidenceIndex -Rows @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds @($script:D2))
                (Get-SIFindingEvidenceValues -Index $ix -DeviceId $script:D2 -Vendors 'wordpress' -Products 'wordpress' -Versions '6.5.0').Kinds | Should -Be 'installed'
                # retention: a device no run has read for more than the stale days before the newest run goes, rows and state
                $old = '0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa'
                $null = Write-SISoftwareEvidence -Invoke $inv -CollectionTime $t3.AddDays(-40) -Devices @(@{ DeviceId = $old; State = 'read'; Rows = 1 }) -Rows @([pscustomobject]@{ DeviceId = $old; Vendor = 'v'; Product = 'p'; Version = '1'; PathType = 'disk'; FullPath = 'C:\x'; InstallKind = 'installed' })
                (Invoke-SISoftwareEvidenceRetention -Invoke $inv -Days 30 -Batch 1).Removed | Should -Be 2
                [int](& $inv 'SELECT COUNT(*) FROM sidata.SoftwareEvidenceDevice WHERE DeviceId = @d' @{ d = $old } 'scalar') | Should -Be 0
                [int](& $inv 'SELECT COUNT(*) FROM sidata.SoftwareEvidenceDevice' @{} 'scalar') | Should -Be 2 -Because 'the devices of the recent runs stay'
                (Invoke-SISoftwareEvidenceRetention -Invoke $inv -Days 30).Removed | Should -Be 0
                Get-SISoftwareEvidenceStaleDays -Setting '' | Should -Be 30
                Get-SISoftwareEvidenceStaleDays -Setting '14' | Should -Be 14
            } finally {
                try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
            }
        }
        It 'the evidence read at a large install''s size: every device''s whole inventory, read 100 devices at a time -- each read a seek by device, the time and calls measured' -Tag 'Scale' -Skip:(-not $script:LocalSql) {
            # SI_BENCH_EV_DEVICES devices (default 1,000) x SI_BENCH_EV_ROWS evidence rows each (default 600: 300 software x 2 paths),
            # read as Risk Analysis reads them (Add-RASoftwareEvidence: groups of 100 devices)
            $devs = 1000; $per = 600
            if ($env:SI_BENCH_EV_DEVICES) { $devs = [int]$env:SI_BENCH_EV_DEVICES }; if ($env:SI_BENCH_EV_ROWS) { $per = [int]$env:SI_BENCH_EV_ROWS }
            $db = 'sievb_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $master = New-LocalInvoke 'master'
            [void](& $master "CREATE DATABASE [$db]; ALTER DATABASE [$db] SET RECOVERY SIMPLE;" @{} 'nonquery')
            try {
                $inv = New-LocalInvoke $db
                [void](& $inv ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))) @{} 'nonquery')
                $fill = @"
SET NOCOUNT ON;
;WITH n AS (SELECT TOP ($devs) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS d FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT sidata.SoftwareEvidenceDevice (DeviceId, State, CollectionTime) SELECT RIGHT(REPLICATE(N'0', 40) + CONVERT(nvarchar(10), d), 40), N'read', '2026-11-16T03:00:00' FROM n;
DECLARE @lo int = 0;
WHILE @lo < $devs
BEGIN
    ;WITH n AS (SELECT TOP ($per) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b),
          d AS (SELECT TOP (CASE WHEN $devs - @lo < 100 THEN $devs - @lo ELSE 100 END) @lo + ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS d FROM sys.all_objects)
    INSERT sidata.SoftwareEvidence (CollectionTime, DeviceId, Vendor, Product, Version, PathType, FullPath, Drive, InstallKind, Application, ApplicationSource)
    SELECT '2026-11-16T03:00:00', RIGHT(REPLICATE(N'0', 40) + CONVERT(nvarchar(10), d.d), 40), N'vendor' + CONVERT(nvarchar(10), n.i / 2), N'product' + CONVERT(nvarchar(10), n.i / 2),
           CONVERT(nvarchar(10), n.i % 7) + N'.0', N'disk', N'C:\Program Files\Vendor' + CONVERT(nvarchar(10), n.i / 2) + N'\Product' + CONVERT(nvarchar(10), n.i / 2) + N'\bin' + CONVERT(nvarchar(10), n.i % 2) + N'\p.dll',
           N'C:', CASE WHEN n.i % 2 = 1 THEN N'bundled' ELSE N'installed' END, N'Host' + CONVERT(nvarchar(10), n.i % 40), N'folder'
    FROM d CROSS JOIN n;
    SET @lo = @lo + 100;
END
"@
                [void](& $inv $fill @{} 'nonquery')
                $all = @(0..($devs - 1) | ForEach-Object { ('{0:D40}' -f $_) })
                $clock = [Diagnostics.Stopwatch]::StartNew(); $rows = 0L; $calls = 0; $slowest = 0.0
                for ($at = 0; $at -lt $all.Count; $at += 100) {
                    $g = @($all[$at..([Math]::Min($all.Count, $at + 100) - 1)])
                    $one = [Diagnostics.Stopwatch]::StartNew()
                    $rows += @(Get-SISoftwareEvidence -Invoke $inv -DeviceIds $g).Count; $calls++
                    if ($one.Elapsed.TotalSeconds -gt $slowest) { $slowest = $one.Elapsed.TotalSeconds }
                }
                $secs = $clock.Elapsed.TotalSeconds
                # the plan the reads ran with: a SEEK into the evidence by device, never a scan of it
                # the plan of one group's read, as the server ran it (SET STATISTICS XML ON: the actual plan of every statement
                # comes back as its own result) -- and the logical reads of the evidence table from the same run
                $plan = New-Object System.Collections.Generic.List[string]
                $cn = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 300
                    $ids = ConvertTo-Json -InputObject @($all[0..99]) -Compress
                    $c.CommandText = 'SET STATISTICS XML ON; ' + (Get-SISoftwareEvidenceReadSql)
                    [void]$c.Parameters.AddWithValue('@ct', ''); [void]$c.Parameters.AddWithValue('@devices', $ids); [void]$c.Parameters.AddWithValue('@ciId', '')
                    $rd = $c.ExecuteReader()
                    try { do { $isPlan = ($rd.FieldCount -eq 1 -and $rd.GetName(0) -like '*Showplan*'); while ($rd.Read()) { if ($isPlan) { $plan.Add([string]$rd.GetValue(0)) } } } while ($rd.NextResult()) } finally { $rd.Dispose() }
                } finally { $cn.Dispose() }
                $plan = @($plan | ForEach-Object { [pscustomobject]@{ PlanXml = $_; Runs = 1; Reads = 0 } })                # every operator that reads the evidence table, from the plan XML: its physical operator and index
                $ops = New-Object System.Collections.Generic.List[string]
                foreach ($x in @($plan | ForEach-Object PlanXml | Where-Object { ([string]$_).TrimStart().StartsWith('<') })) {
                    $xd = [System.Xml.XmlDocument]::new(); $xd.LoadXml([string]$x); $ns = [System.Xml.XmlNamespaceManager]::new($xd.get_NameTable()); $ns.AddNamespace('sp', 'http://schemas.microsoft.com/sqlserver/2004/07/showplan')
                    foreach ($ro in @($xd.SelectNodes("//sp:RelOp[sp:IndexScan/sp:Object[@Table='[SoftwareEvidence]'] or sp:TableScan/sp:Object[@Table='[SoftwareEvidence]']]", $ns))) {
                        $ob = $ro.SelectSingleNode("sp:IndexScan/sp:Object | sp:TableScan/sp:Object", $ns)
                        $ops.Add(('{0} {1}' -f $ro.GetAttribute('PhysicalOp'), $ob.GetAttribute('Index')))
                    }
                }
                Write-Host ('bench: the evidence table in the plan: {0}' -f ($(if ($ops.Count) { ($ops -join '; ') } else { '(not found)' })))
                $seek = @($ops | Where-Object { $_ -match 'Seek' }).Count
                $scan = @($ops | Where-Object { $_ -match 'Scan' }).Count
                $reads = [long](@($plan | ForEach-Object { [long]$_.Reads } | Measure-Object -Sum).Sum); $runs = [long](@($plan | ForEach-Object { [long]$_.Runs } | Measure-Object -Sum).Sum)
                Write-Host ("bench: evidence read: {0:N0} devices x {1} rows = {2:N0} rows in {3} reads of 100 devices: {4:N1} s (slowest read {5:N2} s); the plan of one group's read: {6} seek(s), {7} scan(s) of the evidence" -f $devs, $per, $rows, $calls, $secs, $slowest, $seek, $scan, $reads, $runs)
                $rows | Should -Be ([long]$devs * $per) -Because 'every evidence row of every device is read'
                $plan.Count | Should -BeGreaterThan 0 -Because 'the read''s plan is found'
                $seek | Should -BeGreaterThan 0
                $scan | Should -Be 0 -Because 'a group''s read seeks its devices -- never a scan of every device''s evidence'
            } finally {
                try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
            }
        }
    }
}
