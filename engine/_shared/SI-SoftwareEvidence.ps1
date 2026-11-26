#Requires -Version 5.1
<#
    SOFTWARE EVIDENCE -- WHERE each installed copy of a software is, as SecurityInsight data (one shared foundation for the
    software rules' path conditions and for the findings that must say WHERE and WHO to contact).

    Source: Defender advanced hunting DeviceTvmSoftwareEvidenceBeta (DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion,
    DiskPaths, RegistryPaths, LastSeenTime) -- EVERY path, every drive, the registry too, no cap -- read by the endpoint
    collection one page of devices at a time (engine/asset-profiling/discovery/Get-SIDefenderSoftwareEvidence.ps1).

    THIS FILE (pure functions, unless the name says SQL):
      ConvertTo-SIEvidencePathInfo     one path -> PathType, Drive, InstallKind (before the bundled rule), the product folder
      Get-SIEvidenceFolderApplication  the product folder a path lies in ("C:\Program Files\Adobe\Acrobat DC\x.dll" ->
                                       "Adobe Acrobat DC"; WindowsApps -> the package; Common Files and the Windows driver
                                       store one level deeper; the install-folder table $script:SIEvInstallFolders
                                       first: Azure VM extensions (C:\Packages\Plugins\<Publisher.Type>\<version>,
                                       /var/lib/waagent/<Publisher.Type>-<version>) -> the extension's name, an OEM recovery
                                       copy of a drive -> as on that drive; a registry path -> none)
      Resolve-SIEvidenceApplication    the folder matched to the device's OWN Defender software inventory (name + version,
                                       source 'inventory'); unmatched = the folder name (source 'folder')
      ConvertTo-SISoftwareEvidenceRows evidence + inventory of one device -> the rows of sidata.SoftwareEvidence
      ConvertTo-SISoftwareEvidenceDevice  the same as the device's compact evidence (rule input) and its record part
      Test-SISoftwareSpecConditions    a hasSoftwareInstalled detection's optional pathPatterns / notPathPatterns /
                                       installKinds / versionRange against the device's evidence (the fallback is here)
      Write-SISoftwareEvidence / Get-SISoftwareEvidence / Get-SISoftwareEvidenceForFindings   the SQL interfaces

    INSTALL KINDS (one per path; measured rules, never a guess -- 'unknown' when no rule decides):
      installed      under an install root: <drive>:\Program Files, Program Files (x86), Program Files (Arm), ProgramData,
                     Windows (any drive); a web root (inetpub, wwwroot, htdocs at the top three folder levels; www, websites,
                     web, sites, webroot, webapps as a drive's first folder);
                     /usr, /opt, /bin, /sbin, /lib, /lib64, /snap, /var/www, /srv/www, /srv/http, /Applications, /Library, /System
      bundled        a LIBRARY (openssl, curl, zlib, sqlite, log4j, jackson, python, .net, java, electron, chromium, node.js,
                     libxml2, expat, libpng, libjpeg, libtiff, freetype, pcre, libssh2, nghttp2, libwebp) whose path lies in
                     ANOTHER product's folder (the folder is not the library's own); si_bundled_by names that product
      user-profile   C:\Users\<user>\... (not Public / Default / All Users), /home/<user>/..., /Users/<user>/..., /root/...
      data-folder    a share (\\server\share\...); a top-level data / home / users / shares / profiles folder of a non-system
                     drive; any other path on a drive other than C: that is not an install or web root; /srv (not www/http),
                     /data, /mnt, /media, /share, /nfs, /export
      registry-only  a registry path of a copy Defender found ONLY in the registry (a copy with a disk path is decided by its
                     disk paths; its registry rows are 'unknown')
      unknown        everything else (e.g. C:\xampp, /tmp, /var/lib/docker)
    C: is taken as the system drive (Windows' default); it is the only drive-letter assumption.

    PowerShell 5.1 and 7: no ?. / ??, no ternary. No I/O outside the SQL functions; nothing here writes to Defender.
#>

# ---------------------------------------------------------------------------------------------------------------------
#  Small helpers
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIEvValue {
    <# PURE. A value from a dictionary or an object; $null when absent or DBNull. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    $v = $null
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { $v = $Item[$Name] } }
    else { $p = $Item.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    if ($v -is [System.DBNull]) { return $null }
    return $v
}

function Get-SIEvRows {
    <# PURE. The rows of a SQL seam's answer, whatever its shape: a seam may hand back its rows as ONE list object (a
       `return , $rows`), which @( ) does not unroll -- rows are dictionaries or objects, never lists. #>
    param($Answer)
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IList] -and -not ($x -is [System.Collections.IDictionary])) { foreach ($y in $x) { if ($null -ne $y) { $y } } }
        else { $x }
    }
}

function Get-SIEvTokens {
    <# PURE. A name as lower-case word tokens: split on anything that is not a letter or digit, and between letters and
       digits ("Python311" -> python, 311; "jre1.8.0_381" -> jre, 1, 8, 0, 381; "Office16" -> office, 16). #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return , @() }
    $t = $Text.ToLowerInvariant()
    $t = [regex]::Replace($t, '([a-z])([0-9])', '$1 $2')
    $t = [regex]::Replace($t, '([0-9])([a-z])', '$1 $2')
    return , @($t -split '[^a-z0-9]+' | Where-Object { $_ })
}

function ConvertTo-SIEvArray {
    <# PURE. A list value from advanced hunting (an array, its JSON text, one string, nothing) -> string array. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return , @() }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if (-not $s) { return , @() }
        if ($s.StartsWith('[')) {
            try { $j = ConvertFrom-Json -InputObject $s; return , @(@($j) | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_.Trim() }) } catch { return , @($s) }
        }
        return , @($s)
    }
    return , @(@($Value) | ForEach-Object { if ($null -ne $_) { [string]$_ } } | Where-Object { $_ -and $_.Trim() })
}

# ---------------------------------------------------------------------------------------------------------------------
#  The libraries (bundled detection) -- a software name pattern and the folder tokens that mean "the library's own folder"
# ---------------------------------------------------------------------------------------------------------------------
$script:SIEvLibraries = @(
    @{ Key = 'openssl';   Name = '^(openssl|libssl|libcrypto)';                                         Self = @('openssl', 'libssl') }
    @{ Key = 'curl';      Name = '^(lib)?curl$';                                                         Self = @('curl', 'libcurl') }
    @{ Key = 'zlib';      Name = '^zlib';                                                                Self = @('zlib') }
    @{ Key = 'sqlite';    Name = '^sqlite';                                                              Self = @('sqlite') }
    @{ Key = 'log4j';     Name = 'log4j';                                                                Self = @('log4j') }
    @{ Key = 'jackson';   Name = '^jackson';                                                             Self = @('jackson') }
    @{ Key = 'python';    Name = '^(c)?python([ _\-.]?\d.*)?$';                                         Self = @('python') }
    @{ Key = 'dotnet';    Name = '^(\.net|dotnet|asp\.net|\.net_framework|\.net_core|\.net_runtime)';  Self = @('net', 'dotnet') }
    @{ Key = 'java';      Name = '^(jre|jdk|java|openjdk|java_runtime_environment|java_se|java_development_kit)'; Self = @('java', 'jre', 'jdk', 'openjdk', 'zulu', 'temurin', 'corretto', 'adoptium') }
    @{ Key = 'electron';  Name = '^electron';                                                            Self = @('electron') }
    @{ Key = 'chromium';  Name = '^(chromium|chromium_embedded_framework|cef)$';                        Self = @('chromium', 'cef') }
    @{ Key = 'nodejs';    Name = '^node(\.js|js)?$';                                                     Self = @('node', 'nodejs') }
    @{ Key = 'libxml2';   Name = '^libxml2?';                                                            Self = @('libxml', 'libxml2') }
    @{ Key = 'expat';     Name = '^(lib)?expat';                                                         Self = @('expat', 'libexpat') }
    @{ Key = 'libpng';    Name = '^libpng';                                                              Self = @('libpng') }
    @{ Key = 'libjpeg';   Name = '^libjpeg';                                                             Self = @('libjpeg') }
    @{ Key = 'libtiff';   Name = '^libtiff';                                                             Self = @('libtiff') }
    @{ Key = 'freetype';  Name = '^freetype';                                                            Self = @('freetype') }
    @{ Key = 'pcre';      Name = '^pcre';                                                                Self = @('pcre') }
    @{ Key = 'libssh2';   Name = '^libssh2';                                                             Self = @('libssh2') }
    @{ Key = 'nghttp2';   Name = '^nghttp2';                                                             Self = @('nghttp2') }
    @{ Key = 'libwebp';   Name = '^libwebp';                                                             Self = @('libwebp') }
)

function Get-SIEvLibrary {
    <# PURE. The library entry a Defender software name is (by name), $null when it is not one of the libraries. #>
    param([string]$SoftwareName)
    $n = ([string]$SoftwareName).Trim().ToLowerInvariant()
    if (-not $n) { return $null }
    foreach ($l in $script:SIEvLibraries) { if ([regex]::IsMatch($n, $l.Name)) { return $l } }
    return $null
}

function Test-SIEvLibraryOwnFolder {
    <# PURE. Is the folder application the library's OWN folder ("OpenSSL-Win64" for openssl, "Java jre1.8" for java)? #>
    param($Library, [string]$Folder)
    if ($null -eq $Library -or [string]::IsNullOrWhiteSpace($Folder)) { return $false }
    $tok = Get-SIEvTokens $Folder
    foreach ($s in @($Library.Self)) {
        foreach ($sTok in (Get-SIEvTokens $s)) { if ($tok -contains $sTok) { return $true } }
    }
    return $false
}

# ---------------------------------------------------------------------------------------------------------------------
#  One path -> type, drive, install kind (before the bundled rule) and its product folder
# ---------------------------------------------------------------------------------------------------------------------

# folders that never name a product: structure inside a product folder (the folder above them is the product)
$script:SIEvStructural = @('bin', 'bin64', 'bin32', 'lib', 'lib64', 'libs', 'x64', 'x86', 'amd64', 'arm64', 'win32', 'win64', 'plugins', 'plugin',
    'resources', 'app', 'apps', 'common', 'shared', 'runtime', 'runtimes', 'current', 'latest', 'root', 'program', 'programs', 'dll', 'dlls',
    'modules', 'module', 'components', 'component', 'native', 'ext', 'extensions', 'tools', 'libexec', 'share', 'jre', 'node_modules', 'site-packages', 'dist-packages')
$script:SIEvLinuxSystem = @('x86_64-linux-gnu', 'aarch64-linux-gnu', 'i386-linux-gnu', 'arm-linux-gnueabihf', 'locale', 'doc', 'man', 'info', 'bin', 'sbin', 'lib',
    'lib64', 'share', 'include', 'firmware', 'modules', 'systemd', 'udev', 'pkgconfig', 'icons', 'fonts', 'applications', 'mime', 'ca-certificates', 'zoneinfo')

function Test-SIEvFileName {
    <# PURE. Is the last segment of a path a FILE (an extension with a letter, or a shared library .so[.N]) rather than a folder? #>
    param([string]$Segment)
    if (-not $Segment) { return $false }
    if ([regex]::IsMatch($Segment, '\.so(\.\d+)*$', 'IgnoreCase')) { return $true }
    return [regex]::IsMatch($Segment, '\.[A-Za-z][A-Za-z0-9_\-]{0,7}$')
}

function Get-SIEvVendorProduct {
    <# PURE. The product folder of the folders below an install root: the first folder, plus the second when it is a
       product folder of its own (not structure, not a version): Adobe\Acrobat DC -> "Adobe Acrobat DC", 7-Zip -> "7-Zip",
       Notepad++\plugins -> "Notepad++", Mozilla Firefox -> "Mozilla Firefox". $null without a folder. #>
    param([string[]]$Folders)
    $f = @($Folders | Where-Object { $_ })
    if ($f.Count -eq 0) { return $null }
    $v = [string]$f[0]
    if ($f.Count -lt 2) { return $v }
    $s2 = [string]$f[1]
    $s2l = $s2.ToLowerInvariant()
    if ($script:SIEvStructural -contains $s2l) { return $v }
    if ([regex]::IsMatch($s2, '^[vV]?\d+([._\-]\d+)*$')) { return $v }            # a version folder (150, 4.18.2, v2)
    if ($s2.StartsWith($v, [StringComparison]::OrdinalIgnoreCase)) { return $s2 }   # "Mozilla" \ "Mozilla Maintenance Service"
    return ('{0} {1}' -f $v, $s2)
}

function Get-SIEvPackageName {
    <# PURE. A WindowsApps package folder (Name_Version_Arch_ResourceId_PublisherId) -> its Name. #>
    param([string]$Folder)
    if (-not $Folder) { return $null }
    $m = [regex]::Match($Folder, '^(?<n>[^_]+)_\d+(\.\d+)*_')
    if ($m.Success) { return $m.Groups['n'].Value }
    return $Folder
}

function ConvertTo-SIEvSegments {
    <# PURE. A path -> @{ Style (windows | unc | unix | registry | other); Drive; Segs (the folders + file below the root) }. #>
    param([string]$Path)
    $p = ([string]$Path).Trim().Trim('"')
    if (-not $p) { return @{ Style = 'other'; Drive = $null; Segs = @() } }
    if ([regex]::IsMatch($p, '^(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC|Registry::)', 'IgnoreCase')) { return @{ Style = 'registry'; Drive = $null; Segs = @() } }
    $m = [regex]::Match($p, '^(?<d>[A-Za-z]):[\\/]?(?<rest>.*)$')
    if ($m.Success) {
        $segs = @($m.Groups['rest'].Value -split '[\\/]+' | Where-Object { $_ })
        return @{ Style = 'windows'; Drive = ($m.Groups['d'].Value.ToUpperInvariant() + ':'); Segs = $segs }
    }
    $u = [regex]::Match($p, '^\\\\(?<srv>[^\\/]+)[\\/](?<share>[^\\/]+)(?<rest>.*)$')
    if ($u.Success) {
        $segs = @($u.Groups['rest'].Value -split '[\\/]+' | Where-Object { $_ })
        return @{ Style = 'unc'; Drive = ('\\{0}\{1}' -f $u.Groups['srv'].Value, $u.Groups['share'].Value); Segs = $segs }
    }
    if ($p.StartsWith('/')) { return @{ Style = 'unix'; Drive = $null; Segs = @($p -split '/+' | Where-Object { $_ }) } }
    return @{ Style = 'other'; Drive = $null; Segs = @() }
}

function Get-SIEvFolders {
    <# PURE. The folders of a path's segments (the last one left out when it is a file). #>
    param([string[]]$Segs)
    $s = @($Segs)
    if ($s.Count -eq 0) { return , @() }
    if (Test-SIEvFileName ([string]$s[$s.Count - 1])) { if ($s.Count -eq 1) { return , @() }; return , @($s[0..($s.Count - 2)]) }
    return , $s
}

function Get-SIEvWebRootIndex {
    <# PURE. The index of the web-root folder (inetpub\wwwroot, wwwroot, htdocs within the first three folders; www, websites,
       web, sites, webroot, webapps as the drive's first folder), -1 when none. #>
    param([string[]]$Folders)
    $f = @($Folders)
    if ($f.Count -gt 0 -and ([string]$f[0]).ToLowerInvariant() -in 'www', 'websites', 'web', 'sites', 'webroot', 'webapps') { return 0 }
    for ($i = 0; $i -lt [Math]::Min(3, $f.Count); $i++) {
        $s = ([string]$f[$i]).ToLowerInvariant()
        if ($s -eq 'wwwroot' -or $s -eq 'htdocs') { return $i }
        if ($s -eq 'inetpub') { if (($i + 1) -lt $f.Count -and ([string]$f[$i + 1]).ToLowerInvariant() -eq 'wwwroot') { return ($i + 1) }; return $i }
    }
    return -1
}

# ---------------------------------------------------------------------------------------------------------------------
#  Install folders beyond the standard roots -- ONE table, path shapes only, never a list of applications (owner
#  2026-11-24: "it should detect the folder where it is installed like Azure Monitor Agent"). Each row: the path style, the
#  shape (a regex over the path below the drive / root, its segments joined by '\' (windows) or '/' (unix), case ignored)
#  and how the application is named from it:
#    extension  the group 'x' is an Azure VM extension's folder (<Publisher>.<Type>): named by Get-SIEvExtensionName; the
#               version folder below it is never part of the name (an extension updated keeps the same task)
#    reroot     the group 'd' is a drive letter and 'r' the path below it (an OEM recovery image's copy of a drive): the
#               application of that path as if it lay on that drive
# ---------------------------------------------------------------------------------------------------------------------
$script:SIEvInstallFolders = @(
    @{ Style = 'windows'; Shape = '^packages\\plugins\\(?<x>[^\\]+)\\';           Name = 'extension' }   # C:\Packages\Plugins\<Publisher.Type>\<version>\...
    @{ Style = 'windows'; Shape = '^recovery\\oem\\(?<d>[a-z])\\(?<r>.+)$';       Name = 'reroot' }      # C:\Recovery\OEM\C\Windows\...
    @{ Style = 'unix';    Shape = '^var/lib/waagent/(?<x>[^/]+?)-\d[^/]*/';        Name = 'extension' }   # /var/lib/waagent/<Publisher.Type>-<version>/...
)

# The special cases of the 'extension' rule: an extension folder Defender reports in lower case cannot be split into words,
# so the well-known Azure VM extensions are named here (key: the folder, lower case). Any other extension: its type (the
# last part of <Publisher>.<Type>; "Windows" / "Linux" alone take the part before them too), split into words when its
# case is known ("AzureMonitorWindowsAgent" -> "Azure Monitor Windows Agent").
$script:SIEvExtensionNames = @{
    'microsoft.azure.monitor.azuremonitorwindowsagent'                      = 'Azure Monitor Windows Agent'
    'microsoft.azure.monitor.azuremonitorlinuxagent'                        = 'Azure Monitor Linux Agent'
    'microsoft.guestconfiguration.configurationforwindows'                  = 'Guest Configuration for Windows'
    'microsoft.guestconfiguration.configurationforlinux'                    = 'Guest Configuration for Linux'
    'microsoft.enterprisecloud.monitoring.microsoftmonitoringagent'         = 'Microsoft Monitoring Agent'
    'microsoft.enterprisecloud.monitoring.omsagentforlinux'                 = 'OMS Agent for Linux'
    'microsoft.azure.monitoring.dependencyagent.dependencyagentwindows'     = 'Dependency Agent Windows'
    'microsoft.azure.monitoring.dependencyagent.dependencyagentlinux'       = 'Dependency Agent Linux'
    'microsoft.azure.azuredefenderforservers.mde.windows'                   = 'Microsoft Defender for Endpoint (Windows)'
    'microsoft.azure.azuredefenderforservers.mde.linux'                     = 'Microsoft Defender for Endpoint (Linux)'
    'microsoft.azure.security.iaasantimalware'                              = 'Microsoft Antimalware'
    'microsoft.azure.security.monitoring.azuresecuritywindowsagent'         = 'Azure Security Windows Agent'
    'microsoft.azure.security.monitoring.azuresecuritylinuxagent'           = 'Azure Security Linux Agent'
    'microsoft.compute.customscriptextension'                               = 'Custom Script Extension'
    'microsoft.azure.extensions.customscript'                               = 'Custom Script'
    'microsoft.cplat.core.runcommandwindows'                                = 'Run Command Windows'
    'microsoft.cplat.core.runcommandlinux'                                  = 'Run Command Linux'
    'microsoft.cplat.core.runcommandhandlerwindows'                         = 'Run Command Handler Windows'
    'microsoft.azure.activedirectory.aadloginforwindows'                    = 'AAD Login for Windows'
    'microsoft.azure.activedirectory.aadsshloginforlinux'                   = 'AAD SSH Login for Linux'
    'microsoft.compute.vmaccessagent'                                       = 'VM Access Agent'
    'microsoft.compute.bginfo'                                              = 'BGInfo'
    'microsoft.azure.keyvault.keyvaultforwindows'                           = 'Key Vault for Windows'
    'microsoft.azure.keyvault.keyvaultforlinux'                             = 'Key Vault for Linux'
    'microsoft.azure.automation.hybridworker.hybridworkerforwindows'        = 'Hybrid Worker for Windows'
    'microsoft.azure.automation.hybridworker.hybridworkerforlinux'          = 'Hybrid Worker for Linux'
    'microsoft.software.management.windowsosupdateextension'                = 'Windows OS Update Extension'
    'microsoft.azure.networkwatcher.networkwatcheragentwindows'             = 'Network Watcher Agent Windows'
    'microsoft.azure.networkwatcher.networkwatcheragentlinux'               = 'Network Watcher Agent Linux'
    'microsoft.azure.diagnostics.iaasdiagnostics'                           = 'Azure Diagnostics'
    'microsoft.azure.recoveryservices.vmsnapshot'                           = 'VM Snapshot (Azure Backup)'
}

function Get-SIEvExtensionName {
    <# PURE. An Azure VM extension's folder (<Publisher>.<Type>) -> its display name (see $script:SIEvExtensionNames). #>
    param([string]$Folder)
    $f = ([string]$Folder).Trim()
    if (-not $f) { return $null }
    $k = $f.ToLowerInvariant()
    if ($script:SIEvExtensionNames.ContainsKey($k)) { return $script:SIEvExtensionNames[$k] }
    $parts = @($f.Split('.') | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $f }
    $t = [string]$parts[$parts.Count - 1]
    if ($parts.Count -gt 1 -and $t.ToLowerInvariant() -in 'windows', 'linux') { $t = ('{0} {1}' -f $parts[$parts.Count - 2], $t) }
    if ($t -cmatch '[a-z]' -and $t -cmatch '[A-Z]') { $t = [regex]::Replace($t, '(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', ' ') }
    return $t
}

# The known application names (owner 2026-11-24: "make title tidied consistent"): an application's name as SI shows it,
# whether it comes from the folder or from Defender's inventory. Key: the name in lower case, '_' / '-' as spaces, versions
# left out (Format-SIEvApplicationName). Any other name: Title Case words, spaces for underscores, no version.
$script:SIEvApplicationNames = @{
    'acrobat reader dc'         = 'Adobe Acrobat Reader DC'
    'adobe acrobat reader dc'   = 'Adobe Acrobat Reader DC'
    'acrobat dc'                = 'Adobe Acrobat DC'
    'adobe acrobat dc'          = 'Adobe Acrobat DC'
    'imyfone lockwiper'         = 'iMyFone LockWiper'
    'microsoft onedrive'        = 'Microsoft OneDrive'
    'onedrive'                  = 'Microsoft OneDrive'
    'githubdesktop'             = 'GitHub Desktop'
    'githubdesktop app'         = 'GitHub Desktop'
    'github desktop'            = 'GitHub Desktop'
    'microsoft sdks azure'      = 'Microsoft SDKs Azure'
    'jdk'                       = 'JDK'
    'jre'                       = 'JRE'
}

function Format-SIEvApplicationName {
    <# PURE. ONE RULE for an application's name as SI shows it (a bundled task's name and its Application column), whatever
       gave it -- the install folder, the extension table or Defender's inventory: the known name from
       $script:SIEvApplicationNames, else Title Case words (a word already in mixed / upper case is kept: "DC", "LockWiper"),
       spaces for underscores, every version left out (the version is never part of the name). '' for none. #>
    param([string]$Name)
    $n = ([string]$Name).Trim()
    if (-not $n) { return '' }
    $plain = [regex]::Replace($n, '[_]+', ' ')
    $plain = [regex]::Replace($plain, '(?i)(^|[\s_-])v?\d+(?:[._-]\d+)*(?=$|[\s)])', ' ')
    $plain = ([regex]::Replace($plain, '\s+', ' ')).Trim(' ', '-', '_', '.')
    if (-not $plain) { $plain = [regex]::Replace($n, '[_]+', ' ').Trim() }
    $k = ([regex]::Replace($plain.ToLowerInvariant().Replace('-', ' '), '\s+', ' ')).Trim()
    if ($script:SIEvApplicationNames.ContainsKey($k)) { return $script:SIEvApplicationNames[$k] }
    $words = New-Object System.Collections.Generic.List[string]
    foreach ($w in ($plain -split ' ')) {
        if (-not $w) { continue }
        # a small word inside the name stays lower case ("Guest Configuration for Windows")
        if ($words.Count -gt 0 -and $w -cin 'for', 'of', 'and', 'the', 'to', 'in', 'on', 'with', 'by') { $words.Add($w); continue }
        if ($w -cmatch '^[a-z]') { $words.Add($w.Substring(0, 1).ToUpperInvariant() + $w.Substring(1)) } else { $words.Add($w) }
    }
    return ($words.ToArray() -join ' ')
}

function Get-SIEvidenceApplicationVersion {
    <# PURE. The version of the application a copy lies in (owner 2026-11-24: "Yes, separate column" -- the task's
       "Application version"; never part of its name or key): Defender's version where its inventory names the application,
       else the version folder of the path (an Azure VM extension's <version> folder -- 1.47.1.0 -- or the first folder that is
       a version: \1.2.3\), else a version the application's folder name ends in (jdk-17.0.2, app-3.5.8, Python 3.11). '' when
       none is known. #>
    param($Row)
    if ([string](Get-SIEvValue $Row 'ApplicationSource') -eq 'inventory') {
        $iv = ([string](Get-SIEvValue $Row 'ApplicationVersion')).Trim(); if ($iv) { return $iv }
    }
    $p = [string](Get-SIEvValue $Row 'FullPath')
    if ($p -and [string](Get-SIEvValue $Row 'PathType') -ne 'registry') {
        $x = ConvertTo-SIEvSegments $p
        $folders = @(Get-SIEvFolders $x.Segs)
        if ($x.Style -eq 'windows') {
            $m = [regex]::Match((@($x.Segs) -join '\'), '^packages\\plugins\\[^\\]+\\(?<v>[^\\]+)\\', 'IgnoreCase')
            if ($m.Success) { return $m.Groups['v'].Value }
        }
        if ($x.Style -eq 'unix') {
            $m = [regex]::Match((@($x.Segs) -join '/'), '^var/lib/waagent/[^/]+?-(?<v>\d[^/]*)/', 'IgnoreCase')
            if ($m.Success) { return $m.Groups['v'].Value }
        }
        foreach ($f in $folders) { $m = [regex]::Match([string]$f, '^[vV]?(?<v>\d+(\.\d+)+)$'); if ($m.Success) { return $m.Groups['v'].Value } }
    }
    $an = [string](Get-SIEvValue $Row 'Application')
    if ($an) { $m = [regex]::Match($an, '(^|[\s_-])[vV]?(?<v>\d+([._]\d+)+)$'); if ($m.Success) { return $m.Groups['v'].Value } }
    return ''
}

function Join-SIEvVersions {
    <# PURE. Versions as one text: distinct, sorted as versions (1.9 before 1.10), ', ' between. #>
    param([AllowEmptyCollection()][string[]]$Versions = @())
    $d = @($Versions | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $sorted = $d | Sort-Object { $v = $null; if ([version]::TryParse((($_ -replace '[^\d.]', '.') -replace '\.+', '.').Trim('.'), [ref]$v)) { $v } else { [version]'0.0' } }, { $_ }
    return (@($sorted) -join ', ')
}

function Get-SIEvInstallFolderApplication {
    <# PURE. The application of a path by the install-folder table ($script:SIEvInstallFolders); $null when no row fits.
       -Below: the path below the drive / root, its segments joined by '\' (windows) or '/' (unix). #>
    param([string]$Style, [string]$Below)
    foreach ($row in $script:SIEvInstallFolders) {
        if ($row.Style -ne $Style) { continue }
        $m = [regex]::Match($Below, $row.Shape, 'IgnoreCase')
        if (-not $m.Success) { continue }
        if ($row.Name -eq 'extension') { return (Get-SIEvExtensionName $m.Groups['x'].Value) }
        if ($row.Name -eq 'reroot') { return (Get-SIEvidenceFolderApplication ('{0}:\{1}' -f $m.Groups['d'].Value, $m.Groups['r'].Value)) }
    }
    return $null
}

function Get-SIEvidenceFolderApplication {
    <#
    .SYNOPSIS  PURE. The product folder a disk path lies in, as a name -- $null when the path names none (a registry path, a
               file at a drive root, the operating system's own library folders, a data folder).
    #>
    param([string]$Path)
    $x = ConvertTo-SIEvSegments $Path
    $folders = Get-SIEvFolders $x.Segs
    if ($folders.Count -eq 0) { return $null }
    $f0 = ([string]$folders[0]).ToLowerInvariant()
    if ($x.Style -in 'windows', 'unix') {
        $sep = $(if ($x.Style -eq 'windows') { '\' } else { '/' })
        $byTable = Get-SIEvInstallFolderApplication -Style $x.Style -Below (@($x.Segs) -join $sep)
        if ($byTable) { return $byTable }
    }
    switch ($x.Style) {
        'windows' {
            if ($f0 -match '^program files( \((x86|arm)\))?$') {
                $rest = @(); if ($folders.Count -gt 1) { $rest = @($folders[1..($folders.Count - 1)]) }
                if ($rest.Count -gt 0 -and ([string]$rest[0]).ToLowerInvariant() -eq 'common files') {
                    $rest = @(); if ($folders.Count -gt 2) { $rest = @($folders[2..($folders.Count - 1)]) }
                }
                if ($rest.Count -gt 0 -and ([string]$rest[0]).ToLowerInvariant() -eq 'windowsapps') {
                    if ($rest.Count -gt 1) { return (Get-SIEvPackageName ([string]$rest[1])) }
                    return $null
                }
                return (Get-SIEvVendorProduct $rest)
            }
            if ($f0 -eq 'programdata') {
                if ($folders.Count -lt 2) { return $null }
                return (Get-SIEvVendorProduct @($folders[1..($folders.Count - 1)]))
            }
            if ($f0 -eq 'windows') {
                $low = @($folders | ForEach-Object { ([string]$_).ToLowerInvariant() })
                $ds = [array]::IndexOf($low, 'driverstore')
                if ($ds -ge 0 -and ($ds + 2) -lt $folders.Count -and $low[$ds + 1] -eq 'filerepository') {
                    return ([regex]::Replace([string]$folders[$ds + 2], '_[0-9a-f]{16}$', ''))
                }
                if ($low.Count -gt 1 -and $low[1] -eq 'microsoft.net') { return 'Microsoft.NET' }
                return 'Microsoft Windows'
            }
            if ($f0 -eq 'users' -and $folders.Count -gt 3) {
                $f2 = ([string]$folders[2]).ToLowerInvariant()
                if ($f2 -eq 'appdata' -and $folders.Count -gt 4) {
                    $rest = @($folders[4..($folders.Count - 1)])
                    if (([string]$rest[0]).ToLowerInvariant() -eq 'programs') { if ($rest.Count -lt 2) { return $null }; $rest = @($rest[1..($rest.Count - 1)]) }
                    return (Get-SIEvVendorProduct $rest)
                }
                return $null
            }
            $w = Get-SIEvWebRootIndex $folders
            if ($w -ge 0 -and ($w + 1) -lt $folders.Count) { return [string]$folders[$w + 1] }
            return $null
        }
        'unc' { return $null }
        'unix' {
            $low = @($folders | ForEach-Object { ([string]$_).ToLowerInvariant() })
            if ($low[0] -eq 'opt' -and $folders.Count -gt 1) { return (Get-SIEvVendorProduct @($folders[1..($folders.Count - 1)])) }
            if ($low[0] -eq 'snap' -and $folders.Count -gt 1) { return [string]$folders[1] }
            if ($low[0] -eq 'applications' -and $folders.Count -gt 1) { return ([string]$folders[1] -replace '\.app$', '') }
            if ($low[0] -eq 'usr' -and $folders.Count -gt 2) {
                $i = 1
                if ($low[1] -eq 'local') {
                    if ($low[2] -in 'lib', 'lib64', 'share', 'libexec') { $i = 3 } elseif ($low[2] -in 'bin', 'sbin', 'include', 'etc') { return $null } else { $i = 2 }
                } elseif ($low[1] -in 'lib', 'lib64', 'share', 'libexec') { $i = 2 } else { return $null }
                if ($i -ge $folders.Count) { return $null }
                $p = $low[$i]
                if ($p -eq 'jvm' -and ($i + 1) -lt $folders.Count) { return [string]$folders[$i + 1] }
                if ($script:SIEvLinuxSystem -contains $p) { return $null }
                return [string]$folders[$i]
            }
            if (($low[0] -eq 'var' -and $low.Count -gt 2 -and $low[1] -eq 'www') -or ($low[0] -eq 'srv' -and $low.Count -gt 2 -and $low[1] -in 'www', 'http')) {
                if ($folders.Count -gt 3 -and $low[2] -eq 'html') { return [string]$folders[3] }
                return [string]$folders[2]
            }
            if ($low[0] -eq 'home' -and $folders.Count -gt 4 -and $low[2] -eq '.local' -and $low[3] -eq 'share') { return [string]$folders[4] }
            return $null
        }
    }
    return $null
}

function ConvertTo-SIEvidencePathInfo {
    <#
    .SYNOPSIS  PURE. One evidence path -> @{ PathType (disk | registry); Drive; InstallKind; Folder (the product folder, or
               $null) }. InstallKind here is BEFORE the bundled rule (ConvertTo-SISoftwareEvidenceRows applies it) and for a
               registry path before the copy is known: a registry path says 'registry-only' (the rows builder turns it to
               'unknown' when the same copy has a disk path).
    #>
    param([string]$Path, [string]$PathType = '')
    $x = ConvertTo-SIEvSegments $Path
    $type = $PathType
    if (-not $type) { if ($x.Style -eq 'registry') { $type = 'registry' } else { $type = 'disk' } }
    if ($type -eq 'registry' -or $x.Style -eq 'registry') { return @{ PathType = 'registry'; Drive = $null; InstallKind = 'registry-only'; Folder = $null } }
    $folders = Get-SIEvFolders $x.Segs
    $low = @($folders | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $kind = 'unknown'
    switch ($x.Style) {
        'windows' {
            $f0 = ''; if ($low.Count -gt 0) { $f0 = $low[0] }
            if ($f0 -match '^program files( \((x86|arm)\))?$' -or $f0 -eq 'programdata' -or $f0 -eq 'windows') { $kind = 'installed' }
            elseif ($f0 -eq 'users' -and $x.Drive -eq 'C:') {
                if ($low.Count -gt 1 -and $low[1] -notin 'public', 'default', 'default user', 'all users') { $kind = 'user-profile' }
            }
            elseif ($x.Drive -ne 'C:' -and $f0 -in 'data', 'home', 'homes', 'users', 'shares', 'share', 'profiles', 'userdata', 'userhome', 'userhomes') { $kind = 'data-folder' }
            elseif ((Get-SIEvWebRootIndex $folders) -ge 0) { $kind = 'installed' }
            elseif ($x.Drive -ne 'C:' -and $low.Count -gt 0) { $kind = 'data-folder' }
        }
        'unc' { $kind = 'data-folder' }
        'unix' {
            $f0 = ''; if ($low.Count -gt 0) { $f0 = $low[0] }
            $f1 = ''; if ($low.Count -gt 1) { $f1 = $low[1] }
            if ($f0 -in 'home', 'users' -and $low.Count -gt 1) { $kind = 'user-profile' }
            elseif ($f0 -eq 'root') { $kind = 'user-profile' }
            elseif ($f0 -eq 'var' -and $f1 -eq 'www') { $kind = 'installed' }
            elseif ($f0 -eq 'srv' -and $f1 -in 'www', 'http') { $kind = 'installed' }
            elseif ($f0 -in 'usr', 'opt', 'bin', 'sbin', 'lib', 'lib32', 'lib64', 'snap', 'applications', 'library', 'system') { $kind = 'installed' }
            elseif ($f0 -in 'srv', 'data', 'mnt', 'media', 'share', 'nfs', 'export') { $kind = 'data-folder' }
        }
    }
    return @{ PathType = 'disk'; Drive = $x.Drive; InstallKind = $kind; Folder = (Get-SIEvidenceFolderApplication $Path) }
}

# ---------------------------------------------------------------------------------------------------------------------
#  The folder matched to the device's own Defender software inventory
# ---------------------------------------------------------------------------------------------------------------------

function Resolve-SIEvidenceApplication {
    <#
    .SYNOPSIS  PURE. The application of a product folder: the device's own inventory product whose name words ALL appear in
               the folder name (vendor words count extra; at least one name word of 3+ characters), its name + version
               (Source 'inventory'); two different products scoring the same = no match; a product with several versions on
               the device = its name without a version (which copy is not known). Unmatched = the folder name (Source
               'folder'). No folder = @{ Name = $null; Source = $null }.
    .PARAMETER Inventory  the device's products: @{ Vendor; Name; Version } (lower-case vendor / name, as Defender has them)
    #>
    param([string]$Folder, [AllowEmptyCollection()][object[]]$Inventory = @())
    if ([string]::IsNullOrWhiteSpace($Folder)) { return @{ Name = $null; Vendor = $null; Version = $null; Source = $null } }
    $ft = Get-SIEvTokens $Folder
    $best = $null; $bestScore = 0; $tie = $false
    $byProduct = @{}
    foreach ($i in @($Inventory)) {
        if ($null -eq $i) { continue }
        $name = [string](Get-SIEvValue $i 'Name'); $vendor = [string](Get-SIEvValue $i 'Vendor')
        if (-not $name) { continue }
        $key = ('{0}/{1}' -f $vendor, $name).ToLowerInvariant()
        if (-not $byProduct.ContainsKey($key)) { $byProduct[$key] = @{ Vendor = $vendor; Name = $name; Versions = (New-Object System.Collections.Generic.List[string]) } }
        $ver = [string](Get-SIEvValue $i 'Version')
        if ($ver -and -not $byProduct[$key].Versions.Contains($ver)) { $byProduct[$key].Versions.Add($ver) }
    }
    foreach ($key in @($byProduct.Keys | Sort-Object)) {
        $p = $byProduct[$key]
        $nt = Get-SIEvTokens $p.Name
        if ($nt.Count -eq 0) { continue }
        if (-not @($nt | Where-Object { $_.Length -ge 3 }).Count) { continue }
        $all = $true; foreach ($t in $nt) { if ($ft -notcontains $t) { $all = $false; break } }
        if (-not $all) { continue }
        $score = $nt.Count * 2
        $vt = Get-SIEvTokens $p.Vendor
        if ($vt.Count -gt 0) { $vOk = $true; foreach ($t in $vt) { if ($ft -notcontains $t) { $vOk = $false; break } }; if ($vOk) { $score += 1 } }
        if ($score -gt $bestScore) { $best = $p; $bestScore = $score; $tie = $false }
        elseif ($score -eq $bestScore -and $null -ne $best) { $tie = $true }
    }
    if ($null -ne $best -and -not $tie) {
        $v = $null; if ($best.Versions.Count -eq 1) { $v = $best.Versions[0] }
        return @{ Name = $best.Name; Vendor = $best.Vendor; Version = $v; Source = 'inventory' }
    }
    return @{ Name = $Folder; Vendor = $null; Version = $null; Source = 'folder' }
}

function Format-SIEvidenceApplication {
    <# PURE. The application as one text: "vendor/name version" (inventory) or the folder name; '' when none. #>
    param($Row)
    $n = [string](Get-SIEvValue $Row 'Application'); if (-not $n) { return '' }
    if ([string](Get-SIEvValue $Row 'ApplicationSource') -eq 'inventory') {
        $t = $n; $vd = [string](Get-SIEvValue $Row 'ApplicationVendor'); if ($vd) { $t = $vd + '/' + $n }
        $ver = [string](Get-SIEvValue $Row 'ApplicationVersion'); if ($ver) { $t = $t + ' ' + $ver }
        return $t
    }
    return $n
}

# ---------------------------------------------------------------------------------------------------------------------
#  Evidence of one device -> the table rows, the compact rule input and the record part
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SISoftwareEvidenceRows {
    <#
    .SYNOPSIS  PURE. The evidence rows of ONE device (DeviceTvmSoftwareEvidenceBeta shape: SoftwareVendor, SoftwareName,
               SoftwareVersion, DiskPaths, RegistryPaths, LastSeenTime) + the device's inventory (@{ Vendor; Name; Version })
               -> one row per vendor x product x version x path (duplicates merged, newest LastSeen kept): DeviceId, Vendor,
               Product, Version, PathType, FullPath, Drive, InstallKind, Application, ApplicationVendor, ApplicationVersion,
               ApplicationSource, LastSeen. Every path is kept -- no cap.
    #>
    param([string]$DeviceId, [AllowEmptyCollection()][object[]]$Evidence = @(), [AllowEmptyCollection()][object[]]$Inventory = @())
    $dev = ([string]$DeviceId).Trim().ToLowerInvariant()
    $copies = [ordered]@{}
    foreach ($e in @($Evidence)) {
        if ($null -eq $e) { continue }
        $vendor = ([string](Get-SIEvValue $e 'SoftwareVendor')).Trim().ToLowerInvariant()
        $name = ([string](Get-SIEvValue $e 'SoftwareName')).Trim().ToLowerInvariant()
        $ver = ([string](Get-SIEvValue $e 'SoftwareVersion')).Trim()
        if (-not $name) { continue }
        $ck = '{0}|{1}|{2}' -f $vendor, $name, $ver
        if (-not $copies.Contains($ck)) { $copies[$ck] = @{ Vendor = $vendor; Name = $name; Version = $ver; Paths = [ordered]@{} } }
        $seen = Get-SIEvValue $e 'LastSeenTime'
        $seenT = $null
        if ($null -ne $seen -and "$seen" -ne '') {
            if ($seen -is [datetime]) { $seenT = $seen.ToUniversalTime() }
            else {
                $t = [datetime]::MinValue
                $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
                if ([datetime]::TryParse([string]$seen, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$t)) { $seenT = $t }
            }
        }
        foreach ($pair in @(@('disk', (Get-SIEvValue $e 'DiskPaths')), @('registry', (Get-SIEvValue $e 'RegistryPaths')))) {
            foreach ($p in (ConvertTo-SIEvArray $pair[1])) {
                $fp = ([string]$p).Trim()
                if (-not $fp) { continue }
                $pk = $pair[0] + '|' + $fp.ToLowerInvariant()
                $cur = $copies[$ck].Paths
                if ($cur.Contains($pk)) {
                    if ($null -ne $seenT -and ($null -eq $cur[$pk].LastSeen -or $seenT -gt $cur[$pk].LastSeen)) { $cur[$pk].LastSeen = $seenT }
                } else { $cur[$pk] = @{ Type = $pair[0]; Path = $fp; LastSeen = $seenT } }
            }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($ck in $copies.Keys) {
        $c = $copies[$ck]
        $lib = Get-SIEvLibrary $c.Name
        $hasDisk = $false; foreach ($pv in $c.Paths.Values) { if ($pv.Type -eq 'disk') { $hasDisk = $true; break } }
        foreach ($pv in $c.Paths.Values) {
            $info = ConvertTo-SIEvidencePathInfo -Path $pv.Path -PathType $pv.Type
            $kind = [string]$info.InstallKind
            if ($pv.Type -eq 'registry' -and $hasDisk) { $kind = 'unknown' }
            $app = @{ Name = $null; Vendor = $null; Version = $null; Source = $null }
            if ($pv.Type -eq 'disk' -and $info.Folder) {
                $app = Resolve-SIEvidenceApplication -Folder ([string]$info.Folder) -Inventory $Inventory
                # the folder is the software's OWN (wordpress found in its own folder, openssl in OpenSSL-Win64): the application
                # is the software itself -- never "bundled by" itself
                $own = $false
                if ($app.Source -eq 'inventory' -and ([string]$app.Name).ToLowerInvariant() -eq $c.Name -and ([string]$app.Vendor).ToLowerInvariant() -eq $c.Vendor) { $own = $true }
                if ($null -ne $lib -and (Test-SIEvLibraryOwnFolder -Library $lib -Folder ([string]$info.Folder))) { $own = $true }
                if ($null -ne $lib -and -not $own -and $kind -in 'installed', 'user-profile', 'data-folder', 'unknown') { $kind = 'bundled' }
            }
            $rows.Add([pscustomobject][ordered]@{
                DeviceId = $dev; Vendor = $c.Vendor; Product = $c.Name; Version = $c.Version
                PathType = $pv.Type; FullPath = $pv.Path; Drive = $info.Drive; InstallKind = $kind
                Application = $app.Name; ApplicationVendor = $app.Vendor; ApplicationVersion = $app.Version; ApplicationSource = $app.Source
                LastSeen = $pv.LastSeen
            })
        }
    }
    foreach ($x in $rows) { $x }
}

function ConvertTo-SISoftwareEvidenceDevice {
    <#
    .SYNOPSIS  PURE. One device's rows (ConvertTo-SISoftwareEvidenceRows) + inventory -> @{ State = 'read'; Items } -- the
               compact form the software rules read (record Metadata 'SoftwareEvidence'): one item per vendor/product/version
               of the evidence OR the inventory, @{ p = 'vendor/product'; v = version; paths = @(@{ t; f; k }) } (an inventory
               product without evidence has no paths: its evidence is unknown, never "not installed").
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][object[]]$Inventory = @())
    $items = [ordered]@{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $p = ('{0}/{1}' -f [string](Get-SIEvValue $r 'Vendor'), [string](Get-SIEvValue $r 'Product')).ToLowerInvariant()
        $v = [string](Get-SIEvValue $r 'Version')
        $k = $p + '|' + $v
        if (-not $items.Contains($k)) { $items[$k] = [ordered]@{ p = $p; v = $v; paths = (New-Object System.Collections.Generic.List[object]) } }
        $items[$k].paths.Add([ordered]@{ t = [string](Get-SIEvValue $r 'PathType'); f = [string](Get-SIEvValue $r 'FullPath'); k = [string](Get-SIEvValue $r 'InstallKind') })
    }
    foreach ($i in @($Inventory)) {
        if ($null -eq $i) { continue }
        $name = [string](Get-SIEvValue $i 'Name'); if (-not $name) { continue }
        $p = ('{0}/{1}' -f [string](Get-SIEvValue $i 'Vendor'), $name).ToLowerInvariant()
        $v = [string](Get-SIEvValue $i 'Version')
        $k = $p + '|' + $v
        if (-not $items.Contains($k)) { $items[$k] = [ordered]@{ p = $p; v = $v; paths = (New-Object System.Collections.Generic.List[object]) } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $items.Keys) { $it = $items[$k]; $out.Add([ordered]@{ p = $it.p; v = $it.v; paths = @($it.paths.ToArray()) }) }
    return [ordered]@{ State = 'read'; Items = @($out.ToArray()) }
}

function ConvertTo-SISoftwareEvidencePart {
    <#
    .SYNOPSIS  PURE. One device's rows -> the record part 'softwareEvidence' (data-model/mappings/mde.locked.json): Paths
               ("vendor/product version | install kind | path", the path in full), Kinds ("vendor/product|install kind", distinct) and
               BundledBy ("vendor/product version | application"), each list sorted; $null without rows (unknown, never "none").
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    if (@($Rows).Count -eq 0) { return $null }
    $paths = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $kinds = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $by = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $p = ('{0}/{1}' -f [string](Get-SIEvValue $r 'Vendor'), [string](Get-SIEvValue $r 'Product'))
        $sw = ('{0} {1}' -f $p, [string](Get-SIEvValue $r 'Version')).Trim()
        $k = [string](Get-SIEvValue $r 'InstallKind')
        # the part becomes the CI field si_software_evidence_paths (web app, exports): the FULL path, a user name in it included
        # (owner 2026-11-17: the path is the evidence an Admin needs to fine-tune a wrong detection)
        [void]$paths.Add(('{0} | {1} | {2}' -f $sw, $k, [string](Get-SIEvValue $r 'FullPath')))
        [void]$kinds.Add(('{0}|{1}' -f $p, $k))
        if ($k -eq 'bundled') { $a = Format-SIEvidenceApplication $r; if ($a) { [void]$by.Add(('{0} | {1}' -f $sw, $a)) } }
    }
    return [pscustomobject][ordered]@{ Paths = @($paths); Kinds = @($kinds); BundledBy = @($by) }
}

# ---------------------------------------------------------------------------------------------------------------------
#  Versions
# ---------------------------------------------------------------------------------------------------------------------

function Compare-SIEvVersion {
    <# PURE. -1 / 0 / 1 for two dotted versions (numeric parts; a missing part = 0); $null when either has a part that is not
       a number (they cannot be compared -- never guessed). #>
    param([string]$A, [string]$B)
    $pa = @(([string]$A).Trim() -split '[.\-_+]' | Where-Object { $_ -ne '' })
    $pb = @(([string]$B).Trim() -split '[.\-_+]' | Where-Object { $_ -ne '' })
    if ($pa.Count -eq 0 -or $pb.Count -eq 0) { return $null }
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { if (-not [long]::TryParse([string]$pa[$i], [ref]$x)) { return $null } }
        if ($i -lt $pb.Count) { if (-not [long]::TryParse([string]$pb[$i], [ref]$y)) { return $null } }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }
    return 0
}

function Test-SIEvVersionRange {
    <# PURE. Is -Version in -Range ('>=6.0 <6.4.3', '>=6.0, <6.4.3', '=5.2', '<2.17')? $true / $false; $null when it cannot be
       told (the version or a bound is not a comparable number, or the range does not parse). #>
    param([string]$Version, [string]$Range)
    if ([string]::IsNullOrWhiteSpace($Range)) { return $true }
    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }
    $parts = @(([string]$Range) -split '[,\s]+' | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $null }
    foreach ($p in $parts) {
        $m = [regex]::Match($p, '^(?<op>>=|<=|==|=|>|<)?(?<v>[0-9][0-9A-Za-z.\-_+]*)$')
        if (-not $m.Success) { return $null }
        $op = $m.Groups['op'].Value; if (-not $op) { $op = '=' }
        $c = Compare-SIEvVersion $Version $m.Groups['v'].Value
        if ($null -eq $c) { return $null }
        $ok = switch ($op) { '>=' { $c -ge 0 } '<=' { $c -le 0 } '>' { $c -gt 0 } '<' { $c -lt 0 } default { $c -eq 0 } }
        if (-not $ok) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------------------------------------------------
#  The software rule conditions (hasSoftwareInstalled: pathPatterns / notPathPatterns / installKinds / versionRange)
# ---------------------------------------------------------------------------------------------------------------------
$script:SIEvConditionKeys = @('pathPatterns', 'notPathPatterns', 'installKinds', 'versionRange')

function Get-SIEvSpecList {
    <# PURE. A spec value as a string list (a YAML list, one string, nothing). #>
    param($Spec, [string]$Name)
    # the items are written to the pipeline one by one (callers wrap the call in @( )): never one list object
    $v = Get-SIEvValue $Spec $Name
    if ($null -eq $v) { return }
    if ($v -is [string]) { if ($v.Trim()) { $v.Trim() }; return }
    foreach ($x in @($v)) { if ($null -ne $x -and ([string]$x).Trim()) { ([string]$x).Trim() } }
}

function Test-SISoftwareSpecHasConditions {
    <# PURE. Does a hasSoftwareInstalled detection carry any of the four optional conditions? Without them the rule works
       exactly as before (name only). #>
    param($Spec)
    foreach ($k in $script:SIEvConditionKeys) { if (@(Get-SIEvSpecList $Spec $k).Count -gt 0) { return $true } }
    return $false
}

function Get-SISoftwareSpecKey {
    <# PURE. The stable key of a conditioned hasSoftwareInstalled detection: '<rule id>#<12 hex>' over its names and
       conditions -- the engine records it per device when the detection matched (si_software_rule_hits) and the CI rule
       reads it; both sides compute it from the same rule file. #>
    param([string]$RuleId, $Spec)
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('names=' + ((@(Get-SIEvSpecList $Spec 'tvmSoftwareNames') | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ','))
    $parts.Add('kinds=' + ((@(Get-SIEvSpecList $Spec 'installKinds') | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ','))
    $parts.Add('paths=' + (@(Get-SIEvSpecList $Spec 'pathPatterns') -join [char]31))
    $parts.Add('notpaths=' + (@(Get-SIEvSpecList $Spec 'notPathPatterns') -join [char]31))
    $parts.Add('version=' + (@(Get-SIEvSpecList $Spec 'versionRange') -join ' '))
    $bytes = [Text.Encoding]::UTF8.GetBytes(($parts -join "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    $hex = -join @($h[0..5] | ForEach-Object { $_.ToString('x2') })
    return ('{0}#{1}' -f ([string]$RuleId), $hex)
}

function Test-SIEvRegex {
    <# PURE. Any of -Patterns matches -Text (case-insensitive, bounded); a pattern that does not compile matches nothing. #>
    param([string]$Text, [string[]]$Patterns)
    foreach ($p in @($Patterns)) {
        if (-not $p) { continue }
        try { if ([regex]::IsMatch($Text, $p, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromSeconds(1))) { return $true } } catch { }
    }
    return $false
}

function Test-SISoftwareSpecConditions {
    <#
    .SYNOPSIS  PURE. A hasSoftwareInstalled detection's optional conditions against ONE device whose software already matched
               by name. Returns @{ Match; Fallback; Reason }.
    .DESCRIPTION
        THE FALLBACK (missing data never drops a tier): the device's evidence UNKNOWN (no evidence read, a refused read, a
        page that failed) -> Match = $true, Fallback = $true -- the detection matches by name exactly as before, and the
        caller says so. Per matching software copy:
          versionRange      the copy's version in the range; a version that cannot be compared -> the copy counts (fallback)
          installKinds /    a copy WITHOUT any evidence path counts (fallback: Defender gave no path); a copy WITH paths counts
          pathPatterns /    when ONE path satisfies all three: its install kind is listed (or is 'unknown' -- never decided
          notPathPatterns   against), it matches a pathPattern (when given) and no notPathPattern. A copy with disk paths is
                            decided by its disk paths only (its registry rows are not evidence of where it is).
        The detection matches when any copy counts. It does NOT match only when the evidence is known and every copy is
        known to fail -- e.g. WordPress found only in D:\home\users\x\wordpress (data-folder) with installKinds [installed].
    #>
    param($Spec, $Evidence, [string[]]$Patterns,
          # 'vendor/product' a per-server exception takes away from this rule on this device (engine\_shared\SI-SoftwareException.ps1):
          # such a copy is not a candidate. None = as before.
          $Exclude)
    $kinds = @(Get-SIEvSpecList $Spec 'installKinds' | ForEach-Object { $_.ToLowerInvariant() })
    $inc = @(Get-SIEvSpecList $Spec 'pathPatterns')
    $exc = @(Get-SIEvSpecList $Spec 'notPathPatterns')
    $range = (@(Get-SIEvSpecList $Spec 'versionRange') -join ' ')
    $state = [string](Get-SIEvValue $Evidence 'State')
    if ($null -eq $Evidence -or $state -ne 'read') { return @{ Match = $true; Fallback = $true; Reason = 'evidence-unknown' } }
    $items = @(Get-SIEvValue $Evidence 'Items')
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($it in $items) {
        if ($null -eq $it) { continue }
        $p = ([string](Get-SIEvValue $it 'p')).ToLowerInvariant()
        if ($null -ne $Exclude -and $Exclude.Contains($p)) { continue }
        foreach ($pat in @($Patterns)) { $g = ([string]$pat).ToLowerInvariant(); if ($p -like $g -or $p -like ('*/' + $g)) { $cands.Add($it); break } }
    }
    if ($cands.Count -eq 0) { return @{ Match = $true; Fallback = $true; Reason = 'software-not-in-evidence' } }
    $pathConds = ($kinds.Count -gt 0 -or $inc.Count -gt 0 -or $exc.Count -gt 0)
    $fallback = $false
    foreach ($it in $cands) {
        if ($range) {
            $vr = Test-SIEvVersionRange -Version ([string](Get-SIEvValue $it 'v')) -Range $range
            if ($vr -eq $false) { continue }
            if ($null -eq $vr) { $fallback = $true }
        }
        if (-not $pathConds) { return @{ Match = $true; Fallback = $fallback; Reason = $(if ($fallback) { 'version-not-comparable' } else { 'version' }) } }
        $paths = @(Get-SIEvValue $it 'paths' | Where-Object { $null -ne $_ })
        if ($paths.Count -eq 0) { return @{ Match = $true; Fallback = $true; Reason = 'no-evidence-path' } }
        $disk = @($paths | Where-Object { [string](Get-SIEvValue $_ 't') -eq 'disk' })
        if ($disk.Count -gt 0) { $paths = $disk }
        foreach ($pp in $paths) {
            $k = ([string](Get-SIEvValue $pp 'k')).ToLowerInvariant()
            $f = [string](Get-SIEvValue $pp 'f')
            if ($kinds.Count -gt 0 -and $k -ne 'unknown' -and $kinds -notcontains $k) { continue }
            if ($inc.Count -gt 0 -and -not (Test-SIEvRegex $f $inc)) { continue }
            if ($exc.Count -gt 0 -and (Test-SIEvRegex $f $exc)) { continue }
            $fb = $fallback -or ($kinds.Count -gt 0 -and $k -eq 'unknown')
            return @{ Match = $true; Fallback = $fb; Reason = $(if ($fb) { 'unknown-kind' } else { 'path' }) }
        }
    }
    return @{ Match = $false; Fallback = $false; Reason = 'evidence-excludes' }
}

# ---------------------------------------------------------------------------------------------------------------------
#  SQL: write, retention, read (the interfaces the remediation tasks and the verdict page build on)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SISoftwareEvidenceWriteSql {
    <#
        One chunk of one page of devices, ONE TRANSACTION. Only the newest run is kept: the FIRST chunk removes the page's devices'
        rows (whatever run wrote them) and sets each device's state -- a device READ now 'writing', a device whose evidence could not
        be read 'unknown' (it keeps no rows: an older run's paths are never shown as current); every chunk inserts its rows (of
        devices read now only); the LAST chunk turns the page's 'writing' devices 'read'. Readers take rows of 'read' devices only,
        so a device is shown whole or not at all, also when a later chunk fails. @ct, @devices (JSON [{ DeviceId; State; Rows }]),
        @rows (JSON), @first, @last. Nothing when the tables are not there yet (Written = -1).
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.SoftwareEvidence') IS NULL OR OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NULL BEGIN SELECT -1 AS Written; RETURN; END
DECLARE @t DATETIME2(3) = CONVERT(DATETIME2(3), @ct, 126);
DECLARE @d TABLE (DeviceId NVARCHAR(64) NOT NULL PRIMARY KEY, State NVARCHAR(16) NOT NULL, [Rows] INT NULL);
INSERT @d (DeviceId, State, [Rows])
SELECT x.DeviceId, MIN(x.State), MAX(x.[Rows]) FROM (
    SELECT LEFT(LOWER(j.DeviceId), 64) AS DeviceId, CASE WHEN ISNULL(j.State, N'read') = N'read' THEN N'read' ELSE N'unknown' END AS State, j.[Rows]
    FROM OPENJSON(@devices) WITH (DeviceId NVARCHAR(64), State NVARCHAR(16), [Rows] INT) j WHERE j.DeviceId IS NOT NULL) x
GROUP BY x.DeviceId;
DECLARE @n INT = 0;
BEGIN TRAN;
IF @first = 1
BEGIN
    DELETE e FROM sidata.SoftwareEvidence e JOIN @d d ON d.DeviceId = e.DeviceId;
    MERGE sidata.SoftwareEvidenceDevice AS s
    USING (SELECT DeviceId, CASE WHEN State = N'read' THEN N'writing' ELSE N'unknown' END AS State, [Rows] FROM @d) AS d ON s.DeviceId = d.DeviceId
    WHEN MATCHED THEN UPDATE SET CollectionTime = @t, State = d.State, [Rows] = d.[Rows], WrittenAt = SYSUTCDATETIME()
    WHEN NOT MATCHED THEN INSERT (DeviceId, CollectionTime, State, [Rows]) VALUES (d.DeviceId, @t, d.State, d.[Rows]);
END
INSERT sidata.SoftwareEvidence (CollectionTime, DeviceId, Vendor, Product, Version, PathType, FullPath, Drive, InstallKind,
    Application, ApplicationVendor, ApplicationVersion, ApplicationSource, LastSeen)
SELECT @t, LEFT(LOWER(r.DeviceId), 64), LEFT(ISNULL(r.Vendor, N''), 256), LEFT(ISNULL(r.Product, N''), 256), LEFT(ISNULL(r.Version, N''), 128),
       LEFT(r.PathType, 16), r.FullPath, LEFT(r.Drive, 260), LEFT(r.InstallKind, 16), LEFT(r.Application, 400), LEFT(r.ApplicationVendor, 256),
       LEFT(r.ApplicationVersion, 128), LEFT(r.ApplicationSource, 16), TRY_CONVERT(DATETIME2(3), r.LastSeen, 127)
FROM OPENJSON(@rows) WITH (DeviceId NVARCHAR(64), Vendor NVARCHAR(256), Product NVARCHAR(256), Version NVARCHAR(128), PathType NVARCHAR(16),
    FullPath NVARCHAR(MAX), Drive NVARCHAR(260), InstallKind NVARCHAR(16), Application NVARCHAR(400), ApplicationVendor NVARCHAR(256),
    ApplicationVersion NVARCHAR(128), ApplicationSource NVARCHAR(16), LastSeen NVARCHAR(40)) r
WHERE r.DeviceId IS NOT NULL AND r.FullPath IS NOT NULL
  AND EXISTS (SELECT 1 FROM @d d WHERE d.DeviceId = LEFT(LOWER(r.DeviceId), 64) AND d.State = N'read');
SET @n = @@ROWCOUNT;
IF @last = 1
    UPDATE s SET State = N'read', WrittenAt = SYSUTCDATETIME()
    FROM sidata.SoftwareEvidenceDevice s JOIN @d d ON d.DeviceId = s.DeviceId
    WHERE d.State = N'read' AND s.State = N'writing' AND s.CollectionTime = @t;
COMMIT;
SELECT @n AS Written;
'@
}

function Get-SISoftwareEvidenceRetentionSql {
    <# One batch of the retention: the devices whose evidence was last written more than @days days before the newest run (a
       device no run reads any more -- retired, out of scope) go, their rows first, then their state. Answers the rows removed. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NULL OR OBJECT_ID(N'sidata.SoftwareEvidence') IS NULL BEGIN SELECT 0 AS Removed; RETURN; END
DECLARE @newest DATETIME2(3) = (SELECT MAX(CollectionTime) FROM sidata.SoftwareEvidenceDevice);
IF @newest IS NULL BEGIN SELECT 0 AS Removed; RETURN; END
DECLARE @cut DATETIME2(3) = DATEADD(day, -@days, @newest);
DELETE TOP (@batch) e FROM sidata.SoftwareEvidence e JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = e.DeviceId WHERE s.CollectionTime < @cut;
DECLARE @n INT = @@ROWCOUNT;
IF @n = 0 BEGIN DELETE TOP (@batch) FROM sidata.SoftwareEvidenceDevice WHERE CollectionTime < @cut; SET @n = @@ROWCOUNT; END
SELECT @n AS Removed;
'@
}

function Get-SISoftwareEvidenceStaleDays {
    <# PURE. After how many days without a run that reads it a device's evidence goes: SI_ActiveStaleDays (the one staleness
       setting -- a device not seen for this long is no active CI; default 30, never below 1). #>
    param($Setting = $global:SI_ActiveStaleDays)
    $n = 0
    if ($null -ne $Setting -and [int]::TryParse(([string]$Setting).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    return 30
}

function Write-SISoftwareEvidence {
    <#
    .SYNOPSIS  Writes one page of devices to sidata.SoftwareEvidence / SoftwareEvidenceDevice, REPLACING each device's earlier
               rows (only the newest run is kept), in chunks of rows -- each chunk one transaction; a device's rows are shown
               only once its last chunk is written (Get-SISoftwareEvidenceWriteSql). Never throws: returns @{ Written; Missing
               (the tables are not there yet); Error }. -Invoke: the SQL seam { param($Sql, $Params, $Mode) }.
    .PARAMETER Devices  @{ DeviceId; State ('read' | 'unknown'); Rows } -- every device of the page, read or not
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$CollectionTime,
          [AllowEmptyCollection()][object[]]$Devices = @(), [AllowEmptyCollection()][object[]]$Rows = @(), [int]$ChunkRows = 2000)
    $res = @{ Written = 0; Missing = $false; Error = $null }
    if (@($Devices).Count -eq 0) { return $res }
    try {
        $ct = $CollectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
        $dj = ConvertTo-Json -InputObject @(@($Devices) | ForEach-Object { [ordered]@{ DeviceId = [string](Get-SIEvValue $_ 'DeviceId'); State = [string](Get-SIEvValue $_ 'State'); Rows = [int](Get-SIEvValue $_ 'Rows') } }) -Compress -Depth 3
        if (-not $dj.TrimStart().StartsWith('[')) { $dj = '[' + $dj + ']' }
        if ($ChunkRows -lt 1) { $ChunkRows = 2000 }
        $all = @($Rows)
        $first = 1
        $i = 0
        do {
            $chunk = @(); if ($all.Count -gt 0) { $chunk = @($all[$i..([Math]::Min($i + $ChunkRows, $all.Count) - 1)]) }
            $last = 0; if (($i + $ChunkRows) -ge $all.Count) { $last = 1 }
            $rj = '[]'
            if ($chunk.Count -gt 0) {
                $rj = ConvertTo-Json -InputObject @($chunk | ForEach-Object {
                    $ls = Get-SIEvValue $_ 'LastSeen'; $lst = $null
                    if ($ls -is [datetime]) { $lst = $ls.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture) } elseif ($ls) { $lst = [string]$ls }
                    [ordered]@{ DeviceId = [string](Get-SIEvValue $_ 'DeviceId'); Vendor = [string](Get-SIEvValue $_ 'Vendor'); Product = [string](Get-SIEvValue $_ 'Product'); Version = [string](Get-SIEvValue $_ 'Version')
                        PathType = [string](Get-SIEvValue $_ 'PathType'); FullPath = [string](Get-SIEvValue $_ 'FullPath'); Drive = Get-SIEvValue $_ 'Drive'; InstallKind = [string](Get-SIEvValue $_ 'InstallKind')
                        Application = Get-SIEvValue $_ 'Application'; ApplicationVendor = Get-SIEvValue $_ 'ApplicationVendor'; ApplicationVersion = Get-SIEvValue $_ 'ApplicationVersion'
                        ApplicationSource = Get-SIEvValue $_ 'ApplicationSource'; LastSeen = $lst }
                }) -Compress -Depth 3
                if (-not $rj.TrimStart().StartsWith('[')) { $rj = '[' + $rj + ']' }
            }
            $r = @(Get-SIEvRows (& $Invoke (Get-SISoftwareEvidenceWriteSql) @{ ct = $ct; devices = $dj; rows = $rj; first = $first; last = $last } 'rows'))[0]
            $w = [int](Get-SIEvValue $r 'Written')
            if ($w -lt 0) { $res.Missing = $true; return $res }
            $res.Written += $w
            $first = 0
            $i += $ChunkRows
        } while ($i -lt $all.Count)
    } catch { $res.Error = $_.Exception.Message }
    return $res
}

function Write-SISoftwareEvidenceUnknown {
    <# Marks devices UNKNOWN for this run (their evidence could not be read): their earlier rows go -- never shown as current --
       in pages of 2,000 devices. Never throws: @{ Missing; Errors; First }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][datetime]$CollectionTime, [AllowEmptyCollection()][string[]]$DeviceIds = @())
    $res = @{ Missing = $false; Errors = 0; First = '' }
    $ids = @($DeviceIds | Where-Object { $_ })
    for ($i = 0; $i -lt $ids.Count; $i += 2000) {
        $page = @($ids[$i..([Math]::Min($i + 2000, $ids.Count) - 1)] | ForEach-Object { @{ DeviceId = $_; State = 'unknown'; Rows = 0 } })
        $w = Write-SISoftwareEvidence -Invoke $Invoke -CollectionTime $CollectionTime -Devices $page -Rows @()
        if ($w.Missing) { $res.Missing = $true; break }
        if ($w.Error) { $res.Errors++; if (-not $res.First) { $res.First = [string]$w.Error } }
    }
    return $res
}

function Invoke-SISoftwareEvidenceRetention {
    <# Removes the evidence of devices no run has read for -Days (Get-SISoftwareEvidenceStaleDays) before the newest run, in
       batches. Never throws: @{ Removed; Error }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [int]$Days = (Get-SISoftwareEvidenceStaleDays), [int]$Batch = 5000)
    $res = @{ Removed = 0L; Error = $null }
    if ($Days -lt 1) { $Days = 1 }
    try {
        for ($n = 0; $n -lt 100000; $n++) {
            $r = @(Get-SIEvRows (& $Invoke (Get-SISoftwareEvidenceRetentionSql) @{ days = $Days; batch = $Batch } 'rows'))[0]
            $x = [long](Get-SIEvValue $r 'Removed')
            if ($x -le 0) { break }
            $res.Removed += $x
        }
    } catch { $res.Error = $_.Exception.Message }
    return $res
}

function Get-SISoftwareEvidenceReadSql {
    <# The evidence (each device's newest run -- the only one kept) of a device list (@devices JSON of Defender device ids)
       and / or a CI (@ciId, through sidata.CiLink), of devices whose state is 'read' only (unknown / a write in progress = no
       rows); @ct given = only when the device's evidence is of that run. Rows ordered by device, product, path. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.SoftwareEvidence') IS NULL OR OBJECT_ID(N'sidata.SoftwareEvidenceDevice') IS NULL
BEGIN
    SELECT CAST(NULL AS DATETIME2(3)) AS CollectionTime, CAST(NULL AS NVARCHAR(64)) AS DeviceId WHERE 1 = 0; RETURN;
END
DECLARE @t DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@ct, N''), 126);
DECLARE @dev TABLE (DeviceId NVARCHAR(64) NOT NULL PRIMARY KEY);
INSERT @dev (DeviceId) SELECT DISTINCT LEFT(LOWER(j.[value]), 64) FROM OPENJSON(ISNULL(@devices, N'[]')) j WHERE j.[value] IS NOT NULL AND j.[value] <> N'';
IF NULLIF(@ciId, N'') IS NOT NULL AND OBJECT_ID(N'sidata.CiLink') IS NOT NULL
    INSERT @dev (DeviceId) SELECT DISTINCT LEFT(LOWER(l.NativeId), 64) FROM sidata.CiLink l
    WHERE l.CiId = @ciId AND l.Provider = N'mde' AND NOT EXISTS (SELECT 1 FROM @dev d WHERE d.DeviceId = LEFT(LOWER(l.NativeId), 64));
SELECT e.CollectionTime, e.DeviceId, e.Vendor, e.Product, e.Version, e.PathType, e.FullPath, e.Drive, e.InstallKind, e.Application,
       e.ApplicationVendor, e.ApplicationVersion, e.ApplicationSource, e.LastSeen
FROM @dev p
JOIN sidata.SoftwareEvidenceDevice s ON s.DeviceId = p.DeviceId AND s.State = N'read' AND (@t IS NULL OR s.CollectionTime = @t)
JOIN sidata.SoftwareEvidence e ON e.DeviceId = s.DeviceId
ORDER BY e.DeviceId, e.Vendor, e.Product, e.Version, e.PathType, e.FullPath;
'@
}

function Get-SISoftwareEvidence {
    <#
    .SYNOPSIS  THE INTERFACE: the software evidence of Defender devices (-DeviceIds) and / or a CI (-CiId, its Defender devices
               through sidata.CiLink) -- each device's newest run, the only one kept, of devices READ in it (a device whose
               evidence is unknown gives no rows). -CollectionTime: only when the device's evidence is of that run. Returns the
               rows (empty when nothing is stored). Throws on a database error (the caller decides what unknown means for it).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [AllowEmptyCollection()][string[]]$DeviceIds = @(), [string]$CiId = '', $CollectionTime)
    $ct = ''
    if ($null -ne $CollectionTime -and "$CollectionTime" -ne '') { $ct = ([datetime]$CollectionTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $dj = ConvertTo-Json -InputObject @($ids) -Compress
    if (-not $dj.TrimStart().StartsWith('[')) { $dj = '[' + $dj + ']' }
    Get-SIEvRows (& $Invoke (Get-SISoftwareEvidenceReadSql) @{ ct = $ct; devices = $dj; ciId = [string]$CiId } 'rows')
}

function Get-SIFindingEvidenceKey {
    <# PURE. device|vendor|product|version, lower-case (the version as written). #>
    param([string]$DeviceId, [string]$Vendor, [string]$Product, [string]$Version)
    ('{0}|{1}|{2}|{3}' -f ([string]$DeviceId).Trim().ToLowerInvariant(), ([string]$Vendor).Trim().ToLowerInvariant(), ([string]$Product).Trim().ToLowerInvariant(), ([string]$Version).Trim())
}

function New-SIFindingEvidenceIndex {
    <# PURE. Evidence rows -> key (Get-SIFindingEvidenceKey) -> @{ Paths; Kinds; BundledBy } (each a sorted distinct list).
       Fast at scale: one pass, the values read in place (no call per value), each application text built once per row. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $ix = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) {
            $dv = [string]$r['DeviceId']; $vn = [string]$r['Vendor']; $pr = [string]$r['Product']; $ve = [string]$r['Version']
            $f = [string]$r['FullPath']; $kd = [string]$r['InstallKind']
            $an = [string]$r['Application']; $as = [string]$r['ApplicationSource']; $av = [string]$r['ApplicationVendor']; $aw = [string]$r['ApplicationVersion']
        } else {
            $dv = [string]$r.DeviceId; $vn = [string]$r.Vendor; $pr = [string]$r.Product; $ve = [string]$r.Version
            $f = [string]$r.FullPath; $kd = [string]$r.InstallKind
            $an = [string]$r.Application; $as = [string]$r.ApplicationSource; $av = [string]$r.ApplicationVendor; $aw = [string]$r.ApplicationVersion
        }
        # the key exactly as Get-SIFindingEvidenceKey writes it
        $k = $dv.Trim().ToLowerInvariant() + '|' + $vn.Trim().ToLowerInvariant() + '|' + $pr.Trim().ToLowerInvariant() + '|' + $ve.Trim()
        $x = $ix[$k]
        if ($null -eq $x) {
            $x = @{ Paths = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal))
                    Kinds = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal))
                    BundledBy = (New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)) }
            $ix[$k] = $x
        }
        if ($f) { [void]$x.Paths.Add($f) }
        if ($kd) { [void]$x.Kinds.Add($kd) }
        if ($kd -eq 'bundled' -and $an) {
            # the application text exactly as Format-SIEvidenceApplication writes it
            $a = $an
            if ($as -eq 'inventory') { if ($av) { $a = $av + '/' + $an }; if ($aw) { $a = $a + ' ' + $aw } }
            [void]$x.BundledBy.Add($a)
        }
    }
    return $ix
}

function Get-SIFindingEvidenceValues {
    <#
    .SYNOPSIS  PURE. The evidence fields of ONE finding row: the device (-DeviceId) and the software it names (';'-separated
               vendor / product / version lists, as the Defender reports carry them) joined to the index. Every combination
               present in the index counts (only real copies are in it). @{ Paths; Kinds; BundledBy } as ';'-joined text,
               or $null when no copy of the finding's software is in the evidence (unknown -- the row is left as it is).
               Fast at scale: a finding of ONE copy (the usual case) takes that copy's text, joined once per copy and kept
               on the index; several copies are joined together, sorted and distinct, as one.
    #>
    param([hashtable]$Index, [string]$DeviceId, [string]$Vendors, [string]$Products, [string]$Versions)
    if ($null -eq $Index -or $Index.Count -eq 0 -or -not $DeviceId) { return $null }
    $ps = New-Object System.Collections.Generic.List[string]
    foreach ($x in ([string]$Products).Split(';')) { $y = $x.Trim(); if ($y) { $ps.Add($y) } }
    if ($ps.Count -eq 0) { return $null }
    $vs = New-Object System.Collections.Generic.List[string]
    foreach ($x in ([string]$Vendors).Split(';')) { $y = $x.Trim(); if ($y) { $vs.Add($y) } }
    if ($vs.Count -eq 0) { $vs.Add('') }
    $ns = New-Object System.Collections.Generic.List[string]
    foreach ($x in ([string]$Versions).Split(';')) { $y = $x.Trim(); if ($y) { $ns.Add($y) } }
    if ($ns.Count -eq 0) { $ns.Add('') }
    $dk = $DeviceId.Trim().ToLowerInvariant() + '|'
    $hits = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($v in $vs) { foreach ($p in $ps) { foreach ($n in $ns) {
        $k = $dk + $v.Trim().ToLowerInvariant() + '|' + $p.Trim().ToLowerInvariant() + '|' + $n.Trim()
        $e = $Index[$k]
        if ($null -ne $e -and $seen.Add($k)) { $hits.Add($e) }
    } } }
    if ($hits.Count -eq 0) { return $null }
    if ($hits.Count -eq 1) {
        $e = $hits[0]
        if ($null -eq $e['Text']) { $e['Text'] = @{ Paths = [string]::Join(';', $e.Paths); Kinds = [string]::Join(';', $e.Kinds); BundledBy = [string]::Join(';', $e.BundledBy) } }
        $c = $e['Text']
        return @{ Paths = $c.Paths; Kinds = $c.Kinds; BundledBy = $c.BundledBy }
    }
    $paths = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $kinds = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    $by = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
    foreach ($e in $hits) { $paths.UnionWith($e.Paths); $kinds.UnionWith($e.Kinds); $by.UnionWith($e.BundledBy) }
    return @{ Paths = [string]::Join(';', $paths); Kinds = [string]::Join(';', $kinds); BundledBy = [string]::Join(';', $by) }
}

