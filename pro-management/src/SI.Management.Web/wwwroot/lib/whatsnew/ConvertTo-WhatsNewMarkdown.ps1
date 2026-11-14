<#
WHATS-NEW-1 (framework/REQUIREMENTS.md "## WHATS-NEW-1" point 4; owner 2026-11-13: "it must go into all solutions gui and
invardia.com and github" / "all must have same"): the ONE renderer of a product's WHATSNEW.md for its Community repo on
GitHub, from the same whats-new/<version>.json files the GUI (whats-new.js) and invardia.com show. The products run it in
their mirror step and never hand-write the file; with -Check it is the release gate's conformance check (point 5).

  pwsh -NoProfile -File ConvertTo-WhatsNewMarkdown.ps1 -Folder .\whats-new -OutFile .\WHATSNEW.md -ProductName 'PIM Manager'
  pwsh -NoProfile -File ConvertTo-WhatsNewMarkdown.ps1 -Folder .\whats-new -Check

Reads every *.json in -Folder (one per release, named <version>.json). The rules are whats-new.schema.json: version, date
(YYYY-MM-DD), type fix-only | feature | security, summary, new[] and fixes[] of { title, text, action? }, no other field.
-Check adds the 3a limits (title at most 8 words, text at most 40 words, at most 5 items per section) and refuses a commit
hash or a SUP- ticket number in any text. Output: all releases newest first (version parts compared as numbers), each
"## <version> · <date> · <Feature update|Fix-only|Security>", the summary, the "**Action needed:**" lines first, then
"### New features" and "### Fixes" ("- **title** - text"; an empty section says "None in this version."). LF line ends,
UTF-8 without BOM, the same bytes for the same files.
Exit code: 0 written / check passed; 1 a file is invalid (every problem is listed) or the folder has none; 2 bad arguments.
Plain PowerShell 7 + .NET (System.Text.Json): no module dependencies.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Folder,
  [string]$OutFile,
  [string]$ProductName,
  [switch]$Check
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3
Add-Type -AssemblyName System.Text.Json   # part of .NET itself (not a module); loaded here in case the host has not yet

$Limits = @{ TitleWords = 8; TextWords = 40; ItemsPerSection = 5 }   # = whats-new.schema.json / whats-new.js WHATS_NEW_LIMITS
$TypeLabels = [ordered]@{ 'feature' = 'Feature update'; 'fix-only' = 'Fix-only'; 'security' = 'Security' }
$VersionPattern = '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?$'
$None = 'None in this version.'
$CommitHash = '(?i)(?<![0-9A-Za-z])(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}(?![0-9A-Za-z])'
$Ticket = '(?i)(?<![0-9A-Za-z])SUP-\d{4}-\d+'

function Compare-WnVersion([string]$A, [string]$B) {
  $pa = $A -split '[.-]'; $pb = $B -split '[.-]'
  for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
    if ($i -ge $pa.Count) { return -1 }
    if ($i -ge $pb.Count) { return 1 }
    $na = [Numerics.BigInteger]::Zero; $nb = [Numerics.BigInteger]::Zero
    $isNum = ($pa[$i] -match '^\d+$') -and ($pb[$i] -match '^\d+$') -and [Numerics.BigInteger]::TryParse($pa[$i], [ref]$na) -and [Numerics.BigInteger]::TryParse($pb[$i], [ref]$nb)
    $c = if ($isNum) { $na.CompareTo($nb) } else { [string]::CompareOrdinal($pa[$i], $pb[$i]) }
    if ($c -ne 0) { return [Math]::Sign($c) }
  }
  0
}

function Get-WnString($Obj, [string]$Name) {
  $v = [System.Text.Json.JsonElement]::new()
  if (-not $Obj.TryGetProperty($Name, [ref]$v)) { return $null }
  if ($v.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { return [pscustomobject]@{ NotString = $true } }
  $v.GetString()
}
function Test-WnFilled($V) { $V -is [string] -and $V.Trim().Length -gt 0 }
function Get-WnWords([string]$S) { @($S.Trim() -split '\s+' | Where-Object { $_ }).Count }
function Format-WnLine([string]$S) { ($S -replace '\s+', ' ').Trim() }

<# One file -> @{ File; Version; Data (ordered); Problems; Style } - never throws for the content. #>
function Read-WnFile([IO.FileInfo]$File) {
  $problems = [System.Collections.Generic.List[string]]::new()
  $style = [System.Collections.Generic.List[string]]::new()
  $text = [IO.File]::ReadAllText($File.FullName).TrimStart([char]0xFEFF)
  $doc = $null
  try { $doc = [System.Text.Json.JsonDocument]::Parse($text) } catch { $problems.Add('is not valid JSON'); return [pscustomobject]@{ File = $File.Name; Version = $null; Data = $null; Problems = $problems; Style = $style } }
  try {
    $root = $doc.RootElement
    if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { $problems.Add('the file is not a JSON object'); return [pscustomobject]@{ File = $File.Name; Version = $null; Data = $null; Problems = $problems; Style = $style } }
    foreach ($prop in $root.EnumerateObject()) { if ($prop.Name -notin '$schema', 'version', 'date', 'type', 'summary', 'new', 'fixes') { $problems.Add("unknown field '$($prop.Name)'") } }
    $data = [ordered]@{}
    foreach ($k in 'version', 'date', 'type', 'summary') {
      $v = Get-WnString $root $k
      if ($null -eq $v -or ($v -is [string] -and -not $v.Trim())) { $problems.Add("'$k' is missing"); continue }
      if ($v -isnot [string]) { $problems.Add("'$k' is not a text"); continue }
      $data[$k] = $v
    }
    if ($data.Contains('version') -and $data.version -notmatch $VersionPattern) { $problems.Add("'version' '$($data.version)' is not a release version (like 3.1.21)") }
    if ($data.Contains('version') -and $data.version -match $VersionPattern -and $File.BaseName -cne $data.version) { $problems.Add("the file name must be '$($data.version).json'") }
    if ($data.Contains('date')) {
      $d = [datetime]::MinValue
      if ($data.date -notmatch '^\d{4}-\d{2}-\d{2}$' -or -not [datetime]::TryParseExact($data.date, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { $problems.Add("'date' '$($data.date)' is not a date (YYYY-MM-DD)") }
    }
    if ($data.Contains('type') -and -not $TypeLabels.Contains($data.type)) { $problems.Add("'type' '$($data.type)' is not fix-only, feature or security") }
    if ($data.Contains('summary')) {
      if ($data.summary -match $CommitHash) { $style.Add("summary: names a commit hash ('$($Matches[0])') - say the effect instead") }
      if ($data.summary -match $Ticket) { $style.Add("summary: names a ticket number ('$($Matches[0])')") }
    }
    foreach ($sec in 'new', 'fixes') {
      $list = [System.Text.Json.JsonElement]::new()
      if (-not $root.TryGetProperty($sec, [ref]$list) -or $list.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) { $problems.Add("'$sec' is missing or not a list"); continue }
      $items = [System.Collections.Generic.List[object]]::new()
      $i = 0
      foreach ($it in $list.EnumerateArray()) {
        $at = "$sec[$i]"; $i++
        if ($it.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { $problems.Add("$at is not an object"); continue }
        foreach ($prop in $it.EnumerateObject()) { if ($prop.Name -notin 'title', 'text', 'action') { $problems.Add("${at}: unknown field '$($prop.Name)'") } }
        $item = [ordered]@{}
        foreach ($k in 'title', 'text', 'action') {
          $v = Get-WnString $it $k
          if ($null -eq $v) { if ($k -ne 'action') { $problems.Add("${at}: '$k' is missing") }; continue }
          if ($v -isnot [string]) { $problems.Add("${at}: '$k' is not a text"); continue }
          if (-not $v.Trim()) { $problems.Add($(if ($k -eq 'action') { "${at}: 'action' is empty (leave the field out when there is nothing to do)" } else { "${at}: '$k' is missing" })); continue }
          $item[$k] = $v
          if ($v -match $CommitHash) { $style.Add("$at.${k}: names a commit hash ('$($Matches[0])') - say the effect instead") }
          if ($v -match $Ticket) { $style.Add("$at.${k}: names a ticket number ('$($Matches[0])')") }
        }
        if ($item.Contains('title') -and (Get-WnWords $item.title) -gt $Limits.TitleWords) { $style.Add("${at}: the title has $(Get-WnWords $item.title) words - at most $($Limits.TitleWords)") }
        if ($item.Contains('text') -and (Get-WnWords $item.text) -gt $Limits.TextWords) { $style.Add("${at}: the text has $(Get-WnWords $item.text) words - at most $($Limits.TextWords)") }
        $items.Add($item)
      }
      if ($i -gt $Limits.ItemsPerSection) { $style.Add("'$sec' has $i items - at most $($Limits.ItemsPerSection); group the smaller ones (`"Smaller fixes: ...`")") }
      $data[$sec] = $items.ToArray()
    }
    [pscustomobject]@{ File = $File.Name; Version = $(if ($data.Contains('version')) { $data.version } else { $null }); Data = $data; Problems = $problems; Style = $style }
  } finally { $doc.Dispose() }
}

<# The files (valid, newest first) -> the WHATSNEW.md text, LF line ends, ending in one LF. #>
function ConvertTo-WnMarkdown([object[]]$Files, [string]$Name) {
  $sb = [System.Text.StringBuilder]::new()
  $nl = { param([string]$l) [void]$sb.Append($l).Append("`n") }
  & $nl $(if ($Name) { "# What's new in $(Format-WnLine $Name)" } else { "# What's new" })
  foreach ($f in $Files) {
    $d = $f.Data
    & $nl ''
    & $nl "## $($d.version) · $($d.date) · $($TypeLabels[$d.type])"
    & $nl ''
    & $nl (Format-WnLine $d.summary)
    $actions = @(@($d.new) + @($d.fixes) | Where-Object { $_ -and $_.Contains('action') } | ForEach-Object { Format-WnLine $_.action })
    foreach ($a in $actions) { & $nl ''; & $nl "**Action needed:** $a" }
    foreach ($sec in @(@('New features', 'new'), @('Fixes', 'fixes'))) {
      & $nl ''
      & $nl "### $($sec[0])"
      & $nl ''
      $items = @($d[$sec[1]])
      if (-not $items.Count) { & $nl $None }
      foreach ($it in $items) { & $nl "- **$(Format-WnLine $it.title)** - $(Format-WnLine $it.text)" }
    }
  }
  $sb.ToString()
}

if (-not $Check -and -not $OutFile) { Write-Host 'usage: ConvertTo-WhatsNewMarkdown.ps1 -Folder <dir> -OutFile <WHATSNEW.md> [-ProductName <name>] | -Folder <dir> -Check'; exit 2 }
if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { Write-Host "NOT done: the folder '$Folder' does not exist"; exit 1 }

$files = @(Get-ChildItem -LiteralPath $Folder -File -Filter '*.json' | Sort-Object Name | ForEach-Object { Read-WnFile $_ })
if (-not $files.Count) { Write-Host "NOT done: '$Folder' has no <version>.json files"; exit 1 }
$lines = [System.Collections.Generic.List[string]]::new()
foreach ($f in $files) {
  foreach ($p in $f.Problems) { $lines.Add("$($f.File): $p") }
  if ($Check) { foreach ($p in $f.Style) { $lines.Add("$($f.File): $p") } }
}
foreach ($g in @($files | Where-Object { $_.Version } | Group-Object Version | Where-Object Count -gt 1)) { $lines.Add("version $($g.Name) is in more than one file ($(($g.Group.File) -join ', '))") }
if ($lines.Count) {
  Write-Host "$(if ($Check) { 'CHECK FAILED' } else { 'NOT written' }) - $($lines.Count) problem(s) in $Folder`:"
  foreach ($l in $lines) { Write-Host "  $l" }
  exit 1
}
if ($Check) { Write-Host "CHECK PASSED: $($files.Count) file(s) in $Folder follow WHATS-NEW-1"; exit 0 }

$sorted = [System.Collections.Generic.List[object]]::new()
foreach ($f in $files) { $sorted.Add($f) }
$sorted.Sort([Comparison[object]] { param($a, $b) Compare-WnVersion $b.Version $a.Version })
$md = ConvertTo-WnMarkdown -Files $sorted.ToArray() -Name $ProductName
$target = [IO.Path]::GetFullPath($OutFile, (Get-Location).Path)
$dir = Split-Path $target
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
[IO.File]::WriteAllText($target, $md, [Text.UTF8Encoding]::new($false))
Write-Host "written $target ($($sorted.Count) release(s), newest $($sorted[0].Version))"
exit 0
