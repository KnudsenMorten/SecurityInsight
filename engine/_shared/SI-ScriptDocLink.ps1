#Requires -Version 5.1
<#
    "What does this script do?" in a MAIL (framework section 12.7 SCRIPT-DOC-1): a mail that tells its reader to run one of
    SecurityInsight's scripts (setup\Set-SIMail.ps1, diagnostics\Test-SIInstall.ps1, ...) carries the link to that script's
    documentation page on invardia.com, the same link the web app shows (pro-management ...\Links\ScriptDocs.cs).
    tests\pester\SIv3-ScriptDocs.Tests.ps1 fails when a mail body names a script without going through this.
    PURE. PowerShell 5.1 and 7; no module.
#>

function Get-SIScriptDocUrlForMail {
    <# The documentation page of one script: https://invardia.com/docs/si/scripts/<Script>/ (no .ps1, trailing slash). #>
    param([Parameter(Mandatory)][string]$Script)
    'https://invardia.com/docs/si/scripts/{0}/' -f [uri]::EscapeDataString($Script)
}

function Add-SIScriptDocLink {
    <#
        The text with the documentation link after it for every script it names (each once). Plain text: " (What does this
        script do? <url>)". -Html: the text is HTML already, and an <a> follows it.
    #>
    param([AllowEmptyString()][string]$Text, [switch]$Html)
    if (-not $Text) { return $Text }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($Text, '(?<![\w./\\-])(?:setup|diagnostics)[\\/](?<name>[A-Z][a-z]+-(?:SI[A-Za-z]+|SecurityInsight))\.ps1\b')) {
        if (-not $names.Contains($m.Groups['name'].Value)) { $names.Add($m.Groups['name'].Value) }
    }
    if (-not $names.Count) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($Text)
    foreach ($n in $names) {
        $label = if ($names.Count -eq 1) { 'What does this script do?' } else { 'What does {0} do?' -f $n }
        $url = Get-SIScriptDocUrlForMail -Script $n
        if ($Html) { [void]$sb.Append((' <a href="{0}">{1}</a>' -f $url, [System.Net.WebUtility]::HtmlEncode($label))) }
        else { [void]$sb.Append((' ({0} {1})' -f $label, $url)) }
    }
    $sb.ToString()
}
