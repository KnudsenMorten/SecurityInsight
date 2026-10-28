$ErrorActionPreference = 'Stop'
$yamlText = Get-Content -Raw 'C:/SCRIPTS/AutomateIT/.github/workflows/publish.yml'
$marker = 'name: Stage community edition'
$startIdx = $yamlText.IndexOf($marker)
$runStart = $yamlText.IndexOf('run: |', $startIdx) + 'run: |'.Length
$nextStep = $yamlText.IndexOf("`n      - name:", $runStart)
if ($nextStep -lt 0) { $nextStep = $yamlText.Length }
$body = $yamlText.Substring($runStart, $nextStep - $runStart)
$ps = (($body -split "`n") | ForEach-Object { if ($_.Length -ge 10) { $_.Substring(10) } else { $_ } }) -join "`n"
$err = $null
[System.Management.Automation.PSParser]::Tokenize($ps, [ref]$err) | Out-Null
if ($err.Count) {
    Write-Host ("STAGE PS PARSE FAIL: " + $err[0].Message)
    $err | Select -First 3 | Format-Table Type,Token,@{n='Line';e={$_.StartLine}},@{n='Msg';e={$_.Message}} -AutoSize
} else {
    Write-Host "stage PS body parses OK"
}
