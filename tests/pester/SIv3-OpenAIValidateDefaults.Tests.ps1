#Requires -Version 7.0
<#
    setup\Validate-SIOpenAI.ps1 -- THE LAUNCHER DEFAULTS TOLERATE UNSET GLOBALS (a tester, 2026-11-15): after a service
    principal sign-in, the PUBLISHED (self-unpacking) script invoked as `& $script -SubscriptionId ...` threw at the wrapper's
    `& $__target @PSBoundParameters`: "The variable '$global:SubscriptionId' cannot be retrieved because it has not been set"
    -- the script runs under Set-StrictMode -Version Latest, and its defaults block read $global:<name> directly.

    What is kept true:
      * the script reads NO $global: variable directly (only assignments); a launcher value goes through Get-SIValidateGlobal
        (Get-Variable -Scope Global -ValueOnly -ErrorAction Ignore);
      * the defaults block under strict mode with none of the globals set: no error, the platform defaults, and the
        parameters given count;
      * the PUBLISHED script (release\Build-SISupportScripts.ps1), in a child pwsh with an app's sign-in recorded and no
        launcher global set, invoked with `&` -- and the same through `pwsh -File` of a caller script: it gets past the
        defaults (it stops at the first Azure call this test refuses), never with the strict-mode error.
    Offline: no Azure call is made (the token provider throws a marker).
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Src = [IO.Path]::Combine($script:SIRoot, 'setup', 'Validate-SIOpenAI.ps1')
    $script:Text = [IO.File]::ReadAllText($script:Src)
    $script:Names = @('SubscriptionId', 'ResourceGroupName', 'Location', 'AccountName', 'DeploymentName', 'ModelName', 'ModelVersion',
                      'Capacity', 'PublicNetworkAccess', 'WaitForAccountReady', 'DeploymentSkuOrder', 'WriteModelDumps')
    $script:StrictError = 'cannot be retrieved because it has not been set'
}

Describe 'Validate-SIOpenAI: no direct read of a global' {
    It 'every $global: in the script is an assignment; launcher values go through Get-SIValidateGlobal' {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Text, [ref]$null, [ref]$null)
        $reads = @($ast.FindAll({ param($n)
                    $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.IsGlobal -and
                    -not ($n.Parent -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Parent.Left -eq $n) }, $true) |
                ForEach-Object { '{0} (line {1})' -f $_.Extent.Text, $_.Extent.StartLineNumber })
        $reads | Should -BeNullOrEmpty -Because ($reads -join ', ')
        $script:Text | Should -Match 'Get-Variable -Scope Global -Name \$Name -ValueOnly -ErrorAction Ignore'
    }
}

Describe 'Validate-SIOpenAI: the defaults block under strict mode' {
    BeforeAll {
        $a = $script:Text.IndexOf('#region ================= LAUNCHER-SUPPLIED DEFAULTS')
        $b = $script:Text.IndexOf('#endregion', $a)
        $a | Should -BeGreaterThan 0
        $script:Region = $script:Text.Substring($a, $b - $a)
        # the launcher globals as they were, put back after each case
        $script:Saved = @{}
        foreach ($n in $script:Names) { $v = Get-Variable -Scope Global -Name $n -ErrorAction Ignore; if ($v) { $script:Saved[$n] = $v.Value } }
    }
    BeforeEach { foreach ($n in $script:Names) { Remove-Variable -Scope Global -Name $n -ErrorAction Ignore } }
    AfterAll {
        foreach ($n in $script:Names) { Remove-Variable -Scope Global -Name $n -ErrorAction Ignore }
        foreach ($k in $script:Saved.Keys) { Set-Variable -Scope Global -Name $k -Value $script:Saved[$k] }
    }
    It 'no global set + the parameters given: no error, the platform defaults' {
        $region = $script:Region
        $d = & {
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'
            $SubscriptionId = 's'; $ResourceGroupName = 'rg'; $Location = 'westeurope'; $AccountName = 'a'; $DeploymentName = 'd'
            . ([scriptblock]::Create($region))
            $ScriptDefaults
        }
        $d.SubscriptionId | Should -BeNullOrEmpty
        $d.ModelName | Should -Be 'gpt-4.1-mini'
        $d.ModelVersion | Should -Be 'latest'
        $d.Capacity | Should -Be 100
        $d.PublicNetworkAccess | Should -Be 'Enabled'
        $d.WaitForAccountReady | Should -BeTrue
        @($d.DeploymentSkuOrder) | Should -Be @('GlobalStandard')
        $d.WriteModelDumps | Should -BeTrue
    }
    It 'a launcher global that IS set still counts' {
        $global:Capacity = 25; $global:SubscriptionId = 'from-launcher'
        $region = $script:Region
        $d = & {
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'
            $SubscriptionId = ''; $ResourceGroupName = 'rg'; $Location = 'westeurope'; $AccountName = 'a'; $DeploymentName = 'd'
            . ([scriptblock]::Create($region))
            $ScriptDefaults
        }
        $d.Capacity | Should -Be 25
        $d.SubscriptionId | Should -Be 'from-launcher'
    }
    It 'a value that is neither a parameter nor a global: the plain "must be supplied" message, never the strict-mode error' {
        $region = $script:Region
        $err = $null
        try {
            & {
                Set-StrictMode -Version Latest
                $ErrorActionPreference = 'Stop'
                $SubscriptionId = 's'; $ResourceGroupName = 'rg'; $Location = 'westeurope'; $AccountName = 'a'; $DeploymentName = ''
                . ([scriptblock]::Create($region))
            }
        } catch { $err = $_.Exception.Message }
        $err | Should -Match "'DeploymentName' must be supplied"
        $err | Should -Not -Match $script:StrictError
    }
}

Describe 'Validate-SIOpenAI: the PUBLISHED script after an app sign-in' {
    BeforeAll {
        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ('si-oaivalidate-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $builder = [IO.Path]::Combine($script:SIRoot, 'release', 'Build-SISupportScripts.ps1')
        $null = @(& $builder -OutDir $script:Out -Name 'Validate-SIOpenAI' -Version '9.9.9.1' -Commit 'abcdef0123456789abcdef0123456789abcdef01' -SkipExternalParse -PassThru 6>$null 3>$null)
        $script:Published = Join-Path $script:Out 'Validate-SIOpenAI.ps1'
        # the caller: an app's sign-in recorded in this process (as after an SPN sign-in), NO launcher global, and every Azure
        # token refused with a marker -- the script must get past its defaults and stop at its first Azure call
        $script:Caller = Join-Path $script:Out 'caller.ps1'
        $callerText = @'
param([string]$Script)
$ErrorActionPreference = 'Stop'
$global:SI_AzRestState = @{ Connection = @{ Mode = 'Certificate'; AppId = '11111111-1111-1111-1111-111111111111'; TenantId = '22222222-2222-2222-2222-222222222222'; Thumbprint = 'AB' }; SubscriptionId = $null; TenantId = '22222222-2222-2222-2222-222222222222'; Cache = @{} }
$global:SI_TokenProvider = { param($Resource) throw 'SIV3-STOP-AT-FIRST-AZURE-CALL' }
try { & $Script -SubscriptionId '33333333-3333-3333-3333-333333333333' -ResourceGroupName 'rg-x' -Location 'westeurope' -AccountName 'oai-x' -DeploymentName 'chat' -ValidateOnly -SkipAccessCheck *>&1 | ForEach-Object { "$_" } }
catch { 'CAUGHT: ' + $_.Exception.Message }
'@
        [IO.File]::WriteAllText($script:Caller, $callerText)
    }
    AfterAll { if ($script:Out -and (Test-Path -LiteralPath $script:Out)) { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue } }
    It 'the published file was built' {
        Test-Path -LiteralPath $script:Published | Should -BeTrue
        [IO.File]::ReadAllText($script:Published) | Should -Match ([regex]::Escape('& $__target @PSBoundParameters'))
    }
    It 'invoked with & (in a child pwsh, through pwsh -File of the caller): past the defaults, never the strict-mode error' {
        $pwsh = (Get-Process -Id $PID).Path
        $outText = (& $pwsh -NoProfile -NonInteractive -File $script:Caller -Script $script:Published 2>&1 | ForEach-Object { "$_" }) -join "`n"
        $outText | Should -Not -Match $script:StrictError -Because $outText
        $outText | Should -Not -Match 'must be supplied by the launcher' -Because $outText
        $outText | Should -Match 'SIV3-STOP-AT-FIRST-AZURE-CALL|Selecting subscription' -Because $outText
    }
}
