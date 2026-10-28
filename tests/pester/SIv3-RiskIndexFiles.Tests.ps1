#Requires -Version 5.1
<#
    #398 -- THE RISK INDEX FOLLOWS THE LOCKED + CUSTOM MODEL, WHATEVER THE UPGRADE PATH.

    Until 3.0 the SHIPPED index was called riskscore.index.custom.csv: the signed update kept 2.2's file (it never touches
    *.custom.*), a git pull brought 3.0's, the internal sync overwrote customer edits. What must hold now (PS 5.1 + 7):
      - the shipped index is riskscore.index.locked.csv; the custom name is never shipped (only a *.custom.sample.*);
      - an unchanged copy of any index SecurityInsight shipped under the custom name (whatever its line endings or BOM)
        is removed on the next Risk Analysis run, and the locked file takes over;
      - an edited one is kept as the customer's own rows, read BEFORE the shipped rows, and the run log says so once;
      - the shipped-version list is exactly the versions in git history (when git is available).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexFiles.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    $script:Fx = Join-Path $script:SIRoot 'tests\fixtures\riskindex'
    $script:V22File = Join-Path $script:Fx 'riskscore.index.v22.csv'
    $script:LockedFile = Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'
    function script:New-Folder([string]$Name) { $d = Join-Path $TestDrive $Name; New-Item -ItemType Directory -Force -Path $d | Out-Null; Copy-Item -LiteralPath $script:LockedFile -Destination $d; $d }
    function script:Write-Variant([string]$Path, [string]$Text, [bool]$Crlf, [bool]$Bom) {
        $t = $Text.Replace("`r`n", "`n"); if ($Crlf) { $t = $t.Replace("`n", "`r`n") }
        [System.IO.File]::WriteAllText($Path, $t, (New-Object System.Text.UTF8Encoding($Bom)))
    }
}

Describe 'what ships' {
    It 'the shipped index is riskscore.index.locked.csv and a sample shows the customer''s own rows; the custom name is never shipped' {
        Test-Path -LiteralPath $script:LockedFile | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.custom.sample.csv') | Should -BeTrue
        $tracked = @(& git -C $script:SIRoot ls-files -- risk-analysis-detection 2>$null)
        if ($tracked.Count) {
            $tracked | Should -Contain 'risk-analysis-detection/riskscore.index.locked.csv'
            $tracked | Should -Not -Contain 'risk-analysis-detection/riskscore.index.custom.csv'
        }
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot '.gitignore')) | Should -Match '(?m)^risk-analysis-detection/riskscore\.index\.custom\.csv\s*$'
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot '.dockerignore')) | Should -Not -Match '(?m)^!risk-analysis-detection/riskscore\.index\.custom\.csv'
    }
    It 'the sample is a valid overlay: the index columns (#559: the SI keys), with a Precedence' {
        $s = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.custom.sample.csv'))
        $s.Count | Should -BeGreaterThan 0
        @($s[0].PSObject.Properties.Name) | Should -Be @(@(Import-Csv -LiteralPath $script:LockedFile)[0].PSObject.Properties.Name)
    }
    It 'the shipped-version list is every version of the custom-named index in git history -- no more, no fewer' {
        # Windows PowerShell 5.1 under the gate's ErrorActionPreference Stop turns git's stderr into a terminating error,
        # 2>$null or not -- and rev-parse of the commit that DELETED the file says "fatal: path ... does not exist" (that
        # commit is skipped by the exit-code check below). git's stderr is never an error here.
        $ErrorActionPreference = 'Continue'
        $blobs = New-Object System.Collections.Generic.List[string]
        foreach ($ref in 'origin/main', 'origin/si-v3', 'HEAD') {
            foreach ($c in @(& git -C $script:SIRoot log --format=%H $ref -- 'risk-analysis-detection/riskscore.index.custom.csv' 2>$null)) {
                $b = (& git -C $script:SIRoot rev-parse "${c}:SOLUTIONS/SecurityInsight/risk-analysis-detection/riskscore.index.custom.csv" 2>$null)
                if ($LASTEXITCODE -eq 0 -and $b -and -not $blobs.Contains($b)) { $blobs.Add($b) }
            }
        }
        if (-not $blobs.Count) { Set-ItResult -Skipped -Because 'no git history here (a published copy)'; return }
        $hashes = @(foreach ($b in $blobs) {
            $tmp = Join-Path $TestDrive ("$b.csv")
            $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]((& git -C $script:SIRoot cat-file blob $b) -join "`n") + "`n")
            [System.IO.File]::WriteAllBytes($tmp, $bytes)
            Get-SIRiskIndexFileHash -Path $tmp
        })
        # #559: plus the last 3.0 locked index with the 2.2 columns (the shipped index is SI-keyed since): a copy of it under
        # the custom name is not an edit either
        $last22 = $null
        foreach ($c in @(& git -C $script:SIRoot log --format=%H HEAD -- 'risk-analysis-detection/riskscore.index.locked.csv' 2>$null)) {
            $b = (& git -C $script:SIRoot rev-parse "${c}:SOLUTIONS/SecurityInsight/risk-analysis-detection/riskscore.index.locked.csv" 2>$null)
            if ($LASTEXITCODE -ne 0 -or -not $b) { continue }
            $first = @(& git -C $script:SIRoot cat-file blob $b)[0]
            if ([string]$first -like 'SecurityDomain,*') { $last22 = $b; break }
        }
        if ($last22) {
            $tmp = Join-Path $TestDrive ("$last22.csv")
            [System.IO.File]::WriteAllBytes($tmp, [System.Text.Encoding]::UTF8.GetBytes([string]((& git -C $script:SIRoot cat-file blob $last22) -join "`n") + "`n"))
            $hashes = @($hashes) + @(Get-SIRiskIndexFileHash -Path $tmp)
        }
        @($hashes | Sort-Object -Unique) | Should -Be @($script:SIRiskIndexShippedCustomHashes | Sort-Object -Unique)
    }
    It 'the 2.2 fixture (2.2.0 - 2.2.461) is in the list; the corrected locked index is not a shipped custom copy' {
        Test-SIRiskIndexShippedCopy -Path $script:V22File | Should -BeTrue
        # the locked index changed after the copy ring 1 received (scid-2001 / scid-2000 Very High >= High, owner 2026-10-10): the copies
        # installs hold stay in the list (an untouched one is still recognised); the corrected locked file is not one of them
        Test-SIRiskIndexShippedCopy -Path $script:LockedFile | Should -BeFalse
        # #559: the 3.0 index with the 2.2 columns (kept as a fixture) is a shipped copy -- an unchanged copy of it is removed
        Test-SIRiskIndexShippedCopy -Path (Join-Path $script:Fx 'riskscore.index.v30-v22keys.csv') | Should -BeTrue
    }
}

Describe 'the migration on the first Risk Analysis run after any upgrade' {
    It 'an unchanged 2.2 index under the custom name is removed, in every line-ending / BOM form a path can leave it in' -ForEach @(
        @{ Crlf = $false; Bom = $false }, @{ Crlf = $true; Bom = $false }, @{ Crlf = $true; Bom = $true }, @{ Crlf = $false; Bom = $true }
    ) {
        $d = New-Folder ("m-{0}-{1}" -f $Crlf, $Bom)
        Write-Variant (Join-Path $d 'riskscore.index.custom.csv') ([System.IO.File]::ReadAllText($script:V22File)) $Crlf $Bom
        $r = Resolve-SIRiskIndexFiles -Folder $d
        $r.Action | Should -Be 'removed-unedited'
        $r.CustomPath | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $d 'riskscore.index.custom.csv') | Should -BeFalse
        $r.LockedPath | Should -Be (Join-Path $d 'riskscore.index.locked.csv')
        ($r.Lines -join ' ') | Should -Match 'unchanged risk index of an earlier version'
        # the next run: nothing left to say
        (Resolve-SIRiskIndexFiles -Folder $d).Action | Should -Be 'none'
    }
    It 'an unchanged copy that cannot be deleted (a read-only tree) is ignored, and the run says how to stop the line' {
        $d = New-Folder 'ro'
        Copy-Item -LiteralPath $script:V22File -Destination (Join-Path $d 'riskscore.index.custom.csv')
        $r = Resolve-SIRiskIndexFiles -Folder $d -NoRemove
        $r.Action | Should -Be 'ignored-unedited'
        $r.CustomPath | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $d 'riskscore.index.custom.csv') | Should -BeTrue
        ($r.Lines -join ' ') | Should -Match 'delete riskscore\.index\.custom\.csv'
    }
    It 'an EDITED index is kept as the customer''s own rows, never removed, and the run log says so ONCE' {
        $d = New-Folder 'edited'
        $p = Join-Path $d 'riskscore.index.custom.csv'
        [System.IO.File]::WriteAllText($p, ([System.IO.File]::ReadAllText($script:V22File) -replace ',4,', ',5,'))
        $marker = Join-Path $TestDrive 'logs\state\riskindex-custom-noticed.txt'
        $r = Resolve-SIRiskIndexFiles -Folder $d -NoticeMarker $marker
        $r.Action | Should -Be 'overlay'
        $r.CustomPath | Should -Be $p
        Test-Path -LiteralPath $p | Should -BeTrue
        ($r.Lines -join ' ') | Should -Match 'read FIRST'
        Test-Path -LiteralPath $marker | Should -BeTrue
        $again = Resolve-SIRiskIndexFiles -Folder $d -NoticeMarker $marker
        $again.Action | Should -Be 'overlay'
        @($again.Lines).Count | Should -Be 0 -Because 'said once'
    }
    It 'NEGATIVE: one changed character makes it the customer''s file -- it is never deleted' {
        $d = New-Folder 'onechar'
        $p = Join-Path $d 'riskscore.index.custom.csv'
        [System.IO.File]::WriteAllText($p, ([System.IO.File]::ReadAllText($script:V22File) + ' '))
        (Resolve-SIRiskIndexFiles -Folder $d).Action | Should -Be 'overlay'
        Test-Path -LiteralPath $p | Should -BeTrue
    }
    It 'no custom file: the shipped index only' {
        $d = New-Folder 'none'
        $r = Resolve-SIRiskIndexFiles -Folder $d
        $r.Action | Should -Be 'none'; $r.CustomPath | Should -BeNullOrEmpty; @($r.Lines).Count | Should -Be 0
    }
}

Describe 'scoring: the customer''s rows first, then the shipped index' {
    BeforeAll {
        function script:Write-Info { param($m) }
        function script:Write-Warn2 { param($m) }
        function script:Write-Ok { param($m) }
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        $script:IdxArgs = @{ ColSecurityDomain = 'SecurityDomain'; ColCategory = 'Category'; ColSubCategory = 'SubCategory'; ColConfigId = 'ConfigurationId'; ColSevValue = 'SecuritySeverity'
                             ColTierValue = 'CriticalityTierLevel'; ColConseqScore = 'RiskConsequenceScore_SecuritySeverity'; ColProbScore = 'RiskProbablityScore_CriticialityTierLevel' }
        $script:Locked = @(Import-Csv -LiteralPath $script:LockedFile)
        $script:Findings = @(
            [pscustomobject]@{ SecurityDomain = 'Endpoint'; Category = 'Security controls'; Subcategory = 'EDR'; ConfigurationName = 'mine'; ConfigurationId = 'scid-2002'; SecuritySeverity = 'Very High'; CriticalityTierLevel = 'Critical - tier 0'; AssetName = 'h1' }
            [pscustomobject]@{ SecurityDomain = 'Endpoint'; Category = 'Security controls'; Subcategory = 'Antivirus'; ConfigurationName = 'shipped'; ConfigurationId = 'scid-2014'; SecuritySeverity = 'High'; CriticalityTierLevel = 'Critical - tier 0'; AssetName = 'h2' }
        )
        function script:Calc($idx) {
            $ProgressPreference = 'SilentlyContinue'
            @(Calculate-RiskScore -Rows $script:Findings -RiskIndex $idx -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'T_Detailed') |
                ForEach-Object { '{0}|{1}|{2}' -f $_.ConfigurationName, $_.RiskConsequenceScore, $_.RiskProbabilityScore }
            # #559: RiskConsequenceScore = the asset side, RiskProbabilityScore = the vulnerability side (no factor: the bases)
        }
    }
    It 'the shipped sample''s two rows set the scores of the finding they fit; every other finding scores as the shipped index alone' {
        $plain = @(Calc (New-RiskIndex -CsvRows $script:Locked @script:IdxArgs))
        $sample = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.custom.sample.csv'))
        $idx = New-RiskIndex -CsvRows $script:Locked -OverlayRows $sample @script:IdxArgs
        $idx.OverlayRowCount | Should -Be $sample.Count
        $idx.OrderedRowCount | Should -Be ($sample.Count + $script:Locked.Count)
        $idx.OverlayForm | Should -Be 'si'
        $with = @(Calc $idx)
        $with[0] | Should -Be 'mine|5|5'
        $with[0] | Should -Not -Be $plain[0]
        $with[1] | Should -Be $plain[1]
    }
    It 'a whole edited 2.2 index as the customer''s rows scores exactly as that index did in 2.2 for every finding it fits' {
        $v22 = @(Import-Csv -LiteralPath $script:V22File)
        $idx = New-RiskIndex -CsvRows $script:Locked -OverlayRows $v22 @script:IdxArgs
        $idx.OverlayForm | Should -Be 'v2.2'
        @(Calc $idx) | Should -Be @(Calc (New-RiskIndex -CsvRows $v22 @script:IdxArgs))
    }
    It 'no customer rows: the index is the shipped index, as before' {
        $a = New-RiskIndex -CsvRows $script:Locked @script:IdxArgs
        $a.OverlayRowCount | Should -Be 0
        $a.OverlayForm | Should -Be ''
        $a.OrderedRowCount | Should -Be $script:Locked.Count
    }
    It 'customer rows missing a column are refused with the file named' {
        $bad = @([pscustomobject]@{ SecurityDomain = 'Endpoint'; Category = 'x' })
        { New-RiskIndex -CsvRows $script:Locked -OverlayRows $bad @script:IdxArgs } | Should -Throw '*riskscore.index.custom.csv*'
    }
}

Describe 'WIRING' {
    BeforeAll { $script:Ra = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }
    It 'Risk Analysis reads the locked index, resolves the customer''s file (migrating an unchanged copy) and lays it over -- except for the Pro index' {
        ([regex]::Matches($script:Ra, [regex]::Escape('$global:RiskDefinitionsCsvPath = (Join-Path $global:SettingsPath "riskscore.index.locked.csv")'))).Count | Should -Be 2
        $script:Ra | Should -Not -Match ([regex]::Escape('(Join-Path $global:SettingsPath "riskscore.index.custom.csv")'))
        $script:Ra | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-RiskIndexFiles.ps1')"))
        $res = $script:Ra.IndexOf('$__ri = Resolve-SIRiskIndexFiles -Folder (Split-Path -Parent $global:RiskDefinitionsCsvPath)')
        $res | Should -BeGreaterThan 0
        $res | Should -BeLessThan $script:Ra.IndexOf('$global:RiskIndex = New-RiskIndex')
        $script:Ra | Should -Match ([regex]::Escape('-OverlayRows             $global:RiskDefinitionsOverlay'))
        $script:Ra | Should -Match ([regex]::Escape('if (-not $__riPro) {'))
    }
    It 'the container jobs receive the customer''s rows through the customisation share' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerRunState.ps1')
        Test-SIOverlayPath -RelativePath 'risk-analysis-detection/riskscore.index.custom.csv' | Should -BeTrue
        Test-SIOverlayPath -RelativePath 'risk-analysis-detection/riskscore.index.custom.sample.csv' | Should -BeFalse
        Test-SIOverlayPath -RelativePath 'risk-analysis-detection/riskscore.index.locked.csv' | Should -BeFalse
    }
}
