#Requires -Version 5.1
<#
    NO REPORT MAY READ A DELETED PROFILE COLUMN OFF A PROFILE TABLE.

    🔴 WHY THIS EXISTS. On 2026-08-28 the legacy `AssetName` / `AssetId` columns were removed from all
    four profile schemas -- one name for one thing. The catalog was NOT automatically consistent with
    that: **144 sites across the 126 report entries still read the deleted column directly inside a
    `SI_*_Profile_CL` block** (identity 121, endpoint 13, azure 10). Found only because the operator
    asked *"is all 122 reports fixed for references"*.

    🪤 AND DELETING A COLUMN THE CATALOG READS DOES NOT ERROR. Every read is wrapped in
    `column_ifexists`, so a missing column returns `""` and the query keeps running. The worst case was
    `EpJoinKey`, which fell through to `PrimaryEntityId` on every row -- it still joins, still returns
    rows, and nothing anywhere looks wrong. Silent degradation, not a failure.

    🔑 THE DISTINCTION THIS TEST ENCODES, because a blind search-and-replace destroys it. These two
    lines are textually near-identical and are NOT the same column:

        | extend AssetName = case(isnotempty(column_ifexists("AssetName","")), ...)
              ^ inside a hunting / ExposureGraph pipeline -- that row's OWN column, still exists, leave it

        | extend EpJoinKey = case(isnotempty(column_ifexists("AssetName","")), ...)
              ^ inside a SI_*_Profile_CL let -- the DELETED column, must read SI_AssetName first

    So the rule is contextual: an `AssetName`/`AssetId` read is only a defect when the nearest preceding
    source is a profile table. That is what is asserted, and it is why this cannot be a plain grep.

    📌 THE LEGACY READ IS DELIBERATELY KEPT AS THE TRAILING FALLBACK. A v2.2-era table still carries the
    old column and a v3 table does not; `column_ifexists` tolerates either. Requiring SI_ to come FIRST
    -- rather than requiring the legacy name to be gone -- is what makes the catalog safe to ship while
    customers are mid-migration.

    #505 -- the reports read their assets from the CI (SI_CI_CL; si_asset_name / si_ci_id) instead of the profile
    tables, so the contextual guard has no profile block left to look in (it stays, for a custom report); the
    "SI_ reads present" control is re-pointed at the CI fields, and the legacy-fallback test is retired.
#>

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Catalog   = Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # Returns every line that reads a deleted profile column while inside a profile-table block.
    function script:Get-ProfileTableLegacyReads {
        $lines = Get-Content $script:Catalog
        $hits  = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            if ($l -notmatch 'column_ifexists\("Asset(Name|Id)"') { continue }
            if ($l -match 'SI_Asset') { continue }        # already prefers the surviving column
            # Walk back to the nearest SOURCE. A non-profile source (hunting / EG / Defender tables) or
            # a report boundary means this read belongs to that shape, not to a profile table.
            $src = $null
            for ($j = $i; $j -ge [Math]::Max(0, $i - 60); $j--) {
                if ($lines[$j] -match '(SI_\w+_Profile_CL)')  { $src = $Matches[1]; break }
                if ($lines[$j] -match '^\s+- ReportName:')     { break }
                if ($lines[$j] -match '(ExposureGraph|DeviceTvmSoftware|DeviceInfo|DeviceLogonEvents|IdentityInfo|SecurityRecommendation)') { break }
            }
            if ($src) { [void]$hits.Add([pscustomobject]@{ Line = $i + 1; Table = $src; Text = $l.Trim() }) }
        }
        # 🪤 RETURN THE ArrayList ITSELF, never `,$hits.ToArray()`. With ZERO hits that comma yields an
        # array CONTAINING an empty array, so the caller's @(...) counts 1 and this guard fails on a
        # clean catalog. It did exactly that on first run -- the same PS 5.1 wrapper trap the guard is
        # here to protect against.
        $hits
    }
}

Describe 'the report catalog reads the surviving asset columns' {

    It 'no site reads a DELETED profile column inside a profile-table block' {
        $bad = script:Get-ProfileTableLegacyReads
        $detail = ($bad | Select-Object -First 5 | ForEach-Object { '{0} [{1}] {2}' -f $_.Line, $_.Table, $_.Text }) -join "`n"
        $bad.Count | Should -Be 0 -Because "these read a column that no longer exists and fail SILENTLY to `"`":`n$detail"
    }

    It 'the asset reads are actually present -- the guard must not pass by finding nothing' {
        # 🪤 Without this, a catalog that lost every asset read entirely would satisfy the test above.
        # A guard that cannot distinguish "fixed" from "empty" is not a guard.
        # #505 -- the reports read the asset from the CI (SI_CI_CL): its name is si_asset_name and its id si_ci_id
        # (was SI_AssetName / SI_AssetId off the profile tables). Counted OUTSIDE the canonical CI blocks, so the
        # block's own projection cannot satisfy it.
        $raw = Get-Content $script:Catalog -Raw
        $outside = [regex]::Replace($raw, '(?s)//__SI_CI_(LINK|ASSET)_BEGIN__.*?//__SI_CI_\1_END__', '')
        @([regex]::Matches($outside, '(?m)\bAssetName\s*=[^\r\n]*\bsi_asset_name\b')).Count | Should -BeGreaterThan 50
        @([regex]::Matches($outside, '(?m)\bAssetId\s*=[^\r\n]*\bsi_ci_id\b')).Count         | Should -BeGreaterThan 100
    }

    It 'no report reads a profile table at all -- the CI replaced them, so there is no legacy fallback left to keep' {
        # #505 -- retired: "the legacy read SURVIVES as a fallback". It protected customers whose PROFILE tables a v3 run
        # had not rewritten yet; the reports no longer read a profile table (SI_CI_CL is written by v3 only).
        $raw = Get-Content $script:Catalog -Raw
        $code = [regex]::Replace([regex]::Replace($raw, '"[^"\r\n]*"', '""'), '//[^\r\n]*', '')
        $code | Should -Not -Match 'SI_[A-Za-z]+_Profile_CL'
        ([regex]::Matches($code, '\bSI_CI_CL\b')).Count | Should -BeGreaterThan 100 -Because 'the reports read the CI (control)'
    }

    It 'the pipeline-row reads were NOT rewritten -- they are a different column' {
        # The ~60 reads that belong to a hunting/ExposureGraph shape must still be there. If a future
        # sweep "fixes" them too, those reports lose their own AssetName and nothing errors.
        $lines = Get-Content $script:Catalog
        $pipelineReads = 0
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]
            if ($l -notmatch 'column_ifexists\("Asset(Name|Id)"') { continue }
            $isProfile = $false
            for ($j = $i; $j -ge [Math]::Max(0, $i - 60); $j--) {
                if ($lines[$j] -match 'SI_\w+_Profile_CL') { $isProfile = $true; break }
                if ($lines[$j] -match '^\s+- ReportName:')  { break }
                if ($lines[$j] -match '(ExposureGraph|DeviceTvmSoftware|DeviceInfo|DeviceLogonEvents|IdentityInfo|SecurityRecommendation)') { break }
            }
            if (-not $isProfile) { $pipelineReads++ }
        }
        $pipelineReads | Should -BeGreaterThan 20 -Because 'the hunting/EG shapes carry their own AssetName and must keep reading it'
    }
}
