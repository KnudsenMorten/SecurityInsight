#Requires -Version 5.1
<#
    #55.1 -- the container host writes a run transcript, and it survives the replica.

    BACKGROUND. Start-SILauncherTranscript has been default-on since v2.2.312 and its ValidateSet has
    always declared a 'container' flavour -- but nothing ever passed it. All 15 callers were VM
    launchers, so the host recommended for LARGE tenants was the only host that kept no forensic record
    of a run. A container filesystem is ephemeral, so even the stdout that did exist died with the
    replica once the execution aged out.

    Two halves are asserted here:
      (a) the three container entrypoints actually start a transcript, with -Flavour container
      (b) the transcript is published to the staging blob container, because on this host a file on
          local disk is not a record of anything

    ASCII ONLY, DELIBERATELY. These test files are not guaranteed to carry a BOM, and PowerShell 5.1
    then decodes them as Windows-1252: a 4-byte emoji becomes 4 Latin-1 characters, several of which
    the parser treats as string delimiters (0x92 -> right single quote, 0x94 -> right double quote).
    An emoji inside a test name closes the name early and the rest of the file parses as garbage --
    and pwsh 7 parses the same file cleanly because it defaults to UTF-8, so it only fails under
    Pester on 5.1. Cost a real detour in v2.2.436; do not reintroduce it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'launcher\_lib\Publish-LauncherTranscript.ps1')

    $script:ContainerDir = Join-Path $script:SIRoot 'container'

    function New-MockCtx {
        [pscustomobject]@{
            Mode        = 'Mock'
            AccountName = '<mock>'
            AccountKey  = $null
            AzContext   = $null
            MockState   = @{ Tables = @{}; Blobs = @{}; Queues = @{} }
        }
    }

    function New-TempTranscript {
        param([string]$Content = 'transcript body')
        $p = Join-Path ([System.IO.Path]::GetTempPath()) ('si-runlog-test-{0}.log' -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $p -Value $Content -Encoding ASCII
        return $p
    }
}

Describe '55.1(a) the container entrypoints start a transcript' {

    # These three assertions are the whole of 55.1. If any container entrypoint loses its
    # Start-SILauncherTranscript call, that host silently goes back to keeping no record -- which is
    # exactly the failure that went unnoticed from v2.2.312 until it was measured.
    It '<_> starts a transcript with -Flavour container' -ForEach @(
        'Start-SIInContainer.ps1', 'Start-RiskAnalysisInContainer.ps1', 'Invoke-ShardProducer.ps1'
    ) {
        $src = Get-Content -LiteralPath (Join-Path $script:ContainerDir $_) -Raw
        $src | Should -Match 'Start-SILauncherTranscript'
        $src | Should -Match '-Flavour\s+container'
    }

    It '<_> publishes the transcript before it exits' -ForEach @(
        'Start-SIInContainer.ps1', 'Start-RiskAnalysisInContainer.ps1', 'Invoke-ShardProducer.ps1'
    ) {
        $src = Get-Content -LiteralPath (Join-Path $script:ContainerDir $_) -Raw
        $src | Should -Match 'Publish-SILauncherTranscript'
    }

    It '<_> dot-sources both helpers -- a call without the dot-source is a runtime NRE, not a warning' -ForEach @(
        'Start-SIInContainer.ps1', 'Start-RiskAnalysisInContainer.ps1', 'Invoke-ShardProducer.ps1'
    ) {
        $src = Get-Content -LiteralPath (Join-Path $script:ContainerDir $_) -Raw
        $src | Should -Match 'launcher/_lib/Start-LauncherTranscript\.ps1'
        $src | Should -Match 'launcher/_lib/Publish-LauncherTranscript\.ps1'
    }

    It 'the RA entrypoint captures the exit code before publishing, and exits with it' {
        # Publish-SILauncherTranscript runs commands, so $LASTEXITCODE is no longer the engine's by the
        # time `exit` is reached. Publishing a log must never change what the Container App Job reports.
        $src = Get-Content -LiteralPath (Join-Path $script:ContainerDir 'Start-RiskAnalysisInContainer.ps1') -Raw
        $src | Should -Match '\$raExit\s*=\s*\$LASTEXITCODE'
        $src | Should -Match 'exit\s+\$raExit'
    }

    It 'the classifier branch captures its exit code before publishing, and exits with it' {
        $src = Get-Content -LiteralPath (Join-Path $script:ContainerDir 'Start-SIInContainer.ps1') -Raw
        $src | Should -Match '\$clsExit\s*=\s*\$LASTEXITCODE'
        $src | Should -Match 'exit\s+\$clsExit'
    }

    It 'the producer/ra DISPATCH branches do not start a transcript of their own' {
        # They hand off to a child pwsh that starts its own. Starting one here too would write two
        # files for one run, the outer a duplicate of the inner.
        $src   = Get-Content -LiteralPath (Join-Path $script:ContainerDir 'Start-SIInContainer.ps1') -Raw
        $upTo  = $src.IndexOf("'worker'")
        $upTo  | Should -BeGreaterThan 0
        $head  = $src.Substring(0, $upTo)
        $head  | Should -Not -Match 'Start-SILauncherTranscript'
    }
}

Describe 'Get-SIRunLogBlobName -- the layout a person has to browse' {

    # NOTE: no angle brackets in an It name. Pester expands `<word>` in a test title as a -ForEach
    # template placeholder even when there is no -ForEach, and the expansion is parsed as PowerShell --
    # so a name describing the path layout literally failed to parse. Cost one red test here.
    It 'is prefix / engine / the original file name' {
        Get-SIRunLogBlobName -FileName 'endpoint_container_20260813T101500Z.log' -Engine 'endpoint' |
            Should -BeExactly 'run-logs/endpoint/endpoint_container_20260813T101500Z.log'
    }

    It 'lower-cases the engine so one engine cannot occupy two folders' {
        Get-SIRunLogBlobName -FileName 'a.log' -Engine 'Endpoint' | Should -BeExactly 'run-logs/endpoint/a.log'
    }

    It 'keeps the hyphen in a role-qualified engine -- producer logs must not merge with worker logs' {
        Get-SIRunLogBlobName -FileName 'a.log' -Engine 'endpoint-producer' |
            Should -BeExactly 'run-logs/endpoint-producer/a.log'
    }

    It 'files an unnamed engine under "unknown" rather than at the prefix root' {
        # A blob at 'run-logs/a.log' would sit outside every per-engine listing an operator runs.
        Get-SIRunLogBlobName -FileName 'a.log'            | Should -BeExactly 'run-logs/unknown/a.log'
        Get-SIRunLogBlobName -FileName 'a.log' -Engine '' | Should -BeExactly 'run-logs/unknown/a.log'
    }

    It 'strips path-bearing characters out of the engine segment' {
        # An engine name is env-supplied. '../' in a blob name is a placement bug waiting to happen.
        Get-SIRunLogBlobName -FileName 'a.log' -Engine '../../etc' | Should -BeExactly 'run-logs/etc/a.log'
    }

    It 'tolerates a prefix given with slashes' {
        Get-SIRunLogBlobName -FileName 'a.log' -Engine 'x' -Prefix '/logs/' | Should -BeExactly 'logs/x/a.log'
    }
}

Describe 'Get-SIExpiredRunLogBlob -- the retention decision, as a function a test can run' {

    BeforeAll {
        $script:Cutoff = [datetime]::new(2026, 8, 1, 0, 0, 0, [DateTimeKind]::Utc)
        function Blob { param($Name, $Modified) [pscustomobject]@{ Name = $Name; LastModified = $Modified } }
    }

    It 'deletes what is older than the cutoff' {
        $r = Get-SIExpiredRunLogBlob -Blobs @(Blob 'old.log' ([datetime]::new(2026,7,1,0,0,0,[DateTimeKind]::Utc))) -Cutoff $script:Cutoff
        @($r) | Should -Be @('old.log')
    }

    It 'keeps what is newer than the cutoff' {
        $r = Get-SIExpiredRunLogBlob -Blobs @(Blob 'new.log' ([datetime]::new(2026,8,12,0,0,0,[DateTimeKind]::Utc))) -Cutoff $script:Cutoff
        @($r).Count | Should -Be 0
    }

    It 'KEEPS a blob whose age it cannot read' {
        # The negative case, and the one that matters: deleting on missing metadata destroys a record
        # because we could not determine its age, which inverts what retention is for.
        $r = Get-SIExpiredRunLogBlob -Blobs @(Blob 'nodate.log' $null) -Cutoff $script:Cutoff
        @($r).Count | Should -Be 0
    }

    It 'KEEPS a blob whose LastModified is unparseable' {
        $r = Get-SIExpiredRunLogBlob -Blobs @(Blob 'bad.log' 'not-a-date') -Cutoff $script:Cutoff
        @($r).Count | Should -Be 0
    }

    It 'survives an empty or null listing without throwing' {
        { Get-SIExpiredRunLogBlob -Blobs @()   -Cutoff $script:Cutoff } | Should -Not -Throw
        { Get-SIExpiredRunLogBlob -Blobs $null -Cutoff $script:Cutoff } | Should -Not -Throw
        { Get-SIExpiredRunLogBlob -Blobs @($null) -Cutoff $script:Cutoff } | Should -Not -Throw
    }

    It 'picks only the expired ones out of a mixed listing' {
        $blobs = @(
            (Blob 'a.log' ([datetime]::new(2026,6,1,0,0,0,[DateTimeKind]::Utc)))
            (Blob 'b.log' ([datetime]::new(2026,8,9,0,0,0,[DateTimeKind]::Utc)))
            (Blob 'c.log' ([datetime]::new(2026,5,1,0,0,0,[DateTimeKind]::Utc)))
        )
        $r = @(Get-SIExpiredRunLogBlob -Blobs $blobs -Cutoff $script:Cutoff)
        $r.Count | Should -Be 2
        $r | Should -Contain 'a.log'
        $r | Should -Contain 'c.log'
    }
}

Describe '55.1(b) Publish-SILauncherTranscript' {

    BeforeEach {
        Remove-Variable -Name SI_DisableTranscript -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name SI_TranscriptPath    -Scope Global -ErrorAction SilentlyContinue
    }

    It 'uploads the transcript content under the run-log name' {
        $p   = New-TempTranscript -Content 'RUN COMPLETE'
        $ctx = New-MockCtx
        try {
            $blob = Publish-SILauncherTranscript -Path $p -Context $ctx -Engine 'endpoint'
            $blob | Should -BeExactly ('run-logs/endpoint/{0}' -f (Split-Path -Leaf $p))
            $ctx.MockState.Blobs['sistaging'][$blob] | Should -Match 'RUN COMPLETE'
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    It 'closes an open transcript BEFORE reading it -- otherwise the tail is missing' {
        # Start-Transcript buffers. Uploading while it is still open ships a file without the last
        # lines, which on a failed run are the only lines anyone wants.
        Mock Stop-Transcript { }
        $p = New-TempTranscript
        $global:SI_TranscriptPath = $p
        try {
            Publish-SILauncherTranscript -Path $p -Context (New-MockCtx) -Engine 'endpoint' | Out-Null
            Should -Invoke Stop-Transcript -Times 1 -Exactly
            $global:SI_TranscriptPath | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    It 'does not touch the transcript state when publishing some OTHER file' {
        Mock Stop-Transcript { }
        $mine  = New-TempTranscript
        $other = New-TempTranscript
        $global:SI_TranscriptPath = $mine
        try {
            Publish-SILauncherTranscript -Path $other -Context (New-MockCtx) -Engine 'endpoint' | Out-Null
            Should -Invoke Stop-Transcript -Times 0 -Exactly
            $global:SI_TranscriptPath | Should -BeExactly $mine
        } finally {
            Remove-Item -LiteralPath $mine  -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $other -Force -ErrorAction SilentlyContinue
        }
    }

    It 'falls back to $global:SI_TranscriptPath when no -Path is given' {
        Mock Stop-Transcript { }
        $p   = New-TempTranscript -Content 'from the global'
        $ctx = New-MockCtx
        $global:SI_TranscriptPath = $p
        try {
            $blob = Publish-SILauncherTranscript -Context $ctx -Engine 'identity'
            $blob | Should -Not -BeNullOrEmpty
            $ctx.MockState.Blobs['sistaging'][$blob] | Should -Match 'from the global'
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    It 'honours $global:SI_DisableTranscript and writes nothing' {
        $p   = New-TempTranscript
        $ctx = New-MockCtx
        $global:SI_DisableTranscript = $true
        try {
            Publish-SILauncherTranscript -Path $p -Context $ctx -Engine 'endpoint' | Should -BeNullOrEmpty
            $ctx.MockState.Blobs.Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    # The three negative cases below are one requirement stated three ways: an explanatory artifact
    # must never be able to fail the run that produced it. A collection run's value is its inventory;
    # trading that for a log file is the wrong way round.
    It 'returns null without throwing when the transcript file is gone' {
        $ctx = New-MockCtx
        $missing = Join-Path ([System.IO.Path]::GetTempPath()) ('si-absent-{0}.log' -f ([guid]::NewGuid().ToString('N')))
        { Publish-SILauncherTranscript -Path $missing -Context $ctx -Engine 'endpoint' -WarningAction SilentlyContinue } |
            Should -Not -Throw
        Publish-SILauncherTranscript -Path $missing -Context $ctx -Engine 'endpoint' -WarningAction SilentlyContinue |
            Should -BeNullOrEmpty
    }

    It 'returns null without throwing when no storage context is available' {
        $p = New-TempTranscript
        try {
            { Publish-SILauncherTranscript -Path $p -Context $null -Engine 'endpoint' -WarningAction SilentlyContinue } |
                Should -Not -Throw
            Publish-SILauncherTranscript -Path $p -Context $null -Engine 'endpoint' -WarningAction SilentlyContinue |
                Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    It 'returns null quietly when no transcript was ever started' {
        # Start-SILauncherTranscript already warned about whatever went wrong. A second warning here
        # would train the operator to ignore the line.
        Publish-SILauncherTranscript -Context (New-MockCtx) -Engine 'endpoint' | Should -BeNullOrEmpty
    }
}

Describe 'the orchestrator build context can still contain what the entrypoints need' {

    # WHY THIS TEST EXISTS. #55's code only takes effect once si-orchestrator is rebuilt, and the two
    # helpers it dot-sources (/app/launcher/_lib/*) have to survive into the image. That made the
    # build context worth checking rather than assuming -- and it is currently broken.
    #
    # BOTH images build from the SAME context, the solution root: container/Sync-ContainerModules.ps1
    # uses `Split-Path -Parent $PSScriptRoot`, and analyzer-web/deploy/Deploy-SIAnalyzer.ps1 passes
    # $siRoot. One context means ONE .dockerignore, and the one that is there was written for SIA:
    # `*` followed by an allowlist of analyzer-web + analyzer/seed. Under those rules the orchestrator's
    # `COPY . /app/` copies neither the engine, nor the launcher, nor its own ENTRYPOINT script.
    #
    # It has not bitten yet only because si-orchestrator has not been rebuilt since 2026-08-07. This
    # test states the requirement so the next person sees it as a failing assertion rather than as a
    # container that exits immediately with a file-not-found.

    BeforeAll {
        function Test-SIDockerContextIncludes {
            <#
                Minimal .dockerignore evaluator: last matching pattern wins, '!' re-includes, and a
                path is excluded when any ANCESTOR directory is excluded (which is how a bare '*'
                removes the whole tree). Enough to answer "would this file be uploaded?", which is
                the only question here.
            #>
            param([string[]]$Patterns, [string]$Path)

            $segments = $Path -split '/'
            $probes = @()
            for ($i = 0; $i -lt $segments.Count; $i++) { $probes += ($segments[0..$i] -join '/') }

            $included = $true
            foreach ($raw in $Patterns) {
                $line = $raw.Trim()
                if (-not $line -or $line.StartsWith('#')) { continue }
                $negate = $line.StartsWith('!')
                if ($negate) { $line = $line.Substring(1).Trim() }
                $line = $line.TrimEnd('/')
                if (-not $line) { continue }

                # glob -> regex. '**' spans separators, '*' and '?' do not.
                $rx = [regex]::Escape($line) -replace '\\\*\\\*', '<<GLOBSTAR>>' `
                                             -replace '\\\*', '[^/]*' `
                                             -replace '\\\?', '[^/]'
                $rx = $rx -replace '<<GLOBSTAR>>', '.*'
                $rx = '^' + $rx + '$'

                foreach ($probe in $probes) {
                    # No ternary -- this suite runs on Windows PowerShell 5.1.
                    if ($probe -match $rx) {
                        if ($negate) { $included = $true } else { $included = $false }
                    }
                }
            }
            return $included
        }

        $script:IgnorePath = Join-Path $script:SIRoot '.dockerignore'
        $script:IgnoreLines = if (Test-Path -LiteralPath $script:IgnorePath) {
            @(Get-Content -LiteralPath $script:IgnorePath)
        } else { @() }
    }

    It 'the evaluator agrees with the rules it is reading (self-check)' {
        # Guards the guard: if this drifts, the assertions below stop meaning anything.
        Test-SIDockerContextIncludes -Patterns @('*', '!keep')      -Path 'keep/file.txt' | Should -BeTrue
        Test-SIDockerContextIncludes -Patterns @('*', '!keep')      -Path 'drop/file.txt' | Should -BeFalse
        Test-SIDockerContextIncludes -Patterns @('**/*.custom.ps1') -Path 'config/a.custom.ps1' | Should -BeFalse
        Test-SIDockerContextIncludes -Patterns @()                  -Path 'container/x.ps1' | Should -BeTrue
    }

    It '<_> reaches the orchestrator image' -ForEach @(
        'container/Start-SIInContainer.ps1'
        'container/Start-RiskAnalysisInContainer.ps1'
        'container/Invoke-ShardProducer.ps1'
        'launcher/_lib/Start-LauncherTranscript.ps1'
        'launcher/_lib/Publish-LauncherTranscript.ps1'
        'engine/asset-profiling/Invoke-SIEngineRun.ps1'
        'engine/asset-profiling/storage/StorageContext.ps1'
        'engine/risk-analysis/Invoke-RiskAnalysis.ps1'
    ) {
        if ($script:IgnoreLines.Count -eq 0) { Set-ItResult -Skipped -Because 'no .dockerignore in the build context'; return }
        Test-SIDockerContextIncludes -Patterns $script:IgnoreLines -Path $_ |
            Should -BeTrue -Because ("container/Dockerfile does `COPY . /app/` from the solution root, so '$_' " +
                                     'must survive .dockerignore or the image is built without it')
    }

    It 'customer config is still kept out of the upload' {
        # The SIA rule this file was written for, and it must survive whatever fixes the above.
        if ($script:IgnoreLines.Count -eq 0) { Set-ItResult -Skipped -Because 'no .dockerignore in the build context'; return }
        Test-SIDockerContextIncludes -Patterns $script:IgnoreLines -Path 'config/SecurityInsight.custom.ps1' |
            Should -BeFalse -Because 'customer secrets must never be uploaded to the ACR build service'
    }
}

Describe 'New-SIRunLogStorageContext -- never throws, never prompts' {

    It 'returns null when the storage account is not configured' {
        $keep = $env:SI_STORAGE_ACCOUNT
        $prev = $global:SI_StorageAccount
        try {
            $env:SI_STORAGE_ACCOUNT = ''
            Remove-Variable -Name SI_StorageAccount -Scope Global -ErrorAction SilentlyContinue
            New-SIRunLogStorageContext -StorageContextScript 'C:\does\not\exist.ps1' | Should -BeNullOrEmpty
        } finally {
            $env:SI_STORAGE_ACCOUNT  = $keep
            $global:SI_StorageAccount = $prev
        }
    }

    It 'does not throw when StorageContext.ps1 is not on this host' {
        # The VM launchers share this folder; only the container has /app.
        { New-SIRunLogStorageContext -StorageContextScript 'C:\does\not\exist.ps1' } | Should -Not -Throw
    }
}
