#Requires -Version 5.1
<#
    THE CLASSIFIER'S CATALOG REACHES THE PROFILERS IN A CONTAINER (#137).

    Each Container Apps job runs on its own ephemeral disk, so the classifier job's catalog file vanished
    and the profiler jobs read only the image's copy. Operator ruling 2026-09-29: blob-backed catalog. The
    classifier publishes to storage; a profiler refreshes its local copy when the storage copy is newer, and
    keeps its local copy on any storage failure. No storage account = unchanged behaviour.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    # Storage is plain REST (no Az.Storage module): the SI storage wrappers the catalog code calls are what is mocked.

    . (Join-Path $script:SIRoot 'engine\_shared\SI-CatalogBlob.ps1')
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('sicat-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Force $script:Tmp | Out-Null
    $script:Local = Join-Path $script:Tmp 'privilege-tier-catalog.custom.json'
}
AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'no storage account configured -- behaviour unchanged' {
    It 'publish does nothing and returns $false; refresh reports the local copy and touches no storage' {
        Mock New-SIAzStorageContext { throw 'must not be called' }
        Set-Content -LiteralPath $script:Local -Value '{"Metadata":{}}'
        Publish-SICatalogToBlob -LocalPath $script:Local -AccountName '' | Should -BeFalse
        Update-SICatalogFromBlob -LocalPath $script:Local -AccountName '' | Should -Be 'local'
        Should -Invoke New-SIAzStorageContext -Times 0
    }
}

Describe 'publish (classifier side)' {
    It 'uploads to the sicatalog container' {
        Mock New-SIAzStorageContext { 'ctx' }
        Mock Get-SIAzStorageContainer -RemoveParameterType Context { 'exists' }
        Mock Set-SIAzStorageBlobContent -RemoveParameterType Context { }
        Set-Content -LiteralPath $script:Local -Value '{"Metadata":{}}'
        Publish-SICatalogToBlob -LocalPath $script:Local -AccountName 'acct' | Should -BeTrue
        Should -Invoke Set-SIAzStorageBlobContent -Times 1 -ParameterFilter { $Container -eq 'sicatalog' -and $Blob -eq 'privilege-tier-catalog.custom.json' }
    }
    It 'a failed upload is a warning and $false, never a throw' {
        Mock New-SIAzStorageContext { 'ctx' }
        Mock Get-SIAzStorageContainer -RemoveParameterType Context { 'exists' }
        Mock Set-SIAzStorageBlobContent -RemoveParameterType Context { throw 'AuthorizationPermissionMismatch' }
        $r = Publish-SICatalogToBlob -LocalPath $script:Local -AccountName 'acct' -WarningVariable w -WarningAction SilentlyContinue
        $r | Should -BeFalse
        "$w" | Should -Match 'could not be shared'
    }
}

Describe 'refresh (profiler side)' {
    BeforeEach {
        Set-Content -LiteralPath $script:Local -Value '{"Metadata":{"GeneratedAt":"local"}}'
        (Get-Item -LiteralPath $script:Local).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-2)
        Mock New-SIAzStorageContext { 'ctx' }
    }
    It 'a NEWER storage copy replaces the local file, and takes the storage timestamp' {
        $script:blobTime = [datetimeoffset]::UtcNow.AddMinutes(-5)
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { [pscustomobject]@{ LastModified = $script:blobTime } }
        Mock Get-SIAzStorageBlobContent -RemoveParameterType Context { Set-Content -LiteralPath $Destination -Value '{"Metadata":{"GeneratedAt":"storage"}}' }
        Update-SICatalogFromBlob -LocalPath $script:Local -AccountName 'acct' | Should -Be 'storage'
        (Get-Content -Raw -LiteralPath $script:Local | ConvertFrom-Json).Metadata.GeneratedAt | Should -Be 'storage'
        [Math]::Abs(((Get-Item -LiteralPath $script:Local).LastWriteTimeUtc - $script:blobTime.UtcDateTime).TotalSeconds) | Should -BeLessThan 2
    }
    It 'an OLDER storage copy is ignored' {
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { [pscustomobject]@{ LastModified = [datetimeoffset]::UtcNow.AddDays(-1) } }
        Mock Get-SIAzStorageBlobContent -RemoveParameterType Context { throw 'must not download' }
        Update-SICatalogFromBlob -LocalPath $script:Local -AccountName 'acct' | Should -Be 'local'
        Should -Invoke Get-SIAzStorageBlobContent -Times 0
    }
    It 'nothing published yet -> the local copy stays' {
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { $null }
        Update-SICatalogFromBlob -LocalPath $script:Local -AccountName 'acct' | Should -Be 'local'
    }
    It 'a corrupt download never replaces the local file, and says so' {
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { [pscustomobject]@{ LastModified = [datetimeoffset]::UtcNow } }
        Mock Get-SIAzStorageBlobContent -RemoveParameterType Context { Set-Content -LiteralPath $Destination -Value '{ not json' }
        $r = Update-SICatalogFromBlob -LocalPath $script:Local -AccountName 'acct' -WarningVariable w -WarningAction SilentlyContinue
        $r | Should -Be 'local'
        (Get-Content -Raw -LiteralPath $script:Local | ConvertFrom-Json).Metadata.GeneratedAt | Should -Be 'local'
        "$w" | Should -Match 'using the local copy'
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter '.catalog-*.tmp' -Force).Count | Should -Be 0
    }
}

Describe 'WIRING -- both engines call it' {
    It 'the classifier publishes right after writing its local catalog' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1')
        $src | Should -Match '(?s)Out-File -FilePath \$OutputFile.{0,600}Publish-SICatalogToBlob -LocalPath \$OutputFile'
    }
    It 'the profilers refresh from storage before reading the tenant catalog' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityCatalogTierComputer.ps1')
        $src | Should -Match '(?s)privilege-tier-catalog\.custom\.json.{0,700}Update-SICatalogFromBlob -LocalPath \$CustomPath.{0,4000}Test-Path \$CustomPath'
    }
}
