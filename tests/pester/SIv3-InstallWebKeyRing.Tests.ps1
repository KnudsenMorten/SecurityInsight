#Requires -Version 5.1
<#
    #1098 -- THE INSTALL MAKES THE WEB APP'S SIGN-IN KEY AND ITS GRANT (found live on two fresh installs, one public, one
    private: step 4e got HTTP 403 making SI-Web-KeyRing with the installer's temporary Secrets Officer only; the updater then
    made the key but may not give roles, so the install stayed "grant-missing" until support made the grant by hand).
    OFFLINE (fake ARM / Key Vault / install seams, stubs in SCRIPT scope):
      * the installer gets a temporary Key Vault Crypto Officer (own mark) and it is removed at the end, read back;
      * 4e makes the key and the web identity's grant on THAT key, and reads both back;
      * the setting DataProtection__KeyVaultKeyId is then set, as the updater sets it;
      * a 403 on the grant is a customer task (role, key, identity) -- never a stop, nothing set;
      * a private install whose vault data plane is unreachable still gets the grant when the key exists (ARM).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-WebKeyRing.ps1')
    $script:VaultId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-si'
    $script:KeyUrl = 'https://kv-si.vault.azure.net/keys/SI-Web-KeyRing'

    function script:Invoke-KrRun {
        param([int]$DataPlane = 404, [int]$ArmKey = 404, [int]$ArmKeyCreate = 200, [int]$GrantStatus = 201, [bool]$GrantListed = $true,
              [string]$Current = '', [switch]$CheckOnly, [string]$IdentityName = 'id-si-web', [switch]$PreGranted)
        $calls = New-Object System.Collections.Generic.List[string]
        $st = @{ DpMade = $false; ArmMade = $false; Granted = (New-Object System.Collections.Generic.List[object]) }
        if ($PreGranted) { $pg = [pscustomobject]@{ properties = [pscustomobject]@{ principalId = 'p-web'; roleDefinitionId = '/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/e147488a-f6f5-4113-8e2d-b22465e65bf6' } }; $st.Granted.Add($pg) }
        $kv = {
            param($m, $u, $b) $calls.Add("KV $m $u")
            if ($DataPlane -ne 404 -and $DataPlane -ne 200) { return [pscustomobject]@{ Status = $DataPlane; Json = $null } }
            if ($m -eq 'POST') { $st.DpMade = $true; return [pscustomobject]@{ Status = 200; Json = [pscustomobject]@{ key = @{ kid = 'k' } } } }
            if ($DataPlane -eq 200 -or $st.DpMade) { return [pscustomobject]@{ Status = 200; Json = [pscustomobject]@{ key = @{ kid = 'k' } } } }
            [pscustomobject]@{ Status = 404; Json = $null }
        }.GetNewClosure()
        $arm = {
            param($m, $p, $api, $b) $calls.Add("ARM $m $p")
            if ($p -like '*/keys/SI-Web-KeyRing' -and $m -eq 'GET') {
                if ($st.ArmMade -or $ArmKey -eq 200) { return [pscustomobject]@{ Status = 200; Json = [pscustomobject]@{ name = 'SI-Web-KeyRing'; properties = [pscustomobject]@{ kty = 'RSA' } } } }
                return [pscustomobject]@{ Status = $ArmKey; Json = $null }
            }
            if ($p -like '*/keys/SI-Web-KeyRing' -and $m -eq 'PUT') { if ($ArmKeyCreate -eq 200) { $st.ArmMade = $true }; return [pscustomobject]@{ Status = $ArmKeyCreate; Json = $null } }
            if ($m -eq 'GET' -and $p -like '*/roleAssignments*') { $vals = [object[]]$st.Granted.ToArray(); $lj = [pscustomobject]@{ value = $vals }; return [pscustomobject]@{ Status = 200; Json = $lj } }
            if ($m -eq 'GET') { return [pscustomobject]@{ Status = 200; Json = [pscustomobject]@{ properties = [pscustomobject]@{ enableRbacAuthorization = $true } } } }
            if ($m -eq 'PUT' -and $p -like '*/roleAssignments/*') {
                if ($GrantListed -and ($GrantStatus -eq 409 -or ($GrantStatus -ge 200 -and $GrantStatus -lt 300))) {
                    $gp = [pscustomobject]@{ principalId = [string]$b['properties']['principalId']; roleDefinitionId = [string]$b['properties']['roleDefinitionId'] }
                    $ga = [pscustomobject]@{ properties = $gp }
                    $st.Granted.Add($ga)
                }
                return [pscustomobject]@{ Status = $GrantStatus; Json = $null }
            }
            [pscustomobject]@{ Status = 500; Json = $null }
        }.GetNewClosure()
        $set = { param($n, $v) $calls.Add("SET $n=$v"); $true }.GetNewClosure()
        $r = Invoke-SIWebKeyRingConverge -Arm $arm -KeyVault $kv -SetEnv $set -VaultName 'kv-si' -VaultId $script:VaultId -PrincipalIds @('p-web') `
                -SubscriptionId 's' -CurrentEnv $Current -CheckGrantOnly:$CheckOnly -IdentityName $IdentityName
        [pscustomobject]@{ R = $r; Calls = @($calls) }
    }
}

Describe '#1098: the installer''s temporary Key Vault Crypto Officer' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        function script:New-CryptoCtx([hashtable]$Facts, [string]$Description = '', [switch]$StaysAssigned) {
            $w = @{ Calls = (New-Object System.Collections.Generic.List[string]); Printed = (New-Object System.Collections.Generic.List[string]); Assigned = @{ 'Key Vault Crypto Officer' = $true } }
            $az = {
                param([string]$Command, $Arguments)
                $role = [string]$Arguments['RoleDefinitionName']
                $w.Calls.Add(('{0} {1}' -f $Command, $role))
                switch ($Command) {
                    'Remove-SIRoleAssignment' { if (-not $StaysAssigned) { $w.Assigned[$role] = $false }; return $null }
                    'Get-SIAzRoleAssignment' { if ($w.Assigned[$role]) { return [pscustomobject]@{ Scope = $Arguments['Scope']; RoleDefinitionName = $role; RoleAssignmentId = '/ra/c'; Description = $Description } }; return $null }
                    default { throw "unexpected $Command" }
                }
            }.GetNewClosure()
            $ctx = @{ Facts = $Facts; Log = (New-Object System.Collections.Generic.List[object]); ScriptLog = (New-Object System.Collections.Generic.List[object])
                      Seams = @{ Az = $az; Print = { param($Text, $Color) $w.Printed.Add("$Color|$Text") }.GetNewClosure() } }
            [pscustomobject]@{ Ctx = $ctx; W = $w }
        }
        $script:Kv = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-si'
    }
    It 'WIRING: the key-vault step gives it, with its own mark, next to the Secrets Officer, and never stops on it' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
        $t | Should -Match ([regex]::Escape("-Command 'New-SIAzRoleAssignment' -Arguments ([ordered]@{ ObjectId = `$oid; Scope = `$kvId; RoleDefinitionName = 'Key Vault Crypto Officer'; Description = `$script:SIInstallKvCryptoOfficerMark; ErrorAction = 'Stop' })"))
        $t | Should -Match ([regex]::Escape("`$ctx.Facts['kvCryptoOfficerGrantedAt'] = (& `$ctx.Seams.Now).ToString('o')"))
        $t | Should -Match '(?s)RoleDefinitionName = ''Key Vault Secrets Officer''; Description = \$script:SIInstallKvOfficerMark.{0,1500}RoleDefinitionName = ''Key Vault Crypto Officer''; Description' -Because 'given in the same step, after the Secrets Officer'
        $script:SIInstallKvCryptoOfficerMark | Should -Not -Be $script:SIInstallKvOfficerMark
    }
    It 'given by THIS install: removed at the end, read back, the fact cleared' {
        $k = New-CryptoCtx @{ kvCryptoOfficerGrantedAt = '2026-11-04T10:00:00Z'; userObjectId = 'oid-installer'; keyVaultId = $script:Kv }
        Complete-SIInstallKvOfficer -Ctx $k.Ctx | Should -BeNullOrEmpty
        @($k.W.Calls | Where-Object { $_ -eq 'Remove-SIRoleAssignment Key Vault Crypto Officer' }).Count | Should -Be 1
        @($k.W.Calls | Where-Object { $_ -eq 'Get-SIAzRoleAssignment Key Vault Crypto Officer' }).Count | Should -Be 2 -Because 'found, then read back'
        $k.Ctx.Facts['kvCryptoOfficerGrantedAt'] | Should -BeNullOrEmpty
        ($k.W.Printed -join "`n") | Should -Match 'Key Vault Crypto Officer" on the install''s Key Vault, given for the web app''s sign-in key, was removed again \(read back\)'
    }
    It 'the record lost: found by its mark and removed; a Crypto Officer the person held already is never touched' {
        $k = New-CryptoCtx @{ userObjectId = 'oid-installer'; keyVaultId = $script:Kv } -Description $script:SIInstallKvCryptoOfficerMark
        Complete-SIInstallKvOfficer -Ctx $k.Ctx | Should -BeNullOrEmpty
        @($k.W.Calls | Where-Object { $_ -eq 'Remove-SIRoleAssignment Key Vault Crypto Officer' }).Count | Should -Be 1
        $k2 = New-CryptoCtx @{ userObjectId = 'oid-installer'; keyVaultId = $script:Kv }
        Complete-SIInstallKvOfficer -Ctx $k2.Ctx | Should -BeNullOrEmpty
        @($k2.W.Calls | Where-Object { $_ -like 'Remove-SIRoleAssignment *' }).Count | Should -Be 0
    }
    It 'NEGATIVE: one that does not read back gone is a warning, and the fact stays for the next run' {
        $k = New-CryptoCtx @{ kvCryptoOfficerGrantedAt = '2026-11-04T10:00:00Z'; userObjectId = 'oid-installer'; keyVaultId = $script:Kv } -StaysAssigned
        Complete-SIInstallKvOfficer -Ctx $k.Ctx | Should -Match 'still assigned'
        $k.Ctx.Facts['kvCryptoOfficerGrantedAt'] | Should -Not -BeNullOrEmpty
    }
}

Describe '#1098: step 4e makes the key and the grant, reads both back, then sets the setting' {
    It 'the key is made and read back, the grant is made on THAT key and read back, then the setting' {
        $x = Invoke-KrRun
        $x.R.Ok | Should -BeTrue
        $x.Calls[0] | Should -Match '^KV GET '
        $x.Calls[1] | Should -Match '^KV POST https://kv-si\.vault\.azure\.net/keys/SI-Web-KeyRing/create'
        $x.Calls[2] | Should -Match '^KV GET https://kv-si\.vault\.azure\.net/keys/SI-Web-KeyRing\?' -Because 'the key reads back'
        @($x.Calls | Where-Object { $_ -like 'ARM PUT */keys/SI-Web-KeyRing/providers/Microsoft.Authorization/roleAssignments/*' }).Count | Should -Be 1
        $iPut = [array]::IndexOf($x.Calls, @($x.Calls | Where-Object { $_ -like 'ARM PUT */roleAssignments/*' })[0])
        $iRead = [array]::IndexOf($x.Calls, @($x.Calls | Where-Object { $_ -like 'ARM GET */keys/SI-Web-KeyRing/providers/Microsoft.Authorization/roleAssignments?*' })[0])
        $iSet = [array]::IndexOf($x.Calls, @($x.Calls | Where-Object { $_ -like 'SET *' })[0])
        $iPut | Should -BeLessThan $iRead
        $iRead | Should -BeLessThan $iSet -Because 'the setting only after the grant reads back'
        ($x.R.Lines -join ' ') | Should -Match 'reads back'
        ($x.R.Lines -join ' ') | Should -Match 'that key only; read back'
    }
    It 'the setting is the one the updater sets (DataProtection__KeyVaultKeyId = the versionless key id), so the updater''s first run has nothing left' {
        $x = Invoke-KrRun
        @($x.Calls | Where-Object { $_ -like 'SET *' }) | Should -Be @("SET DataProtection__KeyVaultKeyId=$script:KeyUrl")
        # the updater's run after it: key there, grant listed, setting equal -> nothing changed, nothing to report
        $u = Invoke-KrRun -DataPlane 200 -CheckOnly -Current $script:KeyUrl -PreGranted
        $u.R.Ok | Should -BeTrue
        @($u.R.CustomerAction).Count | Should -Be 0
        @($u.R.Report).Count | Should -Be 0
        @($u.Calls | Where-Object { $_ -like 'SET *' -or $_ -like 'ARM PUT*' -or $_ -like 'KV POST*' }).Count | Should -Be 0
    }
    It 'NEGATIVE: a grant that does not read back sets nothing and is said' {
        $x = Invoke-KrRun -GrantListed $false
        $x.R.Ok | Should -BeFalse
        @($x.Calls | Where-Object { $_ -like 'SET *' }).Count | Should -Be 0
        ($x.R.Report -join ' ') | Should -Match 'did not read back'
    }
    It 'WIRING: Deploy-SIManagement 4e runs the ONE converge with the identity''s name, and reads ARM''s "HTTP Status: 403" as 403' {
        $d = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\deploy\Deploy-SIManagement.ps1'))
        $d | Should -Match 'Invoke-SIWebKeyRingConverge -Arm \$armSeam -KeyVault \$kvSeam -SetEnv'
        $d | Should -Match '-CurrentEnv \$curKr -IdentityName \$IdentityName'
        $d | Should -Match ([regex]::Escape("-match 'HTTP(?: Status:)? (\d{3})'"))
        $d | Should -Match 'WebKeyRingTasks = '
        'Azure Resource Manager PUT https://management.azure.com/x failed. HTTP Status: 403 (Forbidden) Response: {}' -match 'HTTP(?: Status:)? (\d{3})' | Should -BeTrue
        $Matches[1] | Should -Be '403'
        @([regex]::Matches($d, 'function Invoke-SIWebKeyRingConverge')).Count | Should -Be 0 -Because 'never a second implementation'
    }
}

Describe '#1098: a refused role write on the key is a customer task, never a stop' {
    It '403 / 401: a task naming the role, the key and the identity; nothing set; no failure report' {
        foreach ($s in 403, 401) {
            $x = Invoke-KrRun -GrantStatus $s
            $x.R.Ok | Should -BeFalse
            @($x.R.Report).Count | Should -Be 0
            @($x.Calls | Where-Object { $_ -like 'SET *' }).Count | Should -Be 0
            $t = $x.R.CustomerAction -join ' '
            $t | Should -Match 'CUSTOMER TASK \(not known'
            $t | Should -Match '"Key Vault Crypto Service Encryption User"'
            $t | Should -Match ([regex]::Escape("$script:VaultId/keys/SI-Web-KeyRing"))
            $t | Should -Match 'id-si-web \(object id p-web\)'
            $t | Should -Match ("HTTP {0}" -f $s)
        }
    }
    It 'WIRING: the guided install''s web-app step shows the task as a warning (the install goes on)' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1'))
        $g | Should -Match ([regex]::Escape("PSObject.Properties['WebKeyRingTasks']"))
        $g | Should -Match '(?s)if \(\$keyRingTasks\.Count\) \{\s+return \(New-SIInstallResult -State ''warning'''
    }
}

Describe '#1098: a private install whose Key Vault data plane is unreachable' {
    It 'the key exists: read through ARM, the grant (ARM) is made and read back, the setting set' {
        foreach ($dp in 0, 403) {
            $x = Invoke-KrRun -DataPlane $dp -ArmKey 200
            $x.R.Ok | Should -BeTrue
            @($x.Calls | Where-Object { $_ -like 'ARM GET */keys/SI-Web-KeyRing' }).Count | Should -Be 1
            @($x.Calls | Where-Object { $_ -like 'ARM PUT */keys/SI-Web-KeyRing' }).Count | Should -Be 0 -Because 'an existing key is never made again'
            @($x.Calls | Where-Object { $_ -like 'ARM PUT */roleAssignments/*' }).Count | Should -Be 1
            @($x.Calls | Where-Object { $_ -like 'SET *' }).Count | Should -Be 1
            ($x.R.Lines -join ' ') | Should -Match ("read through Azure Resource Manager; the vault's data plane answered HTTP {0}" -f $dp)
        }
    }
    It 'the key is missing: made through ARM (wrap / unwrap only, not exportable) and read back, then the grant' {
        $x = Invoke-KrRun -DataPlane 0 -ArmKey 404
        $x.R.Ok | Should -BeTrue
        @($x.Calls | Where-Object { $_ -like 'ARM PUT */keys/SI-Web-KeyRing' }).Count | Should -Be 1
        @($x.Calls | Where-Object { $_ -like 'ARM GET */keys/SI-Web-KeyRing' }).Count | Should -Be 2 -Because 'looked for, then read back'
        @($x.Calls | Where-Object { $_ -like 'ARM PUT */roleAssignments/*' }).Count | Should -Be 1
        $b = Get-SIWebKeyRingArmCreateBody
        $b.properties.kty | Should -Be 'RSA'; $b.properties.keySize | Should -Be 3072
        @($b.properties.keyOps) | Should -Be @('wrapKey', 'unwrapKey')
        $b.properties.attributes.exportable | Should -BeFalse
    }
    It 'NEGATIVE: neither plane can make or read it -- said plainly, left to the updater, no grant tried, nothing set' {
        $x = Invoke-KrRun -DataPlane 0 -ArmKey 404 -ArmKeyCreate 403
        $x.R.Ok | Should -BeFalse
        @($x.Calls | Where-Object { $_ -like '*roleAssignments*' -or $_ -like 'SET *' }).Count | Should -Be 0
        ($x.R.Report -join ' ') | Should -Match 'could not be made or read from this machine -- the Key Vault answered HTTP 0 \(a private Key Vault answers only inside its network\)'
        ($x.R.Report -join ' ') | Should -Match 'the updater, inside the network, makes the key on its next run'
    }
    It 'THE UPDATER is unchanged: it never goes to ARM for the key and never gives a role' {
        $x = Invoke-KrRun -DataPlane 0 -ArmKey 200 -CheckOnly
        @($x.Calls | Where-Object { $_ -like 'ARM * */keys/SI-Web-KeyRing' -or $_ -like 'ARM PUT*' }).Count | Should -Be 0
        $x.R.Ok | Should -BeFalse
    }
}
