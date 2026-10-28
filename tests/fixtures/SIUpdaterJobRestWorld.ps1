#Requires -Version 5.1
<#
    Install-SIUpdaterJob.ps1's FAKE AZURE over REST (#521: the script calls no az CLI) -- shared by SIv3-Updater.Tests.ps1 and
    SIv3-InvardiaUpdate.Tests.ps1.

    Dot-source it in BeforeAll, then:
        Enable-SIUpdaterJobRestWorld           defines the REST layer the script uses as GLOBAL recording fakes (the script
                                               loads setup\_shared\SI-SetupAzure / SI-SetupArm / SI-AcrBuild only when those
                                               functions are missing, so it runs against these)
        Reset-SIUpdaterJobRestWorld @{ ... }   per test: HasJob, HasUami, Legacy, FeedJob, Manual, Job (an ARM job object),
                                               EnvLocation (the Container Apps environment's location; default westeurope)
        Disable-SIUpdaterJobRestWorld          AfterAll: removes every fake
    $global:SIUJ.Calls: one entry per call -- @{ Fn; Args; Text }. Text: 'create <the create arguments>' for a new job,
    'update <name>=<value> ...' for the read-modify-write, 'role <role> <objectId> <scope>' for a role assignment made,
    'patch <path> <body json>' for an ARM PATCH, 'build <images> <dockerfile>' for the registry build.
#>

$script:SIUJFakes = @('Get-SISetupAzureContext', 'Connect-SISetupAzure', 'Get-SIContainerRegistry', 'Invoke-SIAcrRestBuild', 'Get-SIUserAssignedIdentity',
    'New-SIUserAssignedIdentity', 'Get-SIKeyVaultArm', 'Test-SIRoleAssignmentPresent', 'New-SIRoleAssignment', 'Resolve-SIPrincipalObjectId',
    'Get-SIResourceGroupArm', 'Get-SIContainerAppJob', 'Get-SIManagedEnvironment', 'New-SIContainerAppJobFromArgs', 'Update-SIContainerAppJob', 'Invoke-SIArm',
    'Get-SIKeyVaultSecretValue', 'Get-SISetupAccessToken', 'Get-SIContainerApp')

function script:Add-SIUJCall([string]$Fn, [hashtable]$A, [string]$Text) { $global:SIUJ.Calls.Add([pscustomobject]@{ Fn = $Fn; Args = $A; Text = $Text }) }

function script:Reset-SIUpdaterJobRestWorld([hashtable]$State = @{}) {
    $global:SIUJ = @{ Calls = New-Object System.Collections.Generic.List[object] }
    foreach ($k in $State.Keys) { $global:SIUJ[$k] = $State[$k] }
}

function script:Enable-SIUpdaterJobRestWorld {
    Reset-SIUpdaterJobRestWorld
    $rec = ${function:Add-SIUJCall}
    Set-Item -Path 'function:global:Add-SIUJCall' -Value $rec
    function global:Get-SISetupAzureContext { [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'admin@contoso.example'; Type = 'User' }; Subscription = [pscustomobject]@{ Id = 'sub-1' }; Tenant = [pscustomobject]@{ Id = 'ten-1' } } }
    function global:Connect-SISetupAzure { param([string]$TenantId, [string]$SubscriptionId) Add-SIUJCall 'Connect-SISetupAzure' @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId } 'connect'; Get-SISetupAzureContext }
    function global:Get-SIContainerRegistry { param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIContainerRegistry' @{ ResourceGroupName = $ResourceGroupName; Name = $Name; SubscriptionId = $SubscriptionId } "acr show $Name"
        [pscustomobject]@{ id = '/sub/acr'; name = $Name; location = 'westeurope'; loginServer = 'reg.example.io'; properties = [pscustomobject]@{ loginServer = 'reg.example.io' } } }
    function global:Invoke-SIAcrRestBuild { param([string]$SubscriptionId, [string]$ResourceGroup, [string]$RegistryName, [string]$SourcePath, [string[]]$ImageNames, [string]$DockerFilePath, $OnPoll)
        Add-SIUJCall 'Invoke-SIAcrRestBuild' @{ SubscriptionId = $SubscriptionId; RegistryName = $RegistryName; SourcePath = $SourcePath; ImageNames = $ImageNames; DockerFilePath = $DockerFilePath } ('build {0} {1}' -f ($ImageNames -join ','), $DockerFilePath)
        [pscustomobject]@{ Ok = (-not $global:SIUJ.BuildFails); Status = $(if ($global:SIUJ.BuildFails) { 'Failed' } else { 'Succeeded' }); RunId = 'run-1' } }
    function global:Get-SIUserAssignedIdentity { [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIUserAssignedIdentity' @{ Name = $Name; SubscriptionId = $SubscriptionId } "identity show $Name"
        if ($global:SIUJ.HasUami) { return [pscustomobject]@{ Id = '/sub/uami'; Name = $Name; PrincipalId = 'pid'; ClientId = '0c1d2e3f-1111-4222-8333-0000000c1d00' } }
        $null }
    function global:New-SIUserAssignedIdentity { param([string]$ResourceGroupName, [string]$Name, [string]$Location, [string]$SubscriptionId)
        Add-SIUJCall 'New-SIUserAssignedIdentity' @{ Name = $Name; Location = $Location; SubscriptionId = $SubscriptionId } "identity create $Name"
        [pscustomobject]@{ Id = '/sub/uami'; Name = $Name; PrincipalId = 'pid'; ClientId = '0c1d2e3f-1111-4222-8333-0000000c1d00' } }
    function global:Get-SIKeyVaultArm { param([string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIKeyVaultArm' @{ Name = $Name; SubscriptionId = $SubscriptionId } "keyvault show $Name"
        [pscustomobject]@{ id = '/sub/kv'; name = $Name; properties = [pscustomobject]@{ vaultUri = 'https://kv.vault.azure.net/' } } }
    function global:Test-SIRoleAssignmentPresent { param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName) $false }
    function global:New-SIRoleAssignment { param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName, [string]$PrincipalType)
        Add-SIUJCall 'New-SIRoleAssignment' @{ ObjectId = $ObjectId; Scope = $Scope; Role = $RoleDefinitionName } ('role {0} {1} {2}' -f $RoleDefinitionName, $ObjectId, $Scope) }
    function global:Resolve-SIPrincipalObjectId { param([string]$Id) Add-SIUJCall 'Resolve-SIPrincipalObjectId' @{ Id = $Id } "principal $Id"; "oid-of-$Id" }
    function global:Get-SIResourceGroupArm { param([string]$Name, [string]$SubscriptionId) Add-SIUJCall 'Get-SIResourceGroupArm' @{ Name = $Name } "group show $Name"; [pscustomobject]@{ id = '/sub/rg' } }
    function global:Get-SIManagedEnvironment { param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIManagedEnvironment' @{ Name = $Name } "env show $Name"
        [pscustomobject]@{ id = "/subscriptions/sub-1/resourceGroups/$ResourceGroupName/providers/Microsoft.App/managedEnvironments/$Name"; location = $(if ($global:SIUJ.EnvLocation) { [string]$global:SIUJ.EnvLocation } else { 'westeurope' }) } }
    function global:Get-SIContainerAppJob { param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIContainerAppJob' @{ Name = $Name; SubscriptionId = $SubscriptionId } "job show $Name"
        $s = $global:SIUJ
        if ($s.Job) { return $s.Job }
        if (-not $s.HasJob) { return $null }
        $j = if ($s.Legacy) {   # an updater installed before 3.0.0: GitHub token env + secret
                 @{ name = 'caj-si-updater'; id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'
                    properties = @{ configuration = @{ triggerType = 'Schedule'; secrets = @(@{ name = 'cert-pfx' }, @{ name = 'gh-token' }) }
                                    template = @{ containers = @(@{ env = @(@{ name = 'SI_UPDATER_GITHUB_TOKEN'; secretRef = 'gh-token' },
                                                                           @{ name = 'SI_UPDATER_REPO'; value = 'x' }, @{ name = 'SI_UPDATER_SOURCE_REF'; value = 'si-v3' },
                                                                           @{ name = 'SI_UPDATER_ACR'; value = 'acr' }) }) } } }
             } elseif ($s.FeedJob) {   # ring 1 before the switch to Invardia: the feed link env + secret
                 @{ name = 'caj-si-updater'; id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'
                    properties = @{ configuration = @{ triggerType = 'Schedule'; secrets = @(@{ name = 'src-url' }) }
                                    template = @{ containers = @(@{ env = @(@{ name = 'SI_UPDATER_SOURCE_URL'; secretRef = 'src-url' }, @{ name = 'SI_UPDATER_SOURCE'; value = 'feed' }) }) } } }
             } elseif ($s.Manual) {   # #393: an earlier switch to the pipeline turned the updater to manual
                 @{ name = 'caj-si-updater'; id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'
                    tags = @{ 'si-disabled-cron' = '0 3 * * *'; 'si-installed' = '3.0.0-rc.343' }
                    properties = @{ configuration = @{ triggerType = 'Manual'; replicaTimeout = 3600; manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } } } }
             } else { @{ name = 'caj-si-updater'; id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-updater'; properties = @{ configuration = @{ triggerType = 'Schedule' } } } }
        ($j | ConvertTo-Json -Depth 12) | ConvertFrom-Json }
    function global:New-SIContainerAppJobFromArgs { param([object[]]$CreateArgs, [string]$Location, [string]$EnvironmentId, [string]$SubscriptionId)
        Add-SIUJCall 'New-SIContainerAppJobFromArgs' @{ CreateArgs = $CreateArgs; Location = $Location; EnvironmentId = $EnvironmentId; SubscriptionId = $SubscriptionId } ('create ' + (@($CreateArgs | ForEach-Object { "$_" }) -join ' ')) }
    function global:Update-SIContainerAppJob { param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId, [string]$Image, [string]$Cron, [string]$Cpu, [string]$Memory,
                                                     [object[]]$SetEnv = @(), [string[]]$RemoveEnv = @(), [object[]]$SetSecrets = @(), [string[]]$RemoveSecrets = @(), [object[]]$Tags = @())
        $t = 'update name={0} sub={1} cron={2} image={3} setenv={4} removeenv={5} setsecrets={6} removesecrets={7}' -f $Name, $SubscriptionId, $Cron, $Image,
             (@($SetEnv) -join ','), (@($RemoveEnv) -join ','), (@($SetSecrets) -join ','), (@($RemoveSecrets) -join ',')
        Add-SIUJCall 'Update-SIContainerAppJob' @{ Name = $Name; SubscriptionId = $SubscriptionId; Image = $Image; Cron = $Cron; Cpu = $Cpu; Memory = $Memory; SetEnv = @($SetEnv); RemoveEnv = @($RemoveEnv); SetSecrets = @($SetSecrets); RemoveSecrets = @($RemoveSecrets); Tags = @($Tags) } $t }
    function global:Invoke-SIArm { param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$List, [switch]$AllowNotFound)
        Add-SIUJCall 'Invoke-SIArm' @{ Method = $Method; Path = $Path; ApiVersion = $ApiVersion; Body = $Body } ('{0} {1}?api-version={2} {3}' -f $Method.ToLowerInvariant(), $Path, $ApiVersion, $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 20 -Compress } else { '' }))
        # the secret hand-over: the role assignments listed at the vault (State.Assignments)
        if ($List -and $Path -like '*/providers/Microsoft.Authorization/roleAssignments*' -and $global:SIUJ.Assignments) { return @($global:SIUJ.Assignments) } }
    # the Pro web app (State.WebApp: an ARM container app with its identity), $null by default
    function global:Get-SIContainerApp { param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
        Add-SIUJCall 'Get-SIContainerApp' @{ Name = $Name } "app show $Name"
        if ($global:SIUJ.WebApp) { return (($global:SIUJ.WebApp | ConvertTo-Json -Depth 12) | ConvertFrom-Json) }
        $null }
    function global:Get-SIKeyVaultSecretValue { param([string]$VaultName, [string]$Name) Add-SIUJCall 'Get-SIKeyVaultSecretValue' @{ VaultName = $VaultName; Name = $Name } "secret read $Name"; 'x' }
    function global:Get-SISetupAccessToken { param([string]$Resource) Add-SIUJCall 'Get-SISetupAccessToken' @{ Resource = $Resource } "token $Resource"; 'tok' }
    # An ALIAS wins over a function of the same name in ANY scope -- so the fakes answer even where a suite (or something it
    # loads) has the real REST layer in scope. Each fake is published as SIUJFake_<name> and aliased under its real name.
    # The fake is read from the GLOBAL scope by name (${function:global:<name>}), never by Get-Command: a suite that has the
    # real REST layer loaded in its own scope (SIv3-Updater: Start-SIUpdater -DefineOnly loads SI-UpdateRest -> SI-AzRest,
    # which defines the real Invoke-SIArm / Get-SIKeyVaultSecretValue) would otherwise hand back the REAL function, and the
    # alias would point at a real sign-in.
    foreach ($f in $script:SIUJFakes) {
        $fake = $ExecutionContext.InvokeCommand.InvokeScript(('${{function:global:{0}}}' -f $f))[0]
        if (-not ($fake -is [scriptblock])) { throw "the fake $f is not defined in the global scope" }
        Set-Item -Path ("function:global:SIUJFake_{0}" -f $f) -Value $fake
        Set-Alias -Name $f -Value ("SIUJFake_{0}" -f $f) -Scope Global -Force
    }
}

function script:Disable-SIUpdaterJobRestWorld {
    foreach ($f in $script:SIUJFakes) {
        Remove-Item -Path ("alias:{0}" -f $f) -Force -ErrorAction SilentlyContinue
        Remove-Item -Path ("function:SIUJFake_{0}" -f $f) -ErrorAction SilentlyContinue
        # An unqualified function: path removes the NEAREST function of that name (a scope-qualified one does not resolve).
        # When the suite has the real REST layer in its own scope, that nearest one is the REAL function and the GLOBAL fake
        # stayed behind: a later suite in the same process then saw a global Invoke-SIArm, skipped loading SI-AzRest.ps1
        # ("loaded already") and lost New-SIAzStorageContext (SIv3-ContainerParity, gate 2026-10-11). Remove until the
        # global fake is gone.
        for ($i = 0; $i -lt 8; $i++) {
            $g = $ExecutionContext.InvokeCommand.InvokeScript(('${{function:global:{0}}}' -f $f))[0]
            if (-not ($g -is [scriptblock])) { break }
            Remove-Item -Path ("function:{0}" -f $f) -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Path 'function:Add-SIUJCall' -ErrorAction SilentlyContinue
    Remove-Variable -Scope Global -Name SIUJ -ErrorAction SilentlyContinue
}
