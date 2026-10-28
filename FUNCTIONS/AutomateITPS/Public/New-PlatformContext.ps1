function New-PlatformContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$SettingsPath,

        [string]$CorrelationId = [guid]::NewGuid().ToString('N').Substring(0,8),

        [ValidateSet('Auto','VM','HybridWorker','AzureFunction','LogicApp','Dev')]
        [string]$HostKind = 'Auto',

        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$KeyVaultName,
        [string]$StorageAccountName,
        [string]$SmtpServer,
        [string]$SmtpFrom,
        [string]$TeamsWebhookSecret,

        [ValidateSet('Auto','KeyVault','Local','None')]
        [string]$SecretProvider = 'Auto',

        [ValidateSet('Auto','AzureTable','LocalJson','None')]
        [string]$StateProvider = 'Auto'
    )

    $resolvedHost = if ($HostKind -eq 'Auto') { Get-HostEnvironment } else { $HostKind }

    $isDomainJoined = [bool]($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME)

    $onPremAD = switch ($resolvedHost) {
        'VM'            { $isDomainJoined }
        'HybridWorker'  { $true }
        'Dev'           { $isDomainJoined }
        default         { $false }
    }

    if ($SecretProvider -eq 'Auto') {
        $SecretProvider = if ($resolvedHost -eq 'Dev') { 'Local' } else { 'KeyVault' }
    }
    if ($StateProvider -eq 'Auto') {
        $StateProvider = if ($resolvedHost -eq 'Dev') { 'LocalJson' } else { 'AzureTable' }
    }

    [pscustomobject]@{
        Schema        = 'AutomateIT.Context/1'
        CorrelationId = $CorrelationId
        StartedUtc    = [datetime]::UtcNow
        SettingsPath  = $SettingsPath

        Host = [pscustomobject]@{
            Kind           = $resolvedHost
            ComputerName   = $env:COMPUTERNAME
            UserName       = $env:USERNAME
            IsDomainJoined = $isDomainJoined
            PSVersion      = $PSVersionTable.PSVersion.ToString()
        }

        Capabilities = [pscustomobject]@{
            OnPremAD = $onPremAD
            GraphAPI = $true
            AzureRM  = $true
            Exchange = $true
        }

        Tenant = [pscustomobject]@{
            Id                 = $TenantId
            SubscriptionId     = $SubscriptionId
            KeyVaultName       = $KeyVaultName
            StorageAccountName = $StorageAccountName
            SmtpServer         = $SmtpServer
            SmtpFrom           = $SmtpFrom
            TeamsWebhookSecret = $TeamsWebhookSecret
        }

        Identity = [pscustomobject]@{
            Modern = [pscustomobject]@{
                Azure              = [pscustomobject]@{ AppId = $null; Thumbprint = $null; Secret = $null }
                O365               = [pscustomobject]@{ AppId = $null; Thumbprint = $null; Secret = $null }
                ResourceOnBoarding = [pscustomobject]@{ AppId = $null; Thumbprint = $null; Secret = $null }
                LogIngestionDCR    = [pscustomobject]@{ AppId = $null; Thumbprint = $null; Secret = $null }
            }
            Legacy = [pscustomobject]@{
                Internal = [pscustomobject]@{ Prod = $null; Dev = $null; Test = $null }
                DMZ      = [pscustomobject]@{ Prod = $null; Dev = $null; Test = $null }
                ResourceOnBoarding = [pscustomobject]@{
                    InternalProd = $null
                    DMZProd      = $null
                    InternalDev  = $null
                    InternalTest = $null
                }
                ProvisionVMLocalAdmin = $null
                SMTP                  = $null
            }
        }

        Providers = [pscustomobject]@{
            Secret = $SecretProvider
            State  = $StateProvider
            Log    = 'Stdout'
        }
    }
}
