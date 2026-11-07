#Requires -Version 5.1
<#
    #1102 (framework rules 11 / 11f): the OPTIONAL Azure OpenAI account of a PRIVATE install follows rule 11 -- it would need
    a private endpoint, so setup\Validate-SIOpenAI.ps1 never creates one with public access, and never switches one to it.
    Only logs / the data collection endpoint may stay public (rule 11f).

      Test-SIOpenAIInstallPrivate   is the install private? Its private-network answer (-PrivateNetwork), else its SecurityInsight
                                    database server (sql-si-*) in the install's resource group reads public network access off
                                    (Test-SISqlServerPrivate, setup\_shared\SI-SetupArm.ps1). A read that fails THROWS -- the
                                    script then creates nothing.
      Get-SIOpenAIPrivatePlan       PURE. What the script does with the account: proceed (public install, unchanged), refuse
                                    (private, no account: nothing is created, AI features stay off), report (private, an
                                    existing account reads public Enabled: said, never changed), reuse (private, an existing
                                    account already closed).
    Dot-source AFTER setup\_shared\SI-SetupAzure.ps1 and SI-SetupArm.ps1. No modules.
#>

$script:SIOpenAIPrivateRefusal = 'this install is private: an Azure OpenAI account would need a private endpoint (framework rule 11) -- not created; AI features stay off'

function Test-SIOpenAIInstallPrivate {
    <# @{ Private; Why }. -PrivateNetwork (the install's answer) decides at once; otherwise every SecurityInsight database
       server in -ResourceGroupName is read (ARM GET). No resource group / no server = not private (a public or a new
       install). Any other failure THROWS. #>
    param([bool]$PrivateNetwork, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroupName)
    if ($PrivateNetwork) { return [pscustomobject]@{ Private = $true; Why = 'the install''s private-network answer' } }
    $list = Invoke-SIArm -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers' -f $SubscriptionId, $ResourceGroupName) -ApiVersion '2021-11-01' -AllowNotFound
    $names = @(@(if ($list) { $list.value }) | Where-Object { $_ -and [string]$_.name -like 'sql-si-*' } | ForEach-Object { [string]$_.name })
    foreach ($n in $names) {
        if (Test-SISqlServerPrivate -ResourceGroupName $ResourceGroupName -ServerName $n -SubscriptionId $SubscriptionId) {
            return [pscustomobject]@{ Private = $true; Why = ('its database server {0} has public network access off' -f $n) }
        }
    }
    [pscustomobject]@{ Private = $false; Why = '' }
}

function Get-SIOpenAIPrivatePlan {
    <# PURE. -Account = the account as ARM returns it ($null = not there). @{ Action = proceed | refuse | report | reuse; Line }.
       Nothing here ever writes the account: an existing one is only read. #>
    param([bool]$Private, $Account, [string]$AccountName)
    if (-not $Private) { return [pscustomobject]@{ Action = 'proceed'; Line = '' } }
    if (-not $Account) { return [pscustomobject]@{ Action = 'refuse'; Line = $script:SIOpenAIPrivateRefusal } }
    $pna = ''
    if ($Account.PSObject.Properties['properties'] -and $Account.properties -and $Account.properties.PSObject.Properties['publicNetworkAccess']) { $pna = [string]$Account.properties.publicNetworkAccess }
    if ($pna -eq '' -or $pna -ieq 'Enabled') {
        return [pscustomobject]@{ Action = 'report'; Line = ('this install is private: the existing Azure OpenAI account {0} reads public network access Enabled -- reported, not changed (framework rule 11: it needs a private endpoint, a customer step)' -f $AccountName) }
    }
    [pscustomobject]@{ Action = 'reuse'; Line = ('this install is private: the existing Azure OpenAI account {0} has public network access {1} -- reused as it is' -f $AccountName, $pna) }
}
