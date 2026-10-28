#Requires -Version 5.1
<#
    #430 -- AN AZURE TAG ON A SUBSCRIPTION REACHES EVERY RESOURCE BELOW IT, BY TAG NAME CASE-INSENSITIVELY.

    Operator, 2026-10-07: "add this to my cmdb ... and in the enrichment -- tagging -- this way any resource below this
    will be linked to the cmdb. use also the assettier--si tag as shown". His tags sit on three SUBSCRIPTIONS:
    cmdbID = 1 / 2 / 3 and AssetTier--SI = '<Purpose>--tier<N>--SI'. The rules that read them name the tag 'cmdbId'
    (the operator's Azure tag is 'cmdbID') and 'AssetTier--SI'.

    Azure treats tag NAMES case-insensitively, so SI must too: 'cmdbID' on the subscription IS the rule's 'cmdbId'.
    Nothing tested the detect kind hasAzureTagDirectOrParent or the parent-chain index it reads (both measured to work
    on ring 1, 2026-10-07: 306 Azure rows got their cmdbId from the subscription tag) -- these tests pin it, through the
    REAL index builder (Build-SIParentResourceChainIndex) with Azure Resource Graph answered by a stub:
      * a resource with NO tags of its own, in a resource group with NO tags, inherits the subscription's tags;
      * the tag name matches in any case; the value match is case-insensitive too (endswith for '--tier<N>--SI');
      * a resource in another subscription does not;
      * a tag on the resource itself still counts (direct).
#>

BeforeAll {
    $root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    . (Join-Path $root '..\engine\asset-profiling\shared\RuleEval.ps1')
    . (Join-Path $root '..\engine\asset-profiling\shared\RuleIndexes.ps1')

    $script:SubA = '11111111-1111-1111-1111-111111111111'
    $script:SubB = '22222222-2222-2222-2222-222222222222'
    # Azure Resource Graph, as the three index queries see it (tags arrive as objects, the shape ARG returns)
    # defined AFTER the engine files, in the same scope, so it is the one the index builder calls
    function Get-SIArgPaged {
        param([string]$Query)
        if ($Query -match "microsoft.resources/subscriptions'\s*\r?\n\| project subscriptionId") {
            return @(
                [pscustomobject]@{ subscriptionId = $script:SubA; name = 'sub-a'; tags = [pscustomobject]@{ 'cmdbID' = '3'; 'cmdbName' = 'Intranet'; 'AssetTier--SI' = 'AzDefenderForCloud--tier1--SI' } }
                [pscustomobject]@{ subscriptionId = $script:SubB; name = 'sub-b'; tags = [pscustomobject]@{ 'AssetTier--SI' = 'AzLZDatacenterSub--tier0--SI' } }
            )
        }
        if ($Query -match 'resourcegroups') {
            return @([pscustomobject]@{ id = "/subscriptions/$($script:SubA)/resourceGroups/rg-untagged"; tags = $null; subscriptionId = $script:SubA })
        }
        if ($Query -match '^\s*Resources') {
            return @([pscustomobject]@{ id = "/subscriptions/$($script:SubB)/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-own"; tags = [pscustomobject]@{ 'CMDBID' = '7' }; subscriptionId = $script:SubB; resourceGroup = 'rg-b' })
        }
        @()
    }
    Reset-SIRuleIndexes
    Build-SIParentResourceChainIndex
    $script:Asset = { param([string]$Id) @{ AZ_ResourceId = $Id } }
    $script:Hit = { param([string]$Id, [hashtable]$RuleArgs) Test-SIKind_hasAzureTagDirectOrParent -Asset (& $script:Asset $Id) -Args $RuleArgs }
    $script:InA = "/subscriptions/$($script:SubA)/resourceGroups/rg-untagged/providers/Microsoft.Storage/storageAccounts/stnotags"
    $script:InB = "/subscriptions/$($script:SubB)/resourceGroups/rg-b/providers/Microsoft.Compute/virtualMachines/vm1"
}

Describe '#430 hasAzureTagDirectOrParent -- the subscription tag reaches every resource below it' {
    It 'the index was built from the three Resource Graph queries' {
        (Get-SIRuleIndex -Name 'BuildStats')['parentChain'].Built | Should -BeTrue
    }

    It '🔑 the rule''s cmdbId matches the operator''s cmdbID on the SUBSCRIPTION -- resource and resource group carry no tag' {
        & $script:Hit $script:InA @{ tag = 'cmdbId'; value = '3' } | Should -BeTrue
        & $script:Hit $script:InA @{ tag = 'CMDBID'; value = '3' } | Should -BeTrue
        & $script:Hit $script:InA @{ tag = 'cmdbID'; value = '3' } | Should -BeTrue
    }

    It 'the value must still match -- cmdbID 3 is not service 1' {
        & $script:Hit $script:InA @{ tag = 'cmdbId'; value = '1' } | Should -BeFalse
    }

    It 'the tier from AssetTier--SI: endswith --tier1--SI, in any case' {
        & $script:Hit $script:InA @{ tag = 'assettier--si'; value = '--tier1--SI'; match = 'endswith' } | Should -BeTrue
        & $script:Hit $script:InA @{ tag = 'AssetTier--SI'; value = '--TIER1--si'; match = 'endswith' } | Should -BeTrue
        & $script:Hit $script:InA @{ tag = 'AssetTier--SI'; value = '--tier0--SI'; match = 'endswith' } | Should -BeFalse
    }

    It 'a resource in ANOTHER subscription does not get this subscription''s tags' {
        & $script:Hit $script:InB @{ tag = 'cmdbId'; value = '3' } | Should -BeFalse
        & $script:Hit $script:InB @{ tag = 'AssetTier--SI'; value = '--tier0--SI'; match = 'endswith' } | Should -BeTrue
    }

    It 'a tag on the resource itself counts as well (direct), name in any case' {
        & $script:Hit "/subscriptions/$($script:SubB)/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-own" @{ tag = 'cmdbId'; value = '7' } | Should -BeTrue
    }

    It 'presence-only (no value) finds the tag on the parent' {
        & $script:Hit $script:InA @{ tag = 'cmdbid' } | Should -BeTrue
        & $script:Hit $script:InB @{ tag = 'cmdbid' } | Should -BeFalse
    }
}
