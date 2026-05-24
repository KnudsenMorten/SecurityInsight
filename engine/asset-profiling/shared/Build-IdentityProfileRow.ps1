#Requires -Version 5.1
<#
    Build-IdentityProfileRow.ps1

    Schema-driven row builder for the identity engine. Reads
    profiles/identity.schema.json once (cached), then for each declared
    field looks up the value via its `source` + `sourcePath` (or `derivation`)
    and emits a row whose columns EXACTLY match the schema -- no extras,
    no drops, no renames.

    Honored schema constructs:
      - field.name                 -> output column name
      - field.purpose              -> determines flat vs nested. Nested
                                     purposes (enrichment, forensic, raw)
                                     are NOT emitted as flat columns; they
                                     belong under Properties.* if anywhere.
      - field.source               -> 'entra'|'mdi'|'exposureGraph'|'azure'|'derived'
      - field.sourcePath           -> path on the upstream object; resolved
                                     by Resolve-SISourceValue per source.
      - field.derivation.algorithm -> dispatched by Get-SIDerivedValue.
      - field.emit                 -> default true. When false, field is
                                     declared in schema (for documentation /
                                     downstream consumers) but NOT sent to LA.

    Schema fields this builder doesn't yet know how to populate emit as $null;
    operators see the gap in LA and we add the dispatch.
#>

if (-not (Get-Variable -Name _SISchemaCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaCache = @{}
}

# shared @odata.type stripper for EG rawData blobs.
. (Join-Path $PSScriptRoot 'Convert-EgBlob.ps1')

# ---------------------------------------------------------------------------
# SCHEMA + CATALOG LOADERS
# ---------------------------------------------------------------------------

function Get-SIIdentityFieldRequiredKeys {
    <# v2.2.374 -- mirror of the Azure helper. Given a schema field, return the
       list of metadata keys whose presence is REQUIRED for the field to
       possibly resolve to non-null. Empty list = no fast-null possible. #>
    param($Field)
    $src  = [string]$Field.source
    $name = [string]$Field.name
    $keys = New-Object System.Collections.Generic.List[string]
    if ($script:_SIEntraKeyMap.ContainsKey($name)) {
        [void]$keys.Add([string]$script:_SIEntraKeyMap[$name])
    }
    if ($src -eq 'exposureGraph') { [void]$keys.Add('ENTRA_EgRawData') }
    return $keys
}

function Get-SIIdentitySchema {
    if ($script:_SISchemaCache.ContainsKey('IdentitySchema')) { return $script:_SISchemaCache['IdentitySchema'] }
    # locked + custom merge (profiles/identity.schema.json + profiles-custom/identity.schema.custom.json)
    . (Join-Path $PSScriptRoot 'Get-SISchemaWithCustomMerge.ps1')
    $schema = Get-SISchemaWithCustomMerge -Engine identity
    $script:_SISchemaCache['IdentitySchema'] = $schema
    # v2.2.374 -- pre-filter emit-able fields once + annotate each with
    # _SIRequiredKeys so per-row iteration can fast-null fields whose required
    # source data isn't present. Same pattern as Azure v2.2.371/372.
    $script:_SISchemaCache['IdentityEmitFields'] = @(
        $schema.fields | Where-Object {
            $fn = [string]$_.name
            $fn -and `
            (-not $_.PSObject.Properties['emit'] -or $_.emit -ne $false) -and `
            ([string]$_.purpose -notin 'enrichment','forensic','raw') -and `
            ($fn -notin 'CollectHash','EnrichHash','PostureHash','ClassifyHash')
        } | ForEach-Object {
            $reqKeys = Get-SIIdentityFieldRequiredKeys -Field $_
            Add-Member -InputObject $_ -MemberType NoteProperty -Name '_SIRequiredKeys' -Value $reqKeys -Force
            $_
        }
    )
    return $schema
}

function Get-SIIdentityCatalogVersion {
    if ($script:_SISchemaCache.ContainsKey('IdentityCatalogVersion')) { return $script:_SISchemaCache['IdentityCatalogVersion'] }
    $catPath = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'privilege-tier-catalog/privilege-tier-catalog.locked.json'
    if (-not (Test-Path $catPath)) { return 'unknown' }
    try {
        $raw = Get-Content $catPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $v = [string]$raw.Metadata.GeneratedAt
        $script:_SISchemaCache['IdentityCatalogVersion'] = $v
        return $v
    } catch { return 'unknown' }
}

# ---------------------------------------------------------------------------
# SOURCE EXTRACTORS
# Maps schema field -> location on $Record.Metadata. Engine reads the same
# Metadata blob the v2.2 engine already populates -- no re-collection.
# ---------------------------------------------------------------------------

$script:_SIEntraKeyMap = @{
    'Upn'                     = 'ENTRA_UPN'
    'Mail'                    = 'ENTRA_Mail'
    'OnPremSid'               = 'ENTRA_OnPremSID'
    'OnPremObjectGuid'        = 'ENTRA_OnPremObjectId'
    'OnPremSamAccountName'    = 'ENTRA_OnPremSamAccountName'
    'OnPremDomainName'        = 'ENTRA_OnPremDomainName'
    'OnPremLastSyncDateTime'  = 'ENTRA_OnPremLastSyncDateTime'
    'EmployeeId'              = 'ENTRA_EmployeeId'
    'EmployeeType'            = 'ENTRA_EmployeeType'
    'EmployeeHireDate'        = 'ENTRA_EmployeeHireDate'
    'EmployeeLeaveDateTime'   = 'ENTRA_EmployeeLeaveDateTime'
    'AccountEnabled'          = 'ENTRA_Enabled'
    'UserType'                = 'ENTRA_UserType'
    'CreationType'            = 'ENTRA_CreationType'
    'ExternalUserState'       = 'ENTRA_ExternalUserState'
    'OnPremisesSyncEnabled'   = 'ENTRA_OnPrem'
    'IsManagementRestricted'  = 'ENTRA_IsManagementRestricted'
    'CreatedDateTime'         = 'ENTRA_Created'
    'DeletedDateTime'         = 'ENTRA_DeletedDateTime'
    'LastSignInDateTime'              = 'ENTRA_LastSignInDateTime'
    'LastNonInteractiveSignInDateTime'= 'ENTRA_LastNonInteractiveSignInDateTime'
    'LastSuccessfulSignInDateTime'    = 'ENTRA_LastSuccessfulSignInDateTime'
    'LastPasswordChangeDateTime'      = 'ENTRA_PasswordLastChanged'
    'DisplayName'             = 'ENTRA_DisplayName'
    'AssetName'               = 'ENTRA_DisplayName'   # cross-engine asset-name alias
    'Department'              = 'ENTRA_Department'
    'JobTitle'                = 'ENTRA_JobTitle'
    'Country'                 = 'ENTRA_Country'
    'UsageLocation'           = 'ENTRA_UsageLocation'
    'Manager'                 = 'ENTRA_Manager'
    'ManagerUpn'              = 'ENTRA_ManagerUpn'
    'PasswordPolicies'        = 'ENTRA_PasswordPolicies'
    'LicenseSkuIds'           = 'ENTRA_LicenseSkuIds'
    'AppId'                   = 'ENTRA_SPAppId'
    'AppOwnerOrganizationId'  = 'ENTRA_SPAppOwnerTenant'
    'PublisherName'           = 'ENTRA_SPPublisher'
    'ServicePrincipalType'    = 'ENTRA_SPType'
    'CustomSecurityAttributes'= 'ENTRA_CustomSecurityAttributes'
    'EntraRoles_Permanent'    = 'ENTRA_DirectoryRolesPermanent'
    'EntraRoles_Eligible'     = 'ENTRA_DirectoryRolesEligible'
    'EntraAppPermissions_Application' = 'ENTRA_AppPermissions_Application'
    'EntraAppPermissions_Delegated'   = 'ENTRA_AppPermissions_Delegated'
    'Groups'                  = 'ENTRA_Groups'
    'AdNestedGroupNames'      = 'ENTRA_Groups'
    'AdNestedCriticalGroups'  = 'ENTRA_Groups_Critical'
    'AzureRoles_Assignments'  = 'ENTRA_AzureDelegations'
    'MdiInvestigationPriority'= 'ENTRA_InvestigationPriority'
    # Audit-gap-fill: MS-computed risk + identity-context signals from EG
    'MsCriticalityLevel'      = 'EG_MsCriticalityLevel'
    'IsCompromisedRecently'   = 'EG_IsCompromisedRecently'
    'IsExternalUser'          = 'EG_IsExternalUser'
    'OnPremSyncEnabled'       = 'EG_OnPremSyncEnabled'
    'IsMfaCapable'            = 'EG_IsMfaCapable'
    'IsMfaRegistered'         = 'EG_IsMfaRegistered'
    'EntraAccountObjectId'    = 'EG_AccountObjectId'
    'MdiIsLockedOut'          = 'ENTRA_MdiIsLockedOut'
    'MdiLastSeenActivity'     = 'ENTRA_MdiLastSeenActivity'
    'AdminCount'              = 'ENTRA_AdminCount'
    'UserAccountControl'      = 'ENTRA_UserAccountControl'
    'SidHistory'              = 'ENTRA_SidHistory'
    'EgCriticalityLevel'      = 'ENTRA_EgCriticalityLevel'
    'EgRuleBasedCriticalityLevel'    = 'ENTRA_EgRuleBasedCriticalityLevel'
    'HasLeakedCredentials'    = 'ENTRA_HasLeakedCredentials'
    'HasAdLeakedCredentials'  = 'ENTRA_HasAdLeakedCredentials'
    'HasServicePrincipalName' = 'ENTRA_HasServicePrincipalName'
    'IsAdSensitiveFlagged'    = 'ENTRA_IsAdSensitiveFlagged'
    'MdiIsSensitive'          = 'ENTRA_IsSensitive'
    'MfaIsRegistered'         = 'ENTRA_MfaIsRegistered'
    'MfaIsCapable'            = 'ENTRA_MfaIsCapable'
    'IsPasswordlessCapable'   = 'ENTRA_IsPasswordlessCapable'
    'IsSsprRegistered'        = 'ENTRA_IsSsprRegistered'
    'IsSsprCapable'           = 'ENTRA_IsSsprCapable'
    'IsSsprEnabled'           = 'ENTRA_IsSsprEnabled'
    'MfaMethods'              = 'ENTRA_MfaMethods'
    'MfaMethodCount'          = 'ENTRA_MfaMethodCount'
    'MfaDefaultMethod'        = 'ENTRA_MfaDefaultMethod'
    'MfaSystemPreferredMethods'= 'ENTRA_MfaSystemPreferredMethods'
    'MfaPreferredSecondary'   = 'ENTRA_MfaPreferredSecondary'
    'MfaLastUpdatedDateTime'  = 'ENTRA_MfaLastUpdatedDateTime'
}

function Resolve-SISourceValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Record)
    $meta = if ($Record.Metadata) { $Record.Metadata } else { @{} }

    # PS 5.1 unwraps single-element arrays at function-return through the pipeline.
    # That collapsed 1-role users' EntraRoles_Eligible from ["Global Administrator"]
    # to "Global Administrator" -- LA's Dynamic column then stored a JSON scalar
    # string instead of a JSON array. The comma operator (`,$val`) wraps in an
    # outer 1-element array; PS unwraps the outer wrap, leaving the original
    # value's shape intact (works for arrays, hashtables, scalars, and $null).

    # source: exposureGraph -- walk the schema-declared sourcePath against the
    # cached EG rawData blob (populated by Get-SIExposureGraphIdentities in
    # discovery and stashed as ENTRA_EgRawData on the record). Path format:
    #   eg.node.NodeProperties.rawData.<dotted.path>
    # We strip the well-known prefix and walk the remainder. Adding a new
    # EG-sourced field is now a JSON edit only.
    if ($Field.source -eq 'exposureGraph') {
        # Pull EG raw data via the same shape-tolerant accessor (meta is hashtable; raw is PSCustomObject from ConvertFrom-Json)
        $eg = if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('ENTRA_EgRawData')) { $meta['ENTRA_EgRawData'] } else { $null }
              } else { $meta.ENTRA_EgRawData }
        if (-not $eg) { return $null }

        $sp = [string]$Field.sourcePath
        if (-not $sp) { return $null }
        $sp = $sp -replace '^eg\.node\.NodeProperties\.rawData\.', ''
        $cur = $eg
        foreach ($seg in ($sp -split '\.')) {
            if ($null -eq $cur) { return $null }
            $clean = $seg -replace '\[\*\]$', ''
            if ($cur -is [System.Collections.IDictionary]) {
                if ($cur.Contains($clean)) { $cur = $cur[$clean] } else { return $null }
            } else {
                if ($cur.PSObject.Properties[$clean]) { $cur = $cur.$clean } else { return $null }
            }
        }
        return ,$cur
    }

    # entra / mdi / azure -- use the existing key map (these all merge into ENTRA_*).
    # IMPORTANT: $meta from discovery is a [hashtable] -- PSObject.Properties[$key]
    # only works for [pscustomobject], so the universal accessor is `$meta.$key`
    # (returns $null gracefully if the key is absent on either shape).
    $key = $script:_SIEntraKeyMap[$Field.name]
    if (-not $key) { return $null }
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains($key)) { return ,$meta[$key] }
    } else {
        if ($meta.PSObject.Properties[$key]) { return ,$meta.$key }
    }
    return $null
}

# ---------------------------------------------------------------------------
# DERIVED-VALUE DISPATCH
# ---------------------------------------------------------------------------

if (-not (Get-Variable -Name _SIDerivedSeen -Scope Script -ErrorAction SilentlyContinue)) { $script:_SIDerivedSeen = @{} }

function Get-SIEgValue {
    # Walks a dotted path against $meta.ENTRA_EgRawData (EG NodeProperties.rawData).
    # Returns $null if EG data missing or any path segment unresolved. Shape-tolerant
    # (works for both [hashtable] and [pscustomobject]) since EG data may flow as either.
    param([object]$Meta, [string]$Path)
    $eg = if ($Meta -is [System.Collections.IDictionary]) {
            if ($Meta.Contains('ENTRA_EgRawData')) { $Meta['ENTRA_EgRawData'] } else { $null }
          } else {
            if ($Meta.PSObject.Properties['ENTRA_EgRawData']) { $Meta.ENTRA_EgRawData } else { $null }
          }
    if (-not $eg) { return $null }
    $cur = $eg
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
        } else {
            if ($cur.PSObject.Properties[$seg]) { $cur = $cur.$seg } else { return $null }
        }
    }
    return $cur
}

function Get-SIDerivedValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Context)

    $meta = if ($Context.Record.Metadata) { $Context.Record.Metadata } else { @{} }
    $verdict = $Context.Verdict
    $perSource = $Context.PerSourceVerdicts

    # Per-source verdict family (24 fields)
    if ($Field.name -match '^(EntraRolesPermanent|EntraRolesEligible|EntraApiPermsApplication|EntraApiPermsDelegated|AdBuiltinGroups|AzureRoles)Verdict_(Tier|TopMatch|MatchCount|MissCount)$') {
        $tag = $Matches[1]; $aspect = $Matches[2]
        $v = $perSource[$tag]
        if (-not $v) { return $null }
        return $v.$aspect
    }

    switch ($Field.name) {
        'PrimaryEntityId'   { return $Context.PrimaryEntityId }
        'PrimaryEntityType' { return $Context.PrimaryEntityType }
        'EntityIds'         { return ,$Context.EntityIds }
        'RunId'             { return $Context.Record.SI_RunId }
        'CollectionTime'    { return $Context.RunContext.CollectionTime }
        'IdentityTieringCatalogVersion' { return $Context.CatalogVersion }
        # AssetName: cross-engine alias resolved by walking provider sources
        # in priority order (per user directive "use all the
        # providers as options for the AssetName -- entra, mde, AD, azure, EG").
        # Identity priority: Entra display-name > AD samAccountName > UPN
        # local-part > MDE/Azure (when SP-on-Azure-resource correlation) > appId.
        # Schema added the field but never wired the derivation
        # -> AssetName always null on Identity rows.
        'AssetName' {
            $get = {
                param($m, $k)
                if ($m -is [System.Collections.IDictionary]) { if ($m.Contains($k)) { return [string]$m[$k] } else { return '' } }
                if ($m.PSObject.Properties[$k]) { return [string]$m.$k } else { return '' }
            }
            $candidates = @(
                & $get $meta 'ENTRA_DisplayName'         # Entra (users + service principals)
                & $get $meta 'AD_DisplayName'            # on-prem AD attribute
                & $get $meta 'AD_SamAccountName'         # AD pre-W2K account name
                $(($x = & $get $meta 'ENTRA_UserPrincipalName'); if ($x) { ($x -split '@')[0] } else { '' })   # UPN local-part
                & $get $meta 'MDE_DeviceName'            # MDE (when SP/UAMI on a device)
                & $get $meta 'AZ_Name'                   # Azure (when SP/UAMI on a resource)
                & $get $meta 'EG_DeviceName'             # ExposureGraph
                & $get $meta 'ENTRA_AppId'               # last resort: opaque app id
            )
            foreach ($c in $candidates) {
                if (-not [string]::IsNullOrWhiteSpace($c)) { return $c }
            }
            return $null
        }
        # SIRules carries the AssetProfileBy* YAML rule matches
        # produced by Stage Profile (Verdict.SI_RuleMatches). Always an array;
        # empty array when no rules matched.
        'SIRules' {
            if ($verdict -and $verdict.PSObject.Properties['SI_RuleMatches']) { return ,@($verdict.SI_RuleMatches) }
            return ,@()
        }
        # IsEnabledActive = identity is currently usable AND has
        # signed in within $global:SI_ActiveStaleDays (default 30). Filters out
        # stale ghost accounts that are technically enabled but never used.
        'IsEnabledActive' {
            $stale = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
            if ($meta.ENTRA_Enabled -ne $true) { return $false }
            $days = $null
            if ($null -ne $meta.ENTRA_LastSignInDays) {
                try { $days = [int]$meta.ENTRA_LastSignInDays } catch { $days = $null }
            }
            if ($null -eq $days -or $days -lt 0) { return $false }
            return ($days -le $stale)
        }
        'IdentityType' {
            $t = [string]$meta.ENTRA_AssetType
            $sp = [string]$meta.ENTRA_SPType
            if ($t -eq 'ServicePrincipal' -and $sp -eq 'ManagedIdentity') { return 'ManagedIdentity' }
            elseif ($t -eq 'ServicePrincipal') { return 'ServicePrincipal' }
            else { return 'User' }
        }
        'ObjectType' {
            # v2.1-style alias of IdentityType for legacy asset-tagging
            # KQL back-compat. Same value space as the v2.1 SI_IdentityAssets_CL
            # ObjectType column: 'User' / 'ServicePrincipal' / 'ManagedIdentity' /
            # 'Group' / 'ServiceAccount' / 'Computer'.
            $t  = [string]$meta.ENTRA_AssetType
            $sp = [string]$meta.ENTRA_SPType
            if ($t -in 'Group','ServiceAccount','Computer') { return $t }
            if ($t -eq 'ServicePrincipal' -and $sp -eq 'ManagedIdentity') { return 'ManagedIdentity' }
            elseif ($t -eq 'ServicePrincipal') { return 'ServicePrincipal' }
            else { return 'User' }
        }
        'CSA' {
            # format customSecurityAttributes object as
            # 'set/attribute=value; ...' so legacy asset-tagging KQL like
            # extract(@"tier-(\d+)", 1, tostring(CSA)) keeps working against
            # SI_Identity_Profile_CL. The structured `CustomSecurityAttributes`
            # dynamic column carries the raw graph payload for new queries.
            $csa = $meta.ENTRA_CustomSecurityAttributes
            if ($null -eq $csa) { return $null }
            $parts = @()
            $setNames = if ($csa -is [hashtable]) { $csa.Keys } else { ($csa.PSObject.Properties.Name) }
            foreach ($setName in $setNames) {
                $set = if ($csa -is [hashtable]) { $csa[$setName] } else { $csa.$setName }
                if ($null -eq $set) { continue }
                $attrNames = if ($set -is [hashtable]) { $set.Keys } else { ($set.PSObject.Properties.Name) }
                foreach ($attrName in $attrNames) {
                    if ($attrName -like '@*') { continue }   # skip @odata.type etc.
                    $val = if ($set -is [hashtable]) { $set[$attrName] } else { $set.$attrName }
                    if ($null -ne $val -and -not [string]::IsNullOrWhiteSpace([string]$val)) {
                        $parts += ('{0}/{1}={2}' -f $setName, $attrName, [string]$val)
                    }
                }
            }
            if ($parts.Count -eq 0) { return $null }
            return ($parts -join '; ')
        }
        'SecurityPrincipalType' {
            $t = [string]$meta.ENTRA_AssetType
            if ($t -eq 'ServicePrincipal') { return 'ServiceObject' } else { return 'UserObject' }
        }
        'PrimaryProvider' {
            if ($meta.ENTRA_OnPrem -eq $true) { return 'Hybrid' } else { return 'AzureActiveDirectory' }
        }
        'IsBreakGlass'              { return [bool]$verdict.IsBreakGlass }
        'IsHomeTenantSpn'           { return ([string]$meta.ENTRA_SPAppOwnerTenant -eq [string]$global:SI_SPN_TenantId -and [string]$meta.ENTRA_SPAppOwnerTenant) }
        'IsFirstPartyMicrosoftSpn'  { return ([string]$meta.ENTRA_SPAppOwnerTenant -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a') }
        'IsThirdPartyMultiTenantSpn'{ return ([string]$meta.ENTRA_SPAppOwnerTenant -and [string]$meta.ENTRA_SPAppOwnerTenant -ne 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -and [string]$meta.ENTRA_SPAppOwnerTenant -ne [string]$global:SI_SPN_TenantId) }
        'IsLegacySpn'               { return ([string]$meta.ENTRA_SPType -eq 'Legacy') }
        'IsManagedServiceAccount'   { return ($meta.ENTRA_AssetType -eq 'ServiceAccount' -and ([string]$meta.ENTRA_OnPremSamAccountName).EndsWith('$')) }
        # The booleans below read from EG raw data (populated by Get-SIExposureGraphIdentities).
        'IsDomainControllerAccount' { return [bool](Get-SIEgValue $meta 'isDomainController') }
        'IsExchangeServerAccount'   {
            $a = [bool](Get-SIEgValue $meta 'isExchangeServerDnsName')
            $b = [bool](Get-SIEgValue $meta 'isTaggedAsExchangeServer')
            return ($a -or $b)
        }
        'IsAdSensitiveFlagged'      { return [bool](Get-SIEgValue $meta 'isSensitive') }
        'MiAccountType'                   { return [string](Get-SIEgValue $meta 'managedIdentityMetadata.accountType') }
        'IsSystemAssignedManagedIdentity' { return ([string](Get-SIEgValue $meta 'managedIdentityMetadata.accountType') -eq 'SystemManagedIdentity') }
        'IsUserAssignedManagedIdentity'   { return ([string](Get-SIEgValue $meta 'managedIdentityMetadata.accountType') -eq 'UserAssignedManagedIdentity') }
        'IsExplicitManagedIdentity'       {
            $alt = Get-SIEgValue $meta 'alternativeNames'
            if (-not $alt) { return $false }
            foreach ($e in @($alt)) { if ([string]$e -eq 'isExplicit=True') { return $true } }
            return $false
        }
        'AttachedAzureResourceId' {
            $v = Get-SIEgValue $meta 'managedIdentityMetadata.attachedResourceId'
            if ($v) { return [string]$v }
            $alt = Get-SIEgValue $meta 'alternativeNames'
            foreach ($e in @($alt)) { if ([string]$e -match '^/subscriptions/.+|^/providers/Microsoft\.Management/managementGroups/.+') { return [string]$e } }
            return ''
        }
        'AttachedResourceType' {
            $arm = Get-SIEgValue $meta 'managedIdentityMetadata.attachedResourceId'
            if (-not $arm) { return '' }
            if ($arm -match '/providers/(?<rp>[^/]+/[^/]+)') { return $matches.rp.ToLower() }
            return ''
        }
        'AttachedResourceTier'            { return $null }     # TODO: cross-engine join
        'AttachedResourceCount'           { return $null }     # TODO: count UAMI consumers
        'HasSidHistory' {
            $sh = Get-SIEgValue $meta 'sidHistory'
            return ([int]([array]$sh).Count -gt 0)
        }
        'EgCriticalityRuleNamesPredefined'{ return $null }     # requires MS_Predefined_CriticalityRules.json catalog
        'EgCriticalityRuleNamesCustom'    { return $null }
        'LastSignInDays' {
            if ($null -ne $meta.ENTRA_LastSignInDays) { return [int]$meta.ENTRA_LastSignInDays } else { return -1 }
        }
        'Tier'            { return $Context.AggregatedTier }
        'Group'           { return [string]$verdict.SI_Group }
        'Verdict'         { return ('Tier {0}' -f $Context.AggregatedTier) }
        'AssetType'       { return [string]$verdict.SI_ServiceType }
        'AssetSubtype'    { return '' }
        'AssetGroup'      { return [string]$verdict.SI_Group }
        'PreliminaryTier' { return $Context.AggregatedTier }
        default {
            if (-not $script:_SIDerivedSeen[$Field.name]) {
                Write-Verbose ('  [derive-gap] no dispatch for derived field "{0}"' -f $Field.name)
                $script:_SIDerivedSeen[$Field.name] = $true
            }
            return $null
        }
    }
}

# ---------------------------------------------------------------------------
# PER-SOURCE VERDICT (parses v2.2 TierSources -> per-source tuples)
# ---------------------------------------------------------------------------

function ConvertTo-SIPerSourceVerdict {
    param([object]$TierSourceEntry, [string]$NameField)
    if (-not $TierSourceEntry -or -not $TierSourceEntry.CatalogMatches) {
        return [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
    }
    $matches = @($TierSourceEntry.CatalogMatches)
    if ($matches.Count -eq 0) {
        return [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
    }
    $minTier = [int]::MaxValue; $top = $null
    $proofs = New-Object System.Collections.Generic.List[object]
    foreach ($m in $matches) {
        $t = if ($m.PSObject.Properties['Tier']) { [int]$m.Tier } elseif ($m.PSObject.Properties['CatalogTier']) { [int]$m.CatalogTier } else { $null }
        if ($null -eq $t) { continue }
        $name = if ($m.PSObject.Properties[$NameField]) { [string]$m.($NameField) } else { '' }
        if ($t -lt $minTier) { $minTier = $t; $top = $name }
        $proofs.Add([ordered]@{ name=$name; tier=$t; reason = if ($m.PSObject.Properties['Reason']) { [string]$m.Reason } else { '' } })
    }
    $tierVal = if ($proofs.Count -gt 0) { $minTier } else { $null }
    [pscustomobject]@{
        Tier = $tierVal
        TopMatch = $top; MatchCount = $proofs.Count; MissCount = 0; Proofs = $proofs.ToArray()
    }
}

# ---------------------------------------------------------------------------
# HASH HELPERS
# ---------------------------------------------------------------------------

function Get-SICanonicalJson {
    param([object]$Bag)
    if ($Bag -is [System.Collections.IDictionary]) {
        $sorted = [ordered]@{}
        foreach ($k in ($Bag.Keys | Sort-Object)) { $sorted[$k] = $Bag[$k] }
        return ($sorted | ConvertTo-Json -Compress -Depth 20)
    }
    return ($Bag | ConvertTo-Json -Compress -Depth 20)
}
function Get-SIRowHash {
    param([object]$FieldBag)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-SICanonicalJson $FieldBag))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hex = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $hex.Substring(0, 16)
    } finally { $sha.Dispose() }
}

function _SIHashBag { param($Names, $Row); $h = @{}; foreach ($n in $Names) { if ($Row.Contains($n)) { $h[$n] = $Row[$n] } }; return $h }

# ---------------------------------------------------------------------------
# MAIN ENTRY: Build-SIIdentityProfileRow
# ---------------------------------------------------------------------------

function Build-SIIdentityProfileRow {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $RunContext
    )

    $schema = Get-SIIdentitySchema
    $meta   = if ($Record.Metadata) { $Record.Metadata } else { @{} }
    $verdict = $Record.Verdict

    # Parse v2.2 TierSources blob -> per-source verdicts
    $tierSources = $null
    if ($verdict.TierSources) { try { $tierSources = $verdict.TierSources | ConvertFrom-Json } catch { } }
    $perSource = @{
        EntraRolesPermanent      = ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.EntraID_Roles_Permanent -NameField 'Role'
        EntraRolesEligible       = ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.EntraID_Roles_Eligible  -NameField 'Role'
        EntraApiPermsApplication = ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.EntraID_APIPermissions  -NameField 'Permission'
        EntraApiPermsDelegated   = [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
        AdBuiltinGroups          = ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.AD                      -NameField 'Name'
        AzureRoles               = [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
    }
    if ($tierSources.Azure -and $tierSources.Azure.Assignments) {
        $azProofs = @(); $minAzT = [int]::MaxValue; $topAz = $null
        foreach ($a in @($tierSources.Azure.Assignments)) {
            $eff = if ($a.PSObject.Properties['EffectiveTier']) { [int]$a.EffectiveTier } else { $null }
            if ($null -eq $eff) { continue }
            $name = if ($a.RoleName -and $a.ScopeLabel) { ('{0} @ {1}' -f $a.RoleName, $a.ScopeLabel) } elseif ($a.RoleName) { $a.RoleName } else { '' }
            $azProofs += [ordered]@{ name=$name; tier=$eff }
            if ($eff -lt $minAzT) { $minAzT = $eff; $topAz = $name }
        }
        $azTierVal = if ($azProofs.Count -gt 0) { $minAzT } else { $null }
        $perSource.AzureRoles = [pscustomobject]@{
            Tier = $azTierVal
            TopMatch = $topAz; MatchCount = $azProofs.Count; MissCount = 0; Proofs = @($azProofs)
        }
    }

    $aggTier = if ($null -ne $verdict.SI_Tier) { try { [int]$verdict.SI_Tier } catch { 3 } } else { 3 }

    # PrimaryEntityId = bare AAD GUID (no 'entra-user:' / 'entra-sp:' prefix --
    # PrimaryEntityType already says AadObjectId, prefix breaks correlation joins).
    $oid = $null
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains('ENTRA_SPObjectId') -and $meta['ENTRA_SPObjectId']) { $oid = [string]$meta['ENTRA_SPObjectId'] }
        elseif ($meta.Contains('ENTRA_UserId')   -and $meta['ENTRA_UserId'])   { $oid = [string]$meta['ENTRA_UserId'] }
    } else {
        if ($meta.PSObject.Properties['ENTRA_SPObjectId'] -and $meta.ENTRA_SPObjectId) { $oid = [string]$meta.ENTRA_SPObjectId }
        elseif ($meta.PSObject.Properties['ENTRA_UserId'] -and $meta.ENTRA_UserId)     { $oid = [string]$meta.ENTRA_UserId }
    }
    if (-not $oid) {
        # Fallback: parse bare GUID out of AssetId ('entra-user:<guid>' / 'entra-sp:<guid>')
        $oid = [string]$Record.AssetId
        if ($oid -match '^entra-(?:user|sp):(?<guid>[0-9a-fA-F-]+)$') { $oid = $matches.guid }
    }
    $entityIds = @( @{ type='AadObjectId'; id=$oid; source='entra' } )
    if ($meta.ENTRA_UPN)            { $entityIds += @{ type='Upn';                       id=([string]$meta.ENTRA_UPN).ToLower();  source='entra' } }
    if ($meta.ENTRA_Mail)           { $entityIds += @{ type='Mail';                      id=([string]$meta.ENTRA_Mail).ToLower(); source='entra' } }
    if ($meta.ENTRA_OnPremSID)      { $entityIds += @{ type='SecurityIdentifier';        id=[string]$meta.ENTRA_OnPremSID;        source='entra' } }
    if ($meta.ENTRA_OnPremObjectId) { $entityIds += @{ type='ActiveDirectoryObjectGuid'; id=[string]$meta.ENTRA_OnPremObjectId;   source='mdi' } }

    $catVer = Get-SIIdentityCatalogVersion

    # Properties.collect.entra = ENTRA_* keys with the prefix stripped, mirroring
    # how collect.exposureGraph carries rawData with no prefix. The ENTRA_ prefix
    # exists only inside the engine (to namespace metadata-blob keys); consumers
    # of Properties.collect.entra see clean property names.
    # Excludes the EgRawData blob (lands under collect.exposureGraph instead).
    $collectEntra = @{}
    $collectEg    = $null
    $collectCmdb  = @{}
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys) {
            if ($k -eq 'ENTRA_EgRawData') { $collectEg = $meta[$k]; continue }
            if ($k -like 'ENTRA_*') {
                $cleanKey = $k.Substring(6)   # drop "ENTRA_"
                $collectEntra[$cleanKey] = $meta[$k]
            }
            elseif ($k -like 'CMDB_*') {
                $cleanKey = $k.Substring(5)   # drop "CMDB_"
                $collectCmdb[$cleanKey] = $meta[$k]
            }
        }
    } else {
        foreach ($p in $meta.PSObject.Properties) {
            if ($p.Name -eq 'ENTRA_EgRawData') { $collectEg = $p.Value; continue }
            if ($p.Name -like 'ENTRA_*') {
                $cleanKey = $p.Name.Substring(6)
                $collectEntra[$cleanKey] = $p.Value
            }
            elseif ($p.Name -like 'CMDB_*') {
                $cleanKey = $p.Name.Substring(5)
                $collectCmdb[$cleanKey] = $p.Value
            }
        }
    }

    # strip *@odata.type keys recursively from the EG rawData blob.
    # Microsoft's Exposure Graph JSON includes @odata.type annotations on every
    # collection / sub-object (#Collection(String), #Int64, #microsoft.graph...).
    # They're noise for downstream consumers and bloat the Properties JSON column.
    $collectEg = ConvertTo-SICleanedEgBlob -Value $collectEg

    # drop classify.proofs from Properties. Per-source proofs are already
    # exposed as flat schema columns (AdBuiltinGroupsVerdict_*, EntraRoles_Permanent,
    # AzureRoles_Assignments, etc.) and as the Tier_Proofs JSON column. Duplicating
    # them here was useless data (mostly empty arrays) and surfaced bogus legacy
    # entries with all-blank fields.
    $properties = @{
        meta = @{
            schema_version          = [string]$schema.schemaVersion
            tiering_catalog_version = $catVer
            schema_authority        = 'v2.2/asset-profiling-schema/identity.schema.locked.json'
        }
        collect = @{
            entra         = $collectEntra
            exposureGraph = $collectEg     # whole NodeProperties.rawData blob (or $null), @odata.type stripped
            cmdb          = $collectCmdb   # matched CMDB service record (all CSV columns)
        }
    }

    $ctx = @{
        Record            = $Record
        Verdict           = $verdict
        TierSources       = $tierSources
        PerSourceVerdicts = $perSource
        EntityIds         = $entityIds
        PrimaryEntityId   = $oid
        PrimaryEntityType = 'AadObjectId'
        CatalogVersion    = $catVer
        AggregatedTier    = $aggTier
        RunContext        = $RunContext
    }

    # ---- Iterate schema.fields, emit ONLY declared fields per field.purpose/emit ----
    # v2.2.374 -- use cached emit-fields + per-row availKeys fast-null path.
    # Same pattern as Build-AzureProfileRow v2.2.371/372.
    $row = [ordered]@{}
    $row['TimeGenerated'] = $Record.TimeGenerated
    $_meta = if ($Record.Metadata) { $Record.Metadata } else { @{} }
    $availKeys = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if ($_meta -is [System.Collections.IDictionary]) {
        foreach ($k in $_meta.Keys) {
            $v = $_meta[$k]
            if ($null -ne $v -and "$v" -ne '') { [void]$availKeys.Add([string]$k) }
        }
    } else {
        foreach ($p in $_meta.PSObject.Properties) {
            if ($null -ne $p.Value -and "$p.Value" -ne '') { [void]$availKeys.Add([string]$p.Name) }
        }
    }
    foreach ($f in $script:_SISchemaCache['IdentityEmitFields']) {
        $fname = [string]$f.name
        # Fast-null path: if field requires source keys and NONE are populated, emit null directly.
        $reqKeys = $f._SIRequiredKeys
        $skipResolve = $false
        if ($f.source -ne 'derived' -and $reqKeys -and $reqKeys.Count -gt 0) {
            $hasAny = $false
            foreach ($rk in $reqKeys) { if ($availKeys.Contains($rk)) { $hasAny = $true; break } }
            if (-not $hasAny) { $skipResolve = $true }
        }
        if ($skipResolve) { $row[$fname] = $null; continue }
        $val = if ($f.source -eq 'derived') {
            Get-SIDerivedValue -Field $f -Context $ctx
        } else {
            Resolve-SISourceValue -Field $f -Record $Record
        }
        # defensive shape for `type: dynamic` schema fields. If the
        # underlying DCR column was auto-created as `string` from an early
        # empty-array sample, AzLogDcrIngestPS coerces later array values via
        # space/empty-join (e.g. EntraRoles_Eligible came out as one big mashed
        # string while EntraRoles_Permanent stayed JSON because their DCR types
        # diverged). Force-serialize array/object values as JSON here so the
        # cell receives a parseable literal regardless of declared column type.
        # KQL reads `parse_json(col)` to recover the array shape.
        if ($f.type -eq 'dynamic' -and $null -ne $val) {
            $isArrayShape = ($val -is [System.Collections.IEnumerable]) -and -not ($val -is [string])
            $isObjectShape = ($val -is [System.Collections.IDictionary] -or $val -is [pscustomobject])
            if ($isArrayShape -or $isObjectShape) {
                try { $val = ConvertTo-Json -InputObject $val -Compress -Depth 12 } catch { }
            }
        }
        $row[$fname] = $val
    }

    $row['Properties'] = $properties

    # ---- CMDB / Reconcile flat columns ----
    # derive a numeric weight from cmdbCriticality so RA reports
    # can boost RiskScoreTotal proportionally to business criticality. Same
    # criticalityScoreMap (Critical=3 / High=2 / Medium=1 / Low=0) used by
    # endpoint + azure row builders for consistency.
    # 2026-05-02: defensive scalar coercion for cmdb* string columns. Without this,
    # if any upstream path leaves $Record.cmdbId as @{} (empty hashtable) or a
    # PSCustomObject, the DCR ingest serializes it to the literal string "{}" --
    # which then renders as `{}` in LA + Excel. The expected shape is a clean
    # string scalar; non-string objects/empty containers collapse to ''.
    $cmdbStringFields = @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity',
                          'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','LastSeenInCmdb')
    foreach ($f in $cmdbStringFields) {
        $v = if ($Record.PSObject.Properties[$f]) { $Record.$f } else { $null }
        if ($null -eq $v) { $row[$f] = $null; continue }
        if ($v -is [System.Collections.IDictionary] -or $v -is [pscustomobject] -or
            (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string]))) {
            # Empty container or object -- emit empty string, never `{}` literal.
            $row[$f] = ''
            continue
        }
        $row[$f] = [string]$v
    }
    # CmdbMatchConfidence is numeric -- pass through.
    $v = if ($Record.PSObject.Properties['CmdbMatchConfidence']) { $Record.CmdbMatchConfidence } else { $null }
    $row['CmdbMatchConfidence'] = $v
    # cmdbCriticalityScore moved to riskscore_weighted.schema.json
    # (declarative model). See Build-EndpointProfileRow.ps1 for the rationale.

    # ---- profile-time risk-factor derivations ----
    if (-not (Get-Command -Name Get-SIIdentityRiskFactors -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Get-SIRiskFactors.ps1')
    }
    # v2.2.374 -- avoid Add-Member-per-key loop. Same hashtable-union trick as v2.2.371 Azure.
    $rfHash = @{} + $row
    $rfHash['Verdict']  = $verdict
    $rfHash['Metadata'] = $Record.Metadata
    $rf = Get-SIIdentityRiskFactors -Record ([pscustomobject]$rfHash)
    foreach ($k in $rf.Keys) { $row[$k] = $rf[$k] }

    # ---- Hashes (4 per-stage) over schema-declared fields by writtenBy ----
    $collectFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'collect'         -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $enrichFieldNames   = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'enrich'          -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $postureFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'posture_analyze' -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $classifyFieldNames = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'classify'        -and $_.name -notmatch '^(CollectHash|EnrichHash|PostureHash|ClassifyHash)$' } | ForEach-Object { $_.name })

    $row['CollectHash']  = Get-SIRowHash (_SIHashBag $collectFieldNames  $row)
    $row['EnrichHash']   = Get-SIRowHash (_SIHashBag $enrichFieldNames   $row)
    $row['PostureHash']  = Get-SIRowHash (_SIHashBag $postureFieldNames  $row)
    $row['ClassifyHash'] = Get-SIRowHash (_SIHashBag $classifyFieldNames $row)

    return [pscustomobject]$row
}
