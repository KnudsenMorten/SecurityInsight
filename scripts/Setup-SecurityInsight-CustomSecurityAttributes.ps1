#Requires -Version 5.1
<#
.SYNOPSIS
    OPTIONAL one-time setup: provisions the 'SecurityInsight' Entra ID Custom
    Security Attributes (CSA) schema used by the asset tagging pipeline.

.DESCRIPTION
    This script is OPTIONAL. Run it ONCE per tenant, by an Entra admin who
    holds the elevated roles listed below. After it completes, the three
    CSA attributes (AssetTagName / AssetTier / AssetTagType) exist in the
    'SecurityInsight' AttributeSet and the pipeline identity has the
    'Attribute Assignment Administrator' role.

    What it does:
      1. Verifies / installs the required Microsoft.Graph modules
      2. Reuses an existing Microsoft Graph connection if present
         (launcher-provided), otherwise prompts interactively
      3. Creates the 'SecurityInsight' AttributeSet (idempotent)
      4. Creates the three attribute definitions (idempotent)
      5. Optionally grants the pipeline SPN / MI the CSA roles
      6. Optionally runs a test write + read + cleanup on a target object
      7. Reads back the schema and currently-tagged users + service principals

    Idempotent: re-running skips anything already in place.

.PARAMETER PipelinePrincipalId
    Object ID of the managed identity or service principal that runs the
    tagging pipeline. Granted the Attribute Assignment Administrator +
    Reader roles when supplied.

.PARAMETER TestObjectId
    Object ID of a user or service principal to use for the test write/read.
    Should be a non-production object. Leave empty to skip the test.

.PARAMETER TenantId
    Entra ID tenant ID. Required only when no Graph connection exists yet
    (interactive launch); ignored when a launcher has already connected.

.EXAMPLE
    # Direct interactive run (admin user):
    .\Setup-SecurityInsight-CustomSecurityAttributes.ps1 `
        -PipelinePrincipalId '<spn-object-id>' `
        -TestObjectId        '<test-user-object-id>' `
        -TenantId            '<tenant-guid>'

.EXAMPLE
    # Via launcher (Graph already connected by the launcher):
    .\launcher.community-vm.template.ps1

.NOTES
    Required Entra roles for the IDENTITY running THIS script:
      - Attribute Definition Administrator   (to create the schema)
      - Attribute Assignment Administrator   (to do the test write)
      - Privileged Role Administrator        (to grant the pipeline identity its role)

    A regular SPN with app-only Graph permissions is generally NOT enough --
    these are directory roles that must be explicitly assigned to the caller.

    Required PowerShell modules (installed automatically if missing):
      - Microsoft.Graph.Authentication
      - Microsoft.Graph.Identity.DirectoryManagement

    Solution       : SecurityInsight
    File           : Setup-SecurityInsight-CustomSecurityAttributes.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$PipelinePrincipalId,

    [Parameter(Mandatory = $false)]
    [string]$TestObjectId,

    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

# Match platform convention: StrictMode Off (engines wrap it defensively).
try { Set-StrictMode -Off } catch {}
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-Module -Name @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Identity.DirectoryManagement'
) -Import

# Allow launchers to pass values via globals when direct -param was not used.
if (-not $PipelinePrincipalId -and $global:SI_CSA_PipelinePrincipalId) { $PipelinePrincipalId = [string]$global:SI_CSA_PipelinePrincipalId }
if (-not $TestObjectId        -and $global:SI_CSA_TestObjectId)        { $TestObjectId        = [string]$global:SI_CSA_TestObjectId }
if (-not $TenantId            -and $global:SI_CSA_TenantId)            { $TenantId            = [string]$global:SI_CSA_TenantId }
if (-not $TenantId            -and $global:SpnTenantId)                { $TenantId            = [string]$global:SpnTenantId }

# -----------------------------
# CONSTANTS
# -----------------------------

$ATTRIBUTE_SET_ID   = 'SecurityInsight'
$GRAPH_BASE         = 'https://graph.microsoft.com/v1.0'

# Well-known Entra role definition IDs
$ROLE_ATTR_ASSIGNMENT_ADMIN  = '58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d'  # Attribute Assignment Administrator
$ROLE_ATTR_ASSIGNMENT_READER = 'ffd52fa5-98dc-465c-991d-fc073eb59f8f'  # Attribute Assignment Reader

$ATTRIBUTE_DEFINITIONS = @(
    @{
        name                    = 'AssetTagName'
        description             = 'Full asset tag name assigned by the SI tagging pipeline (e.g. GlobalAdmin--tier0--SI)'
        type                    = 'String'
        isCollection            = $false
        isSearchable            = $true
        usePreDefinedValuesOnly = $false
        allowedValues           = $null
    },
    @{
        name                    = 'AssetTier'
        description             = 'Asset criticality tier assigned by the SI tagging pipeline'
        type                    = 'String'
        isCollection            = $false
        isSearchable            = $true
        usePreDefinedValuesOnly = $true
        allowedValues           = @('tier0', 'tier1', 'tier2', 'tier3')
    },
    @{
        name                    = 'AssetTagType'
        description             = 'Asset tag type assigned by the SI tagging pipeline'
        type                    = 'String'
        isCollection            = $false
        isSearchable            = $true
        usePreDefinedValuesOnly = $true
        allowedValues           = @('AssetTier--SI')
    }
)

# -----------------------------
# HELPERS
# -----------------------------

function Write-Section ([string]$Title) {
    Write-Host ''
    Write-Host ('-' * 60) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('-' * 60) -ForegroundColor DarkGray
}

function Write-OK    ([string]$Msg) { Write-Host "  [OK]   $Msg" -ForegroundColor Green  }
function Write-Skip  ([string]$Msg) { Write-Host "  [SKIP] $Msg" -ForegroundColor Yellow }
function Write-Fail  ([string]$Msg) { Write-Host "  [FAIL] $Msg" -ForegroundColor Red    }
function Write-Info  ([string]$Msg) { Write-Host "  [INFO] $Msg" -ForegroundColor Gray   }

function Invoke-GraphRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Body = $null
    )
    $params = @{
        Method  = $Method
        Uri     = $Uri
        Headers = @{ 'Content-Type' = 'application/json' }
    }
    if ($Body) {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
    }
    try {
        return Invoke-MgGraphRequest @params
    }
    catch {
        $statusCode = $null
        try { $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}
        $gErrMsg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $detail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($detail -and $detail.error -and $detail.error.message) { $gErrMsg = $detail.error.message }
            } catch {}
        }
        throw "Graph API error [$statusCode] on $Method $Uri`n$gErrMsg"
    }
}

function Get-AllPages {
    param([string]$Uri)
    $results = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    do {
        $response = Invoke-GraphRequest -Method GET -Uri $nextUri
        if ($response.value) { foreach ($v in $response.value) { $results.Add($v) } }
        $nextUri = $response.'@odata.nextLink'
    } while ($nextUri)
    return $results
}

# -----------------------------
# STEP 0 - Modules and Graph connection
# -----------------------------

Write-Section 'STEP 0 - Module installation and Graph connection'

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Info "Installing module: $mod"
        Install-Module $mod -Scope CurrentUser -Force -Repository PSGallery
    }
    Import-Module $mod -ErrorAction SilentlyContinue
    Write-OK "Module ready: $mod"
}

$scopes = @(
    'CustomSecAttributeDefinition.ReadWrite.All',
    'CustomSecAttributeAssignment.ReadWrite.All',
    'RoleManagement.ReadWrite.Directory',
    'Directory.Read.All'
)

# Reuse existing Graph connection if a launcher has already signed in.
$context = $null
try { $context = Get-MgContext -ErrorAction SilentlyContinue } catch {}

if ($context -and $context.TenantId) {
    Write-OK "Reusing existing Graph connection: $($context.Account) | Tenant: $($context.TenantId)"
    Write-Info "Auth type: $($context.AuthType)  |  Scopes (sample): $((($context.Scopes) | Select-Object -First 4) -join ', ')"
} else {
    Write-Info 'No existing Graph context. Connecting interactively...'
    $connectParams = @{ Scopes = $scopes }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    Connect-MgGraph @connectParams | Out-Null
    $context = Get-MgContext
    Write-OK "Connected as: $($context.Account) | Tenant: $($context.TenantId)"
}

# -----------------------------
# STEP 1 - Create AttributeSet
# -----------------------------

Write-Section "STEP 1 - Create AttributeSet '$ATTRIBUTE_SET_ID'"

$setExists = $false
try {
    Invoke-GraphRequest -Method GET -Uri "$GRAPH_BASE/directory/attributeSets/$ATTRIBUTE_SET_ID" | Out-Null
    $setExists = $true
} catch {
    $setExists = $false
}

if ($setExists) {
    Write-Skip "AttributeSet '$ATTRIBUTE_SET_ID' already exists - skipping creation"
} else {
    if ($PSCmdlet.ShouldProcess("AttributeSet '$ATTRIBUTE_SET_ID'", 'Create')) {
        $body = @{
            id                  = $ATTRIBUTE_SET_ID
            description         = 'Asset criticality classification for SecurityInsight tagging pipeline'
            maxAttributesPerSet = 500
        }
        Invoke-GraphRequest -Method POST -Uri "$GRAPH_BASE/directory/attributeSets" -Body $body | Out-Null
        Write-OK "Created AttributeSet '$ATTRIBUTE_SET_ID'"
    }
}

# -----------------------------
# STEP 2 - Create attribute definitions
# -----------------------------

Write-Section 'STEP 2 - Create attribute definitions'

$existingDefs = Get-AllPages -Uri "$GRAPH_BASE/directory/customSecurityAttributeDefinitions?`$filter=attributeSet eq '$ATTRIBUTE_SET_ID'"
$existingNames = @($existingDefs | Select-Object -ExpandProperty name)

foreach ($attr in $ATTRIBUTE_DEFINITIONS) {

    if ($existingNames -contains $attr.name) {
        Write-Skip "Attribute '$($attr.name)' already exists - skipping"
        continue
    }

    $body = @{
        attributeSet            = $ATTRIBUTE_SET_ID
        description             = $attr.description
        isCollection            = $attr.isCollection
        isSearchable            = $attr.isSearchable
        name                    = $attr.name
        status                  = 'Available'
        type                    = $attr.type
        usePreDefinedValuesOnly = $attr.usePreDefinedValuesOnly
    }

    if ($attr.allowedValues) {
        $body['allowedValues'] = @(
            $attr.allowedValues | ForEach-Object { @{ id = $_; isActive = $true } }
        )
    }

    if ($PSCmdlet.ShouldProcess("Attribute '$($attr.name)'", 'Create')) {
        Invoke-GraphRequest -Method POST `
            -Uri "$GRAPH_BASE/directory/customSecurityAttributeDefinitions" `
            -Body $body | Out-Null
        Write-OK "Created attribute '$($attr.name)' [$($attr.type), predefinedOnly=$($attr.usePreDefinedValuesOnly)]"
    }
}

# -----------------------------
# STEP 3 - Grant pipeline identity the CSA roles
# -----------------------------

Write-Section 'STEP 3 - Grant pipeline identity role assignments'

if (-not $PipelinePrincipalId) {
    Write-Skip 'No PipelinePrincipalId provided - skipping role assignment'
}
else {
    foreach ($roleId in @($ROLE_ATTR_ASSIGNMENT_ADMIN, $ROLE_ATTR_ASSIGNMENT_READER)) {

        if ($roleId -eq $ROLE_ATTR_ASSIGNMENT_ADMIN) {
            $roleName = 'Attribute Assignment Administrator'
        } else {
            $roleName = 'Attribute Assignment Reader'
        }

        $filter  = "roleDefinitionId eq '$roleId' and principalId eq '$PipelinePrincipalId'"
        $encoded = [Uri]::EscapeDataString($filter)
        $existingAssignments = Get-AllPages -Uri "$GRAPH_BASE/roleManagement/directory/roleAssignments?`$filter=$encoded"

        if ($existingAssignments.Count -gt 0) {
            Write-Skip "Role '$roleName' already assigned to principal $PipelinePrincipalId"
            continue
        }

        if ($PSCmdlet.ShouldProcess("Principal $PipelinePrincipalId", "Assign role '$roleName'")) {
            $body = @{
                roleDefinitionId = $roleId
                principalId      = $PipelinePrincipalId
                directoryScopeId = '/'
            }
            Invoke-GraphRequest -Method POST `
                -Uri "$GRAPH_BASE/roleManagement/directory/roleAssignments" `
                -Body $body | Out-Null
            Write-OK "Assigned '$roleName' to principal $PipelinePrincipalId"
        }
    }
}

# -----------------------------
# STEP 4 - Test write + read on a target object
# -----------------------------

Write-Section 'STEP 4 - Test write and read (verification)'

if (-not $TestObjectId) {
    Write-Skip 'No TestObjectId provided - skipping test write/read'
}
else {
    $objectUri  = $null
    $objectType = $null

    foreach ($candidate in @('users', 'servicePrincipals')) {
        try {
            Invoke-GraphRequest -Method GET -Uri "$GRAPH_BASE/$candidate/$TestObjectId" | Out-Null
            $objectUri  = "$GRAPH_BASE/$candidate/$TestObjectId"
            $objectType = $candidate
            break
        }
        catch { }
    }

    if (-not $objectUri) {
        Write-Fail "TestObjectId '$TestObjectId' not found as user or servicePrincipal - skipping test"
    }
    else {
        Write-Info "Target object type: $objectType"

        $testTagName = 'TestTag--tier0--SI'
        $writeBody = @{
            customSecurityAttributes = @{
                $ATTRIBUTE_SET_ID = @{
                    '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'
                    AssetTagName  = $testTagName
                    AssetTier     = 'tier0'
                    AssetTagType  = 'AssetTier--SI'
                }
            }
        }

        if ($PSCmdlet.ShouldProcess("$objectType/$TestObjectId", 'Write test CSA values')) {
            Invoke-GraphRequest -Method PATCH -Uri $objectUri -Body $writeBody | Out-Null
            Write-OK "Test CSA values written to $objectType/$TestObjectId"
        }

        $readback = Invoke-GraphRequest -Method GET `
            -Uri "$objectUri`?`$select=id,displayName,customSecurityAttributes"

        $csa = $readback.customSecurityAttributes.$ATTRIBUTE_SET_ID

        if ($csa -and $csa.AssetTagName -eq $testTagName) {
            Write-OK 'Read-back verified:'
            Write-Info "  AssetTagName : $($csa.AssetTagName)"
            Write-Info "  AssetTier    : $($csa.AssetTier)"
            Write-Info "  AssetTagType : $($csa.AssetTagType)"
        }
        else {
            Write-Fail 'Read-back did not return expected values. Raw CSA response:'
            Write-Host ($csa | ConvertTo-Json -Depth 5) -ForegroundColor Red
        }

        $cleanupBody = @{
            customSecurityAttributes = @{
                $ATTRIBUTE_SET_ID = @{
                    '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'
                    AssetTagName  = $null
                    AssetTier     = $null
                    AssetTagType  = $null
                }
            }
        }
        if ($PSCmdlet.ShouldProcess("$objectType/$TestObjectId", 'Remove test CSA values')) {
            Invoke-GraphRequest -Method PATCH -Uri $objectUri -Body $cleanupBody | Out-Null
            Write-OK "Test CSA values cleaned up from $objectType/$TestObjectId"
        }
    }
}

# -----------------------------
# STEP 5 - Read back full schema
# -----------------------------

Write-Section 'STEP 5 - Read back schema'

$defs = Get-AllPages -Uri "$GRAPH_BASE/directory/customSecurityAttributeDefinitions?`$filter=attributeSet eq '$ATTRIBUTE_SET_ID'"

Write-OK "Attribute definitions in '$ATTRIBUTE_SET_ID':"
$defs | ForEach-Object {
    Write-Info ('  {0,-20} type={1,-8} searchable={2} predefined={3} status={4}' -f `
        $_.name, $_.type, $_.isSearchable, $_.usePreDefinedValuesOnly, $_.status)

    if ($_.allowedValues) {
        $vals = ($_.allowedValues | ForEach-Object { $_.id }) -join ', '
        Write-Info "    AllowedValues: $vals"
    }
}

# -----------------------------
# STEP 6 - Read currently tagged users and service principals
# -----------------------------

Write-Section 'STEP 6 - Read currently tagged users and service principals'

Write-Info 'Querying tagged users...'
$taggedUsers = Get-AllPages -Uri (
    "$GRAPH_BASE/users" +
    "?`$select=id,displayName,userPrincipalName,userType,customSecurityAttributes" +
    "&`$filter=customSecurityAttributes/$ATTRIBUTE_SET_ID/AssetTagName ne null"
)

if ($taggedUsers.Count -eq 0) {
    Write-Info '  No tagged users found'
}
else {
    Write-OK "Tagged users ($($taggedUsers.Count)):"
    $taggedUsers | ForEach-Object {
        $csa = $_.customSecurityAttributes.$ATTRIBUTE_SET_ID
        Write-Info ('  {0,-40} {1,-12} {2}' -f `
            $_.userPrincipalName, $csa.AssetTier, $csa.AssetTagName)
    }
}

Write-Info 'Querying tagged service principals...'
$taggedSPs = Get-AllPages -Uri (
    "$GRAPH_BASE/servicePrincipals" +
    "?`$select=id,displayName,appId,customSecurityAttributes" +
    "&`$filter=customSecurityAttributes/$ATTRIBUTE_SET_ID/AssetTagName ne null"
)

if ($taggedSPs.Count -eq 0) {
    Write-Info '  No tagged service principals found'
}
else {
    Write-OK "Tagged service principals ($($taggedSPs.Count)):"
    $taggedSPs | ForEach-Object {
        $csa = $_.customSecurityAttributes.$ATTRIBUTE_SET_ID
        Write-Info ('  {0,-40} {1,-12} {2}' -f `
            $_.displayName, $csa.AssetTier, $csa.AssetTagName)
    }
}

Write-Section 'COMPLETE'
Write-OK "AttributeSet '$ATTRIBUTE_SET_ID' is ready for the SecurityInsight tagging pipeline"
Write-Host ''
