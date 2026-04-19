#Requires -Version 5.1
<#
.SYNOPSIS
    Community-edition customer configuration for Setup-SecurityInsight-CustomSecurityAttributes
    (OPTIONAL one-time setup).

.DESCRIPTION
    Copy this file to LauncherConfig.ps1 in the SAME folder and fill in the values
    below. LauncherConfig.ps1 is .gitignore'd so the populated copy stays on your
    machine.

    This engine is OPTIONAL: run it ONCE per tenant to provision the Entra Custom
    Security Attribute schema used by the SecurityInsight tagging pipeline.

    WHO CAN RUN THIS
    The IDENTITY that authenticates must hold these Entra roles in the tenant:
      - Attribute Definition Administrator   (to create the CSA schema)
      - Attribute Assignment Administrator   (for the optional test write)
      - Privileged Role Administrator        (to grant the pipeline SPN its role)

    These are elevated directory roles, typically held by a HUMAN admin. A plain
    app-only SPN will usually NOT be sufficient. Preferred path:
      -> launcher.community-vm.template.ps1 run interactively by an admin user.

    AUTHENTICATION METHODS (pick ONE)
    The launcher resolves auth in this priority order (first match wins):

      1. Interactive (no creds set)                    - DEFAULT for this engine
      2. Managed Identity                              - only if MI has been
                                                         granted the Entra roles
      3. SPN + Key Vault-stored secret                 - only if SPN has been
                                                         granted the Entra roles
      4. SPN + certificate                             - ditto
      5. SPN + plaintext secret                        - testing only

.NOTES
    Solution       : SecurityInsight
    File           : LauncherConfig.sample.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>

# ================================================================================
#  ENGINE PARAMETERS  (applied in every auth mode)
# ================================================================================
# Tenant where you want the SecurityInsight CSA schema created. Required.
$global:SI_CSA_TenantId            = '<your-tenant-id-guid>'

# Object ID of the Managed Identity / Service Principal that will RUN the tagging
# pipeline (CriticalAssetTagging engine). It is granted Attribute Assignment
# Administrator + Reader. Leave empty to skip the role grant.
$global:SI_CSA_PipelinePrincipalId = ''

# Optional: Object ID of a non-production user or service principal used for the
# STEP 4 test write+read+cleanup. Leave empty to skip the test.
$global:SI_CSA_TestObjectId        = ''


# ================================================================================
#  METHOD 1 -- INTERACTIVE  (DEFAULT and recommended for this engine)
# ================================================================================
# Leave all $global:Spn* / $global:UseManagedIdentity values EMPTY / unset.
# The launcher will skip its Connect-* step and the engine will prompt you to
# sign in as an admin user (browser device-code flow).
#
# No extra config needed for this mode.


# ================================================================================
#  METHOD 2 -- Managed Identity
#  (Only works if the MI has been granted the elevated Entra roles above)
# ================================================================================
# $global:UseManagedIdentity = $true
# $global:SpnTenantId        = '<your-tenant-id-guid>'


# ================================================================================
#  METHOD 3 -- Service Principal + Key Vault-stored secret
# ================================================================================
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnKeyVaultName = '<kv-name>'
# $global:SpnSecretName   = 'SecurityInsight-Secret'


# ================================================================================
#  METHOD 4 -- Service Principal + certificate
# ================================================================================
# $global:SpnTenantId              = '<your-tenant-id-guid>'
# $global:SpnClientId              = '<your-app-client-id-guid>'
# $global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'


# ================================================================================
#  METHOD 5 -- Service Principal + plaintext secret  *** TESTING ONLY ***
# ================================================================================
# $global:SpnTenantId     = '<your-tenant-id-guid>'
# $global:SpnClientId     = '<your-app-client-id-guid>'
# $global:SpnClientSecret = '<your-client-secret>'
