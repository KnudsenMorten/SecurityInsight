#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE DATABASE GRANTS OF THE WEB APP AND ITS MCP SERVER, ONE LIST FOR EVERY PATH (#352).

    Read by pro-management\deploy\Deploy-SIManagement.ps1 -GrantSql (the install: database users + these grants, as the
    server's Entra admin) AND by the product updater (caj-si-updater, container\updater\_shared\SI-UpdaterDatabase.ps1),
    which re-applies the GRANTS (never a user, never a fixed-role membership) after it applied a release's schema -- a new
    table the new code writes needs its grant before that code runs (#306 cfg.PipelineQueue, #345 cfg.WebKeyRing).
    One list, so the install and the update can never grant differently. WebWriteGrantsTests compares the list with every
    INSERT / UPDATE / DELETE / MERGE / EXEC in the web app's code, so a new table cannot ship without its grant.
    Every grant runs only when its table exists (a database can be one schema version behind). Strict-mode safe; PS 5.1.
#>

# The web app's writes beyond cfg.Setting / cfg.ChangeLog / the audit role -- one row per table, the verbs its code uses.
$script:WebWriteGrants = @(
    @{ Object = 'cfg.AccessAssignment';        Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.AccessCarriedOver';       Verbs = 'INSERT' }   # #765: the Entra app roles carried over into Access (a mark, never deleted)
    @{ Object = 'cfg.CategoryRole';            Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ChangeAttribution';       Verbs = 'INSERT' }
    @{ Object = 'cfg.CmdbService';             Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.CmdbServiceAsset';        Verbs = 'INSERT, UPDATE' }   # #404: an undo / restore unlinks or relinks a member
    @{ Object = 'cfg.CmdbImportSnapshot';      Verbs = 'EXECUTE' }
    @{ Object = 'cfg.CollectionSend';          Verbs = 'INSERT, UPDATE' }   # #404: resend a collection / undo a connector run (the request)
    @{ Object = 'cfg.ColumnLayout';            Verbs = 'INSERT, UPDATE, DELETE' }   # the CI grid's columns: a person's own / the tenant default; reset removes one
    @{ Object = 'cfg.ConfigApproval';          Verbs = 'INSERT, UPDATE' }   # #404 CONFIG-1.5: a release / restore waiting for a second SuperAdmin
    @{ Object = 'cfg.ConfigBackupImport';      Verbs = 'EXECUTE' }          # #404 CONFIG-1.3: the backups are written only through their procedures
    @{ Object = 'cfg.ConfigBackupPin';         Verbs = 'EXECUTE' }
    @{ Object = 'cfg.ConfigBackupTake';        Verbs = 'EXECUTE' }
    @{ Object = 'cfg.Connector';               Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.Department';              Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.DepartmentAdvisor';       Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.DepartmentMember';        Verbs = 'INSERT, UPDATE, DELETE' }   # #404: an undo / restore sets a member back
    @{ Object = 'cfg.DepartmentSignIn';        Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.DepartmentSignInCode';    Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.Document';                Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.DomainRole';              Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.Exemption';               Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ExemptionMail';           Verbs = 'INSERT' }
    @{ Object = 'cfg.ExemptionRequest';        Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ExemptionRequestItem';    Verbs = 'INSERT' }
    @{ Object = 'cfg.FindingComment';          Verbs = 'INSERT' }
    @{ Object = 'cfg.FindingTask';             Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.FindingTaskHistory';      Verbs = 'INSERT' }
    @{ Object = 'cfg.GovernanceEntry';         Verbs = 'INSERT' }
    @{ Object = 'cfg.GovernanceMail';          Verbs = 'INSERT' }
    @{ Object = 'cfg.GovernanceState';         Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.GuardAck';                Verbs = 'INSERT' }
    @{ Object = 'cfg.GuardEvent';              Verbs = 'INSERT' }
    @{ Object = 'cfg.GuardRelease';            Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.InstallKeyClaimAgainRequest'; Verbs = 'EXECUTE' }      # Settings > Updates: claim the install key again (one row, never the table)
    @{ Object = 'cfg.GuardStrictEndSet';       Verbs = 'EXECUTE' }      # CR4: a SuperAdmin ends the stricter period of the safety checks early (one row, never the table)
    @{ Object = 'cfg.DataHealthOverrideSet';   Verbs = 'EXECUTE' }      # CR2: a SuperAdmin lets one data-out channel through while the data is Unhealthy (never the table)
    @{ Object = 'cfg.FlowRunCancelSet';        Verbs = 'EXECUTE' }      # #700: Operations > Jobs cancels the RUNNING run (its run, queue request and lock; one run, never the table)
    @{ Object = 'cfg.ItemOverride';           Verbs = 'INSERT, UPDATE, DELETE' }
    @{ Object = 'cfg.JobFlow';                 Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.PipelineQueue';           Verbs = 'INSERT, UPDATE' }   # #306: Run now requests + Cancel
    @{ Object = 'cfg.JobTriggerRequest';       Verbs = 'INSERT, UPDATE' }   # CR8: a job's trigger change, applied by the pipeline runner (start-only rights on the jobs); #931: a start's own values, bound to the execution after the start
    @{ Object = 'cfg.SignedRequest';           Verbs = 'INSERT' }           # CR8 step 2 (observe only): each change with the person's signed token
    @{ Object = 'cfg.PendingSecret';           Verbs = 'INSERT, DELETE' }   # the secret hand-over: ciphertext only; a new paste replaces the one still waiting
    @{ Object = 'cfg.MgmtReport';              Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.PivotView';               Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.RaBucketReset';           Verbs = 'INSERT' }   # #640: a one-time reset of a report's bucket count (the run consumes it)
    @{ Object = 'cfg.RaSourceAccept';          Verbs = 'INSERT, UPDATE' }   # #902: an Admin accepts a report's source as empty for good / undoes it
    @{ Object = 'cfg.ReportMail';              Verbs = 'INSERT' }
    @{ Object = 'cfg.RemediationFlow';         Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ResponsibilityOverride';  Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ResponsibilityRule';      Verbs = 'INSERT, UPDATE, DELETE' }   # #404: an undo / restore sets a rule back
    @{ Object = 'cfg.SignInMail';              Verbs = 'INSERT' }
    @{ Object = 'cfg.VerificationDecision';    Verbs = 'INSERT, UPDATE' }   # Operations > Verification (data gaps): ignore / accept a data-collection gap; a review replaces the decision (RevokedAt)
    @{ Object = 'cfg.ViewLayout';              Verbs = 'INSERT, UPDATE, DELETE' }   # a data view's named layouts: a person's own, or published by an Admin; delete removes one
    @{ Object = 'cfg.ViewState';               Verbs = 'INSERT, UPDATE' }
    @{ Object = 'cfg.ViewPin';                 Verbs = 'INSERT, UPDATE, DELETE' }   # a named layout pinned to the menu (My views, or by an Admin for everyone); unpin removes one   # a person's last sort / filters and column widths per data view
    # MAIL-1: the guided mail setup records the Exchange administrator's confirmation (one row, never the table)
    @{ Object = 'cfg.MailRestrictionAttestationSet'; Verbs = 'EXECUTE' }
    @{ Object = 'cfg.WebKeyRing';              Verbs = 'INSERT' }
    @{ Object = 'sidata.Collection';           Verbs = 'UPDATE' }
    @{ Object = 'sidata.CiOverride';           Verbs = 'INSERT, UPDATE' }   # #462: an Admin's manual CI override (a removal is soft: an UPDATE)
    @{ Object = 'cmdbsync.AssetLifecycle';      Verbs = 'UPDATE' }   # #406: an Admin retires an asset in its grace period early (Not seen anymore)
    @{ Object = 'cmdbsync.AssetLifecycleEvent'; Verbs = 'INSERT' }   # #406: ... with who and why
)

# Writes an earlier release granted the web app and this one no longer needs -- REVOKED from the web identity by the
# install and by every update, so an install upgraded from that release loses them too (a GRANT list alone never takes
# a right away). cfg.InstallState: the web app writes its two rows only through procedures (MAIL-1 confirmation, the
# install-key claim); the licence, the ring, the update state and the proven mail restriction are not the web app's.
$script:WebRevokedWrites = @(
    'INSERT, UPDATE ON OBJECT::cfg.InstallState'
)

function Get-SIManagementSid {
    <# PURE. The database SID of an Entra identity by its client id (CREATE USER ... WITH SID = <this>, TYPE = E). #>
    param([Parameter(Mandatory)][string]$ClientId)
    if ($ClientId -like '<*') { return '<client id as binary>' }
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SIManagementGrantSql {
    <#
        PURE. The GRANTS only -- what the install AND the updater apply for an existing database user (-UserName):
          -Writer (the web app): cfg.Setting / cfg.ChangeLog, the audit writer role (#260) and every table of WebWriteGrants;
          else    (the MCP server, read-only): DENY SELECT on cfg.WebKeyRing (#345: a key could forge a sign-in cookie).
        No CREATE USER and no fixed-role membership: those are the install's (they need the server's Entra admin).
    #>
    param([Parameter(Mandatory)][string]$UserName, [switch]$Writer)
    $n = $UserName.Replace(']', ']]')
    $sql = ''
    if ($Writer) {
        $sql += @"
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL GRANT INSERT, UPDATE, DELETE ON OBJECT::cfg.Setting TO [$n];
IF OBJECT_ID(N'cfg.ChangeLog') IS NOT NULL GRANT INSERT ON OBJECT::cfg.ChangeLog TO [$n];
-- #260: the audit trail -- the writer's role is INSERT + SELECT only (no UPDATE / DELETE on the trail; sql\si-pro-settings.sql creates it)
IF DATABASE_PRINCIPAL_ID(N'si_audit_writer') IS NOT NULL EXEC (N'ALTER ROLE si_audit_writer ADD MEMBER [$n]');
"@
        foreach ($g in $script:WebWriteGrants) {
            $sql += "`nIF OBJECT_ID(N'$($g.Object)') IS NOT NULL EXEC (N'GRANT $($g.Verbs) ON OBJECT::$($g.Object) TO [$n]');"
        }
        foreach ($r in $script:WebRevokedWrites) {
            $obj = ($r -split 'OBJECT::')[1]
            $sql += "`nIF OBJECT_ID(N'$obj') IS NOT NULL EXEC (N'REVOKE $r FROM [$n]');"
        }
        $sql += "`n"
    }
    else {
        # #345: the web app's sign-in key ring is not for a read-only identity (a key could forge a sign-in cookie)
        $sql += "IF OBJECT_ID(N'cfg.WebKeyRing') IS NOT NULL EXEC (N'DENY SELECT ON OBJECT::cfg.WebKeyRing TO [$n]');`n"
        # CR8 step 2: the people's signed tokens (kept until the pipeline runner verified them) are not for a read-only identity
        $sql += "IF OBJECT_ID(N'cfg.SignedRequest') IS NOT NULL EXEC (N'DENY SELECT ON OBJECT::cfg.SignedRequest TO [$n]');`n"
    }
    $sql
}

function Get-SIManagementUserSql {
    <#
        PURE. The install's statements for one identity (@{ Name; ClientId }): the contained user by its client id (no
        directory lookup by the server -- FROM EXTERNAL PROVIDER would need the server's own identity to read Entra),
        db_datareader, then Get-SIManagementGrantSql.
    #>
    param([Parameter(Mandatory)]$Identity, [switch]$Writer)
    $n = [string]$Identity.Name
    $sql = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$n')
    CREATE USER [$n] WITH SID = $(Get-SIManagementSid -ClientId ([string]$Identity.ClientId)), TYPE = E;
ALTER ROLE db_datareader ADD MEMBER [$n];

"@
    $sql + (Get-SIManagementGrantSql -UserName $n -Writer:$Writer)
}
