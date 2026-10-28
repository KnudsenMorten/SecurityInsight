#Requires -Version 5.1
<#
    THE CI BUILD IN SQL (#477 steps 2-4, V3-DATA-MODEL 2.20 -- operator 2026-10-09: "we dont support la for correlation,
    sql only", "la is slow"; #501 "performance and cost must be optimed"). The SQL the CI build runs and the items it
    writes -- every statement set-based, one per batch:

      grouping      connected components over sidata.RecordIdentifier, IN SQL: label propagation (every record starts
                    with its own key as its label; each round a record takes the smallest label of the records it shares
                    an identifier with) until nothing changes -> sidata.CiGroupMember (record -> group, batch number).
                    Ordinal (binary) comparison, so the smallest label is the same on every host.
      feeds         per provider + record type: the newest collection and whether it was complete (link states)
      batch         one batch's records (~2,000 CIs): the record JSON + the COLUMNS that change every run (collection time,
                    complete, source last seen -- the JSON may be older when the content did not change)
      ledger        only the batch's identifiers and the ids they point at (the identity ledger may be another database)
                    and the batch's ledger changes in ONE statement (not one per identifier)
      CIs           sidata.Ci / sidata.CiLink / sidata.CiDaily and the records' CiId -- a CI whose CONTENT did not change
                    (hash) is not rewritten; only its last seen is kept current
      SI_CI_CL      the correlated data in Log Analytics for Risk Analysis's Kusto (operator: "we need correlated data in
                    kusto right in la") -- TWO row kinds in the one table (si_row_kind; cheaper than a second table: no
                    new table or rule, the same ingestion, and a slim row is a few columns): a SLIM 'seen' row for EVERY
                    CI every build (id, collection time, content hash, last seen in the source) -- the set of CIs is the
                    newest build's seen rows; a FULL row (only the columns Risk Analysis reads) when the CI's posted
                    content changed, plus a full refresh of every CI when the last one is older than -FullPostDays.
                    Readers (RA-CiContext) take the set from the newest seen rows and each CI's properties from its
                    latest full row within SI_ActiveStaleDays (default 30) -- a device off for a week keeps its
                    properties. The column contract: V3-DATA-MODEL 2.21 (ConvertTo-SICiPostRow).

    Free code (both editions: SQL is required in every v3 install, #477 / #480). It never reads Log Analytics.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIContentHash -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecordSql.ps1') }
# #406 the asset lifecycle's settings and day thresholds (Get-SICiTimeThresholds)
if (-not (Get-Command -Name Get-SICiLifecycleSettings -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-CiLifecycle.ps1') }

# #534 THE BUILD VERSION -- part of the build fingerprint. Bump it ONLY when a change alters what a CI looks like (every CI is
# then rebuilt once); a release that does not is incremental. SICiBuildLogicHash is the logic it was set for
# (Get-SICiBuildLogicHash): the guard test fails when the logic changes without a decision -- bump the version, or, when CIs
# come out the same, re-baseline the hash.
# Version 3 (finding fields) also covers the risk factor model v2 CI changes merged beside it (factor impacts / shortName /
# state on each CI factor, the break-glass classification): both ship in the same release, so ONE rebuild covers both --
# the hash is re-baselined to the merged logic, the version stays 3. The same holds for the classification fix that ships
# with them (a row's list of values is read item by item): one rebuild, version 3.
# Version 4 (2026-10-11): the operator's tier tag is a CI rule claim (asserted, low priority) -- a device tagged tier 2
# that nothing observed claims now gets tier 2 instead of the default 3, so every CI is rebuilt once.
# Version 5 (2026-10-11, #579): every CI explains its tier in one sentence (si_tier_explanation), the claims carry what
# matched, a tag-decided tier says so (si_tier_set_by = tag), a claim's mechanism is the evidence that matched, and the rule
# files' bare tier tag patterns are gone (a PAW was a "Domain Controller") -- every CI is rebuilt once.
# Version 6 (2026-10-11): Azure child resources roll up into their parent CI -- the parent lists them (si_child_resources,
# si_vm_extensions, ...) and links their ids; only the listed Azure types are CIs. (Version 5 is taken by the tier
# explanation, built beside this.)
# Version 7 (2026-10-11): rich context from every source -- a CI carries what Entra, Azure, Intune, Defender, the public IP scan
# and the CMDB know about it (names next to ids, owners, backup, access, risk, sign-ins, hardening ...) and the business
# service's support and assignment groups, so every CI is rebuilt once.
# Version 8 (2026-10-13, #642): an identity ledger id that, by proof, holds several objects (e.g. 11 same-named service
# principals) is split -- each object its own CI, the one the id was minted from keeps it; ids several groups still share are
# built as ONE CI from all their records (never the first group kept); a cloud resource's last seen is the time its source
# listed it. Every CI is rebuilt once -- that rebuild is what repairs the wrong merges an install already has.
# Version 8 (2026-10-13, #643): asset tagging is OFF unless the customer setting SI_AssetTagging_Enabled is a real true --
# then every asset-tagging CI rule is not_used and the tags those rules name are taken off a CI even when a provider brings
# them back; on, a rule runs only when its AutoExcludeRules switch is TRUE (no file / no switch = off). The exclusion tags
# nobody chose come off the CIs, so every CI is rebuilt once.
# Version 9 (2026-10-15, #690 (48)): an identity takes the tier of the highest privilege it holds today -- new identity tier
# rules from the privilege tier catalog (Entra roles permanent and eligible, Azure RBAC at its scope, application permissions,
# critical AD groups), and a condition reads an object value (an Azure role assignment) by its properties. An identity's
# si_tier, its claims and its tier explanation change, so every CI is rebuilt once.
# Version 10 (2026-10-19, #406 / V3-DATA-MODEL 2.5.5): the CI lifecycle is the designed one -- a device its source still lists
# but has not seen within the seen window is not seen, a CI is retired after its category's grace period (default 30 days,
# SI_Pro_AssetRetire_GraceDays_*) or at once when every link is gone, a collection scope change freezes, and every CI carries
# si_lifecycle_since / si_lifecycle_reason / si_not_seen_days. Lifecycles and the stale-record field resolution change, so
# every CI is rebuilt once and the changed CIs' full rows are posted to SI_CI_CL by that build.
# The same version 10 (2026-10-19, #772): every CI carries its OS family (si_os_family: Windows, Linux, macOS, iOS, Android,
# Network OS, Other, Unknown -- the classification's new asset target over the OS name / platform and the device category),
# posted to SI_CI_CL and stored in sidata.Ci.OsFamily. Both changes ship together, so ONE bump (9 -> 10) rebuilds every CI once.
$script:SICiBuildVersion = 10
# The three context lanes merged on si-v3 (2026-10-11): the logic hash is set once for the combined code.
# 2026-10-12: the build's last write fills the columns the CI views read (Pro) -- no CI comes out different, so the hash is
# re-baselined and the version stays 7. (Same day: a failure of that step is said at INFO, never as a warning of the build.)
# 2026-10-13: a long list (a device's installed software) is matched once per rule pattern, the patterns are built once,
# and a batch that takes long says which CI it is working on -- the same CIs come out, so the hash is re-baselined and the
# version stays 7. (It also covers the identity ledger's long identifiers and the batch lines of 2026-10-12, and the time
# limit of one CI's rules: a CI the limit stops is kept out until it is fully evaluated -- nothing of it is written or
# sent, what it had stays, and the next run builds it with every rule -- so a CI that is written is the same as before.)
# 2026-10-13 (#642 + #643, version 8): the identity ledger's wrong merges, one CI per shared id, a cloud CI's last seen; asset tagging off by default.
# 2026-10-15 (#666, Risk Analysis per-row speed): SI-Classification.ps1's finding-row path (ConvertTo-SIFindingClassificationItem,
# Set-SIRaRowDimensions -- Risk Analysis only) got faster; the CI side (New-SIClassificationIndex, Get-SIClassificationValue,
# Set-SICiSqlIaasLinks) only builds its lists with ::new() instead of New-Object -- no CI comes out different, so the hash is
# re-baselined and the version stays 8.
# 2026-10-16 (#690 (48), version 9): the identity privilege tier rules + an object value matched by its properties.
# 2026-10-17 (#739, correlation speed): the same CIs with less work per CI -- no pipelines in the per-CI steps, a text compared
# in place, a classification row / factor leaf / conditions-list entry whose field the CI does not carry decided without
# evaluating it, the factor catalog read once per set, the identity ledger's keys made once per resolve, the threads' shared objects prepared on one thread, a build clock for
# tests. Proven CI for CI against the released build (tests\pester\SIv3-CiBuildSpeed.Tests.ps1 + the offline measurement on the
# test VM) -- no CI comes out different, so the hash is re-baselined and the version stays 9.
# 2026-10-18 (#496, rc11): an install with no business service at all is said in one plain INFO line (Get-SICiNoServiceText) --
# a log line only, no CI comes out different, so the hash is re-baselined and the version stays 9.
# 2026-10-18 (rc12): one CI too large for a Log Analytics post is sent to SI_CI_CL cut to fit (Limit-SICiPostRowSize) instead
# of failing its batch -- the CI itself (SQL) does not change, so the hash is re-baselined and the version stays 9.
# 2026-10-18 (#500, rc12): the ledger type CloudNativeResourceId (mdc_native_resource_id, a resource in AWS / GCP) -- only the new
# multicloud records carry it, no existing CI comes out different, so the hash is re-baselined and the version stays 9.
# 2026-10-19 (rc12 gate): the new CI fields of #497 / #499 / #500 are posted to SI_CI_CL (the end-of-support list database
# only) -- the SI_CI_CL column contract changes (every CI's full row is posted once), the CI itself (SQL) does not, so the
# hash is re-baselined and the version stays 9.
# 2026-10-19 (version 10, rc14 -- two changes merged into ONE version bump 9 -> 10): (#406) the designed CI lifecycle
# (SI-CiLifecycle.ps1 joins the build logic) -- CIs come out different; (#772 subci) the OS family (si_os_family) -- a new
# asset target of the classification, posted to SI_CI_CL; SI-Classification.ps1 also gains the finding side (the ServiceNow
# sub-CI reads the component; a dimension's default is the fallback; a finding row's own OS family; the patch cycle's facts and
# the Microsoft update release dates by KB, finding rows only). The hash is re-baselined over the merged code.
# 2026-10-20 (rc14 gate): si_banner_first_seen is posted to SI_CI_CL (it was database only, so the reports read it empty) -- the
# column contract changes (rc14 posts every CI's full row once anyway), the CI itself (SQL) does not: re-baselined, version 10.
# Same day: SI-Classification.ps1 writes a finding row's si_cve_published in the invariant culture (a da-DK install wrote
# "T00.00.00Z") -- finding rows only, no CI comes out different: re-baselined, version 10.
# 2026-10-23 (#891 part 3):SI-CiBuildRun.ps1 reads SecurityInsight's own CMDB cache through the CMDB
# cache's page reader (Read-SICmdbTablePages: the shared storage helper's retry, every page to the end) instead of its own
# copy of the same loop, and the whole-index fallback refuses a cache read that could not finish. The staged path (every
# updated database) already read every page and threw on a failed page: the same items, the same CIs. Only a FAILED read
# changes (a named build issue instead of a short CMDB) -- no CI built from a cache that was read comes out different, so
# the hash is re-baselined and the version stays 10.
# 2026-10-23: SI-CiBuildRun.ps1 hands the CI workbook to the data-out writer as a cursor of the build's CIs (it passed
# -ReadPages, which the writer no longer had, so the workbook was never written) -- the workbook only, no CI comes out
# different: re-baselined, version 10.
# 2026-10-23 (the release merge): the CI build's two readers log through closures (a logger handed on could call itself:
# call depth overflow) -- logging only, no CI comes out different: re-baselined, version 10.
$script:SICiBuildLogicHash = 'db862af06e448305202bed4fb6d439da7d19492346d2af55a8080bade679a496'
# a CI's fields that change without the CI changing (left out of its content hash)
# (#406 si_not_seen_days: the days since a not seen / retired CI was last seen -- it grows every day by itself)
$script:SICiVolatileFields = @('si_collection_time', 'si_run_id', 'si_days_inactive', 'si_ci_action', 'si_last_seen', 'si_field_sources', 'si_not_seen_days')
# the SI_CI_CL column contract (V3-DATA-MODEL 2.21, Risk Analysis on CIs): a FULL row carries exactly these besides the
# columns every row carries (si_ci_id, si_row_kind, si_collection_time, si_content_hash, si_last_seen) -- nothing else
# (#501: no raw documents)
$script:SICiPostFields = @('si_ci_id', 'si_class', 'si_asset_name', 'si_tier', 'si_tier_set_by', 'si_tier_reason', 'si_risk_factors',
    # #579 the tier in one sentence (who decided, what else claimed and why it lost) and the claims it is built from (slim:
    # ConvertTo-SICiPostRow keeps only the claims on the tier, without the evidence detail the sidata.Ci document holds)
    'si_tier_explanation', 'si_tier_claims',
    'si_criticality_factor', 'si_criticality_source', 'si_cmdb_id', 'si_cmdb_name', 'si_cmdb_criticality', 'si_cmdb_data_sensitivity',
    'si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune', 'si_linked_objects',
    # #546 the identity's origin (it decides the field authority of password age and sign-in) and the fields the build
    # could not decide (unknown is never a finding)
    'si_identity_origin', 'si_unknown_fields',
    # #505 -- every SI field a Risk Analysis report reads about its ASSET (the reports read SI_CI_CL, never the profile
    # tables): the list is engine/risk-analysis/_shared/RA-CiKql.ps1 $script:RACiAssetFields; SIv3-RaReadsCi.Tests.ps1
    # fails when one of those is missing here
    'si_asset_type', 'si_display_name', 'si_link_shodan', 'si_tags', 'si_hostname', 'si_hostnames', 'si_ip_address',
    'si_identity_type', 'si_upn', 'si_account_enabled', 'si_is_external', 'si_external_user_state', 'si_mfa_registered', 'si_created',
    'si_last_sign_in', 'si_password_last_changed', 'si_leave_date', 'si_onprem_synced', 'si_org_department', 'si_country',
    'si_employee_type', 'si_entra_roles_permanent', 'si_entra_roles_eligible', 'si_privilege_tier_permanent', 'si_privilege_tier_eligible',
    'si_azure_role_assignments', 'si_app_permissions', 'si_group_memberships', 'si_ad_critical_groups', 'si_custom_security_attributes',
    'si_is_break_glass', 'si_sp_type', 'si_app_id', 'si_publisher_name', 'si_publisher_verified', 'si_app_owner_org_id',
    'si_is_multitenant_app', 'si_is_third_party_multitenant', 'si_is_orphan_sp', 'si_credential_expiry_days',
    'si_high_risk_permission_grant', 'si_owner', 'si_mdi_risk_state', 'si_mdi_blast_radius', 'si_is_sensitive_account',
    'si_has_leaked_credentials', 'si_is_compromised_recently', 'si_machine_risk', 'si_ms_criticality', 'si_internet_exposed',
    'si_open_ports', 'si_open_port_count', 'si_vulns', 'si_max_cvss', 'si_isp', 'si_org_name', 'si_os_platform', 'si_os_version',
    'si_exposure_level', 'si_is_excluded', 'si_excluded_reason', 'si_is_shadow_admin', 'si_is_service_account', 'si_password_never_expires',
    'si_passwordless_only', 'si_mdi_investigation_priority_pct',
    # #496 what the CI inherits from the business services that own it (a CI no service owns carries si_service_orphan)
    'si_service_keys', 'si_service_owner', 'si_service_criticality', 'si_service_data_sensitivity', 'si_service_environment', 'si_service_orphan',
    # #561 / #562 the one classification mechanism: the refined asset type (and the sources' own), the subtype, the components
    'si_asset_type_source', 'si_asset_subtype', 'si_components', 'si_sql_iaas',
    # #772 the OS family (Windows, Linux, macOS, iOS, Android, Network OS, Other, Unknown) -- the same classification
    'si_os_family',
    # the Azure facts of an Azure CI (type, subscription, resource group, region) -- the Azure CIs had them empty in SI_CI_CL
    # although the CI carried them -- and the virtual machine's extensions (Azure child resources roll up into their parent)
    'si_azure_resource_type', 'si_azure_subscription_id', 'si_azure_resource_group', 'si_azure_location', 'si_vm_extensions',
    # rich context (Azure / Intune / public IP / CMDB lane): the context every report row takes from its CI (RA-CiContext.ps1,
    # Add-RACiContext) -- names next to ids, who owns and supports it, where it runs, and the facts a person prioritises on
    'si_azure_subscription_name', 'si_azure_tenant_id', 'si_azure_tenant_name', 'si_management_group_id', 'si_management_group_name',
    'si_management_group_path', 'si_environment', 'si_cost_center', 'si_app_name', 'si_cmdb_owner', 'si_cmdb_environment',
    'si_cmdb_support_group', 'si_cmdb_support_group_id', 'si_service_department', 'si_service_support_group', 'si_service_support_group_id',
    'si_service_assignment_group', 'si_service_assignment_group_id', 'si_backup_protected', 'si_pending_critical_patches',
    'si_defender_plan_tier', 'si_mde_extension', 'si_attached_resource_id', 'si_attached_resource_name', 'si_is_encrypted',
    'si_primary_user_upn', 'si_intune_last_sync',
    # a device's OPEN alerts (count, highest severity, the newest one's title + id + time) and whether Intune says it is
    # Autopilot enrolled
    'si_open_alerts', 'si_open_alerts_highest_severity', 'si_open_alert_title', 'si_open_alert_id', 'si_open_alert_time', 'si_autopilot_enrolled',
    # rich context, identity (one block): what Entra, Identity Protection, Conditional Access, Privileged Identity Management,
    # access reviews and Defender for Identity know about the identity -- ids AND names -- and a device's registered owner
    'si_manager_upn', 'si_manager_id', 'si_manager_name', 'si_sponsors', 'si_owners', 'si_owner_upns', 'si_owner_ids',
    'si_last_interactive_sign_in', 'si_last_non_interactive_sign_in', 'si_last_app_sign_in', 'si_last_delegated_sign_in',
    'si_mfa_strength', 'si_mfa_default_method', 'si_ca_mfa_enforced', 'si_ca_policy_count', 'si_ca_mfa_policies', 'si_ca_excluded_policies',
    'si_entra_risk_level', 'si_entra_risk_state', 'si_entra_risk_detail', 'si_entra_risk_updated', 'si_risk_detections_30d', 'si_risk_detection_types_30d',
    'si_entra_role_scopes', 'si_role_paths', 'si_pim_activation_requires', 'si_controls_privileged_objects',
    'si_last_access_review', 'si_last_access_review_date', 'si_not_licensed',
    'si_delegated_permissions', 'si_consent_type', 'si_consented_user_count', 'si_delegated_grants', 'si_requested_vs_granted_perms',
    'si_has_client_secret', 'si_has_federated_credential', 'si_federated_credentials', 'si_credentials', 'si_credential_fix',
    'si_attached_resource', 'si_managed_identity_kind', 'si_publisher_domain', 'si_app_notes',
    'si_mdi_tags', 'si_is_honeytoken', 'si_onprem_last_logon', 'si_cleartext_ldap', 'si_ntlm_logons', 'si_ms_criticality_reason',
    'si_primary_user', 'si_primary_user_id', 'si_primary_user_name', 'si_registered_owners',
    # the level inside Tier 0 (a Tier 0 role held on an administrative unit or one object only = level 2), and the facts
    # the break-glass classification is decided on, with the rule that matched in plain words
    'si_privilege_tier_level', 'si_privilege_tier_level_text', 'si_ca_excluded_from_all', 'si_break_glass_attribute', 'si_break_glass_reason',
    # THE CI'S OWN FACTS a person filters and reads in Kusto (owner 2026-10-12: the CI columns must be rich): the device's
    # operating system, addresses, onboarding and hardening, the identity's mail / title / methods, the Azure resource's
    # network and access settings, the public IP's network, and what the build itself decided (lifecycle, first seen, link
    # count, purpose, category, coverage gaps, the CMDB match). The CI carried every one of them in the database; the table
    # had the columns and no row ever filled them.
    'si_os_name', 'si_os_build', 'si_os_architecture', 'si_ip_addresses', 'si_mac_addresses', 'si_fqdn', 'si_logged_on_users', 'si_onboarding_status',
    'si_sensor_health', 'si_join_type', 'si_device_category', 'si_tpm_enabled', 'si_machine_groups', 'si_rdp_enabled', 'si_rdp_nla_required',
    'si_smb1_enabled', 'si_managed_by', 'si_mail', 'si_job_title', 'si_admin_count', 'si_mfa_methods', 'si_frequent_user_tier',
    'si_public_network_access', 'si_https_only', 'si_min_tls_version', 'si_local_auth_enabled', 'si_anonymous_access', 'si_network_default_action',
    'si_ddos_protection', 'si_azure_parent_tags', 'si_bound_resource_id', 'si_cloud_provider', 'si_public_ip', 'si_asn', 'si_geo_country',
    'si_first_seen', 'si_lifecycle', 'si_category', 'si_purpose', 'si_coverage_gaps', 'si_link_count', 'si_is_customer_facing', 'si_cmdb_match_rule',
    'si_cmdb_match_confidence', 'si_cmdb_source', 'si_cmdb_service', 'si_cmdb_criticality_level', 'si_device_value', 'si_internet_exposed_reason',
    'si_on_public_network', 'si_alerts_30d', 'si_last_alert_title', 'si_last_admin_logon',
    # rc12 (#497 / #499 / #500): a multicloud resource's type, region, account and connector (Defender for Cloud), the AD
    # account's OU placement, and a device's software inventory counts (the end-of-support LIST itself is database only)
    'si_cloud_resource_type', 'si_cloud_region', 'si_cloud_account_id', 'si_cloud_connector', 'si_ad_distinguished_name',
    'si_software_count', 'si_software_eos_count',
    # rc14 (#636): a public IP's first Shodan banner -- the source first-seen of its findings; every report row reads it from
    # SI_CI_CL (RA-CiContext.ps1), so it is posted (it was database only, and every row read it empty)
    'si_banner_first_seen')
# EVERY CI FIELD OF THE FIELD CATALOG IS ACCOUNTED FOR (tests/pester/SIv3-CiPostContract.Tests.ps1): it is posted
# ($script:SICiPostFields), or it is one of the two lists below -- so a field added to the catalog cannot silently be a
# column that no row fills.
#   NEVER in a full row: a value that changes every build without the CI changing (the full row would be posted every
#   build), or that every row already carries (collection time, last seen), or the per-field provenance document.
$script:SICiPostNever = @('si_collection_time', 'si_last_seen', 'si_run_id', 'si_ci_action', 'si_days_inactive', 'si_field_sources', 'si_not_seen_days')
#   DATABASE ONLY: detail the web app, the exports and the connectors read from the CI in the database (sidata.Ci) -- the
#   lists (installed software, child resources, certificates ...), the ids behind a posted name, and the summaries. A Log
#   Analytics table holds 500 columns at most; move a field up into the posted list when a report or a person needs it there.
$script:SICiPostDatabaseOnly = @(
    # #406 the lifecycle's evidence (since when, and why) -- the web app's CI page; si_lifecycle itself is posted
    'si_lifecycle_since', 'si_lifecycle_reason',
    'si_owner_ci_id', 'si_user_ci_ids', 'si_services', 'si_service_count', 'si_service_criticality_level', 'si_link_mdi', 'si_link_cmdb',
    'si_link_servicenow', 'si_eg_query_rules', 'si_serial_number', 'si_device_subtype', 'si_installed_software', 'si_device_roles', 'si_is_compliant',
    'si_av_status', 'si_av_mode', 'si_edr_mode', 'si_sensor_version', 'si_os_distribution', 'si_os_version_info', 'si_internet_exposed_detail',
    'si_connectivity_type', 'si_hardening', 'si_hardening_note', 'si_bios_version', 'si_cpu', 'si_hardware_model', 'si_networks',
    'si_default_gateways', 'si_adapter_addresses', 'si_high_alerts_30d', 'si_last_alert_severity', 'si_last_alert_category', 'si_last_alert_time',
    'si_admin_logons_30d', 'si_admin_logon_accounts', 'si_is_production', 'si_handles_sensitive_data', 'si_data_classification_labels',
    'si_internet_exposure_reasons', 'si_internet_exposure_cidrs', 'si_waf_enabled', 'si_nsg_open_rdp', 'si_nsg_open_ssh', 'si_child_resources',
    'si_disks', 'si_network_interfaces', 'si_public_ip_addresses', 'si_subnets', 'si_sql_databases', 'si_sql_firewall_rules', 'si_ai_deployments',
    'si_management_group_id_path', 'si_encryption_at_host', 'si_vm_security_type', 'si_secure_boot', 'si_vtpm_enabled', 'si_patch_mode',
    'si_power_state', 'si_vm_size', 'si_soft_delete_enabled', 'si_purge_protection', 'si_rbac_authorization', 'si_entra_only_auth',
    'si_cross_tenant_replication', 'si_sftp_enabled', 'si_local_users_enabled', 'si_private_endpoint_count', 'si_arc_status',
    'si_arc_last_status_change', 'si_arc_agent_version', 'si_ama_extension', 'si_disk_encryption', 'si_backup_last_status', 'si_backup_last_time',
    'si_backup_vault_id', 'si_backup_vault_name', 'si_backup_policy_id', 'si_backup_policy_name', 'si_privileged_access',
    'si_privileged_access_count', 'si_policy_noncompliant_count', 'si_policy_noncompliant_top', 'si_last_change_time', 'si_last_changed_by',
    'si_last_changed_by_name', 'si_last_change_type', 'si_change_count_14d', 'si_pending_security_patches', 'si_reboot_pending',
    'si_patch_assessed_at', 'si_defender_plan', 'si_defender_plan_sub_plan', 'si_defender_cspm_tier', 'si_attached_resource_type',
    'si_diagnostic_settings_enabled', 'si_diagnostic_settings', 'si_primary_user_mail', 'si_device_owner_type', 'si_compliance_grace_expiry',
    'si_is_jailbroken', 'si_device_manufacturer', 'si_device_model', 'si_enrollment_type', 'si_partner_threat_state', 'si_intune_category',
    'si_intune_status', 'si_noncompliant_policies', 'si_update_rings', 'si_exposed_services', 'si_http_titles', 'si_http_servers',
    'si_tls_certificates', 'si_tls_cert_expired', 'si_tls_self_signed', 'si_tls_earliest_expiry', 'si_tls_legacy_versions', 'si_shodan_tags',
    'si_exposed_os', 'si_domains', 'si_exposed_cloud_provider', 'si_exposed_cloud_region', 'si_exposed_cloud_service',
    'si_banner_last_seen', 'si_cmdb_owner_id', 'si_cmdb_assignment_group', 'si_cmdb_assignment_group_id', 'si_cmdb_assigned_to',
    'si_cmdb_assigned_to_id', 'si_cmdb_location', 'si_cmdb_location_id', 'si_cmdb_install_status', 'si_cmdb_operational_status', 'si_cmdb_updated',
    'si_cmdb_last_discovered', 'si_cmdb_cost_center', 'si_cmdb_cost_center_id', 'si_cmdb_company', 'si_cmdb_company_id', 'si_service_assigned_to',
    'si_service_assigned_to_id', 'si_service_location', 'si_service_location_id', 'si_service_cost_center', 'si_service_cost_center_id',
    'si_service_company', 'si_service_company_id', 'si_service_operational_status', 'si_service_owner_id', 'si_sam_account_name', 'si_ad_domain',
    'si_employee_id', 'si_extension_attributes', 'si_rule_proposals', 'si_overrides', 'si_department', 'si_responsibility_source', 'si_cmdb_class',
    'si_cmdb_owner_department', 'si_ci_risk_score', 'si_ci_weighted_risk_score', 'si_open_findings', 'si_findings_by_severity', 'si_classified_by',
    'si_sql_vm_resource_id', 'si_vuln_count', 'si_vuln_critical_count',
    'si_vuln_high_count', 'si_vuln_medium_count', 'si_vuln_low_count', 'si_vuln_exploitable_count', 'si_vuln_highest_cvss',
    'si_vulnerable_software_count', 'si_vuln_newest_published', 'si_vuln_oldest_published', 'si_vuln_top', 'si_vuln_summary_status',
    'si_config_assessed_count', 'si_config_noncompliant_count', 'si_config_highest_impact', 'si_config_assessed_at',
    'si_config_noncompliant_categories', 'si_config_top', 'si_config_summary_status', 'si_mdc_assessed_count', 'si_mdc_unhealthy_count',
    'si_mdc_high_count', 'si_mdc_medium_count', 'si_mdc_low_count', 'si_mdc_oldest_unhealthy', 'si_mdc_newest_change', 'si_mdc_top',
    # rc12 (#499): the software past (or near) end of support -- a list like si_installed_software (its count is posted)
    'si_software_eos')

function Get-SICiPostContractHash {
    <# PURE. The SI_CI_CL column contract as one value (SHA-256 of the post fields): a release that changes the columns makes
       the next build post every CI's full row (SI-CiBuildRun.ps1, state 'PostContract'). #>
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes((@($script:SICiPostFields) -join ','))))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-SICiPostGainedColumns {
    <# True when THIS process added columns to SI_CI_CL (the ingest's run cache: a table whose new columns it checked) --
       the rows posted while Azure starts storing a new column lose its values. Never throws. #>
    param([string]$Table = 'SI_CI')
    try {
        if (-not (Get-Command -Name Get-SILogIngestRunCache -ErrorAction SilentlyContinue)) { return $false }
        $rc = Get-SILogIngestRunCache
        if ($null -eq $rc -or -not ($rc.ConfirmedTables -is [hashtable])) { return $false }
        return [bool]$rc.ConfirmedTables.ContainsKey(($Table -replace '_CL$', '').ToLowerInvariant())
    } catch { return $false }
}

function Get-SICiGroupingStepSql {
    <#
        The grouping, as SEPARATE statements that each commit (customer H 2026-10-09, Azure SQL Basic, ~100,000 records: the
        one-statement grouping ran 453 s and answered nothing). Labels live in sidata.CiGroupMember (record -> label), the
        identifiers two or more current records share in sidata.CiGroupEdge -- the only identifiers that can join records,
        so a record that shares none (most identities) is never touched by a round.
          prepare   the current records (lookback, a strong identifier, not a CMDB record): records gone are removed, the
                    others get their own key back as label, new ones are added -- on a stable tenant this writes little
          edges     the shared identifiers of the current records (the index on IdType + IdValue)
          round     ONE round of propagation: each record takes the smallest label over the shared identifiers it has --
                    answers the records relabelled; repeated by Invoke-SICiGrouping until 0
          batches   the batch number of every group, ~-BatchCis CIs a batch, in ordinal group order
          stats     Records, Groups, Largest, Batches, Unkeyable
        Labels compare in a binary collation: the smallest label is the same on every host.
    #>
    param([Parameter(Mandatory)][ValidateSet('prepare', 'edges', 'round', 'batches', 'stats')][string]$Step, [int]$LookbackDays = 30, [int]$BatchCis = 2000)
    $since = "DECLARE @since DATETIME2(3) = DATEADD(day, -$LookbackDays, SYSUTCDATETIME());"
    $current = "r.CollectionTime >= @since AND ISNULL(r.RecordType, N'') <> N'cmdb_ci' AND EXISTS (SELECT 1 FROM sidata.RecordIdentifier ri WHERE ri.RecordKey = r.RecordKey)"
    switch ($Step) {
        'prepare' {
            @"
SET NOCOUNT ON;
$since
DELETE m FROM sidata.CiGroupMember m WHERE NOT EXISTS (SELECT 1 FROM sidata.CiRecord r WHERE r.RecordKey = m.RecordKey AND $current);
DECLARE @gone INT = @@ROWCOUNT;
UPDATE sidata.CiGroupMember SET GroupKey = RecordKey WHERE GroupKey COLLATE Latin1_General_BIN2 <> RecordKey COLLATE Latin1_General_BIN2;
DECLARE @reset INT = @@ROWCOUNT;
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo)
SELECT r.RecordKey, r.RecordKey, 0 FROM sidata.CiRecord r WHERE $current AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey);
DECLARE @new INT = @@ROWCOUNT;
SELECT (SELECT COUNT(*) FROM sidata.CiGroupMember) AS Records, @gone AS Gone, @reset AS Reset, @new AS New;
"@
        }
        'edges' {
            @'
SET NOCOUNT ON;
DELETE FROM sidata.CiGroupEdge;
INSERT sidata.CiGroupEdge (RecordKey, IdType, IdValue)
SELECT ri.RecordKey, ri.IdType, ri.IdValue
FROM sidata.RecordIdentifier ri
JOIN (SELECT ri2.IdType, ri2.IdValue FROM sidata.RecordIdentifier ri2 JOIN sidata.CiGroupMember m ON m.RecordKey = ri2.RecordKey
      GROUP BY ri2.IdType, ri2.IdValue HAVING COUNT(*) > 1) s ON s.IdType = ri.IdType AND s.IdValue = ri.IdValue
WHERE EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = ri.RecordKey);
SELECT @@ROWCOUNT AS Edges, (SELECT COUNT(DISTINCT RecordKey) FROM sidata.CiGroupEdge) AS Linked;
'@
        }
        'round' {
            @'
SET NOCOUNT ON;
WITH il AS (SELECT e.IdType, e.IdValue, MIN(m.GroupKey COLLATE Latin1_General_BIN2) AS Label
            FROM sidata.CiGroupEdge e JOIN sidata.CiGroupMember m ON m.RecordKey = e.RecordKey GROUP BY e.IdType, e.IdValue),
     rl AS (SELECT e.RecordKey, MIN(il.Label) AS Label
            FROM sidata.CiGroupEdge e JOIN il ON il.IdType = e.IdType AND il.IdValue = e.IdValue GROUP BY e.RecordKey)
UPDATE m SET GroupKey = rl.Label FROM sidata.CiGroupMember m JOIN rl ON rl.RecordKey = m.RecordKey
WHERE rl.Label < m.GroupKey COLLATE Latin1_General_BIN2;
SELECT @@ROWCOUNT AS Changed;
'@
        }
        'batches' {
            # IDENTITIES BEFORE DEVICES (owner 2026-10-10): the groups of only identity records take the first batches, every
            # other group the batches after them -- an identity CI is written before the device / resource CIs that link to it
            # (their owner, their users) are built, so the link resolves in the same run (Set-SICiIdentityLinks)
            @"
SET NOCOUNT ON;
WITH g AS (SELECT m.GroupKey COLLATE Latin1_General_BIN2 AS GroupKey, MAX(CASE WHEN ISNULL(r.Class, N'') = N'identity' THEN 0 ELSE 1 END) AS Kind
           FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey GROUP BY m.GroupKey COLLATE Latin1_General_BIN2),
     n AS (SELECT CAST(CEILING(SUM(CASE WHEN Kind = 0 THEN 1.0 ELSE 0.0 END) / $BatchCis) AS INT) AS IdBatches FROM g),
     gb AS (SELECT g.GroupKey, ((ROW_NUMBER() OVER (PARTITION BY g.Kind ORDER BY g.GroupKey) - 1) / $BatchCis) + 1 + CASE WHEN g.Kind = 1 THEN ISNULL((SELECT IdBatches FROM n), 0) ELSE 0 END AS BatchNo FROM g)
UPDATE m SET BatchNo = gb.BatchNo FROM sidata.CiGroupMember m JOIN gb ON gb.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2
WHERE m.BatchNo <> gb.BatchNo;
SELECT @@ROWCOUNT AS Changed, ISNULL((SELECT MAX(BatchNo) FROM sidata.CiGroupMember), 0) AS Batches;
"@
        }
        'stats' {
            @"
SET NOCOUNT ON;
$since
SELECT (SELECT COUNT(*) FROM sidata.CiGroupMember) AS Records,
       (SELECT COUNT(DISTINCT GroupKey COLLATE Latin1_General_BIN2) FROM sidata.CiGroupMember) AS Groups,
       ISNULL((SELECT MAX(c) FROM (SELECT COUNT(*) AS c FROM sidata.CiGroupMember GROUP BY GroupKey COLLATE Latin1_General_BIN2) x), 0) AS Largest,
       ISNULL((SELECT MAX(BatchNo) FROM sidata.CiGroupMember), 0) AS Batches,
       (SELECT COUNT(*) FROM sidata.CiRecord r WHERE r.CollectionTime >= @since AND ISNULL(r.RecordType, N'') <> N'cmdb_ci'
            AND NOT EXISTS (SELECT 1 FROM sidata.RecordIdentifier ri WHERE ri.RecordKey = r.RecordKey)) AS Unkeyable;
"@
        }
    }
}

function Invoke-SICiGrouping {
    <#
        Groups the records of the lookback into CIs in SQL -> sidata.CiGroupMember, step by step (Get-SICiGroupingStepSql):
        every step is its own statement and commits, and every step and round is logged with its rows and seconds -- a
        slow database shows WHERE the time goes. Answers ONE object: Records, Groups, Largest, Batches, Unkeyable, Rounds.
        NO CLOCK AND NO ROUND LIMIT (owner 2026-10-22: "i accept no limits" / "remove those stupid breaks"): a round only
        ever LOWERS a label (WHERE rl.Label < m.GroupKey), so every round that changes a row is progress and the rounds always
        end -- a long chain of shared identifiers at 50 M records takes more rounds, never a failed build. Each round is
        logged, so a slow database shows where the time goes. -MaxRounds stays only as an explicit test seam (0 = none,
        the default); -BudgetSeconds is accepted and ignored, for callers that still pass it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [int]$LookbackDays = 30, [int]$BatchCis = 2000, [int]$MaxRounds = 0,
          [int]$BudgetSeconds = 0, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) } }
    $all = [System.Diagnostics.Stopwatch]::StartNew(); $sw = [System.Diagnostics.Stopwatch]::new()
    $step = {
        param($name)
        $sw.Restart()
        $global:SISqlLastRead = $null
        $got = @(& $Sql (Get-SICiGroupingStepSql -Step $name -LookbackDays $LookbackDays -BatchCis $BatchCis) @{} 'rows')
        $row = $got | Select-Object -First 1
        if ($null -eq $row) { throw ("the grouping step '{0}' answered no result ({1})" -f $name, (Get-SISqlLastReadText -Answered $got.Count)) }
        $row
    }
    $p = & $step 'prepare'
    & $Log 'INFO' ("CIs: grouping -- {0} current record(s) ({1} new, {2} relabelled, {3} gone) in {4:N1} s" -f (Get-SIItemValue $p 'Records'), (Get-SIItemValue $p 'New'), (Get-SIItemValue $p 'Reset'), (Get-SIItemValue $p 'Gone'), $sw.Elapsed.TotalSeconds)
    $e = & $step 'edges'
    & $Log 'INFO' ("CIs: grouping -- {0} shared identifier row(s) link {1} record(s) in {2:N1} s" -f (Get-SIItemValue $e 'Edges'), (Get-SIItemValue $e 'Linked'), $sw.Elapsed.TotalSeconds)
    $rounds = 0
    while ($true) {
        if ($MaxRounds -gt 0 -and $rounds -ge $MaxRounds) { throw ('the CI grouping did not settle within {0} rounds -- a chain of shared identifiers longer than the round limit' -f $MaxRounds) }
        $rounds++
        $r = & $step 'round'
        $changed = [int](Get-SIItemValue $r 'Changed')
        & $Log 'INFO' ("CIs: grouping round {0} -- {1} record(s) relabelled in {2:N1} s" -f $rounds, $changed, $sw.Elapsed.TotalSeconds)
        if ($changed -eq 0) { break }
    }
    $b = & $step 'batches'
    & $Log 'INFO' ("CIs: grouping -- {0} batch(es), {1} record(s) moved batch in {2:N1} s" -f (Get-SIItemValue $b 'Batches'), (Get-SIItemValue $b 'Changed'), $sw.Elapsed.TotalSeconds)
    $s = & $step 'stats'
    [pscustomobject]@{ Records = [int](Get-SIItemValue $s 'Records'); Groups = [int](Get-SIItemValue $s 'Groups'); Largest = [int](Get-SIItemValue $s 'Largest')
        Batches = [int](Get-SIItemValue $s 'Batches'); Unkeyable = [int](Get-SIItemValue $s 'Unkeyable'); Rounds = $rounds; Seconds = [Math]::Round($all.Elapsed.TotalSeconds, 1) }
}

function Get-SICiFeedLatestSql {
    <# Per feed (provider + record type) within the lookback: the newest collection time and whether it was complete. #>
    param([int]$LookbackDays = 8)
    @"
SET NOCOUNT ON;
DECLARE @since DATETIME2(3) = DATEADD(day, -$LookbackDays, SYSUTCDATETIME());
WITH f AS (SELECT Provider, ISNULL(RecordType, N'') AS RecordType, MAX(CollectionTime) AS Latest FROM sidata.CiRecord
           WHERE CollectionTime >= @since GROUP BY Provider, ISNULL(RecordType, N''))
SELECT f.Provider, f.RecordType, f.Latest, MIN(CAST(ISNULL(r.Complete, 1) AS INT)) AS Complete
FROM f JOIN sidata.CiRecord r ON r.Provider = f.Provider AND ISNULL(r.RecordType, N'') = f.RecordType AND r.CollectionTime = f.Latest
GROUP BY f.Provider, f.RecordType, f.Latest;
"@
}

function Get-SICiBatchSql {
    <#
        One batch's records: the group, the record key, the per-run columns and the record JSON. @b = the batch number.
        #515: with them, in the SAME read, the CI each record belonged to after the last build and that CI's stored content
        hash (PrevCiId, PrevHash) -- the build then sends the whole document only for a CI whose content changed, and the
        record -> CI link only where it moved (a stable daily run sends neither).
        #534: @only = '1' reads only the members of the batch's DIRTY groups (Get-SICiDirtySql marked them); '0' reads the
        whole batch (a full build). Dirty says, per record, whether its group was dirty -- the full reconcile counts a CI
        that changed although its group was clean.
    #>
    @'
SET NOCOUNT ON;
SELECT m.GroupKey, r.RecordKey, r.CollectionTime, r.Complete, r.SourceLastSeen, r.DocJson,
       r.CiId AS PrevCiId, CONVERT(VARCHAR(64), c.ContentHash, 2) AS PrevHash, m.Dirty,
       c.Lifecycle AS PrevLifecycle,
       CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, '$.si_lifecycle_since') END AS PrevLifecycleSince,
       CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, '$.si_lifecycle_reason') END AS PrevLifecycleReason
FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
LEFT JOIN sidata.Ci c ON c.CiId = r.CiId
WHERE m.BatchNo = CAST(@b AS INT) AND (ISNULL(@only, N'0') <> N'1' OR m.Dirty = 1);
'@
}

function Get-SICiBatchStored {
    <#
        PURE. #515 A batch's rows -> what the last build left: Hash (CiId -> its stored content hash, hex) and RecordCi
        (record key -> the CI it belongs to). A record never built has neither. #406 Lifecycle (CiId -> @{ Lifecycle; Since;
        Reason }): what the CI's lifecycle was -- the CI build keeps "since" while the state holds, and says "reactivated".
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $hash = @{}; $recCi = @{}; $life = @{}
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $ci = [string](Get-SIItemValue $row 'PrevCiId')
        if (-not $ci) { continue }
        $recCi[[string](Get-SIItemValue $row 'RecordKey')] = $ci
        $h = [string](Get-SIItemValue $row 'PrevHash')
        if ($h) { $hash[$ci] = $h }
        $pl = [string](Get-SIItemValue $row 'PrevLifecycle')
        if ($pl -and -not $life.ContainsKey($ci)) {
            $life[$ci] = [pscustomobject]@{ Lifecycle = $pl; Since = (ConvertTo-SIUtcOrNull (Get-SIItemValue $row 'PrevLifecycleSince')); Reason = [string](Get-SIItemValue $row 'PrevLifecycleReason') }
        }
    }
    [pscustomobject]@{ Hash = $hash; RecordCi = $recCi; Lifecycle = $life }
}

function ConvertTo-SICiFeedLatest {
    <# PURE. The feed rows -> the hashtable Get-SIFeedLatest builds ('provider|type' -> @{ Time; Complete }). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $h = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $t = Get-SIItemValue $r 'Latest'
        if ($t -is [datetime]) { $t = [datetime]::SpecifyKind($t, [DateTimeKind]::Utc) } else { $t = ConvertTo-SIUtcOrNull $t }
        $h[('{0}|{1}' -f (Get-SIItemValue $r 'Provider'), (Get-SIItemValue $r 'RecordType'))] = [pscustomobject]@{ Time = $t; Complete = ([int](Get-SIItemValue $r 'Complete') -ne 0) }
    }
    $h
}

function ConvertTo-SICiBatchGroups {
    <#
        PURE. One batch's rows -> the groups Get-SICiGroups would build for them: members in ORDINAL record-key order, each
        with its record (the stored JSON, typed by the catalog; collection time, completeness and source last seen from
        the columns) and its strong identifiers. Groups in ordinal group-key order.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][hashtable]$Types, [hashtable]$TypeMap = (Get-SICiLedgerTypeMap))
    $byGroup = New-Object System.Collections.Hashtable ([StringComparer]::Ordinal)   # group keys are record keys: case matters
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $gk = [string](Get-SIItemValue $row 'GroupKey')
        if (-not $byGroup.ContainsKey($gk)) { $byGroup[$gk] = New-Object System.Collections.Generic.List[object] }
        $byGroup[$gk].Add($row)
    }
    $gkeys = @($byGroup.Keys); [Array]::Sort($gkeys, [StringComparer]::Ordinal)
    $groups = New-Object System.Collections.Generic.List[object]
    $nRec = 0
    foreach ($gk in $gkeys) {
        $grp = $byGroup[$gk].ToArray()
        # typed arrays FIRST: [Array]::Sort on a cast would sort a copy and leave these unsorted
        [string[]]$keys = @($grp | ForEach-Object { [string](Get-SIItemValue $_ 'RecordKey') }); [int[]]$idx = @(0..($grp.Count - 1))
        [Array]::Sort($keys, $idx, [StringComparer]::Ordinal)
        $members = New-Object System.Collections.Generic.List[object]
        foreach ($i in $idx) {
            $row = $grp[$i]
            $rec = ConvertFrom-SICiStoredRecord -Row $row -Types $Types
            if ($null -eq $rec) { continue }
            $ids = Get-SIRecordIdentifiers -Record $rec -TypeMap $TypeMap
            $members.Add([pscustomobject]@{ Identifiers = $ids.ToArray(); Record = $rec; Node = ('rec:' + [string](Get-SIItemValue $row 'RecordKey')) })
            $nRec++
        }
        if ($members.Count -gt 0) { $groups.Add([pscustomobject]@{ Members = $members.ToArray() }) }
    }
    [pscustomobject]@{ Groups = $groups.ToArray(); Records = $nRec }
}

function ConvertFrom-SICiStoredRecord {
    <# PURE. A stored record row (DocJson + the per-run columns) -> the record as the CI build reads it. #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][hashtable]$Types)
    $json = [string](Get-SIItemValue $Row 'DocJson')
    if (-not $json) { return $null }
    $doc = $json | ConvertFrom-Json
    $rec = ConvertFrom-SILogRecordRow -Row $doc -Types $Types
    $utc = { param($v) if ($null -eq $v) { $null } elseif ($v -is [datetime]) { [datetime]::SpecifyKind($v, [DateTimeKind]::Utc) } else { ConvertTo-SIUtcOrNull $v } }
    $ct = & $utc (Get-SIItemValue $Row 'CollectionTime'); if ($ct) { $rec | Add-Member -NotePropertyName 'si_collection_time' -NotePropertyValue $ct -Force }
    $c = Get-SIItemValue $Row 'Complete'; if ($null -ne $c) { $rec | Add-Member -NotePropertyName 'si_collection_complete' -NotePropertyValue ([bool]$c) -Force }
    $sl = & $utc (Get-SIItemValue $Row 'SourceLastSeen')
    if ($sl) { $rec | Add-Member -NotePropertyName 'si_source_last_seen' -NotePropertyValue $sl -Force }
    $rk = [string](Get-SIItemValue $Row 'RecordKey'); if ($rk) { $rec | Add-Member -NotePropertyName 'si_record_key' -NotePropertyValue $rk -Force }
    $rec
}

function ConvertTo-SICiPostRow {
    <# PURE. A CI document -> the SI_CI_CL full row Risk Analysis reads (the column contract only, $script:SICiPostFields: no
       run id and nothing else that changes every build; the lifecycle IS posted -- it changes only when the CI's linked
       objects do; linked objects as { provider, id }, risk factors as { id, axis, impact, stage }). #>
    param([Parameter(Mandatory)]$Ci)
    $r = [ordered]@{}
    foreach ($f in $script:SICiPostFields) {
        if (-not $Ci.Contains($f)) { continue }
        $v = $Ci[$f]
        # (loops, not pipelines: this runs for every CI of the build)
        if ($f -eq 'si_linked_objects') { $v = @(foreach ($x in @($v)) { if ($x) { [ordered]@{ provider = $x.provider; id = $x.id } } }) }
        elseif ($f -eq 'si_risk_factors') {
            # each factor's providers ('by', #464) ride along; the full evidence stays in the sidata.Ci document
            $v = @(foreach ($x in @($v)) { if (-not $x) { continue }
                    # #559: shortName / side / state ride along; axis + stage stay for the reports' CI blocks (si_rf_p / si_rf_c)
                    $o = [ordered]@{ id = $x.id; shortName = (Get-SIItemValue $x 'shortName'); side = (Get-SIItemValue $x 'side'); axis = $x.axis; impact = $x.impact; state = (Get-SIItemValue $x 'state'); stage = $x.stage }
                    $by = Get-SIItemValue $x 'by'; if ($null -ne $by -and @($by).Count -gt 0) { $o['by'] = @($by) }
                    $o })
        }
        elseif ($f -eq 'si_tier' -and $null -ne $v -and "$v" -ne '') { $v = [int]$v }
        elseif ($f -eq 'si_tier_claims') {
            $v = @(foreach ($x in @($v)) { if (-not ($null -ne $x -and $null -ne (Get-SIItemValue $x 'tier') -and "$(Get-SIItemValue $x 'tier')" -ne '')) { continue }
                    [ordered]@{ rule = (Get-SIItemValue $x 'rule'); label = (Get-SIItemValue $x 'label'); kind = (Get-SIItemValue $x 'kind'); tier = [int](Get-SIItemValue $x 'tier')
                        admissible = [bool](Get-SIItemValue $x 'admissible'); winner = [bool](Get-SIItemValue $x 'winner'); reason = (Get-SIItemValue $x 'reason')
                        matched = @(foreach ($mm in @(Get-SIItemValue $x 'matched')) { if ($mm) { [string]$mm } }) } })
        }
        $r[$f] = ConvertTo-SILogValue $v
    }
    # #464: the catalog's per-CI factor columns -- si_rf_<id> (true / false) and si_rf_count -- when the CI build set them
    foreach ($k in @($Ci.Keys)) { if ([string]$k -like 'si_rf_*') { $r[[string]$k] = ConvertTo-SILogValue $Ci[$k] } }
    $r['si_collection_time'] = ConvertTo-SILogValue $Ci['si_collection_time']
    $r['si_last_seen'] = ConvertTo-SILogValue $Ci['si_last_seen']
    [pscustomobject]$r
}

function ConvertTo-SICiSqlItems {
    <#
        PURE. A batch's CI documents -> the sidata.Ci items (grid columns, the whole document, its content hash), the
        sidata.CiLink items, the record -> CI map and the SI_CI_CL rows with their posted-content hash.
        #515 -Stored (Get-SICiBatchStored: what the last build left): a CI whose content hash equals its stored one goes as a
        SLIM item (id, last seen, collection time, hash -- no document, no grid columns, no links: the database keeps them and
        only moves its last seen), and a record -> CI link that did not move is not sent. Unchanged = how many went slim.
        Without -Stored every CI goes whole (the first build, a resend).
    #>
    param([AllowEmptyCollection()][object[]]$Cis = @(), $Stored)
    $storedHash = if ($Stored -and $Stored.Hash) { $Stored.Hash } else { @{} }
    $storedRec = if ($Stored -and $Stored.RecordCi) { $Stored.RecordCi } else { @{} }
    $unchanged = 0
    $iso = { param($v) $x = $v; if ($x -isnot [datetime]) { $x = ConvertTo-SIUtcOrNull $x }; if ($x) { $x.ToUniversalTime().ToString('o') } else { $null } }
    $ciItems = New-Object System.Collections.Generic.List[object]
    $links = New-Object System.Collections.Generic.List[object]
    $map = New-Object System.Collections.Generic.List[object]
    $post = New-Object System.Collections.Generic.List[object]
    # one item per CI id: two groups that resolve to one id (a ledger collision) would break the batch's write -- the
    # first is kept and the others are counted (Duplicates), never written twice
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase); $dup = New-Object System.Collections.Generic.List[string]
    foreach ($c in $Cis) {
        if ($null -eq $c) { continue }
        $id = [string]$c['si_ci_id']; if (-not $id) { continue }
        if (-not $ids.Add($id)) { $dup.Add($id); continue }
        $rf = @(foreach ($x in @($c['si_risk_factors'])) { if ($x -and $x.impact -gt 0) { [string]$x.id } })
        $tier = $c['si_tier']; $ie = $c['si_internet_exposed']
        $hashIn = [ordered]@{}
        foreach ($k in $c.Keys) {
            if ($script:SICiVolatileFields -contains $k) { continue }
            if ($k -eq 'si_linked_objects') { $hashIn[$k] = @(foreach ($x in @($c[$k])) { if ($x) { [ordered]@{ provider = $x.provider; type = $x.type; id = $x.id; record_key = $x.record_key; primary = [bool]$x.primary; state = $x.state } } }); continue }
            $hashIn[$k] = $c[$k]
        }
        $hash = Get-SIContentHash -Item $hashIn
        # the SI_CI_CL full row and its posted-content hash, first: the CI item carries that hash too (#534 PostRowHash -- a CI
        # whose last full row did not reach SI_CI_CL is rebuilt by the next incremental build)
        $pr = ConvertTo-SICiPostRow -Ci $c
        $ph = Get-SIContentHash -Item $pr -Exclude @('si_collection_time', 'si_last_seen')
        $was = [string]$storedHash[$id]
        if ($was -and $was.ToUpperInvariant() -eq $hash.ToUpperInvariant()) {
            # #515 the content did not change: no document is serialised or sent, no link rows
            $unchanged++
            $ciItems.Add([ordered]@{ CiId = $id; LastSeen = (& $iso $c['si_last_seen']); CollectionTime = (& $iso $c['si_collection_time']); Hash = $hash; DocJson = $null; PostHash = $ph })
            foreach ($l in @($c['si_linked_objects'])) {
                if ($null -eq $l -or -not $l.id -or -not $l.record_key) { continue }
                if ([string]$storedRec[[string]$l.record_key] -ne $id) { $map.Add([ordered]@{ RecordKey = [string]$l.record_key; CiId = $id }) }
            }
        } else {
        $ciItems.Add([ordered]@{
                CiId = $id; Class = [string]$c['si_class']; Name = [string]$c['si_asset_name']; AssetType = [string]$c['si_asset_type']
                Tier = $(if ($null -ne $tier -and "$tier" -ne '') { [int]$tier } else { $null }); TierSetBy = [string]$c['si_tier_set_by']
                TierReason = [string]$c['si_tier_reason']; Lifecycle = [string]$c['si_lifecycle']
                InternetExposed = $(if ($null -eq $ie) { $null } elseif ((ConvertTo-SIBoolOrNull $ie) -eq $true) { 1 } elseif ((ConvertTo-SIBoolOrNull $ie) -eq $false) { 0 } else { $null })
                CmdbId = [string]$c['si_cmdb_id']; CmdbName = [string]$c['si_cmdb_name']; CmdbCriticality = [string]$c['si_cmdb_criticality']
                CriticalityFactor = $c['si_criticality_factor']; RiskFactors = ($rf -join ';'); LinkCount = $c['si_link_count']
                LastSeen = (& $iso $c['si_last_seen']); CollectionTime = (& $iso $c['si_collection_time'])
                Hash = $hash; PostHash = $ph
                DocJson = (ConvertTo-Json -InputObject $c -Compress -Depth 12)
            })
        foreach ($l in @($c['si_linked_objects'])) {
            if ($null -eq $l -or -not $l.id) { continue }
            $links.Add([ordered]@{ CiId = $id; Provider = [string]$l.provider; RecordType = [string]$l.type; NativeId = [string]$l.id; IsPrimary = $(if ($l.primary -eq $true) { 1 } else { 0 }); State = [string]$l.state; LastSeen = (& $iso $l.last_seen) })
            if ($l.record_key -and [string]$storedRec[[string]$l.record_key] -ne $id) { $map.Add([ordered]@{ RecordKey = [string]$l.record_key; CiId = $id }) }
        }
        }
        $pr | Add-Member -NotePropertyName 'si_row_kind' -NotePropertyValue 'full'
        $pr | Add-Member -NotePropertyName 'si_content_hash' -NotePropertyValue $ph
        # the SLIM row every CI gets every build (operator: "a device can be off for 1 week, how do we find its latest data if
        # you filter per day"): today's set of CIs = today's seen rows; a CI's properties = its latest FULL row
        $seen = [pscustomobject][ordered]@{ si_ci_id = $id; si_row_kind = 'seen'; si_collection_time = $pr.si_collection_time; si_content_hash = $ph
            si_last_seen = $pr.si_last_seen }
        $post.Add([pscustomobject]@{ CiId = $id; Row = $pr; Seen = $seen; Hash = $ph })
    }
    [pscustomobject]@{ Cis = $ciItems.ToArray(); Links = $links.ToArray(); Map = $map.ToArray(); Post = $post.ToArray(); Duplicates = $dup.ToArray(); Unchanged = $unchanged }
}

function Get-SICiWriteSql {
    <#
        One batch of CIs -> sidata.Ci / CiLink / CiDaily and the records' CiId, ONE transaction. A CI whose content hash did
        not change is not rewritten (only its last seen, when that moved). The finding totals (RiskScore, weighted score,
        open findings) are the data sync's -- never overwritten here. Answers: Cis, Changed, Links, Records, Daily, and
        the CIs' PostedHash (hex) for the SI_CI_CL decision.
        @j = CI items, @l = links, @m = record -> CI, @p = the CIs the PREVIOUS batch posted to SI_CI_CL ([{ CiId; Hash }]).
        #515 ONE round trip per batch: the previous batch's posted marks ride in this statement (Get-SICiMarkPostedSql runs
        once, after the last batch). A SLIM item (no DocJson -- the build saw an unchanged hash) is never written; when the
        database finds such a CI changed after all (its stored hash moved since the batch was read), it is answered as
        'resend' and the build sends it whole.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF @p IS NOT NULL AND @p <> N'' AND @p <> N'[]'
    UPDATE t SET PostedHash = CONVERT(VARBINARY(32), x.Hash, 2), PostedAt = SYSUTCDATETIME()
    FROM sidata.Ci t JOIN OPENJSON(@p) WITH (CiId NVARCHAR(64), Hash VARCHAR(64)) x ON x.CiId = t.CiId;
DECLARE @c TABLE (CiId NVARCHAR(64) PRIMARY KEY, Class NVARCHAR(16), Name NVARCHAR(400), AssetType NVARCHAR(128), Tier INT, TierSetBy NVARCHAR(16), TierReason NVARCHAR(MAX),
    Lifecycle NVARCHAR(16), InternetExposed BIT, CmdbId NVARCHAR(256), CmdbName NVARCHAR(400), CmdbCriticality NVARCHAR(64), CriticalityFactor FLOAT, RiskFactors NVARCHAR(MAX),
    LinkCount INT, LastSeen DATETIME2(3), CollectionTime DATETIME2(3), Hash VARBINARY(32), DocJson NVARCHAR(MAX), PostHash VARBINARY(32));
INSERT @c SELECT CiId, Class, Name, AssetType, Tier, TierSetBy, TierReason, Lifecycle, InternetExposed, CmdbId, CmdbName, CmdbCriticality, CriticalityFactor, RiskFactors,
    LinkCount, TRY_CONVERT(DATETIME2(3), LastSeen, 127), ISNULL(TRY_CONVERT(DATETIME2(3), CollectionTime, 127), SYSUTCDATETIME()), CONVERT(VARBINARY(32), Hash, 2), DocJson, CONVERT(VARBINARY(32), PostHash, 2)
FROM OPENJSON(@j) WITH (CiId NVARCHAR(64), Class NVARCHAR(16), Name NVARCHAR(400), AssetType NVARCHAR(128), Tier INT, TierSetBy NVARCHAR(16), TierReason NVARCHAR(MAX),
    Lifecycle NVARCHAR(16), InternetExposed BIT, CmdbId NVARCHAR(256), CmdbName NVARCHAR(400), CmdbCriticality NVARCHAR(64), CriticalityFactor FLOAT, RiskFactors NVARCHAR(MAX),
    LinkCount INT, LastSeen NVARCHAR(64), CollectionTime NVARCHAR(64), Hash VARCHAR(64), DocJson NVARCHAR(MAX), PostHash VARCHAR(64))
WHERE CiId IS NOT NULL;
DECLARE @chg TABLE (CiId NVARCHAR(64) PRIMARY KEY);
INSERT @chg SELECT c.CiId FROM @c c LEFT JOIN sidata.Ci t ON t.CiId = c.CiId WHERE t.CiId IS NULL OR t.ContentHash IS NULL OR t.ContentHash <> c.Hash;
DECLARE @miss TABLE (CiId NVARCHAR(64) PRIMARY KEY);
INSERT @miss SELECT c.CiId FROM @c c JOIN @chg x ON x.CiId = c.CiId WHERE c.DocJson IS NULL;
DELETE x FROM @chg x WHERE x.CiId IN (SELECT CiId FROM @miss);
DECLARE @nLinks INT = 0, @nRec INT = 0, @nDaily INT = 0, @nSeen INT = 0;
BEGIN TRANSACTION;
-- #464 HISTORY PER CI (V3-DATA-MODEL 2.8.3): before a changed CI is rewritten, what changed on it -- the tracked fields,
-- the links added / removed, a new CI. Only CIs whose content changed are compared; a database without sidata.CiChange
-- (not updated yet) skips this, it never fails the build.
IF OBJECT_ID('sidata.CiChange') IS NOT NULL
BEGIN
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT c.CiId, v.Field, LEFT(v.OldV, 1000), LEFT(v.NewV, 1000), LEFT(v.Src, 64), LEFT(v.Rsn, 512), LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM @c c JOIN @chg x ON x.CiId = c.CiId JOIN sidata.Ci t ON t.CiId = c.CiId
    CROSS APPLY (VALUES
        (N'si_tier', CONVERT(NVARCHAR(1000), t.Tier), CONVERT(NVARCHAR(1000), CASE WHEN c.Tier BETWEEN 0 AND 255 THEN c.Tier END), CONVERT(NVARCHAR(64), c.TierSetBy), LEFT(c.TierReason, 512)),
        (N'si_tier_set_by', t.TierSetBy, c.TierSetBy, c.TierSetBy, NULL),
        -- #406 every lifecycle transition with its evidence (the CI's si_lifecycle_reason: since when, and why)
        (N'si_lifecycle', t.Lifecycle, c.Lifecycle, N'lifecycle', LEFT(JSON_VALUE(c.DocJson, '$.si_lifecycle_reason'), 512)),
        (N'si_internet_exposed', CONVERT(NVARCHAR(1000), t.InternetExposed), CONVERT(NVARCHAR(1000), c.InternetExposed), JSON_VALUE(c.DocJson, '$.si_field_sources.si_internet_exposed.provider'), NULL),
        (N'si_risk_factors', LEFT(t.RiskFactors, 1000), LEFT(c.RiskFactors, 1000), N'risk-factors', NULL),
        (N'si_cmdb_id', t.CmdbId, c.CmdbId, JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_name', t.CmdbName, c.CmdbName, JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_criticality', t.CmdbCriticality, c.CmdbCriticality, JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_data_sensitivity', JSON_VALUE(t.DocJson, '$.si_cmdb_data_sensitivity'), JSON_VALUE(c.DocJson, '$.si_cmdb_data_sensitivity'), JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_owner', JSON_VALUE(t.DocJson, '$.si_cmdb_owner'), JSON_VALUE(c.DocJson, '$.si_cmdb_owner'), JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_owner_department', JSON_VALUE(t.DocJson, '$.si_cmdb_owner_department'), JSON_VALUE(c.DocJson, '$.si_cmdb_owner_department'), JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_service', JSON_VALUE(t.DocJson, '$.si_cmdb_service'), JSON_VALUE(c.DocJson, '$.si_cmdb_service'), JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        (N'si_cmdb_environment', JSON_VALUE(t.DocJson, '$.si_cmdb_environment'), JSON_VALUE(c.DocJson, '$.si_cmdb_environment'), JSON_VALUE(c.DocJson, '$.si_cmdb_source'), NULL),
        -- #495 owner, service ownership and exposure: who owns the CI, which services, what it inherits from them
        (N'si_owner', JSON_VALUE(t.DocJson, '$.si_owner'), JSON_VALUE(c.DocJson, '$.si_owner'), JSON_VALUE(c.DocJson, '$.si_field_sources.si_owner.provider'), NULL),
        (N'si_owner_ci_id', JSON_VALUE(t.DocJson, '$.si_owner_ci_id'), JSON_VALUE(c.DocJson, '$.si_owner_ci_id'), N'ci_build', NULL),
        (N'si_exposure_level', JSON_VALUE(t.DocJson, '$.si_exposure_level'), JSON_VALUE(c.DocJson, '$.si_exposure_level'), JSON_VALUE(c.DocJson, '$.si_field_sources.si_exposure_level.provider'), NULL),
        (N'si_service_keys', JSON_QUERY(t.DocJson, '$.si_service_keys'), JSON_QUERY(c.DocJson, '$.si_service_keys'), N'services', NULL),
        (N'si_service_owner', JSON_VALUE(t.DocJson, '$.si_service_owner'), JSON_VALUE(c.DocJson, '$.si_service_owner'), N'services', NULL),
        (N'si_service_criticality', JSON_VALUE(t.DocJson, '$.si_service_criticality'), JSON_VALUE(c.DocJson, '$.si_service_criticality'), N'services', NULL),
        (N'si_service_data_sensitivity', JSON_VALUE(t.DocJson, '$.si_service_data_sensitivity'), JSON_VALUE(c.DocJson, '$.si_service_data_sensitivity'), N'services', NULL),
        (N'si_service_environment', JSON_VALUE(t.DocJson, '$.si_service_environment'), JSON_VALUE(c.DocJson, '$.si_service_environment'), N'services', NULL)
    ) v(Field, OldV, NewV, Src, Rsn)
    WHERE ISNULL(v.OldV, N'') <> ISNULL(v.NewV, N'');
    -- #495 software: one row per package installed or removed (si_installed_software), on a CI that existed before
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT c.CiId, N'software', LEFT(o.v, 1000), NULL, N'software', N'removed', LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM @c c JOIN @chg x ON x.CiId = c.CiId JOIN sidata.Ci t ON t.CiId = c.CiId
    CROSS APPLY (SELECT DISTINCT j.value AS v FROM OPENJSON(t.DocJson, '$.si_installed_software') j WHERE j.value IS NOT NULL) o
    WHERE NOT EXISTS (SELECT 1 FROM OPENJSON(c.DocJson, '$.si_installed_software') n WHERE n.value = o.v);
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT c.CiId, N'software', NULL, LEFT(o.v, 1000), N'software', N'installed', LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM @c c JOIN @chg x ON x.CiId = c.CiId JOIN sidata.Ci t ON t.CiId = c.CiId
    CROSS APPLY (SELECT DISTINCT j.value AS v FROM OPENJSON(c.DocJson, '$.si_installed_software') j WHERE j.value IS NOT NULL) o
    WHERE NOT EXISTS (SELECT 1 FROM OPENJSON(t.DocJson, '$.si_installed_software') n WHERE n.value = o.v);
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT c.CiId, N'ci', NULL, N'created', N'ledger', NULL, LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM @c c JOIN @chg x ON x.CiId = c.CiId WHERE NOT EXISTS (SELECT 1 FROM sidata.Ci t WHERE t.CiId = c.CiId);
    DECLARE @nl TABLE (CiId NVARCHAR(64), Provider NVARCHAR(32), NativeId NVARCHAR(450));
    INSERT @nl SELECT x.CiId, x.Provider, LEFT(x.NativeId, 450) FROM OPENJSON(@l) WITH (CiId NVARCHAR(64), Provider NVARCHAR(32), NativeId NVARCHAR(MAX)) x
    WHERE x.CiId IN (SELECT CiId FROM @chg);
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT l.CiId, N'link', LEFT(l.Provider + N':' + l.NativeId, 1000), NULL, l.Provider, N'removed', LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM sidata.CiLink l JOIN @c c ON c.CiId = l.CiId
    WHERE l.CiId IN (SELECT CiId FROM @chg) AND NOT EXISTS (SELECT 1 FROM @nl n WHERE n.CiId = l.CiId AND n.Provider = l.Provider AND n.NativeId = l.NativeId);
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT n.CiId, N'link', NULL, LEFT(n.Provider + N':' + n.NativeId, 1000), n.Provider, N'added', LEFT(JSON_VALUE(c.DocJson, '$.si_run_id'), 64)
    FROM @nl n JOIN @c c ON c.CiId = n.CiId
    WHERE EXISTS (SELECT 1 FROM sidata.Ci t WHERE t.CiId = n.CiId)
      AND NOT EXISTS (SELECT 1 FROM sidata.CiLink l WHERE l.CiId = n.CiId AND l.Provider = n.Provider AND l.NativeId = n.NativeId);
END
MERGE sidata.Ci AS t USING (SELECT c.* FROM @c c JOIN @chg x ON x.CiId = c.CiId) AS s ON t.CiId = s.CiId
WHEN MATCHED THEN UPDATE SET Class = s.Class, Name = s.Name, AssetType = s.AssetType, Tier = CASE WHEN s.Tier BETWEEN 0 AND 255 THEN s.Tier END, TierSetBy = s.TierSetBy,
     TierReason = LEFT(s.TierReason, 512), Lifecycle = s.Lifecycle, InternetExposed = s.InternetExposed, CmdbId = s.CmdbId, CmdbName = s.CmdbName, CmdbCriticality = s.CmdbCriticality,
     CriticalityFactor = s.CriticalityFactor, RiskFactors = LEFT(s.RiskFactors, 1000), LinkCount = s.LinkCount, LastSeen = s.LastSeen, CollectionTime = s.CollectionTime,
     ContentHash = s.Hash, DocJson = s.DocJson, PostRowHash = s.PostHash, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (CiId, Class, Name, AssetType, Tier, TierSetBy, TierReason, Lifecycle, InternetExposed, CmdbId, CmdbName, CmdbCriticality, CriticalityFactor,
     RiskFactors, LinkCount, OpenFindings, LastSeen, CollectionTime, ContentHash, DocJson, PostRowHash)
     VALUES (s.CiId, s.Class, s.Name, s.AssetType, CASE WHEN s.Tier BETWEEN 0 AND 255 THEN s.Tier END, s.TierSetBy, LEFT(s.TierReason, 512), s.Lifecycle, s.InternetExposed, s.CmdbId,
     s.CmdbName, s.CmdbCriticality, s.CriticalityFactor, LEFT(s.RiskFactors, 1000), s.LinkCount, 0, s.LastSeen, s.CollectionTime, s.Hash, s.DocJson, s.PostHash);
UPDATE t SET LastSeen = c.LastSeen FROM sidata.Ci t JOIN @c c ON c.CiId = t.CiId
WHERE c.CiId NOT IN (SELECT CiId FROM @chg) AND c.CiId NOT IN (SELECT CiId FROM @miss) AND ISNULL(t.LastSeen, '19000101') <> ISNULL(c.LastSeen, '19000101');
SET @nSeen = @@ROWCOUNT;
-- #534 the posted-content hash of an unchanged CI (a CI written before it existed gets it here; not counted as a write)
UPDATE t SET PostRowHash = c.PostHash FROM sidata.Ci t JOIN @c c ON c.CiId = t.CiId
WHERE c.CiId NOT IN (SELECT CiId FROM @chg) AND c.CiId NOT IN (SELECT CiId FROM @miss) AND c.PostHash IS NOT NULL AND (t.PostRowHash IS NULL OR t.PostRowHash <> c.PostHash);
DELETE l FROM sidata.CiLink AS l WHERE l.CiId IN (SELECT CiId FROM @chg);
INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State, LastSeen)
SELECT x.CiId, x.Provider, x.RecordType, LEFT(x.NativeId, 450), ISNULL(x.IsPrimary, 0), x.State, TRY_CONVERT(DATETIME2(3), x.LastSeen, 127)
FROM OPENJSON(@l) WITH (CiId NVARCHAR(64), Provider NVARCHAR(32), RecordType NVARCHAR(32), NativeId NVARCHAR(MAX), IsPrimary BIT, State NVARCHAR(16), LastSeen NVARCHAR(64)) x
WHERE x.CiId IN (SELECT CiId FROM @chg);
SET @nLinks = @@ROWCOUNT;
UPDATE r SET CiId = x.CiId FROM sidata.CiRecord r JOIN OPENJSON(@m) WITH (RecordKey NVARCHAR(450), CiId NVARCHAR(64)) x ON x.RecordKey = r.RecordKey
WHERE ISNULL(r.CiId, N'') <> x.CiId;
SET @nRec = @@ROWCOUNT;
MERGE sidata.CiDaily AS d USING (SELECT CONVERT(date, SYSUTCDATETIME()) AS [Day], t.CiId, t.Tier, t.RiskScore, t.WeightedRiskScore, t.OpenFindings FROM sidata.Ci t
                                 WHERE t.CiId IN (SELECT CiId FROM @c)) AS s
ON d.[Day] = s.[Day] AND d.CiId = s.CiId
WHEN MATCHED AND (ISNULL(d.Tier, 255) <> ISNULL(s.Tier, 255)) THEN UPDATE SET Tier = s.Tier
WHEN NOT MATCHED THEN INSERT ([Day], CiId, Tier, RiskScore, WeightedRiskScore, OpenFindings) VALUES (s.[Day], s.CiId, s.Tier, s.RiskScore, s.WeightedRiskScore, s.OpenFindings);
SET @nDaily = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT N'summary' AS Kind, CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS VARCHAR(64)) AS PostedHash, (SELECT COUNT(*) FROM @c) AS Cis, (SELECT COUNT(*) FROM @chg) AS Changed, @nSeen AS LastSeenOnly,
       @nLinks AS Links, @nRec AS Records, @nDaily AS Daily
UNION ALL
SELECT N'posted', t.CiId, CONVERT(VARCHAR(64), t.PostedHash, 2), NULL, NULL, NULL, NULL, NULL, NULL FROM sidata.Ci t WHERE t.CiId IN (SELECT CiId FROM @c) AND t.CiId NOT IN (SELECT CiId FROM @miss)
UNION ALL
SELECT N'resend', x.CiId, NULL, NULL, NULL, NULL, NULL, NULL, NULL FROM @miss x;
'@
}

function Get-SICiMarkPostedSql {
    <# The CIs posted to SI_CI_CL: their posted hash and time (@p = [{ CiId; Hash }]). #>
    @'
SET NOCOUNT ON;
UPDATE t SET PostedHash = CONVERT(VARBINARY(32), x.Hash, 2), PostedAt = SYSUTCDATETIME()
FROM sidata.Ci t JOIN OPENJSON(@p) WITH (CiId NVARCHAR(64), Hash VARCHAR(64)) x ON x.CiId = t.CiId;
SELECT @@ROWCOUNT;
'@
}

function Get-SICiStateSql {
    <# Read (@set empty) or write (@set = value) one build-state value (@name). #>
    @'
SET NOCOUNT ON;
IF @set IS NOT NULL AND @set <> N''
    MERGE sidata.CiBuildState AS t USING (SELECT @name AS Name, @set AS Value) AS s ON t.Name = s.Name
    WHEN MATCHED THEN UPDATE SET Value = s.Value, UpdatedAt = SYSUTCDATETIME()
    WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (s.Name, s.Value);
SELECT Value FROM sidata.CiBuildState WHERE Name = @name;
'@
}

function Select-SICiPostRows {
    <#
        PURE. Which CIs of a batch go to SI_CI_CL: every one when -Full, else only those whose posted-content hash differs
        from the one stored (never posted = differs). Returns the post items to send.
    #>
    param([AllowEmptyCollection()][object[]]$Post = @(), [hashtable]$PostedHash = @{}, [switch]$Full)
    foreach ($p in $Post) {
        if ($null -eq $p) { continue }
        if ($Full) { $p; continue }
        $h = $PostedHash[[string]$p.CiId]
        if (-not $h -or ([string]$h).ToUpperInvariant() -ne ([string]$p.Hash).ToUpperInvariant()) { $p }
    }
}

$script:SICiPostKeepWhole = @('si_ci_id', 'si_class', 'si_asset_name', 'si_tier', 'si_tier_set_by', 'si_row_kind', 'si_collection_time',
    'si_last_seen', 'si_content_hash', 'si_cmdb_id', 'si_cmdb_name', 'si_identity_origin', 'si_collection_complete', 'si_truncated')

function Measure-SICiPostRowBytes {
    <# PURE. The bytes one SI_CI_CL row takes in a Log Ingestion post: its JSON, gzip-compressed when -Compressed (as the
       post measures it). #>
    param([Parameter(Mandatory)]$Row, [bool]$Compressed = $false)
    $b = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Row -Compress -Depth 100))
    if (-not $Compressed) { return [long]$b.Length }
    $ms = New-Object System.IO.MemoryStream
    try {
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
        try { $gz.Write($b, 0, $b.Length) } finally { $gz.Dispose() }
        return [long]$ms.Length
    } finally { $ms.Dispose() }
}

function Limit-SICiPostRowSize {
    <#
        PURE. One SI_CI_CL row made to fit ONE Log Ingestion post (-MaxBytes, the API's limit, at the post's fill level).
        A row that fits is returned as it is. A row that does not (a CI with tens of thousands of linked objects or risk
        factors -- support 2026-10-18: one CI of 2,001,077 bytes failed its whole batch on every build) is cut where it
        is largest, measured again after every cut: the largest list keeps its first half, the largest text its first
        half, until the row fits. The CI's identity, class, name, tier, keys and row bookkeeping ($script:SICiPostKeepWhole)
        are never cut. si_truncated names each field cut and how much of it was kept. The SQL copy of the CI is not
        touched -- it keeps the whole CI. Returns @{ Row; Trimmed; Fits; OriginalBytes; Bytes; Fields }.
    #>
    param([Parameter(Mandatory)]$Row, [long]$MaxBytes = 1MB, [double]$Fill = 0.95, [bool]$Compressed = $false)
    $budget = [long][Math]::Floor($MaxBytes * $Fill) - 2
    # uncompressed first (cheap); gzip only for a row whose plain JSON is over the limit while the post compresses
    $orig = Measure-SICiPostRowBytes -Row $Row -Compressed $false
    if ($orig -gt $budget -and $Compressed) { $orig = Measure-SICiPostRowBytes -Row $Row -Compressed $true }
    if ($orig -le $budget) { return [pscustomobject]@{ Row = $Row; Trimmed = $false; Fits = $true; OriginalBytes = $orig; Bytes = $orig; Fields = @() } }
    $r = [ordered]@{}
    if ($Row -is [System.Collections.IDictionary]) { foreach ($k in @($Row.Keys)) { $r[[string]$k] = $Row[$k] } }
    else { foreach ($p in $Row.PSObject.Properties) { $r[$p.Name] = $p.Value } }
    $origLen = @{}; $kind = @{}
    $size = $orig
    while ($size -gt $budget) {
        $best = $null; $bestLen = -1L
        foreach ($k in @($r.Keys)) {
            if ($script:SICiPostKeepWhole -contains $k) { continue }
            $v = $r[$k]; if ($null -eq $v) { continue }
            $isList = ($v -is [System.Collections.IList] -and -not ($v -is [string]))
            if ($isList -and $v.Count -eq 0) { continue }
            if ($v -is [string] -and $v.Length -le 64) { continue }
            if (-not $isList -and -not ($v -is [string]) -and ($v -is [ValueType])) { continue }
            $len = [long]([System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $v -Compress -Depth 100)))
            if ($len -gt $bestLen) { $best = $k; $bestLen = $len }
        }
        if ($null -eq $best) { break }
        $v = $r[$best]
        if ($v -is [System.Collections.IList] -and -not ($v -is [string])) {
            if (-not $origLen.ContainsKey($best)) { $origLen[$best] = $v.Count; $kind[$best] = 'items' }
            $n = [int][Math]::Floor($v.Count / 2)
            if ($n -gt 0) { $cut = New-Object object[] $n; for ($i = 0; $i -lt $n; $i++) { $cut[$i] = $v[$i] }; $r[$best] = $cut }
            else { $r[$best] = $null }
        } elseif ($v -is [string]) {
            if (-not $origLen.ContainsKey($best)) { $origLen[$best] = $v.Length; $kind[$best] = 'characters' }
            $r[$best] = $v.Substring(0, [int][Math]::Floor($v.Length / 2))
        } else {
            if (-not $origLen.ContainsKey($best)) { $origLen[$best] = 0; $kind[$best] = 'removed' }
            $r[$best] = $null
        }
        $size = Measure-SICiPostRowBytes -Row ([pscustomobject]$r) -Compressed $Compressed
    }
    $fields = @(foreach ($k in @($origLen.Keys | Sort-Object)) {
        $now = $r[$k]
        $kept = if ($null -eq $now) { 0 } elseif ($kind[$k] -eq 'items') { @($now).Count } elseif ($kind[$k] -eq 'characters') { ([string]$now).Length } else { 0 }
        if ($kind[$k] -eq 'removed') { '{0} (left out)' -f $k } else { '{0} ({1} of {2} {3} kept)' -f $k, $kept, $origLen[$k], $kind[$k] }
    })
    $r['si_truncated'] = ('cut to fit the {0}-byte limit of one Log Analytics post ({1} bytes before): {2}' -f $MaxBytes, $orig, ($fields -join '; '))
    $final = Measure-SICiPostRowBytes -Row ([pscustomobject]$r) -Compressed $Compressed
    [pscustomobject]@{ Row = [pscustomobject]$r; Trimmed = $true; Fits = ($final -le $budget + 2); OriginalBytes = $orig; Bytes = $final; Fields = $fields }
}

function Test-SICiFullPostDue {
    <# PURE. A full SI_CI_CL snapshot is due when none was ever posted or the last one is older than -Days. #>
    param([AllowNull()]$Last, [datetime]$Now = [datetime]::UtcNow, [int]$Days = 7)
    if ($null -eq $Last -or "$Last" -eq '') { return $true }
    $t = ConvertTo-SIUtcOrNull $Last
    if ($null -eq $t) { return $true }
    return (($Now - $t).TotalDays -ge $Days)
}

# =====================================================================================================================
# #534 THE INCREMENTAL CI BUILD -- only the groups whose input changed are read and built; a FULL RECONCILE rebuilds
# every group weekly (SI_CiBuild_FullReconcileDays), at once when what the build is made of changes (its fingerprint),
# after a build that failed or was partial, and when forced. Owner 2026-10-10: "can we improve the speed of ci corelation
# by validating on hash values or similar ... and then a weekly full reconsile process".
#
#   A GROUP IS DIRTY when one of its records
#     * is new, changed (its content hash differs from BuiltHash, the hash it had when its group was last built) or moved
#       group, or a record LEFT the group (moved to another group, or gone from the lookback);
#     * changed its link state (active / not seen / frozen -- its feed's newest collection moved past it);
#     * crossed a time threshold since its last build: its time signature (which of the build's day thresholds its dates
#       are within -- field freshness, the trust list's evidence age, every date condition of the rules and the model --
#       and its place in its group by last seen) differs from BuiltTimeSig. Computed in SQL from the stored dates, so time
#       never needs a rebuild of everything;
#   or when one of its identifiers' identity-ledger anchors (or the CI id they point at) changed since the last build,
#   a manual override of its CI was set, removed or expired since the last build, or its CI's newest full row did not
#   reach SI_CI_CL (PostRowHash <> PostedHash).
#   The finding lifecycle (SI-DataCiLifecycle.ps1) is reconciled per data-sync run from Risk Analysis's findings and the
#   CI's stored lifecycle -- independent of the CI build -- so open findings never make a group dirty.
#
#   RULE 4: a group that is not rebuilt keeps its CI exactly (only its collection time moves, and today's trend row is
#   written); nothing is resolved, retired or closed because it was skipped.
# =====================================================================================================================

function Get-SICiTimeThresholds {
    <#
        PURE. Every day threshold a CI's content can cross with time alone, as @{ Field; Seconds } -- Field '' = the record's
        last seen in its source (si_source_last_seen), else a date field of the record:
          * field freshness: every catalog staleDays (default 30) -- a candidate is fresh while its source saw it within them
          * the trust list's maxAgeDays -- a rule's evidence older than it is not admissible
          * every date condition (older_than_days / newer_than_days) of the rules and the model's templates, on its field
          * si_days_inactive compared with a number -> si_last_seen at that number of days and the day after (it is floored)
        Sorted by field, then seconds (ordinal) -- the order the time signature is computed in. Part of the build fingerprint.
    #>
    param($Model, [AllowEmptyCollection()][object[]]$Rules = @(),
          # #406 the lifecycle settings (Get-SICiLifecycleSettings): the seen windows and every category's grace period are day
          # thresholds on the source's last seen -- a CI crossing one (active -> not seen -> retired) is rebuilt; not given =
          # the settings in force
          $Lifecycle)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[object]
    $add = {
        param($Field, $Days)
        $d = ConvertTo-SINumberOrNull $Days
        if ($null -eq $d -or $d -lt 0) { return }
        $f = ([string]$Field).Trim().ToLowerInvariant()
        if ($f -eq 'si_source_last_seen') { $f = '' }
        if ($f -and $f -notmatch '^[a-z0-9_]{1,64}$') { return }
        $s = [long][Math]::Min([double]2000000000, [Math]::Round([double]$d * 86400))   # (doubles: a day count of a large setting never overflows)
        if ($seen.Add(('{0}|{1}' -f $f, $s))) { $out.Add([pscustomobject]@{ Field = $f; Seconds = $s }) }
    }
    & $add '' 30
    if ($null -eq $Lifecycle) { $Lifecycle = Get-SICiLifecycleSettings }
    foreach ($ld in @(Get-SICiSeenThresholdDays -Settings $Lifecycle)) { & $add '' $ld }
    if ($Model) {
        foreach ($f in @($Model['field-catalog'].fields)) {
            if ($null -eq $f -or $null -eq $f.resolution) { continue }
            $sd = Get-SIItemValue $f.resolution 'staleDays'
            if ($null -ne $sd) { & $add '' $sd }
        }
        foreach ($e in @(Get-SIItemValue $Model['trust'] 'order')) { if ($null -ne $e -and $null -ne (Get-SIItemValue $e 'maxAgeDays')) { & $add '' (Get-SIItemValue $e 'maxAgeDays') } }
    }
    # every leaf condition { field; op; value } in the rules and the model's rule-bearing templates
    $stack = New-Object System.Collections.Generic.Stack[object]
    foreach ($r in @($Rules)) { if ($null -ne $r) { $stack.Push(@($r, 0)) } }
    if ($Model) { foreach ($n in 'risk-factors', 'criticality-mapping', 'coverage-checks', 'trust') { if ($null -ne $Model[$n]) { $stack.Push(@($Model[$n], 0)) } } }
    # an object reached twice (a shared reference) is walked once
    $refEq = 'System.Collections.Generic.ReferenceEqualityComparer' -as [type]
    $visited = $null; if ($refEq) { $visited = New-Object 'System.Collections.Generic.HashSet[object]' ($refEq::Instance) }
    while ($stack.Count -gt 0) {
        $top = $stack.Pop(); $node = $top[0]; $depth = [int]$top[1]
        if ($null -eq $node -or $depth -gt 40) { continue }
        if ($node -is [string] -or $node -is [ValueType]) { continue }
        if ($null -ne $visited -and -not $visited.Add($node)) { continue }
        $isMap = ($node -is [System.Collections.IDictionary]) -or ($node -is [System.Management.Automation.PSCustomObject])
        if ($isMap) {
            $op = [string](Get-SIItemValue $node 'op'); $field = [string](Get-SIItemValue $node 'field')
            if ($op -and $field) {
                if ($op -in 'older_than_days', 'newer_than_days') { & $add $field (Get-SIItemValue $node 'value') }
                elseif ($field -eq 'si_days_inactive' -and $op -in 'gt', 'gte', 'lt', 'lte', 'eq', 'ne') {
                    $v = ConvertTo-SINumberOrNull (Get-SIItemValue $node 'value')
                    if ($null -ne $v) { & $add 'si_last_seen' $v; & $add 'si_last_seen' ($v + 1) }
                }
            }
            $vals = if ($node -is [System.Collections.IDictionary]) { @($node.Values) } else { @($node.PSObject.Properties | ForEach-Object { $_.Value }) }
            foreach ($v in $vals) { if ($null -ne $v -and -not ($v -is [string]) -and -not ($v -is [ValueType])) { $stack.Push(@($v, ($depth + 1))) } }
        } elseif ($node -is [System.Collections.IEnumerable]) {
            foreach ($v in $node) { if ($null -ne $v -and -not ($v -is [string]) -and -not ($v -is [ValueType])) { $stack.Push(@($v, ($depth + 1))) } }
        }
    }
    $arr = $out.ToArray()
    if ($arr.Count -eq 0) { return @() }
    [string[]]$keys = @($arr | ForEach-Object { '{0}|{1:D12}' -f $_.Field, $_.Seconds }); [int[]]$ix = @(0..($arr.Count - 1))
    [Array]::Sort($keys, $ix, [StringComparer]::Ordinal)
    @(foreach ($i in $ix) { $arr[$i] })
}

function Get-SICiThresholdSql {
    <#
        PURE. The SQL pieces the day thresholds need (Get-SICiTimeThresholds): Fields (the record date fields read from the
        record's JSON, [a-z0-9_] only), Apply (the OPENJSON over r.DocJson that reads them, '' when none) and per threshold
        its source expression and seconds. -SeenOnly: only the thresholds on the source's last seen (a column -- no JSON).
    #>
    param([AllowEmptyCollection()][object[]]$Thresholds = @(), [switch]$SeenOnly)
    $fields = New-Object System.Collections.Generic.List[string]
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Thresholds)) {
        if ($null -eq $t) { continue }
        $f = [string]$t.Field; $s = [long]$t.Seconds
        if ($SeenOnly -and $f) { continue }
        if ($f -and $f -notmatch '^[a-z0-9_]{1,64}$') { continue }
        if ($f -and $f -ne 'si_collection_time' -and -not $fields.Contains($f)) { $fields.Add($f) }
        $src = if (-not $f) { 'r.SourceLastSeen' } elseif ($f -eq 'si_collection_time') { 'r.CollectionTime' } else { ("CAST(SWITCHOFFSET(TRY_CONVERT(DATETIMEOFFSET(7), j.f{0}), '+00:00') AS DATETIME2(3))" -f $fields.IndexOf($f)) }
        $items.Add([pscustomobject]@{ Src = $src; Seconds = $s })
    }
    $apply = ''
    if ($fields.Count -gt 0) {
        $cols = @(for ($i = 0; $i -lt $fields.Count; $i++) { "f$i NVARCHAR(64) '$.""$($fields[$i])""'" })
        $apply = "OUTER APPLY OPENJSON(CASE WHEN ISJSON(r.DocJson) = 1 THEN r.DocJson END) WITH (" + ($cols -join ', ') + ") j"
    }
    [pscustomobject]@{ Fields = $fields.ToArray(); Apply = $apply; Items = $items.ToArray() }
}

function Get-SICiDirtySql {
    <#
        #534 ONE statement, after the grouping: computes every current record's inputs from its COLUMNS only (content hash,
        link state, last-seen signature -> CiGroupMember.Cur*; no record JSON is read), marks the DIRTY groups
        (CiGroupMember.Dirty) and answers why and where.
        TIME: a record is due when its NextDueAt (the earliest moment one of its day thresholds flips, stored when its group
        was built -- Get-SICiMarkBuiltSql) has passed, or its last-seen signature (which of the last-seen thresholds its
        source's last seen is within, and its place in its group by last seen) changed since that build. The date fields in
        the record's JSON change only with its content (its hash) or with time (NextDueAt): no per-run scan of every record.
        @nowText = the build's time (ISO), @sinceText = the last build's start (ISO; empty = none), @lk = the identity-ledger
        anchors changed since then ([{ t; v }]), @lc = the CI ids they point at ([ "id" ]), @ck = the owning CMDB's lookup
        keys and their content hashes NOW ([{ k; h }], Get-SICiCmdbKeyHashes) and @ckOn = '1' to compare them with the last
        build's (sidata.CiCmdbKey). -Thresholds: Get-SICiTimeThresholds.
        Answers a 'summary' row (Groups, DirtyGroups and the reasons: records New / Changed / Moved / Gone / State /
        TimeDue, groups Ledger / Overrides / PostPending / Cmdb / IdentityRefs / NotRebuilt) and one 'batch' row per batch.
        @carry = '1': this build CARRIES ON a rebuild of every CI that was stopped (Test-SICiCarryOn). A group with a record
        that build did not finish -- its BuiltAt is older than that build's start (@sinceText), or it has none -- is dirty;
        every other group is as that build left it (or as this statement finds it changed since, by the rules above).
        -CmdbStaged (#639): the CMDB keys and hashes NOW are read from sidata.CiBuildStage (Kind 'ck', staged in chunks by
        Write-SICiStageRows) instead of @ck -- never one parameter holding every key of a tenant-sized CMDB.
    #>
    param([int]$LookbackDays = 30, [AllowEmptyCollection()][object[]]$Thresholds = @(), [switch]$CmdbStaged)
    if ($CmdbStaged) {
        $ckNowSql = '    -- #639 the keys and hashes NOW, staged in chunks (sidata.CiBuildStage) -- compared in SQL'
        $ckSource = "(SELECT K, H FROM sidata.CiBuildStage WHERE Kind = N'ck')"
    } else {
        $ckNowSql = @'
    DECLARE @ckNow TABLE (K NVARCHAR(450) NOT NULL PRIMARY KEY, H VARCHAR(64) NULL);
    INSERT @ckNow SELECT LEFT(x.k, 450), MAX(LEFT(x.h, 64)) FROM OPENJSON(@ck) WITH (k NVARCHAR(450), h VARCHAR(64)) x WHERE x.k IS NOT NULL GROUP BY LEFT(x.k, 450);
'@
        $ckSource = '@ckNow'
    }
    $ts = Get-SICiThresholdSql -Thresholds $Thresholds -SeenOnly
    $bits = @(foreach ($i in $ts.Items) { "CASE WHEN {0} IS NULL THEN 'x' WHEN DATEADD(second, {1}, {0}) >= @now THEN '1' ELSE '0' END" -f $i.Src, $i.Seconds })
    $sig = if ($bits.Count -gt 0) { '(' + ($bits -join ' + ') + ')' } else { "''" }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @since DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@sinceText, N''), 127);
DECLARE @lb DATETIME2(3) = DATEADD(day, -$LookbackDays, SYSUTCDATETIME());
-- 1. what every current record is NOW, from its columns: its content hash, its link state against its feed's newest
--    collection (as Get-SIRecordLinkState decides it), its last-seen signature
WITH f AS (SELECT Provider, ISNULL(RecordType, N'') AS RecordType, MAX(CollectionTime) AS Latest FROM sidata.CiRecord
           WHERE CollectionTime >= @lb GROUP BY Provider, ISNULL(RecordType, N'')),
     fl AS (SELECT f.Provider, f.RecordType, f.Latest, MIN(CAST(ISNULL(r.Complete, 1) AS INT)) AS Complete
            FROM f JOIN sidata.CiRecord r ON r.Provider = f.Provider AND ISNULL(r.RecordType, N'') = f.RecordType AND r.CollectionTime = f.Latest
            GROUP BY f.Provider, f.RecordType, f.Latest),
     cur AS (SELECT m.RecordKey, r.ContentHash AS H,
                    CASE WHEN fl.Latest IS NULL OR r.CollectionTime >= fl.Latest THEN 'a' WHEN fl.Complete = 1 THEN 'n' ELSE 'f' END AS St,
                    HASHBYTES('SHA2_256', CAST($sig + '|' + CAST(DENSE_RANK() OVER (PARTITION BY m.GroupKey COLLATE Latin1_General_BIN2 ORDER BY r.SourceLastSeen DESC) AS VARCHAR(12)) AS VARCHAR(4000))) AS Sig
             FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
             LEFT JOIN fl ON fl.Provider = r.Provider AND fl.RecordType = ISNULL(r.RecordType, N''))
UPDATE m SET CurHash = cur.H, CurState = cur.St, CurTimeSig = cur.Sig, Dirty = 0
FROM sidata.CiGroupMember m JOIN cur ON cur.RecordKey = m.RecordKey;
-- 2. why a record makes its group dirty (counted per record, for the run log)
DECLARE @nNew INT, @nChanged INT, @nMoved INT, @nState INT, @nTime INT, @nGone INT, @nLedger INT = 0, @nOverride INT = 0, @nPost INT = 0, @nCmdb INT = 0;
SELECT @nNew = ISNULL(SUM(CASE WHEN r.BuiltGroupKey IS NULL THEN 1 ELSE 0 END), 0),
       @nChanged = ISNULL(SUM(CASE WHEN r.BuiltGroupKey IS NOT NULL AND (r.BuiltHash IS NULL OR m.CurHash IS NULL OR r.BuiltHash <> m.CurHash) THEN 1 ELSE 0 END), 0),
       @nMoved = ISNULL(SUM(CASE WHEN r.BuiltGroupKey IS NOT NULL AND r.BuiltGroupKey COLLATE Latin1_General_BIN2 <> m.GroupKey COLLATE Latin1_General_BIN2 THEN 1 ELSE 0 END), 0),
       @nState = ISNULL(SUM(CASE WHEN r.BuiltGroupKey IS NOT NULL AND ISNULL(r.BuiltState, '') <> ISNULL(m.CurState, '') THEN 1 ELSE 0 END), 0),
       @nTime = ISNULL(SUM(CASE WHEN r.BuiltGroupKey IS NOT NULL AND (r.NextDueAt <= @now OR r.BuiltTimeSig IS NULL OR m.CurTimeSig IS NULL OR r.BuiltTimeSig <> m.CurTimeSig) THEN 1 ELSE 0 END), 0)
FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey;
SET @nGone = (SELECT COUNT(*) FROM sidata.CiRecord r WHERE r.BuiltGroupKey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey));
DECLARE @g TABLE (GroupKey NVARCHAR(450) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY);
INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
WHERE r.BuiltGroupKey IS NULL OR r.BuiltHash IS NULL OR m.CurHash IS NULL OR r.BuiltHash <> m.CurHash
   OR r.BuiltGroupKey COLLATE Latin1_General_BIN2 <> m.GroupKey COLLATE Latin1_General_BIN2
   OR ISNULL(r.BuiltState, '') <> ISNULL(m.CurState, '')
   OR r.NextDueAt <= @now
   OR r.BuiltTimeSig IS NULL OR m.CurTimeSig IS NULL OR r.BuiltTimeSig <> m.CurTimeSig;
-- a group a record LEFT (to another group, or out of the lookback): the records that stay in it are dirty too
DECLARE @left TABLE (GroupKey NVARCHAR(450) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY);
INSERT @left SELECT DISTINCT r.BuiltGroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiRecord r LEFT JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
WHERE r.BuiltGroupKey IS NOT NULL AND (m.RecordKey IS NULL OR r.BuiltGroupKey COLLATE Latin1_General_BIN2 <> m.GroupKey COLLATE Latin1_General_BIN2);
INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
JOIN @left l ON l.GroupKey = r.BuiltGroupKey COLLATE Latin1_General_BIN2
WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
-- 3. the identity ledger: anchors changed since the last build, and the CI ids they point at
IF @lk IS NOT NULL AND @lk <> N'' AND @lk <> N'[]'
BEGIN
    INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m
    JOIN sidata.RecordIdentifier ri ON ri.RecordKey = m.RecordKey
    JOIN (SELECT DISTINCT LEFT(x.t, 40) AS t, LEFT(x.v, 400) AS v FROM OPENJSON(@lk) WITH (t NVARCHAR(64), v NVARCHAR(450)) x WHERE x.t IS NOT NULL AND x.v IS NOT NULL) k
      ON k.t = ri.IdType AND ri.IdValue = (CASE WHEN LEN(k.v) > 128 THEN N'sha256:' + LOWER(CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CAST(LOWER(LTRIM(RTRIM(k.v))) AS NVARCHAR(4000))), 2)) ELSE LOWER(LTRIM(RTRIM(k.v))) END)
    WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
    SET @nLedger = @nLedger + @@ROWCOUNT;
END
IF @lc IS NOT NULL AND @lc <> N'' AND @lc <> N'[]'
BEGIN
    INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
    JOIN (SELECT DISTINCT LEFT(x.value, 64) AS CiId FROM OPENJSON(@lc) x WHERE x.value IS NOT NULL) c ON c.CiId = r.CiId
    WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
    SET @nLedger = @nLedger + @@ROWCOUNT;
END
-- 4. manual overrides set, removed or expired since the last build (a database without the table has none)
DECLARE @oc TABLE (CiId NVARCHAR(64));
IF @since IS NOT NULL AND OBJECT_ID('sidata.CiOverride') IS NOT NULL
    INSERT @oc EXEC sp_executesql N'SELECT DISTINCT CiId FROM sidata.CiOverride WHERE SetAt >= @s OR RemovedAt >= @s OR (ExpiresAt > @s AND ExpiresAt <= @n)',
        N'@s DATETIME2(3), @n DATETIME2(3)', @s = @since, @n = @now;
INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
JOIN @oc o ON o.CiId = r.CiId
WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
SET @nOverride = @@ROWCOUNT;
-- 5. a CI whose newest full row did not reach SI_CI_CL
INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
JOIN sidata.Ci c ON c.CiId = r.CiId
WHERE c.PostRowHash IS NOT NULL AND (c.PostedHash IS NULL OR c.PostedHash <> c.PostRowHash)
  AND NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
SET @nPost = @@ROWCOUNT;
-- 6. the owning CMDB: a lookup key (a service id, an Azure resource id, an Entra object id, an FQDN) whose CMDB item is new,
--    changed (in the fields that reach a CI) or gone since the last build dirties ONLY the groups whose CI looked it up
--    (sidata.CiCmdbUse, written when the group was built)
IF @ckOn = N'1'
BEGIN
$ckNowSql
    DECLARE @ckChanged TABLE (K NVARCHAR(450) NOT NULL PRIMARY KEY);
    INSERT @ckChanged SELECT ISNULL(c.K, s.RefKey) FROM $ckSource c FULL OUTER JOIN sidata.CiCmdbKey s ON s.RefKey = c.K
    WHERE c.K IS NULL OR s.RefKey IS NULL OR ISNULL(s.Hash, '') <> ISNULL(c.H, '');
    INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiCmdbUse f JOIN @ckChanged k ON k.K = f.RefKey
    JOIN sidata.CiGroupMember m ON m.RecordKey = f.RecordKey
    WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
    SET @nCmdb = @@ROWCOUNT;
END
-- 6b. a rebuild of every CI that was stopped carries on (@carry = '1'): a group with a record the stopped build did not
--     finish (not built since that build started, or never) is built now. Before step 7, so a device that names an
--     identity still to be rebuilt is built after it.
DECLARE @nCarry INT = 0;
IF @carry = N'1' AND @since IS NOT NULL
BEGIN
    INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey
    WHERE (r.BuiltAt IS NULL OR r.BuiltAt < @since)
      AND NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
    SET @nCarry = @@ROWCOUNT;
END
-- 7. identities before devices: a device / resource whose owner or user (sidata.CiIdentityRef, written when its group was
--    built) is an identity of a DIRTY identity group, or of an identity record gone from the look-back, is dirty too -- an
--    identity that arrives or changes after its device re-links the device in the same run
DECLARE @nIdentity INT = 0;
DECLARE @ik TABLE (K NVARCHAR(400) NOT NULL PRIMARY KEY);
DECLARE @ir TABLE (RecordKey NVARCHAR(450) NOT NULL PRIMARY KEY);
INSERT @ir SELECT r.RecordKey FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey JOIN @g g ON g.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2
WHERE r.Class = N'identity'
UNION
SELECT r.RecordKey FROM sidata.CiRecord r WHERE r.Class = N'identity' AND r.BuiltGroupKey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey);
INSERT @ik SELECT DISTINCT LEFT(LOWER(x.K), 400) FROM (
    SELECT ri.IdValue AS K FROM sidata.RecordIdentifier ri JOIN @ir i ON i.RecordKey = ri.RecordKey WHERE ri.IdType IN (N'AadObjectId', N'SecurityIdentifier')
    UNION ALL
    SELECT JSON_VALUE(r.DocJson, '$.si_upn') FROM sidata.CiRecord r JOIN @ir i ON i.RecordKey = r.RecordKey WHERE ISJSON(r.DocJson) = 1
) x WHERE x.K IS NOT NULL AND x.K <> N'';
IF EXISTS (SELECT 1 FROM @ik)
BEGIN
    INSERT @g SELECT DISTINCT m.GroupKey COLLATE Latin1_General_BIN2 FROM sidata.CiIdentityRef f JOIN @ik k ON k.K = f.RefValue
    JOIN sidata.CiGroupMember m ON m.RecordKey = f.RecordKey
    WHERE NOT EXISTS (SELECT 1 FROM @g x WHERE x.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2);
    SET @nIdentity = @@ROWCOUNT;
END
UPDATE m SET Dirty = 1 FROM sidata.CiGroupMember m JOIN @g g ON g.GroupKey = m.GroupKey COLLATE Latin1_General_BIN2;
SELECT N'summary' AS Kind, CAST(NULL AS INT) AS BatchNo, (SELECT COUNT(DISTINCT GroupKey COLLATE Latin1_General_BIN2) FROM sidata.CiGroupMember) AS Groups,
       (SELECT COUNT(*) FROM @g) AS DirtyGroups, @nNew AS New, @nChanged AS Changed, @nMoved AS Moved, @nGone AS Gone, @nState AS State, @nTime AS TimeDue,
       @nLedger AS Ledger, @nOverride AS Overrides, @nPost AS PostPending, @nIdentity AS IdentityRefs, @nCmdb AS Cmdb, @nCarry AS NotRebuilt
UNION ALL
SELECT N'batch', m.BatchNo, COUNT(DISTINCT m.GroupKey COLLATE Latin1_General_BIN2), COUNT(DISTINCT CASE WHEN m.Dirty = 1 THEN m.GroupKey COLLATE Latin1_General_BIN2 END),
       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
FROM sidata.CiGroupMember m GROUP BY m.BatchNo;
"@
}

function Get-SICiMarkBuiltSql {
    <#
        #534 after a build that finished: what every record of a BUILT group was (BuiltHash / BuiltGroupKey / BuiltState /
        BuiltTimeSig = this build's Cur*) and its NextDueAt -- the earliest moment after this build at which one of its day
        thresholds (-Thresholds, Get-SICiTimeThresholds: its source's last seen and the date fields of its JSON) flips; only
        the records being built are read here. The built marks of records gone from the lookback are cleared. @all = '1'
        marks every current record (a full build). A record whose group's CI was not written (no CiId) stays unmarked -- it
        is built again. Answers Marked, Cleared.
        -Batch: the same marks for ONE batch (@b), written when that batch is finished -- a rebuild of every CI that is
        stopped later is carried on from there by the next build (Test-SICiCarryOn). With them, in the same transaction,
        the batch's posted marks (@p = [{ CiId; Hash }], the CIs whose full row reached SI_CI_CL -- else they ride in the
        next batch's write): a kept batch leaves nothing open. Nothing is cleared.
        @h = [ "record key" ] (both forms; '[]' = none): the records of the CIs the rules' time limit stopped in this build
        (SI-CiBuildRun.ps1, Get-SICiHeld). Nothing of such a CI was written, so the posted mark cannot bring it back: its
        records lose the hash they were built from (and BuiltAt) here, in the same transaction, AFTER the marks -- the next
        build finds the group changed (step 2 of Get-SICiDirtySql; step 6b when it carries on) and builds it again.
    #>
    param([AllowEmptyCollection()][object[]]$Thresholds = @(), [switch]$Batch)
    $ts = Get-SICiThresholdSql -Thresholds $Thresholds
    $vals = @(foreach ($i in $ts.Items) { "(CASE WHEN {0} IS NOT NULL AND DATEADD(second, {1}, {0}) > @now THEN DATEADD(second, {1}, {0}) END)" -f $i.Src, $i.Seconds })
    $due = if ($vals.Count -gt 0) { 'CROSS APPLY (SELECT MIN(v.x) AS Due FROM (VALUES ' + ($vals -join ', ') + ') v(x)) d' } else { 'CROSS APPLY (SELECT CAST(NULL AS DATETIME2(3)) AS Due) d' }
    if ($Batch) {
        return @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @marked INT;
BEGIN TRANSACTION;
IF @p IS NOT NULL AND @p <> N'' AND @p <> N'[]'
    UPDATE t SET PostedHash = CONVERT(VARBINARY(32), x.Hash, 2), PostedAt = SYSUTCDATETIME()
    FROM sidata.Ci t JOIN OPENJSON(@p) WITH (CiId NVARCHAR(64), Hash VARCHAR(64)) x ON x.CiId = t.CiId;
UPDATE r SET BuiltHash = m.CurHash, BuiltGroupKey = m.GroupKey, BuiltState = m.CurState, BuiltTimeSig = m.CurTimeSig, BuiltAt = @now, NextDueAt = d.Due
FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
$($ts.Apply)
$due
WHERE (m.Dirty = 1 OR @all = N'1') AND r.CiId IS NOT NULL AND m.BatchNo = CAST(@b AS INT);
SET @marked = @@ROWCOUNT;
-- KEEP IT OUT UNTIL FULLY EVALUATED: the records of a CI the rules' time limit stopped in this build (@h = [ "record key" ])
-- do not count as built -- without the hash they were built from, the next build finds their group changed and builds it
-- again with every rule; without BuiltAt, a build that carries on a stopped rebuild takes it up too
IF @h IS NOT NULL AND @h <> N'' AND @h <> N'[]'
    UPDATE r SET BuiltHash = NULL, BuiltAt = NULL
    FROM sidata.CiRecord r JOIN OPENJSON(@h) WITH (RecordKey NVARCHAR(450) '$') x ON x.RecordKey = r.RecordKey;
COMMIT TRANSACTION;
SELECT @marked AS Marked, 0 AS Cleared;
"@
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @marked INT = 0, @cleared INT = 0;
-- #881 IN KEY RANGES, each its own short transaction (every record of the build in ONE transaction filled the log at the
-- largest tenants); a range's size follows the measured time of the one before (about two seconds, at most double).
-- KEEP IT OUT UNTIL FULLY EVALUATED: the records of a CI the rules' time limit stopped in this build (@h = [ "record key" ])
-- are never marked here (so a build stopped between two ranges cannot leave one counted as built), and lose the hash they
-- were built from (and BuiltAt) below -- the next build finds their group changed and builds it again with every rule
CREATE TABLE #held (RecordKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
IF @h IS NOT NULL AND @h <> N'' AND @h <> N'[]'
    INSERT #held (RecordKey) SELECT DISTINCT x.RecordKey FROM OPENJSON(@h) WITH (RecordKey NVARCHAR(450) '$') x WHERE x.RecordKey IS NOT NULL;
DECLARE @lo NVARCHAR(450) = N'', @hi NVARCHAR(450), @first BIT = 1, @n BIGINT = 10000, @t0 DATETIME2(3), @ms BIGINT;
WHILE 1 = 1
BEGIN
    SET @hi = NULL;
    SELECT @hi = MAX(k.RecordKey) FROM (SELECT TOP (@n) g.RecordKey FROM sidata.CiGroupMember g WHERE (@first = 1 OR g.RecordKey > @lo) ORDER BY g.RecordKey) k;
    IF @hi IS NULL BREAK;
    SET @t0 = SYSUTCDATETIME();
    BEGIN TRANSACTION;
    UPDATE r SET BuiltHash = m.CurHash, BuiltGroupKey = m.GroupKey, BuiltState = m.CurState, BuiltTimeSig = m.CurTimeSig, BuiltAt = @now, NextDueAt = d.Due
    FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
    $($ts.Apply)
    $due
    WHERE (m.Dirty = 1 OR @all = N'1') AND r.CiId IS NOT NULL AND (@first = 1 OR m.RecordKey > @lo) AND m.RecordKey <= @hi
      AND NOT EXISTS (SELECT 1 FROM #held hk WHERE hk.RecordKey = r.RecordKey);
    SET @marked += @@ROWCOUNT;
    COMMIT TRANSACTION;
    SELECT @first = 0, @lo = @hi, @ms = DATEDIFF_BIG(MILLISECOND, @t0, SYSUTCDATETIME());
    SET @n = CASE WHEN @ms <= 0 THEN 2 * @n WHEN @n * 2000 / @ms > 2 * @n THEN 2 * @n ELSE @n * 2000 / @ms END;
    IF @n < 1 SET @n = 1;
    IF @n > 2147483647 SET @n = 2147483647;
END
UPDATE r SET BuiltHash = NULL, BuiltAt = NULL FROM sidata.CiRecord r JOIN #held x ON x.RecordKey = r.RecordKey;
-- the built marks of records gone from the lookback: in key ranges of the records too
SELECT @lo = N'', @first = 1, @n = 10000;
WHILE 1 = 1
BEGIN
    SET @hi = NULL;
    SELECT @hi = MAX(k.RecordKey) FROM (SELECT TOP (@n) r.RecordKey FROM sidata.CiRecord r WHERE (@first = 1 OR r.RecordKey > @lo) ORDER BY r.RecordKey) k;
    IF @hi IS NULL BREAK;
    SET @t0 = SYSUTCDATETIME();
    UPDATE r SET BuiltHash = NULL, BuiltGroupKey = NULL, BuiltState = NULL, BuiltTimeSig = NULL, NextDueAt = NULL
    FROM sidata.CiRecord r
    WHERE (@first = 1 OR r.RecordKey > @lo) AND r.RecordKey <= @hi
      AND r.BuiltGroupKey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey);
    SET @cleared += @@ROWCOUNT;
    SELECT @first = 0, @lo = @hi, @ms = DATEDIFF_BIG(MILLISECOND, @t0, SYSUTCDATETIME());
    SET @n = CASE WHEN @ms <= 0 THEN 2 * @n WHEN @n * 2000 / @ms > 2 * @n THEN 2 * @n ELSE @n * 2000 / @ms END;
    IF @n < 1 SET @n = 1;
    IF @n > 2147483647 SET @n = 2147483647;
END
SELECT @marked AS Marked, @cleared AS Cleared;
"@
}

function Get-SICiMarkBatchBuiltSql {
    <# ONE finished batch's built marks and posted marks (Get-SICiMarkBuiltSql -Batch): @nowText, @all, @b, @p, @h. #>
    param([AllowEmptyCollection()][object[]]$Thresholds = @())
    Get-SICiMarkBuiltSql -Thresholds $Thresholds -Batch
}

# =====================================================================================================================
# A REBUILD OF EVERY CI THAT IS STOPPED CARRIES ON. A build that rebuilds every CI (what the CIs are built from changed,
# the weekly reconcile, the weekly SI_CI_CL refresh) can take longer than the job may run on a large tenant; the platform
# then stops it. The CIs it wrote are in the database, but the records' built marks and the build's fingerprint were
# written only at the END -- so the next build knew nothing of them and rebuilt every CI again, and was stopped again.
#
#   * EVERY FINISHED BATCH IS KEPT: when a batch of a full build is written (CIs, links, refs, graph) and its rows are
#     posted, its records get their built marks at once (Get-SICiMarkBuiltSql -Batch), with BuiltAt = that build's start.
#   * THE BUILD SAYS WHAT IT IS BUILDING WITH: sidata.CiBuildState CarryOnFingerprint (the build fingerprint),
#     CarryOnPostContract (the SI_CI_CL columns), CarryOnFullPost (every full row is posted) -- written when it starts.
#   * THE NEXT BUILD CARRIES ON (Test-SICiCarryOn) when the last one did not finish and all of that is the same now: the
#     groups not built since the stopped build started are dirty (Get-SICiDirtySql step 6b) besides the groups whose
#     input changed since; every other group is skipped as in an incremental build (rule 4). The groups it keeps are
#     stamped with its own start (Get-SICiCarryOnKeepSql), so a build that is stopped again leaves the same picture.
#   A batch whose rows did not reach SI_CI_CL, or that was posted while Azure was adding columns to SI_CI_CL, is not
#   kept: it is built again. Anything else -- another fingerprint, a forced build, a failed build -- starts from the top.
# =====================================================================================================================

function Test-SICiCarryOn {
    <#
        PURE. Whether this build carries on the rebuild of every CI a stopped build started, instead of starting again.
        Yes when this build is full, the last build did not finish (LastBuildStatus 'running': it was stopped, not failed),
        it said what it built with (CarryOnFingerprint) and that is what this build builds with (-Fingerprint), the SI_CI_CL
        columns are the same (-PostContract), a full row of every CI is not asked for now unless the stopped build posted
        them too (-FullPost / CarryOnFullPost), its start is known (LastBuildStart) and nobody forced a full build (-Force).
        Returns @{ CarryOn; Stopped (the last build was a stopped rebuild); Why (when Stopped and not carried on) }.
    #>
    param([hashtable]$State = @{}, [string]$Fingerprint = '', [string]$PostContract = '', [bool]$FullBuild = $true, [bool]$FullPost = $false, [switch]$Force)
    $no = { param($stopped, $why) [pscustomobject]@{ CarryOn = $false; Stopped = [bool]$stopped; Why = [string]$why } }
    if ($null -eq $State) { $State = @{} }
    $was = [string]$State['CarryOnFingerprint']
    if (([string]$State['LastBuildStatus']).Trim().ToLowerInvariant() -ne 'running' -or -not $was) { return (& $no $false '') }
    if (-not $FullBuild) { return (& $no $true '') }
    if ($Force) { return (& $no $true 'a full build was asked for') }
    if (-not $Fingerprint -or $was -ne $Fingerprint) { return (& $no $true 'what the CIs are built from changed since') }
    if ([string]$State['CarryOnPostContract'] -ne $PostContract) { return (& $no $true 'the columns of SI_CI_CL changed since') }
    if ($FullPost -and [string]$State['CarryOnFullPost'] -ne '1') { return (& $no $true 'every CI''s full row is posted to SI_CI_CL now') }
    if ($null -eq (ConvertTo-SIUtcOrNull $State['LastBuildStart'])) { return (& $no $true 'its start time is not recorded') }
    [pscustomobject]@{ CarryOn = $true; Stopped = $true; Why = '' }
}

function Get-SICiCarryOnKeepSql {
    <#
        A build that carries on (Test-SICiCarryOn), after its dirty statement: the records of the groups it KEEPS (clean:
        rebuilt by the stopped build and unchanged since) get this build's start as their BuiltAt (@nowText). If this build
        is stopped too, the next one tells by BuiltAt alone what is done -- kept or built in this build -- and what is not:
        a group this build found dirty and did not reach keeps its older BuiltAt. Answers Records.
    #>
    @'
SET NOCOUNT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
UPDATE r SET BuiltAt = @now FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey WHERE m.Dirty = 0;
SELECT @@ROWCOUNT AS Records;
'@
}

function Format-SICiCarryOnLine {
    <# PURE. The run-log line of a build that carries on: how much the stopped build left done, how much is built now. #>
    param([int]$Groups = 0, [int]$ToBuild = 0, [int]$NotRebuilt = 0, [AllowNull()][string]$Since)
    $kept = [Math]::Max(0, $Groups - $ToBuild)
    $t = ConvertTo-SIUtcOrNull $Since
    $when = ''; if ($t) { $when = (' (the rebuild started {0} UTC)' -f $t.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)) }
    'CIs: the previous build was stopped before it finished -- this build carries on{0}: {1:N0} of {2:N0} CI group(s) are already rebuilt and are kept, {3:N0} are built now ({4:N0} of them only because the stopped build did not reach them).' -f $when, $kept, $Groups, $ToBuild, [Math]::Min($NotRebuilt, $ToBuild)
}

function Get-SICiSeenSql {
    <#
        #534 the CIs of the CLEAN groups (not built this run), in ONE set-based statement: their collection time moves to
        this build's (@nowText) and today's trend row (sidata.CiDaily) is written -- nothing else of the CI changes (rule 4:
        a skipped CI keeps its content, links, lifecycle and findings exactly; its last seen is its records' newest, which did
        not change, or the group would be dirty). Answers a 'summary' row (Touched, Daily) and one 'seen' row per clean CI
        (CiId, PostHash, LastSeen) -- the slim SI_CI_CL 'seen' row it gets every build (#515).
        -Stage (#639): the clean CIs go to sidata.CiBuildStage (Kind 'seen', emptied first by the build) and only the
        'summary' row is answered -- the seen rows are read from there a page at a time (Get-SICiSeenPageSql), never every
        clean CI of a tenant in one answer.
    #>
    param([switch]$Stage)
    if ($Stage) {
        return @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
INSERT sidata.CiBuildStage (Kind, K)
SELECT N'seen', x.CiId FROM (
    SELECT r.CiId FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE m.Dirty = 0 AND r.CiId IS NOT NULL
    EXCEPT SELECT r.CiId FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE m.Dirty = 1 AND r.CiId IS NOT NULL) x
WHERE NOT EXISTS (SELECT 1 FROM sidata.CiBuildStage s WHERE s.Kind = N'seen' AND s.K = x.CiId);
DECLARE @touched INT = 0, @daily INT = 0;
-- #881 IN KEY RANGES of the staged CI ids (the stage's own key), each its own short transaction -- every clean CI of the
-- tenant in ONE transaction filled the log at the largest tenants. A range's size follows the measured time of the one
-- before (about two seconds each, at most double). A build that stops part-way is not finished: the next build stages the
-- clean CIs again and moves the rest (a CI's collection time only moves forward; the trend row is per day and CI).
DECLARE @lo NVARCHAR(450) = N'', @hi NVARCHAR(450), @first BIT = 1, @n BIGINT = 10000, @t0 DATETIME2(3), @ms BIGINT;
WHILE 1 = 1
BEGIN
    SET @hi = NULL;
    SELECT @hi = MAX(k.K) FROM (SELECT TOP (@n) s.K FROM sidata.CiBuildStage s WHERE s.Kind = N'seen' AND (@first = 1 OR s.K > @lo) ORDER BY s.K) k;
    IF @hi IS NULL BREAK;
    SET @t0 = SYSUTCDATETIME();
    BEGIN TRANSACTION;
    UPDATE t SET CollectionTime = @now FROM sidata.Ci t JOIN sidata.CiBuildStage c ON c.Kind = N'seen' AND c.K = t.CiId
    WHERE (@first = 1 OR c.K > @lo) AND c.K <= @hi AND (t.CollectionTime IS NULL OR t.CollectionTime <> @now);
    SET @touched += @@ROWCOUNT;
    MERGE sidata.CiDaily AS d USING (SELECT CONVERT(date, SYSUTCDATETIME()) AS [Day], t.CiId, t.Tier, t.RiskScore, t.WeightedRiskScore, t.OpenFindings FROM sidata.Ci t
                                     JOIN sidata.CiBuildStage c ON c.Kind = N'seen' AND c.K = t.CiId WHERE (@first = 1 OR c.K > @lo) AND c.K <= @hi) AS s
    ON d.[Day] = s.[Day] AND d.CiId = s.CiId
    WHEN MATCHED AND (ISNULL(d.Tier, 255) <> ISNULL(s.Tier, 255)) THEN UPDATE SET Tier = s.Tier
    WHEN NOT MATCHED THEN INSERT ([Day], CiId, Tier, RiskScore, WeightedRiskScore, OpenFindings) VALUES (s.[Day], s.CiId, s.Tier, s.RiskScore, s.WeightedRiskScore, s.OpenFindings);
    SET @daily += @@ROWCOUNT;
    COMMIT TRANSACTION;
    SELECT @first = 0, @lo = @hi, @ms = DATEDIFF_BIG(MILLISECOND, @t0, SYSUTCDATETIME());
    SET @n = CASE WHEN @ms <= 0 THEN 2 * @n WHEN @n * 2000 / @ms > 2 * @n THEN 2 * @n ELSE @n * 2000 / @ms END;
    IF @n < 1 SET @n = 1;
    IF @n > 2147483647 SET @n = 2147483647;
END
SELECT N'summary' AS Kind, @touched AS Touched, @daily AS Daily, (SELECT COUNT(*) FROM sidata.CiBuildStage s JOIN sidata.Ci t ON t.CiId = s.K WHERE s.Kind = N'seen') AS Seen;
'@
    }
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127), SYSUTCDATETIME());
DECLARE @c TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY);
INSERT @c SELECT r.CiId FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE m.Dirty = 0 AND r.CiId IS NOT NULL
EXCEPT SELECT r.CiId FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE m.Dirty = 1 AND r.CiId IS NOT NULL;
DECLARE @touched INT = 0, @daily INT = 0;
BEGIN TRANSACTION;
UPDATE t SET CollectionTime = @now FROM sidata.Ci t JOIN @c c ON c.CiId = t.CiId WHERE t.CollectionTime IS NULL OR t.CollectionTime <> @now;
SET @touched = @@ROWCOUNT;
MERGE sidata.CiDaily AS d USING (SELECT CONVERT(date, SYSUTCDATETIME()) AS [Day], t.CiId, t.Tier, t.RiskScore, t.WeightedRiskScore, t.OpenFindings FROM sidata.Ci t
                                 JOIN @c c ON c.CiId = t.CiId) AS s
ON d.[Day] = s.[Day] AND d.CiId = s.CiId
WHEN MATCHED AND (ISNULL(d.Tier, 255) <> ISNULL(s.Tier, 255)) THEN UPDATE SET Tier = s.Tier
WHEN NOT MATCHED THEN INSERT ([Day], CiId, Tier, RiskScore, WeightedRiskScore, OpenFindings) VALUES (s.[Day], s.CiId, s.Tier, s.RiskScore, s.WeightedRiskScore, s.OpenFindings);
SET @daily = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT N'summary' AS Kind, CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS VARCHAR(64)) AS PostHash, CAST(NULL AS DATETIME2(3)) AS LastSeen, @touched AS Touched, @daily AS Daily
UNION ALL
SELECT N'seen', t.CiId, CONVERT(VARCHAR(64), ISNULL(t.PostRowHash, t.PostedHash), 2), t.LastSeen, NULL, NULL FROM sidata.Ci t JOIN @c c ON c.CiId = t.CiId;
'@
}

function Get-SICiRetireDays {
    <# The CI retire brake (owner 2026-10-11): a CI nothing records any more is retired only once it has been unseen this many
       days -- SI_Cmdb_RetireAfterDays, default 7, never under 1. #>
    param($Value = $global:SI_Cmdb_RetireAfterDays)
    $n = 0
    if ($null -ne $Value -and [int]::TryParse(([string]$Value).Trim(), [ref]$n) -and $n -ge 1) { return $n }
    return 7
}

function Get-SICiRetireSql {
    <#
        AFTER A BUILD THAT FINISHED: the CIs that NO current record builds any more are RETIRED -- never deleted (owner
        2026-10-11). A CI is current while one of the records the grouping holds (sidata.CiGroupMember: the records of the
        lookback with a strong identifier) points to it. A CI none of them points to -- its records aged out of the lookback
        (an asset gone; an Azure child resource, now a part of its parent; an Azure type that is not a CI type), or it has no
        record at all (an orphan of an earlier build, last seen never) -- is retired once its last seen is older than
        -FloorDays (Get-SICiRetireDays). A CI the collection scope or a disabled account leaves out still has its records in
        the grouping and is never retired by this. Retired: sidata.Ci Lifecycle and the document's si_lifecycle say
        'retired', its content hash is cleared (a CI that is recorded again is rewritten whole, active), and the change is
        recorded (sidata.CiChange). Answers Retired, Orphans (of them, CIs that had no record at all).
    #>
    param([int]$FloorDays = 7)
    if ($FloorDays -lt 1) { $FloorDays = 1 }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @floor DATETIME2(3) = DATEADD(day, -$FloorDays, SYSUTCDATETIME());
DECLARE @r TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY, OldLifecycle NVARCHAR(16) NULL, LastSeen DATETIME2(3) NULL, Orphan BIT NOT NULL);
INSERT @r (CiId, OldLifecycle, LastSeen, Orphan)
SELECT c.CiId, c.Lifecycle, c.LastSeen,
       CASE WHEN EXISTS (SELECT 1 FROM sidata.CiRecord r0 WHERE r0.CiId = c.CiId) THEN 0 ELSE 1 END
FROM sidata.Ci c
WHERE ISNULL(c.Lifecycle, N'') <> N'retired'
  AND (c.LastSeen IS NULL OR c.LastSeen < @floor)
  AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE r.CiId = c.CiId);
BEGIN TRANSACTION;
IF OBJECT_ID('sidata.CiChange') IS NOT NULL
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT x.CiId, N'si_lifecycle', x.OldLifecycle, N'retired', N'ci_build',
           CASE WHEN x.LastSeen IS NULL OR x.LastSeen < '19010101' THEN N'no source records it' ELSE LEFT(N'not seen since ' + CONVERT(NVARCHAR(10), x.LastSeen, 23), 512) END,
           LEFT(@run, 64)
    FROM @r x;
UPDATE c SET Lifecycle = N'retired', ContentHash = NULL, UpdatedAt = SYSUTCDATETIME(),
       DocJson = CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(c.DocJson, '$.si_lifecycle', N'retired'),
                      '$.si_lifecycle_since', CONVERT(NVARCHAR(30), SYSUTCDATETIME(), 127) + N'Z'),
                      '$.si_lifecycle_reason', CASE WHEN x.LastSeen IS NULL OR x.LastSeen < '19010101' THEN N'retired: no source records it any more'
                                                    ELSE N'retired: no source records it any more (not seen since ' + CONVERT(NVARCHAR(10), x.LastSeen, 23) + N')' END)
                 ELSE c.DocJson END
FROM sidata.Ci c JOIN @r x ON x.CiId = c.CiId;
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM @r) AS Retired, (SELECT COUNT(*) FROM @r WHERE Orphan = 1) AS Orphans;
"@
}

function Get-SICiCleanDocSql {
    <#
        #534 the stored documents of one batch's CLEAN CIs (@b) -- only when the build must hand every CI on (Risk Analysis
        building the CIs in its own run, the CI workbook): a skipped CI is read back as the last build wrote it.
    #>
    @'
SET NOCOUNT ON;
SELECT t.CiId, t.DocJson FROM sidata.Ci t
WHERE t.DocJson IS NOT NULL
  AND t.CiId IN (SELECT r.CiId FROM sidata.CiGroupMember m JOIN sidata.CiRecord r ON r.RecordKey = m.RecordKey WHERE m.BatchNo = CAST(@b AS INT) AND m.Dirty = 0 AND r.CiId IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM sidata.CiRecord r2 JOIN sidata.CiGroupMember m2 ON m2.RecordKey = r2.RecordKey WHERE r2.CiId = t.CiId AND m2.Dirty = 1);
'@
}

function Get-SICiLedgerChangedSql {
    <#
        #534 on the IDENTITY LEDGER's connection (it may be another database): the anchors written AFTER the last build
        started (@sinceText, ISO) -- a new or re-pointed anchor sets LastSeen -- and the ids superseded since then (old and
        new). Kind anchor | id. The last build's OWN writes carry its start time exactly (the ledger keeps whole seconds:
        @since is rounded the way the column rounds it) and are left out: they are what that build already built.
    #>
    @'
SET NOCOUNT ON;
DECLARE @since DATETIME2(0) = CAST(TRY_CONVERT(DATETIME2(3), NULLIF(@sinceText, N''), 127) AS DATETIME2(0));
IF @since IS NULL
    SELECT CAST(NULL AS NVARCHAR(16)) AS Kind, CAST(NULL AS NVARCHAR(64)) AS T, CAST(NULL AS NVARCHAR(450)) AS V, CAST(NULL AS NVARCHAR(64)) AS C WHERE 1 = 0;
ELSE
    SELECT N'anchor' AS Kind, o.IdentifierType AS T, o.IdentifierValue AS V, o.SI_CorrelationId AS C FROM si.ObjectIdentity o WHERE o.LastSeen > @since
    UNION ALL SELECT N'id', NULL, NULL, s.OldId FROM si.ObjectIdentitySuperseded s WHERE s.SupersededAt > @since
    UNION ALL SELECT N'id', NULL, NULL, s.NewId FROM si.ObjectIdentitySuperseded s WHERE s.SupersededAt > @since;
'@
}

function ConvertTo-SICiLedgerChanges {
    <#
        PURE. The changed-ledger rows (Get-SICiLedgerChangedSql, or a blob ledger's entries first seen since the last build)
        -> @{ Keys = [ { t; v } ] (identifier type + lower-cased value); CiIds = [ id ] }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $k = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $c = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $keys = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $t = [string](Get-SIItemValue $r 'T'); $v = ([string](Get-SIItemValue $r 'V')).ToLowerInvariant(); $id = [string](Get-SIItemValue $r 'C')
        if ($t -and $v -and $k.Add("$t|$v")) { $keys.Add([ordered]@{ t = $t; v = $v }) }
        if ($id) { [void]$c.Add($id) }
    }
    [pscustomobject]@{ Keys = $keys.ToArray(); CiIds = [string[]]@($c) }
}

function Get-SICiStateAllSql {
    <# #534 every build-state value in one read: Name, Value (the CarryOn* values: what a build that rebuilds every CI is
       building with -- Test-SICiCarryOn). #>
    @'
SET NOCOUNT ON;
SELECT Name, Value FROM sidata.CiBuildState WHERE Name IN (N'LastFullPost', N'LastFullBuild', N'BuildFingerprint', N'LastBuildStatus', N'LastBuildStart', N'PostContract',
    N'CarryOnFingerprint', N'CarryOnPostContract', N'CarryOnFullPost', N'CarryOnSince');
'@
}

function Get-SICiStateSetSql {
    <# #534 several build-state values in one statement: @j = [{ n; v }]. #>
    @'
SET NOCOUNT ON;
MERGE sidata.CiBuildState AS t USING (SELECT LEFT(x.n, 64) AS Name, LEFT(x.v, 400) AS Value FROM OPENJSON(@j) WITH (n NVARCHAR(128), v NVARCHAR(MAX)) x WHERE x.n IS NOT NULL) AS s
ON t.Name = s.Name
WHEN MATCHED THEN UPDATE SET Value = s.Value, UpdatedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (Name, Value) VALUES (s.Name, s.Value);
SELECT @@ROWCOUNT AS Written;
'@
}

function ConvertTo-SICiCanonicalText {
    <#
        PURE. Any value as one deterministic text: dictionary keys and object properties in ORDINAL order, datetimes as UTC
        ISO, numbers invariant. The same content gives the same text in every process (a .NET hashtable's own order
        differs per process) -- the build fingerprint hashes it. -Skip: property names left out (cache bookkeeping).
    #>
    param($Value, [string[]]$Skip = @())
    $sb = New-Object System.Text.StringBuilder
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@('v', $Value, 0))
    while ($stack.Count -gt 0) {
        $e = $stack.Pop()
        if ($e[0] -eq 't') { [void]$sb.Append([string]$e[1]); continue }
        $v = $e[1]; $d = [int]$e[2]
        if ($d -gt 40) { [void]$sb.Append('~'); continue }
        if ($null -eq $v) { [void]$sb.Append('null'); continue }
        if ($v -is [string]) { [void]$sb.Append('"').Append($v.Replace('\', '\\').Replace('"', '\"')).Append('"'); continue }
        if ($v -is [bool]) { [void]$sb.Append($(if ($v) { 'true' } else { 'false' })); continue }
        if ($v -is [datetime]) { [void]$sb.Append($v.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)); continue }
        if ($v -is [datetimeoffset]) { [void]$sb.Append($v.UtcDateTime.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)); continue }
        if ($v -is [ValueType]) { [void]$sb.Append([Convert]::ToString($v, [System.Globalization.CultureInfo]::InvariantCulture)); continue }
        if ($v -is [scriptblock] -or $v -is [regex]) { [void]$sb.Append('"').Append($v.ToString()).Append('"'); continue }
        $names = $null; $vals = $null
        if ($v -is [System.Collections.IDictionary]) {
            $names = [string[]]@($v.Keys | ForEach-Object { [string]$_ })
            $vals = @{}; foreach ($k in $v.Keys) { $vals[[string]$k] = $v[$k] }
        } elseif ($v -is [System.Management.Automation.PSCustomObject]) {
            $names = [string[]]@($v.PSObject.Properties | ForEach-Object { $_.Name })
            $vals = @{}; foreach ($p in $v.PSObject.Properties) { $vals[$p.Name] = $p.Value }
        }
        if ($null -ne $names) {
            [Array]::Sort($names, [StringComparer]::Ordinal)
            $keep = @($names | Where-Object { $Skip -notcontains $_ })
            # pushed in reverse: the stack pops them in order
            $stack.Push(@('t', '}'))
            for ($i = $keep.Count - 1; $i -ge 0; $i--) {
                $n = [string]$keep[$i]
                $stack.Push(@('v', $vals[$n], ($d + 1)))
                $stack.Push(@('t', ('"' + $n + '":')))
                if ($i -gt 0) { $stack.Push(@('t', ',')) }
            }
            $stack.Push(@('t', '{'))
            continue
        }
        if ($v -is [System.Collections.IEnumerable]) {
            $items = @($v)
            $stack.Push(@('t', ']'))
            for ($i = $items.Count - 1; $i -ge 0; $i--) {
                $stack.Push(@('v', $items[$i], ($d + 1)))
                if ($i -gt 0) { $stack.Push(@('t', ',')) }
            }
            $stack.Push(@('t', '['))
            continue
        }
        [void]$sb.Append('"').Append([string]$v).Append('"')
    }
    $sb.ToString()
}

function Get-SICiBuildLogicFiles {
    <# PURE. The scripts a CI is made by (relative to engine\data-model) -- what Get-SICiBuildLogicHash hashes, in order. #>
    @('SI-CiBuild.ps1', 'SI-CiBuildRun.ps1', 'SI-CiBuildSql.ps1', 'SI-CiEnrich.ps1', 'SI-CiRules.ps1', 'SI-FieldResolution.ps1', 'SI-Conditions.ps1', 'SI-CiGraph.ps1', 'identity\SI-ObjectIdentity.ps1', 'SI-Classification.ps1', 'SI-CiLifecycle.ps1')
}

function Get-SICiBuildLogicHash {
    <#
        The CI build's LOGIC as one SHA-256: the code tokens (comments left out, line endings irrelevant) of the scripts a CI is
        made by -- SI-CiBuild*.ps1, the enrichment, the rules, field resolution, conditions, identity. The two version lines
        ($script:SICiBuildVersion / $script:SICiBuildLogicHash) are left out. NOT part of the build fingerprint (a release
        never rebuilds every CI by itself): the guard test compares it with $script:SICiBuildLogicHash, so a change to the
        logic makes the developer decide -- bump $script:SICiBuildVersion when CIs come out different, else re-baseline.
    #>
    param([string]$Root = $PSScriptRoot)
    $files = Get-SICiBuildLogicFiles
    $sb = New-Object System.Text.StringBuilder
    foreach ($f in $files) {
        $p = [IO.Path]::Combine($Root, $f)
        [void]$sb.Append('#file ').Append($f).Append("`n")
        if (-not [IO.File]::Exists($p)) { [void]$sb.Append("missing`n"); continue }
        $text = [regex]::Replace([IO.File]::ReadAllText($p), '(?m)^\s*\$script:SICiBuild(Version|LogicHash)\s*=.*$', '')
        $tokens = $null; $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errs)
        foreach ($t in $tokens) {
            if ($t.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment -or $t.Kind -eq [System.Management.Automation.Language.TokenKind]::NewLine -or $t.Kind -eq [System.Management.Automation.Language.TokenKind]::EndOfInput) { continue }
            [void]$sb.Append($t.Text.Replace("`r`n", "`n")).Append(' ')
        }
        [void]$sb.Append("`n")
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString()))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Get-SICiBuildFingerprint {
    <#
        PURE. #534 a fingerprint of everything a CI is made of besides its records and the owning CMDB's items -- the data model
        (field catalog, mappings, risk factors, lists, trust, the criticality / sensitivity mapping, coverage), the CI rules,
        the CMDB OWNER (SIWeb_CmdbSource), the internet-exposed ranges setting, the lookback, the time thresholds and the
        build VERSION ($script:SICiBuildVersion -- bumped only when a change alters what a CI looks like; a release that does
        not is incremental). The CMDB's items are NOT in it: a changed, new or gone CMDB item dirties only the groups that use
        it (Get-SICiDirtySql step 6). Same fingerprint = a CI built now from the same records and CMDB items is the same CI.
        Like the privilege tier classifier's input fingerprint (#528). Returns 'sha256:<hex>'.
    #>
    param($Model, [AllowEmptyCollection()][object[]]$Rules = @(), [string]$CmdbOwner = '', [AllowEmptyCollection()][object[]]$Thresholds = @(),
          [int]$LookbackDays = 30, [int]$BuildVersion = $script:SICiBuildVersion, [string]$ExposedRanges = '',
          # 60.5.0d the collection scope per provider (Get-SICiCollectionScope): a scope change rebuilds every CI once, so every
          # record a provider last listed before the change is frozen at once
          [string]$CollectionScope = '')
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add('buildVersion=' + $BuildVersion); $parts.Add('owner=' + $CmdbOwner); $parts.Add('lookback=' + $LookbackDays); $parts.Add('ranges=' + $ExposedRanges)
    if ($CollectionScope) { $parts.Add('scope=' + $CollectionScope) }
    $parts.Add('thresholds=' + (@($Thresholds | Where-Object { $_ } | ForEach-Object { '{0}:{1}' -f $_.Field, $_.Seconds }) -join ','))
    if ($Model) {
        [string[]]$names = @($Model.Keys | ForEach-Object { [string]$_ }); [Array]::Sort($names, [StringComparer]::Ordinal)
        foreach ($n in $names) {
            if ($n -in 'Root', 'States') { continue }
            $parts.Add(('model.{0}={1}' -f $n, (ConvertTo-SICiCanonicalText $Model[$n])))
        }
    }
    $parts.Add('rules=' + (ConvertTo-SICiCanonicalText @($Rules)))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { 'sha256:' + ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($parts -join "`n")))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE OWNING CMDB PER CI (#534 follow-up, owner 2026-10-10: the CMDB out of the fingerprint). A CI looks the owning CMDB up
# by its CMDB id (a rule sets it), its Azure resource id, its Entra object id and its FQDN (Set-SICiCmdb). Every lookup key a
# built CI used is kept per record (sidata.CiCmdbUse); the content hash of the CMDB item behind every key of the index is
# kept per build (sidata.CiCmdbKey). A key whose item is new, changed (in the fields that reach a CI) or gone since the last
# build dirties only the groups that used it.
# ---------------------------------------------------------------------------------------------------------------------

# the fields of a CMDB item that reach a CI (Set-SICiCmdb's names, both the CMDB cache's and an external owner's records)
$script:SICiCmdbReachFields = @('id', 'RowKey', 'si_cmdb_id', 'cmdb_record_id', 'servicenow_sys_id', 'si_cmdb_name', 'name', 'cmdbName', 'si_cmdb_class', 'class', 'Class', 'sys_class_name',
    'si_cmdb_criticality', 'criticality', 'Criticality', 'si_cmdb_data_sensitivity', 'dataSensitivity', 'DataSensitivity', 'si_cmdb_environment', 'environment', 'Environment',
    'si_cmdb_owner', 'owner', 'Owner', 'OwnerMail', 'si_cmdb_owner_department', 'department', 'Department', 'si_cmdb_service', 'service', 'serviceName',
    'si_cmdb_support_group', 'supportGroup', 'SupportGroup', 'support_group')

function Get-SICiCmdbKey {
    <# PURE. One CMDB lookup key: '<kind>|<value>' in lower case (svc | arm | entra | fqdn); a key too long to index is hashed. #>
    param([Parameter(Mandatory)][string]$Kind, [AllowNull()][AllowEmptyString()][string]$Value)
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $v) { return '' }
    $k = $Kind + '|' + $v
    if ($k.Length -le 400) { return $k }   # with a 450-character record key the pair stays inside 1,700 bytes
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ($Kind + '|sha:' + (([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($v))) -replace '-', '').ToLowerInvariant())) } finally { $sha.Dispose() }
}

function Get-SICiCmdbItemHash {
    <# PURE. The content hash (32 hex) of the fields of a CMDB item that reach a CI -- a column nothing reads changes nothing. #>
    param($Item)
    if ($null -eq $Item) { return '' }
    $o = [ordered]@{}
    foreach ($f in $script:SICiCmdbReachFields) { $v = Get-SIItemValue $Item $f; if (-not (Test-SIValueEmpty $v)) { $o[$f] = [string]$v } }
    (Get-SIContentHash -Item $o).Substring(0, 32)
}

function Get-SICiCmdbKeyHashes {
    <#
        PURE. The owning CMDB's index (New-SICiCmdbIndex / New-SICiCmdbIndexFromRecords) -> every lookup key with the hash of
        the item behind it: [{ k; h }] in ordinal key order (the @ck of Get-SICiDirtySql / Get-SICiCmdbKeySaveSql).
    #>
    param([hashtable]$Index)
    $out = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
    if ($null -eq $Index) { return @() }
    foreach ($pair in @(@('Services', 'svc'), @('ByArm', 'arm'), @('ByEntra', 'entra'), @('ByFqdn', 'fqdn'))) {
        $map = $Index[$pair[0]]
        if ($null -eq $map) { continue }
        foreach ($k in @($map.Keys)) {
            $key = Get-SICiCmdbKey -Kind $pair[1] -Value ([string]$k)
            if ($key) { $out[$key] = Get-SICiCmdbItemHash -Item $map[$k] }
        }
    }
    @(foreach ($e in $out.GetEnumerator()) { [ordered]@{ k = $e.Key; h = $e.Value } })
}

function Get-SICiCmdbRefKeys {
    <#
        PURE. The CMDB lookup keys a built CI used (Set-SICiCmdb): its CMDB id, its Azure resource id link, its Entra object id
        link and its FQDN -- whether an item was found or not (a CMDB item that appears later for the key dirties the CI).
    #>
    param([Parameter(Mandatory)]$Ci)
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@('si_cmdb_id', 'svc'), @('si_link_azure', 'arm'), @('si_link_entra', 'entra'), @('si_fqdn', 'fqdn'))) {
        foreach ($v in @(Get-SIItemValue $Ci $pair[0])) {
            if ($null -eq $v -or -not ($v -is [string] -or $v -is [ValueType])) { continue }
            $k = Get-SICiCmdbKey -Kind $pair[1] -Value ([string]$v)
            if ($k -and -not $keys.Contains($k)) { $keys.Add($k) }
        }
    }
    # #496 the business-service keys the CI used (its CMDB page links, the service model rules, each service it is in)
    if (Get-Command -Name Get-SICiServiceRefKeys -ErrorAction SilentlyContinue) {
        foreach ($k in (Get-SICiServiceRefKeys -Ci $Ci)) { if ($k -and -not $keys.Contains($k)) { $keys.Add($k) } }
    }
    $keys.ToArray()
}

function Get-SICiCmdbRefs {
    <# PURE. A batch's CI documents -> the CMDB refs of their records: Refs [{ RecordKey; RefKey }], RecordKeys (replaced). #>
    param([AllowEmptyCollection()][object[]]$Docs = @())
    $refs = New-Object System.Collections.Generic.List[object]
    $rks = New-Object System.Collections.Generic.List[string]
    foreach ($d in $Docs) {
        if ($null -eq $d) { continue }
        $rk = @(@($d['si_linked_objects']) | Where-Object { $null -ne $_ -and $_.record_key } | ForEach-Object { [string]$_.record_key })
        foreach ($r in $rk) { $rks.Add($r) }
        foreach ($k in (Get-SICiCmdbRefKeys -Ci $d)) { foreach ($r in $rk) { $refs.Add([ordered]@{ RecordKey = $r; RefKey = $k }) } }
    }
    [pscustomobject]@{ Refs = $refs.ToArray(); RecordKeys = $rks.ToArray() }
}

function Get-SICiCmdbRefWriteSql {
    <# The CMDB lookup keys one batch's records used: @rk = their record keys (replaced), @r = [{ RecordKey; RefKey }]. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRANSACTION;
DELETE f FROM sidata.CiCmdbUse f JOIN (SELECT DISTINCT LEFT(x.value, 450) AS RecordKey FROM OPENJSON(@rk) x) k ON k.RecordKey = f.RecordKey;
INSERT sidata.CiCmdbUse (RecordKey, RefKey)
SELECT DISTINCT LEFT(x.RecordKey, 450), LEFT(x.RefKey, 400) FROM OPENJSON(@r) WITH (RecordKey NVARCHAR(450), RefKey NVARCHAR(400)) x
WHERE x.RecordKey IS NOT NULL AND x.RefKey IS NOT NULL AND x.RefKey <> N'';
COMMIT TRANSACTION;
SELECT @@ROWCOUNT AS Written;
'@
}

function Get-SICiCmdbKeySaveSql {
    <# After a build that finished: the owning CMDB's lookup keys and item hashes as this build saw them (@ck = [{ k; h }]).
       -FromStage (#639): read from sidata.CiBuildStage (Kind 'ck', staged in chunks) instead of @ck. #>
    param([switch]$FromStage)
    if ($FromStage) {
        return @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRANSACTION;
DELETE s FROM sidata.CiCmdbKey s WHERE NOT EXISTS (SELECT 1 FROM sidata.CiBuildStage c WHERE c.Kind = N'ck' AND c.K = s.RefKey);
UPDATE s SET Hash = c.H FROM sidata.CiCmdbKey s JOIN sidata.CiBuildStage c ON c.Kind = N'ck' AND c.K = s.RefKey WHERE ISNULL(s.Hash, '') <> ISNULL(c.H, '');
INSERT sidata.CiCmdbKey (RefKey, Hash) SELECT c.K, c.H FROM sidata.CiBuildStage c WHERE c.Kind = N'ck' AND NOT EXISTS (SELECT 1 FROM sidata.CiCmdbKey s WHERE s.RefKey = c.K);
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM sidata.CiCmdbKey) AS Keys;
'@
    }
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @ckNow TABLE (K NVARCHAR(450) NOT NULL PRIMARY KEY, H VARCHAR(64) NULL);
INSERT @ckNow SELECT LEFT(x.k, 450), MAX(LEFT(x.h, 64)) FROM OPENJSON(@ck) WITH (k NVARCHAR(450), h VARCHAR(64)) x WHERE x.k IS NOT NULL GROUP BY LEFT(x.k, 450);
BEGIN TRANSACTION;
DELETE s FROM sidata.CiCmdbKey s WHERE NOT EXISTS (SELECT 1 FROM @ckNow c WHERE c.K = s.RefKey);
UPDATE s SET Hash = c.H FROM sidata.CiCmdbKey s JOIN @ckNow c ON c.K = s.RefKey WHERE ISNULL(s.Hash, '') <> ISNULL(c.H, '');
INSERT sidata.CiCmdbKey (RefKey, Hash) SELECT c.K, c.H FROM @ckNow c WHERE NOT EXISTS (SELECT 1 FROM sidata.CiCmdbKey s WHERE s.RefKey = c.K);
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM sidata.CiCmdbKey) AS Keys;
'@
}

function Get-SICiFullReconcileDays {
    <# The setting SI_CiBuild_FullReconcileDays: a whole number 0-365 (0 = a full build every run); anything else = 7. #>
    param($Value = $global:SI_CiBuild_FullReconcileDays)
    if ($null -eq $Value -or "$Value" -eq '') { return 7 }
    $n = 0
    if ([int]::TryParse(([string]$Value).Trim(), [ref]$n) -and $n -ge 0 -and $n -le 365) { return $n }
    return 7
}

function Get-SICiFullReconcileDecision {
    <#
        PURE. #534 whether this build is FULL (every group) or INCREMENTAL (dirty groups only), and why. Full when:
          * forced (-Force: the -FullReconcile switch, for support), or SI_CiBuild_FullReconcileDays = 0
          * no full build was recorded, or the last is -Days or more old (weekly by default)
          * the build fingerprint differs from the one the last build stored (data model, rules, mappings, CMDB, code ...)
          * the previous build failed, was partial (some SI_CI_CL rows not posted) or did not finish
          * the weekly full SI_CI_CL refresh is due (-FullPostDue): every CI's full row is posted, so every CI is built
        -State: @{ LastFullBuild; BuildFingerprint; LastBuildStatus } (Get-SICiStateAllSql). Returns @{ Full; Reasons;
        FingerprintChanged }.
    #>
    param([hashtable]$State = @{}, [string]$Fingerprint = '', [datetime]$Now = [datetime]::UtcNow, [int]$Days = 7, [switch]$Force, [switch]$FullPostDue)
    $why = New-Object System.Collections.Generic.List[string]
    $fpChanged = $false
    if ($Force) { $why.Add('forced') }
    if ($Days -le 0) { $why.Add('a full build every run (SI_CiBuild_FullReconcileDays = 0)') }
    $last = ConvertTo-SIUtcOrNull $State['LastFullBuild']
    if ($null -eq $last) { $why.Add('no full build recorded yet') }
    elseif ($Days -gt 0 -and ($Now - $last).TotalDays -ge $Days) { $why.Add(('the last full build is {0:N1} day(s) old (a full reconcile every {1} day(s))' -f ($Now - $last).TotalDays, $Days)) }
    $was = [string]$State['BuildFingerprint']
    if ($was -and $Fingerprint -and $was -ne $Fingerprint) { $fpChanged = $true; $why.Add('what the CIs are built from changed (data model, mappings, risk factors, rules, CMDB or the build itself)') }
    elseif (-not $was -and $null -ne $last) { $fpChanged = $true; $why.Add('no build fingerprint recorded yet') }
    $st = ([string]$State['LastBuildStatus']).Trim().ToLowerInvariant()
    if ($st -eq 'running') { $why.Add('the previous build did not finish') }
    elseif ($st -eq 'failed') { $why.Add('the previous build failed') }
    elseif ($st -eq 'partial') { $why.Add('the previous build was partial (some rows did not reach SI_CI_CL)') }
    if ($FullPostDue) { $why.Add('the weekly full SI_CI_CL refresh is due') }
    [pscustomobject]@{ Full = ($why.Count -gt 0); Reasons = $why.ToArray(); FingerprintChanged = $fpChanged }
}

function Get-SICiReconcileMismatch {
    <#
        PURE. #534 on a FULL build: the CIs whose content differed from what the incremental builds had stored although their
        group was NOT dirty -- what the incremental build would have kept wrong. -Items: ConvertTo-SICiSqlItems's Cis (an
        item with a DocJson went whole: its hash differed from the stored one); -Docs: the batch's CI documents (their linked
        record keys); -DirtyRecords: the record keys of dirty groups (a HashSet); -Stored: Get-SICiBatchStored (a CI without
        a stored hash is new, never a mismatch). Returns the CI ids.
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [AllowEmptyCollection()][object[]]$Docs = @(), $DirtyRecords, $Stored)
    $whole = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($i in $Items) { if ($null -ne $i -and $null -ne $i['DocJson']) { [void]$whole.Add([string]$i['CiId']) } }
    if ($whole.Count -eq 0) { return @() }
    $hash = @{}; if ($Stored -and $Stored.Hash) { $hash = $Stored.Hash }
    @(foreach ($d in $Docs) {
        if ($null -eq $d) { continue }
        $id = [string]$d['si_ci_id']
        if (-not $whole.Contains($id) -or -not $hash[$id]) { continue }
        $dirty = $false
        foreach ($l in @($d['si_linked_objects'])) { if ($null -ne $l -and $l.record_key -and $null -ne $DirtyRecords -and $DirtyRecords.Contains([string]$l.record_key)) { $dirty = $true; break } }
        if (-not $dirty) { $id }
    })
}

function Format-SICiBuildModeLine {
    <#
        PURE. #534 the ONE run-log line about the build's mode: incremental or full, groups built / skipped, why a full ran,
        what made the groups dirty, and the CI work the skip saved (seconds, from this run's time per built group).
    #>
    param([bool]$Full, [string[]]$Reasons = @(), [int]$Groups = 0, [int]$Built = 0, $Dirty, [double]$WorkSeconds = 0)
    $skipped = [Math]::Max(0, $Groups - $Built)
    if ($Full) {
        return ('CIs: FULL build -- {0:N0} of {1:N0} group(s) built; why: {2}' -f $Built, $Groups, $(if (@($Reasons).Count) { @($Reasons) -join '; ' } else { 'requested' }))
    }
    $saved = ''
    if ($Built -gt 0 -and $skipped -gt 0 -and $WorkSeconds -gt 0) { $saved = (' -- about {0:N0} s of CI work skipped' -f ($WorkSeconds / $Built * $skipped)) }
    $d = ''
    if ($Dirty) {
        $d = ('; dirty because of: {0} new, {1} changed, {2} moved and {3} gone record(s), {4} link state(s), {5} time threshold(s) crossed or last-seen order(s) changed; {6} group(s) by the identity ledger, {7} by a manual override, {8} with a full row not yet in SI_CI_CL, {9} by a changed owner or user identity, {10} by a changed CMDB item' -f `
            [int](Get-SIItemValue $Dirty 'New'), [int](Get-SIItemValue $Dirty 'Changed'), [int](Get-SIItemValue $Dirty 'Moved'), [int](Get-SIItemValue $Dirty 'Gone'),
            [int](Get-SIItemValue $Dirty 'State'), [int](Get-SIItemValue $Dirty 'TimeDue'), [int](Get-SIItemValue $Dirty 'Ledger'), [int](Get-SIItemValue $Dirty 'Overrides'), [int](Get-SIItemValue $Dirty 'PostPending'), [int](Get-SIItemValue $Dirty 'IdentityRefs'), [int](Get-SIItemValue $Dirty 'Cmdb'))
    }
    'CIs: incremental build -- {0:N0} of {1:N0} group(s) built, {2:N0} skipped (unchanged since their last build){3}{4}' -f $Built, $Groups, $skipped, $d, $saved
}

# =====================================================================================================================
# IDENTITIES BEFORE DEVICES (owner 2026-10-10: "identities before devices in the CI build"). The grouping numbers the
# batches so that every group of only identity records (users, service principals, managed identities) comes first; their
# CIs are written before any device / resource CI is built. A device / resource CI then links, in the same run, to the
# identity CIs its owner (si_owner) and its users (si_logged_on_users) name -- si_owner_ci_id, si_user_ci_ids. The values it
# named are kept per record (sidata.CiIdentityRef): an identity group that becomes dirty -- it arrives, changes or goes --
# makes the device groups that name it dirty too (Get-SICiDirtySql step 6).
# =====================================================================================================================

function Get-SICiIdentityRefKeys {
    <#
        PURE. The owner / user values a CI names, lower case: si_owner (a UPN, an object id), and every user of
        si_logged_on_users (a text, or an object's sid / upn / name / id). Owner = the owner's values; Users = the users'.
    #>
    param([Parameter(Mandatory)]$Ci)
    $norm = { param($v) $s = ([string]$v).Trim().ToLowerInvariant(); if ($s.Length -gt 400) { $s = $s.Substring(0, 400) }; $s }
    $owner = New-Object System.Collections.Generic.List[string]
    foreach ($v in @(Get-SIItemValue $Ci 'si_owner')) { if ($null -ne $v -and ($v -is [string] -or $v -is [ValueType])) { $s = & $norm $v; if ($s -and -not $owner.Contains($s)) { $owner.Add($s) } } }
    $users = New-Object System.Collections.Generic.List[string]
    $userSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($u in @(Get-SIItemValue $Ci 'si_logged_on_users')) {
        if ($null -eq $u) { continue }
        $vals = if ($u -is [string]) { @($u) } else { @('sid', 'upn', 'userPrincipalName', 'name', 'id', 'accountName' | ForEach-Object { Get-SIItemValue $u $_ }) }
        foreach ($v in $vals) { if ($null -ne $v -and $v -is [string]) { $s = & $norm $v; if ($s -and $userSeen.Add($s)) { $users.Add($s) } } }
    }
    [pscustomobject]@{ Owner = $owner.ToArray(); Users = $users.ToArray() }
}

function ConvertTo-SICiIdentityIndex {
    <# PURE. (K, CiId) rows -> value (lower case) -> identity CI id; a value two CIs carry takes the ordinally smallest id. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Into)
    $idx = $Into
    if ($null -eq $idx) { $idx = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase) }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $k = ([string](Get-SIItemValue $r 'K')).Trim().ToLowerInvariant(); $c = [string](Get-SIItemValue $r 'CiId')
        if (-not $k -or -not $c) { continue }
        if (-not $idx.ContainsKey($k) -or [string]::CompareOrdinal($c, [string]$idx[$k]) -lt 0) { $idx[$k] = $c }
    }
    $idx
}

function Get-SICiIdentityDocKeys {
    <# PURE. An identity CI document's values a device can name: its Entra object id, its SID, its UPN -> (K, CiId) rows. #>
    param([AllowEmptyCollection()][object[]]$Docs = @())
    foreach ($d in $Docs) {
        if ($null -eq $d -or [string]$d['si_class'] -ne 'identity') { continue }
        $id = [string]$d['si_ci_id']; if (-not $id) { continue }
        foreach ($f in 'entra_object_id', 'ad_sid', 'si_upn') { foreach ($v in @($d[$f])) { if ($null -ne $v -and "$v" -ne '') { [pscustomobject]@{ K = [string]$v; CiId = $id } } } }
    }
}

function Set-SICiIdentityLinks {
    <#
        PURE. Every device / resource CI of -Docs gets its links to identity CIs from -Index (ConvertTo-SICiIdentityIndex):
        si_owner_ci_id (the first owner value that is an identity CI) and si_user_ci_ids (the users' identity CIs, sorted);
        a link it no longer has is removed. Answers Refs ([{ RecordKey; RefValue }] -- every value each record of a linking
        CI named) and RecordKeys (the records of the device / resource CIs: their refs are replaced) and Linked (CIs with a link).
    #>
    param([AllowEmptyCollection()][object[]]$Docs = @(), [hashtable]$Index = @{})
    $refs = New-Object System.Collections.Generic.List[object]
    $keys = New-Object System.Collections.Generic.List[string]
    $linked = 0
    foreach ($d in $Docs) {
        if ($null -eq $d -or [string]$d['si_class'] -eq 'identity') { continue }
        $rk = @(@($d['si_linked_objects']) | Where-Object { $null -ne $_ -and $_.record_key } | ForEach-Object { [string]$_.record_key })
        foreach ($k in $rk) { $keys.Add($k) }
        $named = Get-SICiIdentityRefKeys -Ci $d
        $owner = $null
        foreach ($v in $named.Owner) { if ($Index.ContainsKey($v)) { $owner = [string]$Index[$v]; break } }
        $users = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
        foreach ($v in $named.Users) { if ($Index.ContainsKey($v)) { [void]$users.Add([string]$Index[$v]) } }
        if ($d.Contains('si_owner_ci_id')) { $d.Remove('si_owner_ci_id') }
        if ($d.Contains('si_user_ci_ids')) { $d.Remove('si_user_ci_ids') }
        if ($owner) { $d['si_owner_ci_id'] = $owner }
        if ($users.Count -gt 0) { $d['si_user_ci_ids'] = [string[]]@($users) }
        if ($owner -or $users.Count -gt 0) { $linked++ }
        # every value once, in order (a set: a host that thousands of users logged on to names thousands of values)
        $once = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($v in @(@($named.Owner) + @($named.Users))) { if ($once.Add([string]$v)) { foreach ($k in $rk) { $refs.Add([ordered]@{ RecordKey = $k; RefValue = $v }) } } }
    }
    [pscustomobject]@{ Refs = $refs.ToArray(); RecordKeys = $keys.ToArray(); Linked = $linked }
}

function Get-SICiIdentityIndexSql {
    <#
        The identity CIs of this run's groups, by the values a device names: Entra object id and SID (the record identifiers)
        and UPN -> (K, CiId). Read once per build, when the first device / resource batch needs it -- after every identity
        batch of the run is written.
    #>
    @'
SET NOCOUNT ON;
SELECT LOWER(ri.IdValue) AS K, r.CiId FROM sidata.RecordIdentifier ri JOIN sidata.CiRecord r ON r.RecordKey = ri.RecordKey
JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
WHERE r.Class = N'identity' AND r.CiId IS NOT NULL AND ri.IdType IN (N'AadObjectId', N'SecurityIdentifier')
UNION ALL
SELECT LOWER(JSON_VALUE(r.DocJson, '$.si_upn')), r.CiId FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
WHERE r.Class = N'identity' AND r.CiId IS NOT NULL AND ISJSON(r.DocJson) = 1 AND JSON_VALUE(r.DocJson, '$.si_upn') IS NOT NULL;
'@
}

function Get-SICiIdentityRefWriteSql {
    <# The owner / user values of one batch's device / resource records: @rk = their record keys (replaced), @r = [{ RecordKey; RefValue }]. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
BEGIN TRANSACTION;
DELETE f FROM sidata.CiIdentityRef f JOIN (SELECT DISTINCT LEFT(x.value, 450) AS RecordKey FROM OPENJSON(@rk) x) k ON k.RecordKey = f.RecordKey;
INSERT sidata.CiIdentityRef (RecordKey, RefValue)
SELECT DISTINCT LEFT(x.RecordKey, 450), LEFT(x.RefValue, 400) FROM OPENJSON(@r) WITH (RecordKey NVARCHAR(450), RefValue NVARCHAR(400)) x
WHERE x.RecordKey IS NOT NULL AND x.RefValue IS NOT NULL AND x.RefValue <> N'';
COMMIT TRANSACTION;
SELECT @@ROWCOUNT AS Written;
'@
}

# =====================================================================================================================
# #639 THE CI BUILD AT MILLIONS OF ASSETS (2026-10-21, owner: "memory issues must not be a problem in any step. env must
# work in millions of assets env"). What the build used to hold for the WHOLE tenant at once -- every clean CI's seen row,
# the identity index, the owning CMDB's index with every item parsed, every CMDB key hash in one parameter -- is staged in
# SQL in chunks (sidata.CiBuildStage) and read back per page or per batch. Memory = one batch / one page at any size.
#   Kind 'ck'    the owning CMDB's and the business services' lookup keys (K) with the hash of what is behind each (H);
#                V = the CMDB item's fields a CI reads (Set-SICiCmdb) as JSON, for the per-batch lookup
#   Kind 'seen'  the CIs of the clean groups (Get-SICiSeenSql -Stage), read a page at a time (Get-SICiSeenPageSql)
#   Kind 'idk'   the identity CIs by the values a device names (Get-SICiIdentityStageSql), looked up per batch
# A database the updater has not updated yet (no sidata.CiBuildStage) keeps the whole-set path of before, and says so.
# =====================================================================================================================

function Get-SICiStageCheckSql {
    <# Is the build's stage there (an updated database)? Answers HasStage 1 / 0. #>
    "SET NOCOUNT ON; SELECT CASE WHEN OBJECT_ID(N'sidata.CiBuildStage') IS NULL THEN 0 ELSE 1 END AS HasStage;"
}

function Get-SICiStageClearSql {
    <# One step of emptying one kind of the build's stage (@kind, @n rows per statement): answers Deleted. Repeated by
       Clear-SICiStage until nothing is left -- never one statement over millions of rows. #>
    @'
SET NOCOUNT ON;
DELETE TOP (CONVERT(INT, @n)) FROM sidata.CiBuildStage WHERE Kind = @kind;
SELECT @@ROWCOUNT AS Deleted;
'@
}

function Clear-SICiStage {
    <# Empties one kind of the build's stage in steps. -Sql: the build's seam. Answers the rows removed. #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$Kind, [int]$Step = 50000)
    $n = 0L
    while ($true) {
        $r = @(& $Sql (Get-SICiStageClearSql) @{ kind = $Kind; n = [string]$Step } 'rows') | Select-Object -First 1
        $d = 0; if ($r) { $d = [int](Get-SIItemValue $r 'Deleted') }
        $n += $d
        if ($d -lt $Step) { break }
    }
    $n
}

function Get-SICiStageWriteSql {
    <# One chunk of stage rows (@kind; @j = [{ k; h; v }], one row per key -- the writer keeps the last of a key): a key
       already staged takes the chunk's hash and value (the last item of a key wins, as the in-memory index did). #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
MERGE sidata.CiBuildStage AS t
USING (SELECT @kind AS Kind, LEFT(x.k, 450) AS K, LEFT(x.h, 64) AS H, x.v AS V
       FROM OPENJSON(@j) WITH (k NVARCHAR(450), h VARCHAR(64), v NVARCHAR(MAX)) x WHERE x.k IS NOT NULL AND x.k <> N'') AS s
ON t.Kind = s.Kind AND t.K = s.K
WHEN MATCHED THEN UPDATE SET H = s.H, V = s.V
WHEN NOT MATCHED THEN INSERT (Kind, K, H, V) VALUES (s.Kind, s.K, s.H, s.V);
SELECT @@ROWCOUNT AS Written;
'@
}

function Get-SICiStageChunkBytes {
    <# The text size of one staging statement's rows: SI_CiBuild_StageChunkKB (default 2048 KB). It paces the round trips;
       it never limits how many rows are staged. #>
    $kb = 0
    if ($global:SI_CiBuild_StageChunkKB -and [int]::TryParse(([string]$global:SI_CiBuild_StageChunkKB).Trim(), [ref]$kb) -and $kb -gt 0) { return ($kb * 1024) }
    return (2048 * 1024)
}

function New-SICiStageWriter {
    <#
        A writer of stage rows in chunks: .Add(k, h, v) keeps the row (a key added twice keeps the last), and when the rows
        held reach the chunk size (Get-SICiStageChunkBytes) they are written in one statement and let go. .Flush() writes
        the rest. Memory = one chunk. Rows / Statements / MaxHeld count what it did.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$Kind, [int]$ChunkBytes = 0)
    if ($ChunkBytes -le 0) { $ChunkBytes = Get-SICiStageChunkBytes }
    $w = [pscustomobject]@{ Kind = $Kind; Rows = 0L; Statements = 0; Bytes = 0L; MaxHeld = 0
        Held = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)); ChunkBytes = $ChunkBytes; Sql = $Sql }
    $w | Add-Member -MemberType ScriptMethod -Name Flush -Value {
        if ($this.Held.Count -eq 0) { return }
        if ($this.Held.Count -gt $this.MaxHeld) { $this.MaxHeld = $this.Held.Count }
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($e in $this.Held.Values) { $items.Add($e) }
        $null = & $this.Sql (Get-SICiStageWriteSql) @{ kind = $this.Kind; j = (ConvertTo-SIJsonArray $items.ToArray() -Depth 3) } 'rows'
        $this.Rows += $this.Held.Count; $this.Statements++
        $this.Held.Clear(); $this.Bytes = 0L
    }
    $w | Add-Member -MemberType ScriptMethod -Name Add -Value {
        param([string]$K, [string]$H, [string]$V)
        if (-not $K) { return }
        $this.Held[$K] = [ordered]@{ k = $K; h = $H; v = $V }
        $this.Bytes += $K.Length + 8 + $(if ($H) { $H.Length } else { 0 }) + $(if ($V) { $V.Length } else { 0 })
        if ($this.Bytes -ge $this.ChunkBytes) { $this.Flush() }
    }
    $w
}

function Get-SICiSeenPageSql {
    <# One page of the clean CIs' slim 'seen' rows (#639): the stage's 'seen' keys after @after, in key order, @n of them. #>
    @'
SET NOCOUNT ON;
SELECT TOP (CONVERT(INT, @n)) s.K AS CiId, CONVERT(VARCHAR(64), ISNULL(t.PostRowHash, t.PostedHash), 2) AS PostHash, t.LastSeen
FROM sidata.CiBuildStage s JOIN sidata.Ci t ON t.CiId = s.K
WHERE s.Kind = N'seen' AND s.K > @after
ORDER BY s.K;
'@
}

function Get-SICiOwnerCmdbRecordPageSql {
    <# #463 / #639 one page of the owning EXTERNAL CMDB's records (provider = @p, type cmdb_ci): after @after, in record key
       order, @n of them -- the same records Get-SICiOwnerCmdbRecordSql reads, never all of them in one answer. #>
    @'
SET NOCOUNT ON;
SELECT TOP (CONVERT(INT, @n)) r.RecordKey, r.DocJson FROM sidata.CiRecord r
WHERE r.Provider = @p AND r.RecordType = N'cmdb_ci' AND r.DocJson IS NOT NULL AND r.RecordKey > @after
ORDER BY r.RecordKey;
'@
}

function Get-SICiCmdbStageLookupSql {
    <# #639 the staged CMDB items of one batch's lookup keys (@k = [ "key" ]): K, V (the item's fields a CI reads). #>
    @'
SET NOCOUNT ON;
SELECT s.K, s.V FROM sidata.CiBuildStage s
JOIN (SELECT DISTINCT LEFT(x.value, 450) AS K FROM OPENJSON(@k) x WHERE x.value IS NOT NULL AND x.value <> N'') k ON k.K = s.K
WHERE s.Kind = N'ck' AND s.V IS NOT NULL;
'@
}

function ConvertTo-SICiCmdbStageItem {
    <#
        PURE. One CMDB item (a CMDB cache service / CI, or an external owner's cmdb_ci record) -> the stage rows of its lookup
        keys: [{ K; H; V }] where V = { m = the index it belongs to (Services | ByArm | ByEntra | ByFqdn); v = the value as
        the in-memory index keyed it (lower case); i = the item's fields a CI reads }. -Kind: 'service' (a CMDB cache
        service: Services by its id), 'ci' (a CMDB cache CI: ByArm / ByEntra / ByFqdn), 'record' (an external owner's
        record: all four, as New-SICiCmdbIndexFromRecords keys it). H = Get-SICiCmdbItemHash of the ITEM (the hash the
        in-memory path computed), so an unchanged item never looks changed.
    #>
    param($Item, [Parameter(Mandatory)][ValidateSet('service', 'ci', 'record')][string]$Kind)
    if ($null -eq $Item) { return }
    $fields = [ordered]@{}
    foreach ($f in $script:SICiCmdbReachFields) { $v = Get-SIItemValue $Item $f; if (-not (Test-SIValueEmpty $v)) { $fields[$f] = [string]$v } }
    $h = Get-SICiCmdbItemHash -Item $Item
    $emit = {
        param([string]$Map, [string]$KeyKind, [string]$Raw)
        $k = Get-SICiCmdbKey -Kind $KeyKind -Value $Raw
        if (-not $k) { return }
        [pscustomobject]@{ K = $k; H = $h; V = (ConvertTo-Json -InputObject ([ordered]@{ m = $Map; v = $Raw.ToLowerInvariant(); i = $fields }) -Compress -Depth 4) }
    }
    switch ($Kind) {
        'service' {
            $id = [string](Get-SIItemValue $Item 'id'); if (-not $id) { $id = [string](Get-SIItemValue $Item 'RowKey') }
            if ($id) { & $emit 'Services' 'svc' $id }
        }
        'ci' {
            $a = [string](Get-SIItemValue $Item 'azure_resource_id'); if ($a) { & $emit 'ByArm' 'arm' $a }
            $e = [string](Get-SIItemValue $Item 'entra_object_id'); if ($e) { & $emit 'ByEntra' 'entra' $e }
            $f = [string](Get-SIItemValue $Item 'fqdn'); if ($f) { & $emit 'ByFqdn' 'fqdn' $f }
        }
        'record' {
            $id = [string](Get-SIItemValue $Item 'si_cmdb_id'); if (-not $id) { $id = [string](Get-SIItemValue $Item 'cmdb_record_id') }; if (-not $id) { $id = [string](Get-SIItemValue $Item 'servicenow_sys_id') }
            if ($id) { & $emit 'Services' 'svc' $id }
            foreach ($a in (Get-SIValueList (Get-SIItemValue $Item 'azure_resource_id'))) { if ($a) { & $emit 'ByArm' 'arm' ([string]$a) } }
            foreach ($e in (Get-SIValueList (Get-SIItemValue $Item 'entra_object_id'))) { if ($e) { & $emit 'ByEntra' 'entra' ([string]$e) } }
            $f = [string](Get-SIItemValue $Item 'si_fqdn'); if ($f) { & $emit 'ByFqdn' 'fqdn' $f }
        }
    }
}

function Get-SICiCmdbLookupKeys {
    <#
        PURE. The CMDB lookup keys one batch's CIs can use (Set-SICiCmdb): each CI's CMDB id, Azure resource id link, Entra
        object id link and FQDN -- as the documents hold them before the rules -- plus -ExtraIds (the CMDB ids the rules and
        the manual overrides can set, Get-SICiRuleCmdbIds). Answers the keys (Get-SICiCmdbKey), each once.
    #>
    param([AllowEmptyCollection()][object[]]$Docs = @(), [AllowEmptyCollection()][string[]]$ExtraIds = @())
    $keys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $add = {
        param($kind, $v)
        if ($null -eq $v) { return }
        foreach ($x in @($v)) { if ($null -ne $x -and ($x -is [string] -or $x -is [ValueType])) { $k = Get-SICiCmdbKey -Kind $kind -Value ([string]$x); if ($k) { [void]$keys.Add($k) } } }
        # (Set-SICiCmdb reads the value as one text)
        $s = [string]$v; if ($s) { $k = Get-SICiCmdbKey -Kind $kind -Value $s; if ($k) { [void]$keys.Add($k) } }
    }
    foreach ($d in $Docs) {
        if ($null -eq $d) { continue }
        & $add 'svc' (Get-SIItemValue $d 'si_cmdb_id')
        & $add 'arm' (Get-SIItemValue $d 'si_link_azure')
        & $add 'entra' (Get-SIItemValue $d 'si_link_entra')
        & $add 'fqdn' (Get-SIItemValue $d 'si_fqdn')
    }
    foreach ($x in @($ExtraIds)) { if ($x) { $k = Get-SICiCmdbKey -Kind 'svc' -Value ([string]$x); if ($k) { [void]$keys.Add($k) } } }
    $out = New-Object 'string[]' $keys.Count; $keys.CopyTo($out); $out
}

function Get-SICiRuleCmdbIds {
    <# PURE. The CMDB ids the CI rules and the manual overrides can set (a rule's set.si_cmdb_id, an override of si_cmdb_id)
       -- looked up with every batch, since they are set after a CI's own values are known. Each once. #>
    param([AllowEmptyCollection()][object[]]$Rules = @(), [hashtable]$Overrides)
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $s = Get-SIItemValue $r 'set'
        if ($null -eq $s) { continue }
        $v = Get-SIItemValue $s 'si_cmdb_id'
        foreach ($x in @($v)) { if ($null -ne $x -and "$x" -ne '') { [void]$ids.Add([string]$x) } }
    }
    if ($Overrides) {
        foreach ($k in @($Overrides.Keys)) { foreach ($o in @($Overrides[$k])) { if ($o -and [string]$o.field -eq 'si_cmdb_id' -and "$($o.value)" -ne '') { [void]$ids.Add([string]$o.value) } } }
    }
    $out = New-Object 'string[]' $ids.Count; $ids.CopyTo($out); $out
}

function ConvertTo-SICiCmdbBatchIndex {
    <# PURE. Staged rows (K, V) -> the index shape New-SICiCmdbIndex answers (Services / ByArm / ByEntra / ByFqdn), only the
       batch's items; Count = -Total (the size of the whole owning CMDB, so Set-SICiCmdb never takes it for "no CMDB"). #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [long]$Total = 0)
    $ix = @{ Services = @{}; ByArm = @{}; ByEntra = @{}; ByFqdn = @{}; Count = 0 }
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $js = [string](Get-SIItemValue $r 'V'); if (-not $js) { continue }
        $o = $null; try { $o = ConvertFrom-Json -InputObject $js } catch { continue }
        if ($null -eq $o -or -not $o.m -or $null -eq $o.v) { continue }
        $item = [ordered]@{}
        if ($o.i) { foreach ($p in $o.i.PSObject.Properties) { $item[$p.Name] = [string]$p.Value } }
        $map = $ix[[string]$o.m]; if ($null -eq $map) { continue }
        $map[[string]$o.v] = [pscustomobject]$item
    }
    $n = $ix.Services.Count + $ix.ByArm.Count + $ix.ByEntra.Count + $ix.ByFqdn.Count
    $ix['Count'] = [Math]::Max([long]$n, $Total)
    $ix
}

function Get-SICiIdentityStageSql {
    <#
        #639 the identity CIs of this run's groups by the values a device names (as Get-SICiIdentityIndexSql reads them) go to
        the build's stage ONCE (Kind 'idk': K = the value, lower case; V = the ordinally smallest CI id that carries it --
        ConvertTo-SICiIdentityIndex's rule), set-based in SQL. Each batch then looks up only the values its CIs name
        (Get-SICiIdentityLookupSql). Answers Staged.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
INSERT sidata.CiBuildStage (Kind, K, V)
SELECT N'idk', x.K, MIN(x.CiId COLLATE Latin1_General_BIN2) FROM (
    SELECT LEFT(LOWER(LTRIM(RTRIM(ri.IdValue))), 450) AS K, r.CiId FROM sidata.RecordIdentifier ri JOIN sidata.CiRecord r ON r.RecordKey = ri.RecordKey
    JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
    WHERE r.Class = N'identity' AND r.CiId IS NOT NULL AND ri.IdType IN (N'AadObjectId', N'SecurityIdentifier')
    UNION ALL
    SELECT LEFT(LOWER(LTRIM(RTRIM(JSON_VALUE(r.DocJson, '$.si_upn')))), 450), r.CiId FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
    WHERE r.Class = N'identity' AND r.CiId IS NOT NULL AND ISJSON(r.DocJson) = 1 AND JSON_VALUE(r.DocJson, '$.si_upn') IS NOT NULL) x
WHERE x.K IS NOT NULL AND x.K <> N''
GROUP BY x.K;
SELECT @@ROWCOUNT AS Staged;
'@
}

function Get-SICiIdentityLookupSql {
    <# #639 the identity CIs of one batch's owner / user values (@k = [ "value" ], lower case): (K, CiId) from the stage. #>
    @'
SET NOCOUNT ON;
SELECT s.K, s.V AS CiId FROM sidata.CiBuildStage s
JOIN (SELECT DISTINCT LEFT(x.value, 450) AS K FROM OPENJSON(@k) x WHERE x.value IS NOT NULL AND x.value <> N'') k ON k.K = s.K
WHERE s.Kind = N'idk';
'@
}

function Get-SICiIdentityBatchKeys {
    <# PURE. The owner / user values one batch's device / resource CIs name (Get-SICiIdentityRefKeys), each once. #>
    param([AllowEmptyCollection()][object[]]$Docs = @())
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($d in $Docs) {
        if ($null -eq $d -or [string]$d['si_class'] -eq 'identity') { continue }
        $n = Get-SICiIdentityRefKeys -Ci $d
        foreach ($v in @(@($n.Owner) + @($n.Users))) { if ($v) { [void]$set.Add([string]$v) } }
    }
    $out = New-Object 'string[]' $set.Count; $set.CopyTo($out); $out
}

function Get-SICiWorkbookPageSql {
    <# #639 one page of the CIs of THIS build for the CI workbook (every CI the build wrote, kept or saw: its collection time
       is the build's, @nowText): after @after, in id order, @n of them -- the workbook is read a page at a time, no cap. #>
    @'
SET NOCOUNT ON;
DECLARE @now DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@nowText, N''), 127);
SELECT TOP (CONVERT(INT, @n)) t.CiId, t.DocJson FROM sidata.Ci t
WHERE t.DocJson IS NOT NULL AND t.CiId > @after AND t.CollectionTime = @now
ORDER BY t.CiId;
'@
}
