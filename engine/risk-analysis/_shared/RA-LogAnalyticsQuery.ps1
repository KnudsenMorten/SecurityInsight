#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Log Analytics / Advanced Hunting query execution and its literal-escaping helpers.
#
#  The one place a KQL string is actually sent to a workspace, plus the helpers that decide which
#  table owner answers and how a value is escaped into a query literal.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Invoke-LogAnalyticsKqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 600
    )

    # Reuse the existing Connect-AzAccount session via Az.OperationalInsights -- no manual
    # token retrieval, no REST plumbing. Az.OperationalInsights ships with the Az meta-module,
    # which is in $script:SecurityInsight_RequiredModules (already ensured at engine startup).
    $custId = Resolve-WorkspaceCustomerId -WorkspaceResourceId $WorkspaceResourceId
    try {
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $custId -Query $Query -Wait $TimeoutSec -ErrorAction Stop
    } catch {
        # Diagnostic dump: when LA returns 400/BadRequest, Az.OperationalInsights surfaces only
        # the bare HTTP status -- the actual KQL parse error is in the inner exception's response
        # body. Persist query + full exception chain + body to staging so we can see exactly which
        # column / syntax LA rejected per failing report.
        # NOTE: missing-table errors ('Failed to resolve table or column expression named SI_*_CL')
        # are real REPORT-DESIGN bugs, not transient state. They mean a report's KQL declared a
        # source dependency the customer's environment hasn't satisfied (asset-profiling not yet
        # run, or that report shouldn't have been included in the template). v2.2.80's graceful-skip
        # was reverted in v2.2.82 -- per operator policy, surface the failure loudly so report
        # authors can either (a) fix the dependency declaration or (b) gate the report behind a
        # SourceTables manifest entry the engine can pre-flight before submitting the query.
        try {
            $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
            $stagingDir = if ($global:SI_StagingPath) { Join-Path $global:SI_StagingPath 'risk-analysis' }
                          elseif ($global:OutputPath) { Join-Path $global:OutputPath 'staging\risk-analysis' }
                          else { Join-Path $env:TEMP 'si-ra' }
            New-Item -Path $stagingDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            $errFile = Join-Path $stagingDir ("ra-laerr-{0}.txt" -f $stamp)
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("=== Workspace ===")
            [void]$sb.AppendLine($WorkspaceResourceId)
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Outer exception ===")
            [void]$sb.AppendLine([string]$_.Exception.Message)
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Exception type chain ===")
            $e = $_.Exception
            while ($null -ne $e) {
                [void]$sb.AppendLine([string]$e.GetType().FullName + " :: " + [string]$e.Message)
                $e = $e.InnerException
            }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== HTTP response body (LA's actual error) ===")
            # Az.OperationalInsights ErrorResponseException exposes the body via several paths
            # depending on SDK version. Try them all and dump whatever we find.
            $bodyCandidates = @()
            try {
                $ex = $_.Exception
                # Path 1: Azure SDK -- .Body is a deserialised ErrorResponse object with .Error.{Code,Message,Details}
                if ($ex.Body) {
                    $bodyCandidates += "[.Body]"
                    $bodyCandidates += try { $ex.Body | ConvertTo-Json -Depth 8 } catch { [string]$ex.Body }
                }
                # Path 2: .Response.Content -- HttpResponseMessage style
                if ($ex.Response -and $ex.Response.Content) {
                    $bodyCandidates += "[.Response.Content]"
                    $bodyCandidates += try { $ex.Response.Content | ConvertTo-Json -Depth 8 } catch { [string]$ex.Response.Content }
                }
                # Path 3: WebException-style stream
                $webResp = $null
                if ($ex.Response -and $ex.Response.GetType().Name -eq 'HttpWebResponse') { $webResp = $ex.Response }
                elseif ($ex.InnerException -and $ex.InnerException.Response -and $ex.InnerException.Response.GetType().Name -eq 'HttpWebResponse') { $webResp = $ex.InnerException.Response }
                if ($webResp) {
                    try {
                        $stream = $webResp.GetResponseStream()
                        if ($stream.CanSeek) { $stream.Position = 0 }
                        $reader = New-Object System.IO.StreamReader($stream)
                        $bodyCandidates += "[.Response stream]"
                        $bodyCandidates += $reader.ReadToEnd()
                    } catch { $bodyCandidates += "(stream read failed: " + $_.Exception.Message + ")" }
                }
                # Path 4: ErrorRecord's TargetObject
                if ($_.TargetObject) {
                    $bodyCandidates += "[.TargetObject]"
                    $bodyCandidates += try { $_.TargetObject | ConvertTo-Json -Depth 6 } catch { [string]$_.TargetObject }
                }
                # Path 5: ErrorDetails on the ErrorRecord
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    $bodyCandidates += "[.ErrorDetails.Message]"
                    $bodyCandidates += [string]$_.ErrorDetails.Message
                }
                # Path 6: dump every public property name of the exception so we know what's available
                $bodyCandidates += "[exception public properties]"
                $bodyCandidates += try { ($ex | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -join ', ' } catch { '(none)' }
            } catch { $bodyCandidates += "(body capture threw: " + $_.Exception.Message + ")" }
            if ($bodyCandidates.Count -eq 0) { $bodyCandidates += "(no response body found through any known path)" }
            foreach ($c in $bodyCandidates) { [void]$sb.AppendLine($c); [void]$sb.AppendLine('') }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("=== Query ===")
            [void]$sb.AppendLine($Query)
            Set-Content -LiteralPath $errFile -Value $sb.ToString() -Encoding UTF8
            Write-Warn2 ("LA query failed -- full detail dumped to {0}" -f $errFile)
        } catch { }
        throw
    }

    # Comma-protect so PowerShell emits the rows array as a SINGLE value to the
    # pipeline (preserving array shape across function-output unwrap). Caller
    # MUST use plain assignment, NOT @() wrap -- @(call) re-wraps the single
    # comma-protected value into [Object[1] of Object[N]], which broke the
    # downstream foreach in v2.1.199 / v2.1.202 / v2.1.203.
    if (-not $resp -or -not $resp.Results) { return ,@() }
    return ,@($resp.Results)
}

function ConvertTo-KqlStringLiteral {
    param($Value)
    if ($null -eq $Value) { return '""' }
    $s = [string]$Value
    $s = $s.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    return '"' + $s + '"'
}

function Get-DefenderTableOwner {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TableName)

    # Map a missing-table name to a customer-friendly explanation of which Defender service
    # owns the table and what licence / onboarding is required to make it appear in advanced
    # hunting. Used by the schema-error short-circuit in Invoke-GraphHuntingQuery so the log
    # line tells the customer exactly what to fix instead of just 'table not found'.
    switch -Regex ($TableName) {
        '_CL$' {
            return ("Custom Log Analytics table -- ingestion engine has not yet written to it, " +
                    "or the workspace is wrong. Check `$global:WorkspaceResourceId and run the " +
                    "matching SI ingestion engine (e.g. AssetProfileEngine for SI_*_Profile_CL, " +
                    "PublicIpScanner for SI_VulnerabilityPIP_CL).")
        }
        '^Device(?!Tvm)' {
            return ("Owned by Microsoft Defender for Endpoint (MDE Plan 2 / M365 E5 Security / M365 E5). " +
                    "Devices may already be onboarded for inventory + risk + exposure (Defender for Business / " +
                    "MDE Plan 1 also support those), but the EDR advanced-hunting schema (Device*, DeviceInfo, " +
                    "DeviceProcessEvents, DeviceLogonEvents, etc.) requires Plan 2. Newly upgraded tenants " +
                    "typically see the tables appear within minutes to ~24h while the backend re-provisions.")
        }
        '^DeviceTvm' {
            return ("Owned by Microsoft Defender Vulnerability Management (MDVM standalone add-on, or bundled " +
                    "in MDE Plan 2 / M365 E5). DeviceTvm* tables require either license + device onboarding.")
        }
        '^Identity' {
            return ("Owned by Microsoft Defender for Identity (MDI / EMS E5 / M365 E5). Requires the MDI sensor " +
                    "deployed on AD domain controllers and / or AD FS / Entra Connect servers.")
        }
        '^(AADSignInEvents|EntraIdSignInEvents|AADSpnSignInEvents|EntraIdSpnSignInEvents|GraphAPIAuditEvents|IdentityAccountInfo)' {
            return ("Owned by Microsoft Entra (Defender XDR pulls Entra sign-in / audit logs into advanced hunting). " +
                    "Requires Entra ID P1 / P2 with diagnostic-settings forwarding enabled. " +
                    "ALTERNATIVE: forward Entra Sign-in + Audit logs to your Log Analytics workspace via " +
                    "Entra > Diagnostic settings (preferably routed through Microsoft Sentinel for retention + " +
                    "analytic-rule coverage). The engine can then run sign-in queries against the LA-side " +
                    "SigninLogs / AADNonInteractiveUserSignInLogs / AuditLogs tables instead of the XDR ones, " +
                    "which avoids the advanced-hunting body cap on big-tenant let-block bridges.")
        }
        '^ExposureGraph' {
            return ("Owned by Microsoft Security Exposure Management (MDEM -- bundled in M365 E5 Security / " +
                    "M365 E5 / standalone Exposure Management SKU).")
        }
        '^Email|^Message|^UrlClickEvents' {
            return ("Owned by Microsoft Defender for Office 365 Plan 2 (MDO P2 -- bundled in M365 E5 / E5 Security / " +
                    "MDO P2 standalone).")
        }
        '^CloudApp|^AppFile' {
            return ("Owned by Microsoft Defender for Cloud Apps (MDA -- bundled in M365 E5 / EMS E5 / MDA standalone).")
        }
        '^Cloud(Audit|Dns|Process|Storage)' {
            return ("Owned by Microsoft Defender for Cloud (workload protection plans for Servers / Storage / DNS).")
        }
        '^(Alert|Behavior)' {
            return ("Owned by Microsoft Defender XDR (alerts + behaviors aggregated across all Defender services). " +
                    "Requires at least one Defender plan generating alerts.")
        }
        default {
            return ("Owner unknown -- check the Defender XDR advanced-hunting schema browser for which service " +
                    "exposes this table and confirm the corresponding licence / onboarding is in place.")
        }
    }
}

function Test-AdvancedHuntingHasTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName
    )

    if ($null -eq $script:_TableInAdvHunting) { $script:_TableInAdvHunting = @{} }
    if ($script:_TableInAdvHunting.ContainsKey($TableName)) { return $script:_TableInAdvHunting[$TableName] }

    Write-Info ("Probing whether {0} is queryable from advanced hunting (unified Defender XDR portal / data-lake mirroring check) ..." -f $TableName)
    # 🔑 v2.2.445 -- THIS PROBE IS *SUPPOSED* TO FAIL, AND THE FAILURE MUST NOT LOOK LIKE ONE.
    # A customer-facing SI_*_CL table is normally NOT mirrored into advanced hunting, so the expected
    # answer here is a 400 "Failed to resolve table". That is a ROUTING ANSWER, not a fault -- the
    # engine immediately and correctly falls through to Log Analytics direct.
    # 🪤 It used to be asked with `-ErrorAction Stop`, which PROMOTES the cmdlet's non-terminating
    # error to a TERMINATING one. PowerShell transcripts record every terminating error -- even a
    # caught one -- as a `PS>TerminatingError(...)` block complete with HTTP status, request ids and
    # x-ms-ags-diagnostic headers. So a healthy run printed four alarming stack dumps, and customers
    # reading their own transcript asked why their report had errors. It had none.
    # 🔒 -ErrorAction SilentlyContinue + -ErrorVariable asks the SAME question and gets the SAME
    # answer without ever raising a terminating error, so nothing reaches the transcript. The
    # try/catch stays for a genuinely terminating failure (auth, transport).
    # 🔴 NOTHING IN HERE MAY `throw` ON THE EXPECTED PATH -- a re-thrown error is still a terminating
    # error, and the transcript would record the very block this change exists to remove. So the
    # probe result is carried as a MESSAGE and classified below, outside any throw.
    $msg = $null
    try {
        Ensure-GraphAuth
        $probeErr = $null
        $null = Start-MgBetaSecurityHuntingQuery -Query ("{0} | take 1" -f $TableName) `
                    -ErrorAction SilentlyContinue -ErrorVariable probeErr
        if ($probeErr) { $msg = [string]$probeErr[0].Exception.Message }
    } catch {
        # Only a GENUINELY terminating failure (auth, transport) reaches here now.
        $msg = $_.Exception.Message
    }

    if ([string]::IsNullOrWhiteSpace($msg)) {
        $script:_TableInAdvHunting[$TableName] = $true
        Write-Ok ("{0} IS queryable from advanced hunting. Preferred path." -f $TableName)
    }
    elseif ($msg -match ("Failed to resolve table or column expression named '{0}'" -f [regex]::Escape($TableName))) {
        # THE EXPECTED ANSWER for a customer CL table. Routing information, not a fault.
        $script:_TableInAdvHunting[$TableName] = $false
        Write-Info ("{0} is NOT queryable from advanced hunting -- will route to Log Analytics direct." -f $TableName)
    }
    else {
        # 🔴 AN INCONCLUSIVE ANSWER IS NOT KNOWLEDGE, AND IT MUST NOT RESOLVE TO ADVANCED HUNTING.
        # The two routes are not symmetric. A query against an SI-owned SI_*_CL table works over
        # Log Analytics direct because SI writes that table to the workspace; advanced hunting only
        # works if the customer has ALSO mirrored it (their choice, and not the common case). So the
        # route that MIGHT fail is AH, and the route that works is LA-direct.
        #
        # This branch used to cache $true -- "assume the table is accessible and let the real call
        # decide" -- which sends the query to the one destination that can fail. When it does, the
        # bucket returns nothing, the report ships PARTIAL, and the findings are missing from the
        # workbook AND the CL table while the run reports success. Reproduced against the real
        # routing function: any probe error that is not the exact "Failed to resolve table" string
        # took this branch and routed to AH.
        #
        # 🪤 AND IT CACHED THE GUESS FOR THE WHOLE RUN, so one transient blip -- a throttle, a
        # timeout, an auth hiccup, a reworded service error -- mis-routed EVERY later query
        # touching that table, not just the one that hit the blip. The comment below this branch
        # already said "Don't cache"; the code did anyway. That divergence is the bug.
        #
        # Now: answer with the route that works, and DO NOT remember it. The next query re-probes,
        # so a momentary failure costs one cheap `take 1` instead of the rest of the run -- and a
        # customer who HAS mirrored their tables gets their advanced-hunting path back as soon as
        # the service answers cleanly again.
        Write-Warn2 ("AdvancedHunting probe for {0} was inconclusive ({1}). Routing this query to Log Analytics direct, which always works for this table, and re-probing on the next query rather than assuming." -f $TableName, $msg)
        return $false
    }
    return $script:_TableInAdvHunting[$TableName]
}
