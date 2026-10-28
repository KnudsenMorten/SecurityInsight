#Requires -Version 5.1
<#
    SI -- THE SCHEMA APPROVAL GATE (SCHEMA-1, DOCS/REQUIREMENTS.md, resolved 2026-08-13).

    🔴 A SCHEMA CHANGE MUST NEVER REACH A CUSTOMER DATABASE WITHOUT A HUMAN IN THE LOOP.

    `sync/` auto-deploys to ~30 customers from `main` with no review step, and that was only ever
    acceptable because a deploy was a FILE COPY. A migration is the one deploy action that is neither a
    file copy nor trivially reversible: a failed or partial one leaves a customer's database in a state
    the next nightly sync will try again from. Ring gating answers WHEN, not WHETHER -- and today it
    answers nothing at all, because release-map.json has `default: null` and every target resolves to
    track-current.

    PURE, and that is the point: the decision to touch a customer database is exactly the decision worth
    proving offline, before there is a database to get it wrong against.

    THE RULES, each of which exists because its absence is a way to defeat the gate:
      1. Approval is PER CUSTOMER. One customer's approval is not another's.
      2. Approval is PER SCHEMA VERSION. Approving 1.0 does not approve 1.1 -- otherwise the first
         approval is a permanent blank cheque.
      3. Approval must be RECORDED, with who and when. An approval nobody signed cannot be audited, and
         an unsigned record is indistinguishable from one written by the process it authorises.
      4. A WILDCARD approval is REFUSED OUTRIGHT. "All tenants" or "all versions" is not an approval,
         it is the removal of the gate, and it would be the obvious shortcut under deadline pressure.
      5. Absent an approval the answer is REFUSE AND REPORT -- never skip silently. A silent skip leaves
         the customer on an old schema while the run reports success, which is the "wrong is worse than
         empty, because empty is visible" failure one more time.
#>

# Wildcards are refused rather than interpreted. Listed explicitly so the refusal is a decision in the
# code and not an accident of string matching.
$script:SISchemaWildcards = @('*', 'all', 'any', '<all>', 'default')

function Test-SISchemaIsAdditive {
    <#
        Refuse a migration that could destroy data, before anyone is asked to approve it.

        The gate asks "may we?"; this asks "is this thing even the shape we promised?". SCHEMA-1 says
        the solution applies its own schema to the PIM pattern -- preflight, apply, re-preflight, NEVER
        DESTRUCTIVE -- and PIM marks its schema step non-rollbackable precisely because reverting an add
        could drop a column with data. So additive-ness has to be checked, not assumed: "the migration
        is additive" is a claim about the SQL as written, and this is what makes it true of the SQL as
        shipped.

        Comment lines are ignored -- these files explain themselves, and the word DROP appears in the
        prose of this very repository.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql)

    # THE WHOLE SCRIPT IS SCANNED, NOT ONE LINE AT A TIME (#128). The line-by-line version was
    # defeated by ordinary SQL formatting: `UPDATE t` / `SET x = 1` on two lines, `DELETE t` (FROM is
    # optional in T-SQL), `/* */` block comments, `[name with spaces]`, and verbs it never listed
    # (DROP VIEW/PROCEDURE/FUNCTION, MERGE). So: blank out comments and string literals over the whole
    # text -- replacing every character but newlines with a space, so line numbers survive -- then match
    # each pattern across line breaks.
    $clean = [regex]::Replace($Sql, "(?s)/\*.*?\*/|--[^\r\n]*|'(?:[^']|'')*'", {
        param($m) [regex]::Replace($m.Value, '[^\r\n]', ' ')
    })
    # A PERMISSION statement names verbs without running them: `DENY UPDATE, DELETE ON OBJECT::cfg.AuditEvent TO public`
    # (#289, the append-only trail) changes who may write, never a row. Only the statement's own shape is blanked --
    # verbs, ON <securable>, TO / FROM <principals> -- so a real DELETE after it, even on the same line, is still found.
    $clean = [regex]::Replace($clean, '(?i)\b((GRANT|DENY)[ \t]+|REVOKE[ \t]+(GRANT[ \t]+OPTION[ \t]+FOR[ \t]+)?)[A-Z]+([ \t]+[A-Z]+)*([ \t]*,[ \t]*[A-Z]+([ \t]+[A-Z]+)*)*([ \t]+ON[ \t]+(\w+::)?[\w\[\]\.]+)?[ \t]+(?(2)TO|(TO|FROM))[ \t]+(\[[^\]]*\]|\w+)([ \t]*,[ \t]*(\[[^\]]*\]|\w+))*', {
        param($m) [regex]::Replace($m.Value, '[^\r\n]', ' ')
    })

    # ALTER TABLE ... ADD is additive and must stay allowed; ALTER TABLE ... ALTER COLUMN can truncate.
    # FK clauses `ON DELETE CASCADE` / `ON UPDATE CASCADE` are additive DDL and are excluded explicitly.
    $destructive = @(
        @{ Pattern = '\bDROP\s+(TABLE|COLUMN|SCHEMA|INDEX|CONSTRAINT|DATABASE|VIEW|PROC|PROCEDURE|FUNCTION|TRIGGER|TYPE|SEQUENCE|SYNONYM|STATISTICS)\b'; Why = 'drops an object' }
        @{ Pattern = '\bTRUNCATE\s+TABLE\b';                                  Why = 'empties a table' }
        @{ Pattern = '(?<!\bON\s+)\bDELETE\b(?!\s+(CASCADE|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT)\b)'; Why = 'deletes rows' }
        @{ Pattern = '\bALTER\s+TABLE\b[^;]*?\bALTER\s+COLUMN\b';             Why = 'can truncate an existing column' }
        @{ Pattern = '\bEXEC(UTE)?\s+(\w+\.)*sp_rename\b';                    Why = 'renames, which breaks every existing reader' }
        @{ Pattern = '(?<!\bON\s+)\bUPDATE\b(?!\s+(STATISTICS|CASCADE|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT)\b)[^;]*?\bSET\b'; Why = 'rewrites existing rows' }
        @{ Pattern = '\bMERGE\b';                                             Why = 'can update or delete existing rows' }
    )

    $findings = New-Object System.Collections.Generic.List[object]
    $opts = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, Singleline'
    foreach ($d in $destructive) {
        foreach ($m in [regex]::Matches($clean, $d.Pattern, $opts)) {
            $lineNo = ([regex]::Matches($clean.Substring(0, $m.Index), "`n")).Count + 1
            $text = (($Sql -split "`r?`n")[$lineNo - 1]).Trim()
            [void]$findings.Add([pscustomobject]@{ Line = $lineNo; Why = $d.Why; Text = $text })
        }
    }
    $sorted = @($findings.ToArray() | Sort-Object Line)

    [pscustomobject]@{
        IsAdditive = ($sorted.Count -eq 0)
        Findings   = $sorted
    }
}

function Test-SISchemaApproval {
    <#
        May this schema version be applied to THIS customer?

        Approvals are records: @{ TenantId; SchemaVersion; ApprovedBy; ApprovedAt }.
        Returns a verdict plus a REASON, always -- a gate that only says "no" teaches the operator to
        route around it, and a refusal without a reason is indistinguishable from a bug.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$TenantId,
        [Parameter(Mandatory)][AllowEmptyString()][string]$SchemaVersion,
        [Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$Approvals
    )

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        return [pscustomobject]@{ Approved = $false; Reason = 'no tenant id supplied -- cannot tell whose database this is, so refuse'; MatchedBy = $null }
    }
    if ([string]::IsNullOrWhiteSpace($SchemaVersion)) {
        return [pscustomobject]@{ Approved = $false; Reason = 'no schema version supplied -- an approval must name what it approves'; MatchedBy = $null }
    }

    $all = @($Approvals | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) {
        return [pscustomobject]@{
            Approved = $false; MatchedBy = $null
            Reason = ('no approval recorded for tenant {0} schema {1} -- refusing. Record an approval naming this tenant AND this version.' -f $TenantId, $SchemaVersion)
        }
    }

    foreach ($a in $all) {
        $at = [string]$a.TenantId
        $av = [string]$a.SchemaVersion
        $by = [string]$a.ApprovedBy

        # RULE 4 -- a wildcard is not a narrow approval, it is the gate removed. Refuse the whole run
        # rather than ignoring the record: a wildcard sitting in the approvals file means someone
        # intended it to apply, and silently skipping it would leave them believing it had.
        if ($script:SISchemaWildcards -contains $at.Trim().ToLowerInvariant() -or
            $script:SISchemaWildcards -contains $av.Trim().ToLowerInvariant()) {
            return [pscustomobject]@{
                Approved = $false; MatchedBy = $null
                Reason = ('a WILDCARD approval is present (tenant="{0}", version="{1}") and is refused outright. An approval must name one tenant and one schema version; a wildcard is the removal of the gate, not an approval.' -f $at, $av)
            }
        }

        if ($at -ne $TenantId -or $av -ne $SchemaVersion) { continue }

        # RULE 3 -- unsigned is unapproved. A record the process could have written itself proves
        # nothing about a human being in the loop, which is the entire requirement.
        if ([string]::IsNullOrWhiteSpace($by)) {
            return [pscustomobject]@{
                Approved = $false; MatchedBy = $null
                Reason = ('an approval exists for tenant {0} schema {1} but names no approver -- an unsigned approval is not an approval.' -f $TenantId, $SchemaVersion)
            }
        }
        if ($null -eq $a.ApprovedAt -or [string]::IsNullOrWhiteSpace([string]$a.ApprovedAt)) {
            return [pscustomobject]@{
                Approved = $false; MatchedBy = $null
                Reason = ('an approval exists for tenant {0} schema {1} but carries no timestamp -- it cannot be audited.' -f $TenantId, $SchemaVersion)
            }
        }

        return [pscustomobject]@{
            Approved = $true; MatchedBy = $a
            Reason = ('approved for tenant {0} schema {1} by {2} at {3}' -f $TenantId, $SchemaVersion, $by, $a.ApprovedAt)
        }
    }

    [pscustomobject]@{
        Approved = $false; MatchedBy = $null
        Reason = ('{0} approval(s) recorded, none naming tenant {1} AND schema {2} -- refusing. Approving another tenant, or an earlier version, does not approve this one.' -f $all.Count, $TenantId, $SchemaVersion)
    }
}

function Get-SISchemaApplyPlan {
    <#
        The whole decision, in one call, in the order SCHEMA-1 fixed: is it additive, is it needed, is
        it approved. Returns a plan; applying is the caller's job and needs a database.

        ORDER MATTERS AND IS NOT COSMETIC. Additive-ness is checked FIRST, so nobody is ever asked to
        approve a destructive migration -- an approval obtained for the wrong thing is worse than no
        approval, because it looks like diligence.
        "Already applied" is checked BEFORE approval so a no-op run does not demand an approval it does
        not need, which is how gates get routed around.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Sql,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TenantId,
        [Parameter(Mandatory)][AllowEmptyString()][string]$SchemaVersion,
        [Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$Approvals,
        [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$AppliedVersions
    )

    $additive = Test-SISchemaIsAdditive -Sql $Sql
    if (-not $additive.IsAdditive) {
        $first = @($additive.Findings)[0]
        return [pscustomobject]@{
            Action = 'refuse'; Approved = $false; Findings = $additive.Findings
            Reason = ('REFUSED: the migration is not additive -- line {0} {1}. SI applies additive, idempotent schema only (SCHEMA-1); reverting an add could drop a column with data, which is why this step is not rollbackable.' -f $first.Line, $first.Why)
        }
    }

    if (@($AppliedVersions) -contains $SchemaVersion) {
        return [pscustomobject]@{
            Action = 'noop'; Approved = $true; Findings = @()
            Reason = ('schema {0} is already applied -- nothing to do, and no approval needed for a no-op.' -f $SchemaVersion)
        }
    }

    $gate = Test-SISchemaApproval -TenantId $TenantId -SchemaVersion $SchemaVersion -Approvals $Approvals
    if (-not $gate.Approved) {
        return [pscustomobject]@{
            Action = 'refuse'; Approved = $false; Findings = @()
            Reason = ('REFUSED: {0}' -f $gate.Reason)
        }
    }

    [pscustomobject]@{
        Action = 'apply'; Approved = $true; Findings = @()
        Reason = ('{0}. Apply preflight -> apply -> re-preflight; never destructive.' -f $gate.Reason)
    }
}
