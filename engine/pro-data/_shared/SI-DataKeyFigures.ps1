#Requires -Version 7.0
<#
    SecurityInsight Pro -- THE KEY FIGURES (#636, owner 2026-10-19: "we need to have some core stats relevant for mgmt like
    Missing patches (cve's) on windows vs. linux, servers vs clients and others" / "one could be report and other could be
    click to see the stats with buttons of most interesting topics so they can click around").

    ONE SOURCE for Overview > Executive overview (the topics to explore) AND Overview > Executive report (the page to read,
    its PDF and the scheduled management mail): sidata.KeyFigure, one row per collection + block + figure + two dimensions,
    written HERE once per collection by the data sync -- never computed per page load, so the two pages can never disagree.
    "Change since the last report" is the same row of the collection before.

    FROM WHAT (all stored tables; no Log Analytics read):
      sidata.Finding        the collection's findings (open = not exempted): CVE, severity, tier, exploit, end of support,
                            fix due date, the source's first-detected date
      sidata.Ci (+ CiLink)  each finding's CI (the CI id, else the CI that carries the id as a linked object) and the CI's
                            OS family (si_os_platform: windows / windows_server -> Windows, linux -> Linux, macos, ios,
                            android), device type (si_asset_type: Server, Workstation, Mobile, IoT, Network device, else
                            Other), class, lifecycle, onboarding, internet exposure, Azure VM / Defender agent, MFA, sign-in
      sidata.CiFindingState the finding lifecycle: opened / fixed in the last N days and the mean time to fix (#859: every
                            window is a setting, Get-SIKeyFigureWindowSettings)
    A device / identity attribute is the CI's CURRENT one (the CI list is current state). A figure the data cannot answer
    (no first-detected date, no due date, no MFA state ...) is written Available = 0 with the reason -- never as 0.
    Never fails the data sync. No PowerShell module.
#>

$script:SIKeyFigureBlocks = @('headline', 'patching', 'exposure', 'coverage', 'identity', 'cloud')

function Get-SIDataKeyFiguresSchemaCheckSql {
    <# 1 when the database carries the table and every column the figures read; else 0. #>
    $need = @("OBJECT_ID('sidata.KeyFigure')", "COL_LENGTH('sidata.Collection', 'KeyFiguresAt')", "COL_LENGTH('sidata.Collection', 'ContextAt')")
    foreach ($c in 'Cve', 'Severity', 'Tier', 'HasExploit', 'EosStatus', 'FixDueDate', 'SourceFirstDetected', 'ExemptionId', 'AssetKey', 'FixRecommendedUpdate', 'FixRecommendedUpdateId', 'FixRemediation', 'AffectedProduct', 'AffectedVersion', 'AffectedSoftware', 'SecurityDomain', 'ReportName') { $need += "COL_LENGTH('sidata.Finding', '$c')" }
    foreach ($c in 'Class', 'AssetType', 'OsPlatform', 'Lifecycle', 'LastSeen', 'OnboardingStatus', 'InternetExposed', 'AzureResourceType', 'MdeDeviceId',
                   'AccountEnabled', 'MfaRegistered', 'LastSignIn', 'PrivilegedAccessCount', 'AzureSubscriptionName', 'AzureSubscriptionId', 'Tier') { $need += "COL_LENGTH('sidata.Ci', '$c')" }
    $need += "OBJECT_ID('sidata.CiLink')"; $need += "OBJECT_ID('sidata.RiskExecView')"; $need += "OBJECT_ID('sidata.CiFindingState')"; $need += "COL_LENGTH('sidata.CiFindingState', 'CloseReason')"
    'SELECT CASE WHEN ' + (($need | ForEach-Object { "$_ IS NOT NULL" }) -join ' AND ') + ' THEN 1 ELSE 0 END'
}

function Get-SIDataUnfiguredSql {
    <#
        Complete Detailed collections with their prepared context and no key figures (or figures older than the context),
        among the -Newest complete ones only (#818, owner 2026-10-20: a run can be compared with the ones before it right after
        an update -- the back-fill of runs synced before the figures existed is bounded, never every stored run). Newest first.
        A run figured before the per-view finding counts existed (no protection / findings_lifecycle row, owner 2026-10-20) is
        figured again -- in the same bounded set.
    #>
    param([int]$Newest = 4)
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter }
    $n = [Math]::Max(1, $Newest)
    "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = 'Complete' AND ContextAt IS NOT NULL" +
    " AND (KeyFiguresAt IS NULL OR KeyFiguresAt < ContextAt OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure AS kx WHERE kx.CollectionId = sidata.Collection.CollectionId AND kx.Block = N'protection' AND kx.Figure = N'findings_lifecycle')" +
    " OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure AS ka WHERE ka.CollectionId = sidata.Collection.CollectionId AND ka.Block = N'meta' AND ka.Figure = N'active_assets_only')" +
    " OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure AS kg WHERE kg.CollectionId = sidata.Collection.CollectionId AND kg.Block = N'meta' AND kg.Figure = N'grace_by_kind')" +
    # #855 W11: a run figured before the not-onboarded devices were split by status is figured again (bounded as above)
    " OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure AS ko WHERE ko.CollectionId = sidata.Collection.CollectionId AND ko.Block = N'meta' AND ko.Figure = N'onboarding_by_status'))$live" +
    " AND CollectionId IN (SELECT TOP ($n) n.CollectionId FROM sidata.Collection AS n WHERE n.Kind = N'Detailed' AND n.Status = 'Complete' ORDER BY n.CollectionTime DESC) ORDER BY CollectionTime DESC"
}

function Get-SIKeyFigureDomainSql {
    <#
        PURE. The security domain of a finding (alias f) as the Risk Analysis domain x severity table counts it
        (Invoke-RiskAnalysis: SecurityDomain, PublicIp = PublicIP, else _DomainFromReportName on the report's name): Endpoint |
        Identity | Azure | PublicIP | Other.
    #>
    "CASE WHEN NULLIF(LTRIM(RTRIM(f.SecurityDomain)), N'') IS NOT NULL THEN CASE LOWER(LTRIM(RTRIM(f.SecurityDomain))) WHEN N'endpoint' THEN N'Endpoint' WHEN N'identity' THEN N'Identity' WHEN N'azure' THEN N'Azure' WHEN N'publicip' THEN N'PublicIP' ELSE N'Other' END" +
    " WHEN LOWER(f.ReportName) LIKE N'%public[_]ip[_]to[_]vm%' OR LOWER(f.ReportName) LIKE N'%device[_]with[_]high[_]severity[_]vulnerabilities%' THEN N'Endpoint'" +
    " WHEN LOWER(f.ReportName) LIKE N'publicip[_]%' THEN N'PublicIP'" +
    " WHEN LOWER(f.ReportName) LIKE N'device[_]%' OR LOWER(f.ReportName) LIKE N'endpoint[_]%' THEN N'Endpoint'" +
    " WHEN LOWER(f.ReportName) LIKE N'identity[_]%' OR LOWER(f.ReportName) LIKE N'%credential[_]based[_]lateral[_]movement%' OR LOWER(f.ReportName) LIKE N'%identity[_]group[_]membership%' OR LOWER(f.ReportName) LIKE N'%data[_]sensitivity[_]to[_]exposed[_]credentials%' THEN N'Identity'" +
    " WHEN LOWER(f.ReportName) LIKE N'azure[_]%' OR LOWER(f.ReportName) LIKE N'%github[_]to[_]azure%' OR LOWER(f.ReportName) LIKE N'%to[_]azure[_]resources%' THEN N'Azure'" +
    " ELSE N'Other' END"
}

function Get-SIKeyFigureOsFamilySql {
    <# PURE. The OS family of a CI (alias c) from si_os_platform. #>
    "CASE LOWER(c.OsPlatform) WHEN N'windows' THEN N'Windows' WHEN N'windows_server' THEN N'Windows' WHEN N'linux' THEN N'Linux' WHEN N'macos' THEN N'macOS' WHEN N'ios' THEN N'iOS' WHEN N'android' THEN N'Android' WHEN N'other' THEN N'Other' ELSE N'Unknown' END"
}

function Get-SIKeyFigureDeviceTypeSql {
    <# PURE. The device type of a CI (alias c) from si_asset_type (a Windows server platform without a type counts as a server). #>
    "CASE WHEN c.AssetType = N'Server' OR (c.AssetType IS NULL AND LOWER(c.OsPlatform) = N'windows_server') THEN N'Server' WHEN c.AssetType = N'Workstation' THEN N'Workstation' WHEN c.AssetType = N'Mobile' THEN N'Mobile' WHEN c.AssetType = N'IoT' THEN N'IoT' WHEN c.AssetType = N'Network device' THEN N'Network device' ELSE N'Other' END"
}

function Get-SIKeyFigurePatchesSql {
    <#
        PURE. The topic "Missing patches & findings" (owner 2026-10-19: "is it possible to detail the windows more into the sub
        categories like os, browser, etc so i can figure out what is happening. what patches are missing" / "with the
        breakdown to show fx CVEs but also all security findings like this" / "we need a filter option, where we filter
        between 'being fixed during monthly lifecycle' vs. 'catch-up older than 1 month'"): over the open findings on ACTIVE
        DEVICES, with CVEs only (mode cve) and with every security finding (mode all), and for each PATCH CYCLE (cyc): all |
        cycle (in the monthly cycle) | catchup (catch-up, the fix is older than -CatchUpDays) | nofix (no fix available) |
        unknown -- Block 'patches', figure '<what>_<mode>_<cyc>':
          matrix    Dim1 OS family ('(all)' = every), Dim2 Server | Client | Other ('(all)'): findings, devices, distinct CVEs /
                    recommendations (Items), Very High findings; Total = the findings of that mode and cycle (a share)
          component Dim1 the component (si_component), Dim2 Server | Client | Other | '(all)'
          software  Dim1 the affected software (product + version), the 50 with the most findings
          fix       Dim1 the recommended update's id, Dim2 its name (the 50 that close the most); a finding without an update
                    id is grouped by its remediation text under Dim1 '(no single update)'. Servers / Clients = the devices of
                    each; Note = how far behind: current | 1 month behind | 2+ months behind | not known (the update's month,
                    from its name, against the collection's month)
          fixlag    Dim1 that months-behind split
          devices   Dim1 the CI id, Dim2 its name: the 50 devices with the most findings of that cycle (Note = Server | Client | Other)
        and 'cycle_<mode>': Dim1 the cycle -- findings and devices (the two headline numbers side by side).
        THE PATCH CYCLE: the finding's si_patch_cycle when its source gives one ("In monthly cycle", "Catch-up (older than 1
        month)", "No fix available", "Unknown"); else: no recommended update = no single update (browsers, third-party
        software, configuration: fixed by their own owner); an update whose month is known
        = in the cycle while its release (the 2nd Tuesday of its month) is at most -CatchUpDays before the collection, else
        catch-up; anything else unknown.
        Needs #fd / #d / #kf of Get-SIDataKeyFiguresSql (and @t).
    #>
    param([int]$CatchUpDays = 30)
    @"
CREATE TABLE #pm (Mode VARCHAR(3) NOT NULL, Cyc VARCHAR(8) NOT NULL, CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, Fam NVARCHAR(16) NOT NULL, Dc NVARCHAR(8) NOT NULL, Cls CHAR(2) NOT NULL,
                  Rec NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Comp NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, Soft NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL,
                  FixKey NVARCHAR(200) COLLATE DATABASE_DEFAULT NOT NULL, FixName NVARCHAR(120) COLLATE DATABASE_DEFAULT NOT NULL, Lag NVARCHAR(24) NOT NULL);
WITH x AS (
    SELECT fd.*, d.Fam, CASE d.Typ WHEN N'Server' THEN N'Server' WHEN N'Workstation' THEN N'Client' ELSE N'Other' END AS Dc,
           -- the 2nd Tuesday of the update's month: its release (Patch Tuesday)
           CASE WHEN fd.FixMonth IS NULL THEN NULL
                ELSE DATEADD(day, 7 + ((1 - (DATEDIFF(day, '19000101', fd.FixMonth) % 7) + 7) % 7), fd.FixMonth) END AS Released,
           LOWER(fd.Cycle) AS Given
    FROM #fd AS fd JOIN #d AS d ON d.CiId = fd.CiId
    WHERE d.Class = N'device' AND d.Active = 1
), y AS (
    SELECT x.*, CASE WHEN x.Given LIKE N'in monthly%' THEN 'cycle' WHEN x.Given LIKE N'catch%' THEN 'catchup' WHEN x.Given LIKE N'no fix%' THEN 'nofix' WHEN x.Given LIKE N'unknown%' THEN 'unknown'
                     WHEN x.FixId IS NULL AND x.FixName IS NULL THEN 'nofix'
                     WHEN x.Released IS NOT NULL AND DATEDIFF(day, x.Released, @t) <= $CatchUpDays THEN 'cycle'
                     WHEN x.Released IS NOT NULL THEN 'catchup'
                     ELSE 'unknown' END AS Own
    FROM x
)
INSERT #pm
SELECT m.Mode, c.Cyc, y.CiId, y.Fam, y.Dc, y.Cls, y.Rec, ISNULL(y.Comp, N'Other'), y.Soft,
       COALESCE(y.FixId, N'(no single update)'), LEFT(COALESCE(CASE WHEN y.FixId IS NOT NULL THEN COALESCE(y.FixName, N'Security update ' + y.FixId) END, y.Remedy, N'(no remediation given)'), 120),
       CASE WHEN y.FixMonth IS NULL THEN N'not known'
            WHEN DATEDIFF(month, y.FixMonth, DATEFROMPARTS(YEAR(@t), MONTH(@t), 1)) <= 0 THEN N'current'
            WHEN DATEDIFF(month, y.FixMonth, DATEFROMPARTS(YEAR(@t), MONTH(@t), 1)) = 1 THEN N'1 month behind'
            ELSE N'2+ months behind' END
FROM y
CROSS JOIN (VALUES ('cve'), ('all')) AS m (Mode)
CROSS APPLY (VALUES ('all'), (y.Own)) AS c (Cyc)
WHERE m.Mode = 'all' OR y.Cve IS NOT NULL;
CREATE TABLE #pt (Mode VARCHAR(3) NOT NULL, Cyc VARCHAR(8) NOT NULL, N INT NOT NULL, PRIMARY KEY (Mode, Cyc));
INSERT #pt SELECT v.Mode, w.Cyc, ISNULL((SELECT COUNT(*) FROM #pm AS p WHERE p.Mode = v.Mode AND p.Cyc = w.Cyc), 0)
FROM (VALUES ('cve'), ('all')) AS v (Mode) CROSS JOIN (VALUES ('all'), ('cycle'), ('catchup'), ('nofix'), ('unknown')) AS w (Cyc);
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'cycle_' + p.Mode, p.Cyc, N'', COUNT(*), COUNT(DISTINCT p.CiId), t.N, 1, NULL, COUNT(DISTINCT p.Rec), SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END),
       COUNT(DISTINCT CASE WHEN p.Dc = N'Server' THEN p.CiId END), COUNT(DISTINCT CASE WHEN p.Dc = N'Client' THEN p.CiId END)
FROM #pm AS p JOIN #pt AS t ON t.Mode = p.Mode AND t.Cyc = 'all' WHERE p.Cyc <> 'all' GROUP BY p.Mode, p.Cyc, t.N;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'matrix_' + g.Mode + N'_' + g.Cyc, g.Fam, g.Dc, g.N, g.Devices, t.N, 1, NULL, g.Items, g.Vh, g.Servers, g.Clients
FROM (SELECT p.Mode, p.Cyc, CASE WHEN GROUPING(p.Fam) = 1 THEN N'(all)' ELSE p.Fam END AS Fam, CASE WHEN GROUPING(p.Dc) = 1 THEN N'(all)' ELSE p.Dc END AS Dc,
             COUNT(*) AS N, COUNT(DISTINCT p.CiId) AS Devices, COUNT(DISTINCT p.Rec) AS Items, SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END) AS Vh,
             COUNT(DISTINCT CASE WHEN p.Dc = N'Server' THEN p.CiId END) AS Servers, COUNT(DISTINCT CASE WHEN p.Dc = N'Client' THEN p.CiId END) AS Clients
      FROM #pm AS p GROUP BY GROUPING SETS ((p.Mode, p.Cyc, p.Fam, p.Dc), (p.Mode, p.Cyc, p.Fam), (p.Mode, p.Cyc, p.Dc), (p.Mode, p.Cyc))) AS g
JOIN #pt AS t ON t.Mode = g.Mode AND t.Cyc = g.Cyc;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'component_' + g.Mode + N'_' + g.Cyc, g.Comp, g.Dc, g.N, g.Devices, t.N, 1, NULL, g.Items, g.Vh, NULL, NULL
FROM (SELECT p.Mode, p.Cyc, p.Comp, CASE WHEN GROUPING(p.Dc) = 1 THEN N'(all)' ELSE p.Dc END AS Dc, COUNT(*) AS N, COUNT(DISTINCT p.CiId) AS Devices,
             COUNT(DISTINCT p.Rec) AS Items, SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END) AS Vh
      FROM #pm AS p GROUP BY GROUPING SETS ((p.Mode, p.Cyc, p.Comp, p.Dc), (p.Mode, p.Cyc, p.Comp))) AS g
JOIN #pt AS t ON t.Mode = g.Mode AND t.Cyc = g.Cyc;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'software_' + s.Mode + N'_' + s.Cyc, s.Soft, N'', s.N, s.Devices, t.N, 1, NULL, s.Items, s.Vh, s.Servers, s.Clients
FROM (SELECT p.Mode, p.Cyc, p.Soft, COUNT(*) AS N, COUNT(DISTINCT p.CiId) AS Devices, COUNT(DISTINCT p.Rec) AS Items, SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END) AS Vh,
             COUNT(DISTINCT CASE WHEN p.Dc = N'Server' THEN p.CiId END) AS Servers, COUNT(DISTINCT CASE WHEN p.Dc = N'Client' THEN p.CiId END) AS Clients,
             ROW_NUMBER() OVER (PARTITION BY p.Mode, p.Cyc ORDER BY COUNT(*) DESC, p.Soft) AS Rn
      FROM #pm AS p WHERE p.Soft IS NOT NULL GROUP BY p.Mode, p.Cyc, p.Soft) AS s
JOIN #pt AS t ON t.Mode = s.Mode AND t.Cyc = s.Cyc WHERE s.Rn <= 50;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'fix_' + s.Mode + N'_' + s.Cyc, s.FixKey, s.FixName, s.N, s.Devices, t.N, 1, s.Lag, s.Items, s.Vh, s.Servers, s.Clients
FROM (SELECT p.Mode, p.Cyc, p.FixKey, p.FixName, MAX(p.Lag) AS Lag, COUNT(*) AS N, COUNT(DISTINCT p.CiId) AS Devices, COUNT(DISTINCT p.Rec) AS Items,
             SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END) AS Vh,
             COUNT(DISTINCT CASE WHEN p.Dc = N'Server' THEN p.CiId END) AS Servers, COUNT(DISTINCT CASE WHEN p.Dc = N'Client' THEN p.CiId END) AS Clients,
             ROW_NUMBER() OVER (PARTITION BY p.Mode, p.Cyc ORDER BY COUNT(*) DESC, p.FixKey, p.FixName) AS Rn
      FROM #pm AS p GROUP BY p.Mode, p.Cyc, p.FixKey, p.FixName) AS s
JOIN #pt AS t ON t.Mode = s.Mode AND t.Cyc = s.Cyc WHERE s.Rn <= 50;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'fixlag_' + p.Mode + N'_' + p.Cyc, p.Lag, N'', COUNT(*), COUNT(DISTINCT p.CiId), t.N, 1, NULL, COUNT(DISTINCT CASE WHEN p.FixKey <> N'(no single update)' THEN p.FixKey END),
       SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END), COUNT(DISTINCT CASE WHEN p.Dc = N'Server' THEN p.CiId END), COUNT(DISTINCT CASE WHEN p.Dc = N'Client' THEN p.CiId END)
FROM #pm AS p JOIN #pt AS t ON t.Mode = p.Mode AND t.Cyc = p.Cyc WHERE p.FixKey <> N'(no single update)' GROUP BY p.Mode, p.Cyc, p.Lag, t.N;
-- the devices that carry the most of each cycle (the devices behind, the single machines far behind): Dim1 the CI id, Dim2
-- its name, Items = the distinct updates / software, Servers = 1 when it is a server; the 50 with the most findings
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT N'patches', N'devices_' + s.Mode + N'_' + s.Cyc, s.CiId, LEFT(ISNULL(d.Name, s.CiId), 120), s.N, 1, t.N, 1, s.Dc, s.Items, s.Vh,
       CASE WHEN s.Dc = N'Server' THEN 1 ELSE 0 END, CASE WHEN s.Dc = N'Client' THEN 1 ELSE 0 END
FROM (SELECT p.Mode, p.Cyc, p.CiId, MAX(p.Dc) AS Dc, COUNT(*) AS N, COUNT(DISTINCT COALESCE(NULLIF(p.FixKey, N'(no single update)'), p.Soft)) AS Items,
             SUM(CASE WHEN p.Cls = 'vh' THEN 1 ELSE 0 END) AS Vh, ROW_NUMBER() OVER (PARTITION BY p.Mode, p.Cyc ORDER BY COUNT(*) DESC, p.CiId) AS Rn
      FROM #pm AS p GROUP BY p.Mode, p.Cyc, p.CiId) AS s
JOIN #pt AS t ON t.Mode = s.Mode AND t.Cyc = s.Cyc
LEFT JOIN #d AS d ON d.CiId = s.CiId
WHERE s.Rn <= 50;
"@
}
function Get-SIKeyFigureProtectionSql {
    <#
        PURE. THE PROTECTION SCORE (#636, owner 2026-10-19: "here i propose we define a new number which defines our ability to
        protect our assets. that is a % from 0-100. a higher number is good" / "i think we need to have 2 views as both are
        accepted by mgmt: view 1 shows the raw protection score where a new patch coming out yesterday impacts our score ...
        the other includes our lifecycle, which are under 'accepted risks' lifecycle process"):
          the share of the in-scope ACTIVE CIs (devices, identities but groups, cloud resources, public IPs) in GOOD STANDING
          -- no open, non-exempted finding of a counted severity (@Sevs, default Very High / Critical / High) -- each CI
          weighted by its tier (@W0..@W3, default 8 / 4 / 2 / 1; unclassified = @W3). Two views:
            technical  every such finding counts
            lifecycle  "within accepted lifecycle": a finding younger than its asset type's grace (@GraceDevice,
                       @GraceIdentity, @GraceCloud, @GracePublicIp; SI_ProtectionScore_GraceDays_*, default 30) does not count
                       -- #860 (owner 2026-10-21: "grace 0 for non-patch"): that grace is for a PATCH finding only (a
                       vulnerability with a vendor fix: a fix release date, a recommended update -- its name or id -- or a
                       source's patch cycle In monthly cycle / Catch-up; Test-SIProtectionPatchFinding is the engine's twin).
                       Every other finding (configuration, identity, Azure, attack paths) has its own grace per asset type
                       (@OtherGraceDevice ...; SI_ProtectionScore_OtherGraceDays_*, default 0 = it counts from day one)
          THE AGE of a finding, the first that is known: the fix's release (si_fix_release_date, else the 2nd Tuesday of the
          update's month), the source's own first-seen (sidata.Finding.SourceFirstDetected), SI's first detection (the finding
          lifecycle: "first seen by SecurityInsight on <date>", the dates kept in the basis row's Note); no date = it COUNTS
          (a risk with no first-seen date) -- and how many had no date is stored ('no date (counted)').
        Block 'protection': figure technical | lifecycle, Dim1 Devices | Identities | Cloud resources | Public IPs | (all),
        Dim2 Tier 0..3 | Unclassified | (all): Value = the %, Assets = CIs in good standing, Total = CIs in scope; 'agebasis'
        Dim1 = where the age came from; and the headline twins headline / protection_technical, protection_lifecycle.
        The findings of each view (owner 2026-10-20, the wall board's domain x severity table follows the view chosen):
        figure findings_technical | findings_lifecycle, Dim1 Endpoint | Identity | Azure | PublicIP | Other | (all), Dim2
        Critical | High | Medium | Low | Other | (all): Value = the findings the view counts, Total = every open finding there.
        Needs #f / #m / #d of Get-SIDataKeyFiguresSql (and @t).
    #>
    # #860: a PATCH finding (alias f of #f) -- the engine's twin is Test-SIProtectionPatchFinding (SI-ProtectionScore.ps1)
    $patch = "CASE WHEN f.FixRelease IS NOT NULL OR f.FixId IS NOT NULL OR f.FixName IS NOT NULL OR LOWER(f.Cycle) LIKE N'in monthly%' OR LOWER(f.Cycle) LIKE N'catch%' THEN 1 ELSE 0 END"
    $graceOf = "CASE d.Class WHEN N'device' THEN @pgDev WHEN N'identity' THEN @pgId WHEN N'cloud_resource' THEN @pgCloud ELSE @pgIp END"
    $otherOf = "CASE d.Class WHEN N'device' THEN @ogDev WHEN N'identity' THEN @ogId WHEN N'cloud_resource' THEN @ogCloud ELSE @ogIp END"
    @"
DECLARE @pw0 float = TRY_CONVERT(float, @W0), @pw1 float = TRY_CONVERT(float, @W1), @pw2 float = TRY_CONVERT(float, @W2), @pw3 float = TRY_CONVERT(float, @W3),
        @pgDev int = TRY_CONVERT(int, @GraceDevice), @pgId int = TRY_CONVERT(int, @GraceIdentity), @pgCloud int = TRY_CONVERT(int, @GraceCloud), @pgIp int = TRY_CONVERT(int, @GracePublicIp),
        @ogDev int = TRY_CONVERT(int, @OtherGraceDevice), @ogId int = TRY_CONVERT(int, @OtherGraceIdentity), @ogCloud int = TRY_CONVERT(int, @OtherGraceCloud), @ogIp int = TRY_CONVERT(int, @OtherGracePublicIp);
CREATE TABLE #pf (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, AgeDate DATETIME2(3) NULL, Basis TINYINT NOT NULL, Patch BIT NOT NULL);
INSERT #pf (CiId, AgeDate, Basis, Patch)
SELECT m.CiId, COALESCE(f.FixRelease, r.Released, f.First, s.FirstDetected),
       CASE WHEN f.FixRelease IS NOT NULL OR r.Released IS NOT NULL THEN 1 WHEN f.First IS NOT NULL THEN 2 WHEN s.FirstDetected IS NOT NULL THEN 3 ELSE 0 END,
       $patch
FROM #f AS f
JOIN #m AS m ON m.AssetKey = f.AssetKey AND m.CiId IS NOT NULL
CROSS APPLY (SELECT CASE WHEN f.FixMonth IS NULL THEN NULL ELSE DATEADD(day, 7 + ((1 - (DATEDIFF(day, '19000101', f.FixMonth) % 7) + 7) % 7), CONVERT(datetime2(3), f.FixMonth)) END AS Released) AS r
OUTER APPLY (SELECT MIN(st.FirstDetected) AS FirstDetected FROM sidata.CiFindingState AS st WHERE st.OwnerKey = m.CiId AND st.FindingKey IN (f.Rec, f.Cve) AND st.State <> N'closed') AS s
WHERE f.Sev IN (SELECT LTRIM(RTRIM(v.[value])) FROM OPENJSON(@Sevs) AS v);
CREATE INDEX IX_pf ON #pf (CiId);
CREATE TABLE #pc (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, TypeName NVARCHAR(24) NOT NULL, TierName NVARCHAR(16) NOT NULL, W FLOAT NOT NULL,
                  BadTech BIT NOT NULL, BadLife BIT NOT NULL);
INSERT #pc
SELECT d.CiId,
       CASE d.Class WHEN N'device' THEN N'Devices' WHEN N'identity' THEN N'Identities' WHEN N'cloud_resource' THEN N'Cloud resources' ELSE N'Public IPs' END,
       CASE d.Tier WHEN 0 THEN N'Tier 0' WHEN 1 THEN N'Tier 1' WHEN 2 THEN N'Tier 2' WHEN 3 THEN N'Tier 3' ELSE N'Unclassified' END,
       CONVERT(float, CASE d.Tier WHEN 0 THEN @pw0 WHEN 1 THEN @pw1 WHEN 2 THEN @pw2 ELSE @pw3 END),
       CASE WHEN EXISTS (SELECT 1 FROM #pf AS p WHERE p.CiId = d.CiId) THEN 1 ELSE 0 END,
       CASE WHEN EXISTS (SELECT 1 FROM #pf AS p WHERE p.CiId = d.CiId
                         AND (p.AgeDate IS NULL OR DATEDIFF(day, p.AgeDate, @t) >= CASE WHEN p.Patch = 1 THEN $graceOf ELSE $otherOf END)) THEN 1 ELSE 0 END
FROM #d AS d
WHERE d.Active = 1 AND d.Class IN (N'device', N'identity', N'cloud_resource', N'public_ip') AND ISNULL(d.AssetType, N'') NOT IN (N'Group', N'Security group', N'Microsoft 365 group');
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'protection', v.Fig, CASE WHEN GROUPING(c.TypeName) = 1 THEN N'(all)' ELSE c.TypeName END, CASE WHEN GROUPING(c.TierName) = 1 THEN N'(all)' ELSE c.TierName END,
       ROUND(100.0 * SUM(CASE WHEN (v.Fig = N'technical' AND c.BadTech = 0) OR (v.Fig = N'lifecycle' AND c.BadLife = 0) THEN c.W ELSE 0 END) / NULLIF(SUM(c.W), 0), 1),
       SUM(CASE WHEN (v.Fig = N'technical' AND c.BadTech = 0) OR (v.Fig = N'lifecycle' AND c.BadLife = 0) THEN 1 ELSE 0 END), COUNT(*), 1, NULL
FROM #pc AS c CROSS JOIN (VALUES (N'technical'), (N'lifecycle')) AS v (Fig)
GROUP BY GROUPING SETS ((v.Fig, c.TypeName, c.TierName), (v.Fig, c.TypeName), (v.Fig, c.TierName), (v.Fig));
-- the figure's name from the view list, never from the joined row: a collection with NO active asset in scope has no
-- protection row to join, and its two headline rows still say so (Available = 0, the reason) -- the mail prints that line
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'headline', N'protection_' + f.Fig, N'', N'', k.Value, k.Assets, ISNULL(k.Total, 0), CASE WHEN k.Total > 0 THEN 1 ELSE 0 END,
       CASE WHEN k.Total IS NULL OR k.Total = 0 THEN N'no active asset is in scope yet' END
FROM (VALUES (N'technical'), (N'lifecycle')) AS f (Fig)
LEFT JOIN #kf AS k ON k.Block = N'protection' AND k.Figure = f.Fig AND k.Dim1 = N'(all)' AND k.Dim2 = N'(all)';
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'protection', N'agebasis', b.Name, N'', COUNT(p.CiId), COUNT(DISTINCT p.CiId), (SELECT COUNT(*) FROM #pf AS q WHERE q.CiId IN (SELECT CiId FROM #pc)), 1,
       -- #860 (b): "first seen by SecurityInsight on <date>" -- the first and the last such date, for the page to say
       CASE WHEN b.Basis = 3 AND COUNT(p.CiId) > 0 THEN CONVERT(nvarchar(10), MIN(p.AgeDate), 23) + N'|' + CONVERT(nvarchar(10), MAX(p.AgeDate), 23) END
FROM (VALUES (1, N'fix release'), (2, N'source first seen'), (3, N'SI first detected'), (0, N'no date (counted)')) AS b (Basis, Name)
LEFT JOIN #pf AS p ON p.Basis = b.Basis AND p.CiId IN (SELECT c.CiId FROM #pc AS c)
GROUP BY b.Basis, b.Name;
-- the FINDINGS of each view by domain x severity (owner 2026-10-20: "the toggle is also confusing as it just flips the 2
-- numbers around, but the numbers below doesnt chg"): findings_technical = every open finding of the run; findings_lifecycle =
-- the ones the lifecycle view counts -- on an active in-scope CI and past its asset type's grace (no date = it counts)
CREATE TABLE #pg (Dom NVARCHAR(16) NOT NULL, SevB NVARCHAR(16) NOT NULL, Life BIT NOT NULL);
INSERT #pg (Dom, SevB, Life)
SELECT f.Dom,
       CASE WHEN f.Sev IN (N'Very High', N'Critical') THEN N'Critical' WHEN f.Sev IN (N'High', N'Medium-High', N'MediumHigh') THEN N'High'
            WHEN f.Sev = N'Medium' THEN N'Medium' WHEN f.Sev = N'Low' THEN N'Low' ELSE N'Other' END,
       CASE WHEN d.CiId IS NULL THEN 0
            WHEN a.AgeDate IS NULL THEN 1
            WHEN DATEDIFF(day, a.AgeDate, @t) >= CASE WHEN $patch = 1 THEN $graceOf ELSE $otherOf END THEN 1
            ELSE 0 END
FROM #f AS f
LEFT JOIN #m AS m ON m.AssetKey = f.AssetKey
LEFT JOIN #d AS d ON d.CiId = m.CiId AND d.Active = 1 AND d.Class IN (N'device', N'identity', N'cloud_resource', N'public_ip')
                 AND ISNULL(d.AssetType, N'') NOT IN (N'Group', N'Security group', N'Microsoft 365 group')
CROSS APPLY (SELECT CASE WHEN f.FixMonth IS NULL THEN NULL ELSE DATEADD(day, 7 + ((1 - (DATEDIFF(day, '19000101', f.FixMonth) % 7) + 7) % 7), CONVERT(datetime2(3), f.FixMonth)) END AS Released) AS r
-- SI's first detection only when the finding carries no other date (the same order as #pf)
OUTER APPLY (SELECT MIN(st.FirstDetected) AS FirstDetected FROM sidata.CiFindingState AS st
             WHERE d.CiId IS NOT NULL AND f.FixRelease IS NULL AND r.Released IS NULL AND f.First IS NULL
               AND st.OwnerKey = d.CiId AND st.FindingKey IN (f.Rec, f.Cve) AND st.State <> N'closed') AS s
CROSS APPLY (SELECT COALESCE(f.FixRelease, r.Released, f.First, s.FirstDetected) AS AgeDate) AS a;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'protection', v.Fig, CASE WHEN GROUPING(g.Dom) = 1 THEN N'(all)' ELSE g.Dom END, CASE WHEN GROUPING(g.SevB) = 1 THEN N'(all)' ELSE g.SevB END,
       SUM(CASE WHEN v.Fig = N'findings_technical' OR g.Life = 1 THEN 1 ELSE 0 END), NULL, COUNT(*), 1, NULL
FROM #pg AS g CROSS JOIN (VALUES (N'findings_technical'), (N'findings_lifecycle')) AS v (Fig)
GROUP BY GROUPING SETS ((v.Fig, g.Dom, g.SevB), (v.Fig, g.Dom), (v.Fig, g.SevB), (v.Fig));
-- a run with no open finding still has its two (all) rows (0), so the page shows 0s, never "not computed"
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'protection', v.Fig, N'(all)', N'(all)', 0, NULL, 0, 1, NULL
FROM (VALUES (N'findings_technical'), (N'findings_lifecycle')) AS v (Fig)
WHERE NOT EXISTS (SELECT 1 FROM #pg);
"@
}
function Get-SIDataKeyFiguresSql {
    <#
        ONE collection (@CollectionId): every figure into #kf, then the collection's sidata.KeyFigure rows replaced and
        Collection.KeyFiguresAt stamped in one transaction. Answers the number of figure rows. -CatchUpDays: the patch cycle's
        threshold (SI_PatchCycle_CatchUpDays, default 30).
    #>
    param([int]$CatchUpDays = 30)
    $fam = Get-SIKeyFigureOsFamilySql
    $dom = Get-SIKeyFigureDomainSql
    $protection = Get-SIKeyFigureProtectionSql
    $typ = Get-SIKeyFigureDeviceTypeSql
    $patches = Get-SIKeyFigurePatchesSql -CatchUpDays $CatchUpDays
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c int = CONVERT(int, @CollectionId);
DECLARE @t datetime2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @c);
-- #859: every window is the install's setting (Get-SIKeyFigureWindowSettings; never a literal here): opened / fixed in the
-- last N days, the mean time to fix over the last N days, privileged accounts without a sign-in for N days, the CVE age bands
DECLARE @kfRecent int = CONVERT(int, @RecentDays), @kfMttr int = CONVERT(int, @MttrDays), @kfStale int = CONVERT(int, @StaleAdminDays);
DECLARE @kfLo bigint = 0, @kfHi bigint = 9223372036854775807;
-- SI:STEP setup
CREATE TABLE #ageBand (Dim NVARCHAR(40) NOT NULL, Days INT NOT NULL);
INSERT #ageBand (Dim, Days) SELECT DISTINCT N'older than ' + CONVERT(nvarchar(10), b.Days) + N' days', b.Days
FROM (SELECT TRY_CONVERT(int, v.[value]) AS Days FROM OPENJSON(@CveAgeBands) AS v) AS b WHERE b.Days > 0;
CREATE TABLE #kf (Block NVARCHAR(16) NOT NULL, Figure NVARCHAR(48) NOT NULL, Dim1 NVARCHAR(200) NOT NULL, Dim2 NVARCHAR(120) NOT NULL,
                  Value FLOAT NULL, Assets INT NULL, Total INT NULL, Available BIT NOT NULL, Note NVARCHAR(400) NULL,
                  Items INT NULL, VeryHigh INT NULL, Servers INT NULL, Clients INT NULL);
-- the collection's OPEN findings (not exempted), narrow; severity as a class: vh = Very High / Critical, h = High
CREATE TABLE #f (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, Cve NVARCHAR(100) COLLATE DATABASE_DEFAULT NULL, Sev NVARCHAR(30) NULL, Cls CHAR(2) NOT NULL,
                 Tier TINYINT NULL, Exploit BIT NOT NULL, Eos BIT NOT NULL, Due DATETIME2(3) NULL, First DATETIME2(3) NULL,
                 Rec NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Comp NVARCHAR(64) COLLATE DATABASE_DEFAULT NULL, Soft NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL,
                 FixId NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL, FixName NVARCHAR(120) COLLATE DATABASE_DEFAULT NULL, Remedy NVARCHAR(120) COLLATE DATABASE_DEFAULT NULL, FixMonth DATE NULL, Cycle NVARCHAR(40) COLLATE DATABASE_DEFAULT NULL,
                 FixRelease DATETIME2(3) NULL, Dom NVARCHAR(16) NOT NULL);
-- SI:STEP findings
-- (one key range of the collection's findings at a time when run in steps: @kfLo < FindingId <= @kfHi, a clustered-key seek)
INSERT #f
SELECT f.AssetKey, NULLIF(f.Cve, N''), f.Severity,
       CASE WHEN f.Severity IN (N'Very High', N'Critical') THEN 'vh' WHEN f.Severity = N'High' THEN 'h' ELSE 'o' END,
       f.Tier, ISNULL(f.HasExploit, 0), CASE WHEN f.EosStatus LIKE N'EOS%' THEN 1 ELSE 0 END, f.FixDueDate, f.SourceFirstDetected,
       LEFT(COALESCE(NULLIF(f.Cve, N''), NULLIF(f.ConfigurationId, N''), f.Title), 256),
       -- the component (si_component: OS, Browser, Application, Office, SQL, Network, Hardware, Other), read once per finding
       COALESCE(CASE WHEN f.DetailJson IS NOT NULL AND ISJSON(f.DetailJson) = 1 THEN NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_component'))), 64), N'') END, N'Other'),
       LEFT(NULLIF(LTRIM(RTRIM(COALESCE(NULLIF(LTRIM(RTRIM(f.AffectedProduct)), N'') + COALESCE(N' ' + NULLIF(LTRIM(RTRIM(f.AffectedVersion)), N''), N''), f.AffectedSoftware))), N''), 200),
       LEFT(NULLIF(LTRIM(RTRIM(f.FixRecommendedUpdateId)), N''), 200), LEFT(NULLIF(LTRIM(RTRIM(f.FixRecommendedUpdate)), N''), 120),
       LEFT(NULLIF(LTRIM(RTRIM(f.FixRemediation)), N''), 120),
       -- the month of the recommended update, from its name ("October 2026 Security Updates"); none = not known
       (SELECT TOP (1) DATEFROMPARTS(TRY_CONVERT(int, SUBSTRING(f.FixRecommendedUpdate, PATINDEX(N'%20[0-9][0-9]%', f.FixRecommendedUpdate), 4)), mo.N, 1)
        FROM (VALUES (N'January', 1), (N'February', 2), (N'March', 3), (N'April', 4), (N'May', 5), (N'June', 6), (N'July', 7), (N'August', 8), (N'September', 9),
                     (N'October', 10), (N'November', 11), (N'December', 12)) AS mo (Name, N)
        WHERE f.FixRecommendedUpdate LIKE N'%' + mo.Name + N'%' AND PATINDEX(N'%20[0-9][0-9]%', f.FixRecommendedUpdate) > 0 ORDER BY mo.N),
       -- the patch cycle a source gave the finding (si_patch_cycle), else worked out below from the update's month
       CASE WHEN f.DetailJson IS NOT NULL AND ISJSON(f.DetailJson) = 1 THEN NULLIF(LEFT(LTRIM(RTRIM(JSON_VALUE(f.DetailJson, '$.si_patch_cycle'))), 40), N'') END,
       -- the fix's release date a source gives (si_fix_release_date), the protection score's first age basis
       CASE WHEN f.DetailJson IS NOT NULL AND ISJSON(f.DetailJson) = 1 THEN TRY_CONVERT(datetime2(3), LEFT(JSON_VALUE(f.DetailJson, '$.si_fix_release_date'), 23), 126) END,
       $dom
FROM sidata.Finding AS f WHERE f.CollectionId = @c AND f.FindingId > @kfLo AND f.FindingId <= @kfHi AND f.ExemptionId IS NULL;
-- SI:STEP assets
-- each finding's CI: the CI id itself, else the CI that carries the id as a linked object (built ONCE per distinct asset)
-- #860 (d) THE COMPOSITE KEY FORMS, resolved the way the CI list resolves an asset key (CiViews.CiOfAsset: the CI id, else the
-- CI that links the id, else an 'az:' key by its ARM id) plus the forms the Risk Analysis reports write:
--   'tenantid=<t>;objectid=<o>' (the identity / attack-path reports) -> the Entra object id <o>: the CI that links it, else
--                                   the CI whose record carries it as AadObjectId (sidata.RecordIdentifier)
--   '<prefix>/subscriptions/...[;...]' (an ARM id inside a composite key) -> that ARM id
-- One alternative key per DISTINCT asset key (Alt), then index seeks (IX_CiLink_Native, IX_RecordIdentifier_Id) -- set-based.
CREATE TABLE #m (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NULL,
                 Alt NVARCHAR(450) COLLATE DATABASE_DEFAULT NULL, Oid NVARCHAR(36) COLLATE DATABASE_DEFAULT NULL);
INSERT #m (AssetKey, CiId, Alt, Oid)
SELECT a.AssetKey, COALESCE(ci.CiId, lk.CiId), x.Alt, x.Oid
FROM (SELECT DISTINCT AssetKey FROM #f WHERE AssetKey IS NOT NULL) AS a
CROSS APPLY (SELECT LOWER(a.AssetKey) AS K, CHARINDEX(N'objectid=', LOWER(a.AssetKey)) AS O, CHARINDEX(N'/subscriptions/', LOWER(a.AssetKey)) AS S) AS k
CROSS APPLY (SELECT CASE WHEN k.O > 0 AND TRY_CONVERT(uniqueidentifier, SUBSTRING(k.K, k.O + 9, 36)) IS NOT NULL THEN SUBSTRING(k.K, k.O + 9, 36) END AS Oid,
                    CASE WHEN k.K LIKE N'az:%' THEN SUBSTRING(k.K, 4, 450)
                         WHEN k.S > 1 THEN LEFT(SUBSTRING(k.K, k.S, 450), CHARINDEX(N';', SUBSTRING(k.K, k.S, 450) + N';') - 1) END AS Arm) AS y
CROSS APPLY (SELECT y.Oid, COALESCE(y.Oid, y.Arm) AS Alt) AS x
LEFT JOIN sidata.Ci AS ci ON LEN(a.AssetKey) <= 64 AND ci.CiId = a.AssetKey
OUTER APPLY (SELECT TOP (1) l.CiId FROM sidata.CiLink AS l WHERE ci.CiId IS NULL AND LEN(a.AssetKey) <= 450 AND l.NativeId = LOWER(a.AssetKey) ORDER BY l.IsPrimary DESC, l.LastSeen DESC) AS lk;
UPDATE m SET CiId = lk.CiId
FROM #m AS m
CROSS APPLY (SELECT TOP (1) l.CiId FROM sidata.CiLink AS l WHERE l.NativeId = m.Alt ORDER BY l.IsPrimary DESC, l.LastSeen DESC) AS lk
WHERE m.CiId IS NULL AND m.Alt IS NOT NULL;
IF OBJECT_ID('sidata.RecordIdentifier') IS NOT NULL AND OBJECT_ID('sidata.CiRecord') IS NOT NULL
    UPDATE m SET CiId = r.CiId
    FROM #m AS m
    CROSS APPLY (SELECT TOP (1) cr.CiId FROM sidata.RecordIdentifier AS ri JOIN sidata.CiRecord AS cr ON cr.RecordKey = ri.RecordKey
                 WHERE ri.IdType = N'AadObjectId' AND ri.IdValue = m.Oid AND cr.CiId IS NOT NULL ORDER BY cr.CollectionTime DESC) AS r
    WHERE m.CiId IS NULL AND m.Oid IS NOT NULL;
-- the CIs with their dimensions
CREATE TABLE #d (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Class NVARCHAR(16) NULL, Fam NVARCHAR(16) NOT NULL, Typ NVARCHAR(32) NOT NULL,
                 Active BIT NOT NULL, Tier TINYINT NULL, Internet BIT NOT NULL, Onboarded NVARCHAR(32) NULL, NotSeen BIT NOT NULL, AzureVm BIT NOT NULL, HasMde BIT NOT NULL,
                 AssetType NVARCHAR(128) NULL, Enabled BIT NULL, Mfa BIT NULL, LastSignIn DATETIME2(3) NULL, Privileged BIT NOT NULL, Sub NVARCHAR(400) NULL, Name NVARCHAR(400) NULL);
INSERT #d
SELECT c.CiId, c.Class, $fam, $typ,
       CASE WHEN ISNULL(c.Lifecycle, N'active') = N'active' THEN 1 ELSE 0 END, c.Tier, ISNULL(c.InternetExposed, 0), LOWER(c.OnboardingStatus),
       CASE WHEN c.Lifecycle = N'not_seen' THEN 1 ELSE 0 END,
       CASE WHEN LOWER(c.AzureResourceType) = N'microsoft.compute/virtualmachines' THEN 1 ELSE 0 END, CASE WHEN NULLIF(c.MdeDeviceId, N'') IS NULL THEN 0 ELSE 1 END,
       c.AssetType, c.AccountEnabled, c.MfaRegistered, c.LastSignIn, CASE WHEN c.Tier = 0 OR ISNULL(c.PrivilegedAccessCount, 0) > 0 THEN 1 ELSE 0 END,
       COALESCE(NULLIF(c.AzureSubscriptionName, N''), NULLIF(c.AzureSubscriptionId, N'')), c.Name
FROM sidata.Ci AS c WHERE ISNULL(c.Lifecycle, N'active') <> N'retired';
-- #855 (owner 2026-10-21: "we need to be able to trust all data" / "default filter is active, so it should be active only"):
-- every figure counts the findings of ACTIVE assets only -- a finding on a CI that is not seen or retired is left out here,
-- once, before any figure reads #f. A finding no CI carries stays (its asset is not known to be gone).
DELETE f FROM #f AS f JOIN #m AS m ON m.AssetKey = f.AssetKey
WHERE m.CiId IS NOT NULL AND NOT EXISTS (SELECT 1 FROM #d AS d WHERE d.CiId = m.CiId AND d.Active = 1);
CREATE TABLE #fd (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, Cve NVARCHAR(100) COLLATE DATABASE_DEFAULT NULL, Cls CHAR(2) NOT NULL, Tier TINYINT NULL, Exploit BIT NOT NULL, Eos BIT NOT NULL,
                  Rec NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, Comp NVARCHAR(64) COLLATE DATABASE_DEFAULT NULL, Soft NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL,
                  FixId NVARCHAR(200) COLLATE DATABASE_DEFAULT NULL, FixName NVARCHAR(120) COLLATE DATABASE_DEFAULT NULL, Remedy NVARCHAR(120) COLLATE DATABASE_DEFAULT NULL, FixMonth DATE NULL, Cycle NVARCHAR(40) COLLATE DATABASE_DEFAULT NULL);
INSERT #fd SELECT m.CiId, f.Cve, f.Cls, f.Tier, f.Exploit, f.Eos, f.Rec, f.Comp, f.Soft, f.FixId, f.FixName, f.Remedy, f.FixMonth, f.Cycle FROM #f AS f JOIN #m AS m ON m.AssetKey = f.AssetKey WHERE m.CiId IS NOT NULL;
CREATE INDEX IX_fd ON #fd (CiId);

-- SI:STEP figures
-- ==== (0) HEADLINE ================================================================================================
-- the Risk Analysis KPI (0-100) of the run behind this collection (the kept Risk Analysis view) -- kept per collection for its own
-- trend. It is NOT the protection score (owner 2026-10-19: the 0-100 management number is the protection score, below); a run
-- that kept no view is not available, never 0
DECLARE @score float = (SELECT TOP (1) TRY_CONVERT(float, JSON_VALUE(v.PayloadJson, '$.Kpi.GlobalScore')) FROM sidata.RiskExecView AS v
                        WHERE v.CollectionTime = @t AND ISJSON(v.PayloadJson) = 1 ORDER BY CASE v.Grain WHEN N'Detailed' THEN 0 ELSE 1 END);
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'headline', N'ra_kpi', N'', N'', @score, NULL, NULL, CASE WHEN @score IS NULL THEN 0 ELSE 1 END,
                   CASE WHEN @score IS NULL THEN N'the Risk Analysis run of this collection kept no KPI' END);
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'headline', N'open_findings', N'', N'', COUNT_BIG(*), COUNT(DISTINCT AssetKey), NULL, 1, NULL FROM #f;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'headline', N'very_high_high', N'', N'', SUM(CASE WHEN Cls IN ('vh', 'h') THEN 1 ELSE 0 END), COUNT(DISTINCT CASE WHEN Cls IN ('vh', 'h') THEN AssetKey END), COUNT(DISTINCT AssetKey), 1, NULL FROM #f;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'headline', N'known_exploited', N'', N'', COUNT(DISTINCT CASE WHEN Exploit = 1 THEN Cve END), COUNT(DISTINCT CASE WHEN Exploit = 1 AND Cve IS NOT NULL THEN AssetKey END), NULL, 1, NULL FROM #f;

-- ==== (1) PATCHING ================================================================================================
-- missing patches (open CVE findings) and the devices they are on, per OS family x device type, with every total
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'patching', N'missing_patches', CASE WHEN GROUPING(d.Fam) = 1 THEN N'(all)' ELSE d.Fam END, CASE WHEN GROUPING(d.Typ) = 1 THEN N'(all)' ELSE d.Typ END,
       COUNT(x.Cve), COUNT(DISTINCT CASE WHEN x.Cve IS NOT NULL THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId AND x.Cve IS NOT NULL
WHERE d.Class = N'device' AND d.Active = 1
GROUP BY GROUPING SETS ((d.Fam, d.Typ), (d.Fam), (d.Typ), ());
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'patching', N'very_high_cve_devices', CASE WHEN GROUPING(d.Fam) = 1 THEN N'(all)' ELSE d.Fam END, CASE WHEN GROUPING(d.Typ) = 1 THEN N'(all)' ELSE d.Typ END,
       COUNT(x.Cve), COUNT(DISTINCT CASE WHEN x.Cve IS NOT NULL THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId AND x.Cve IS NOT NULL AND x.Cls = 'vh'
WHERE d.Class = N'device' AND d.Active = 1
GROUP BY GROUPING SETS ((d.Fam, d.Typ), (d.Fam), (d.Typ), ());
-- known-exploited CVEs open: how many CVEs, on how many devices, and on how many servers
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'known_exploited', N'', N'', COUNT(DISTINCT x.Cve), COUNT(DISTINCT x.CiId), (SELECT COUNT(*) FROM #d WHERE Class = N'device' AND Active = 1), 1, NULL
FROM #fd AS x WHERE x.Exploit = 1 AND x.Cve IS NOT NULL;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'known_exploited_servers', N'', N'', COUNT(DISTINCT x.Cve), COUNT(DISTINCT x.CiId), (SELECT COUNT(*) FROM #d WHERE Class = N'device' AND Active = 1 AND Typ = N'Server'), 1, NULL
FROM #fd AS x JOIN #d AS d ON d.CiId = x.CiId WHERE x.Exploit = 1 AND x.Cve IS NOT NULL AND d.Typ = N'Server';
-- age of open CVE findings (the source's first-detected date)
IF EXISTS (SELECT 1 FROM #f WHERE Cve IS NOT NULL AND First IS NOT NULL)
    INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'cve_age', a.Dim, N'', SUM(CASE WHEN f.First < DATEADD(day, -a.Days, @t) THEN 1 ELSE 0 END),
                      COUNT(DISTINCT CASE WHEN f.First < DATEADD(day, -a.Days, @t) THEN f.AssetKey END), COUNT(*), 1, NULL
    FROM #f AS f CROSS JOIN #ageBand AS a
    WHERE f.Cve IS NOT NULL GROUP BY a.Dim;
ELSE INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'patching', N'cve_age', N'', N'', NULL, NULL, NULL, 0, N'the sources give no first-detected date for these vulnerabilities');
-- SLA breaches: open findings past their fix due date, per severity
IF EXISTS (SELECT 1 FROM #f WHERE Due IS NOT NULL)
    INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'sla_breaches', CASE WHEN GROUPING(ISNULL(Sev, N'(none)')) = 1 THEN N'(all)' ELSE ISNULL(Sev, N'(none)') END, N'',
                      SUM(CASE WHEN Due < @t THEN 1 ELSE 0 END), COUNT(DISTINCT CASE WHEN Due < @t THEN AssetKey END), SUM(CASE WHEN Due IS NOT NULL THEN 1 ELSE 0 END), 1, NULL
    FROM #f GROUP BY GROUPING SETS ((ISNULL(Sev, N'(none)')), ());
ELSE INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'patching', N'sla_breaches', N'(all)', N'', NULL, NULL, NULL, 0, N'no finding has a fix due date (a remediation flow or service level sets si_fix_due_date)');
-- opened vs fixed in the last @kfRecent days (SI_KeyFigures_RecentDays) and the mean time to fix over the last @kfMttr days
-- (SI_KeyFigures_MeanTimeToFixDays) -- the finding lifecycle, CVE findings. The figures' keys keep their old names
-- (opened_30d / fixed_30d); the window in force is the meta 'window' row below
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'opened_30d', N'', N'', COUNT_BIG(*), COUNT(DISTINCT s.CiId), NULL, 1, NULL FROM sidata.CiFindingState AS s
WHERE s.FindingKey LIKE N'CVE-%' AND s.FirstDetected > DATEADD(day, -@kfRecent, @t) AND s.FirstDetected <= @t;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'fixed_30d', N'', N'', COUNT_BIG(*), COUNT(DISTINCT s.CiId), NULL, 1, NULL FROM sidata.CiFindingState AS s
WHERE s.FindingKey LIKE N'CVE-%' AND s.ClosedAt > DATEADD(day, -@kfRecent, @t) AND s.ClosedAt <= @t AND s.CloseReason = N'remediated';
-- #855: FIXED means remediated -- a finding closed because its asset was retired, is no longer monitored or its report changed
-- was not fixed, and never counts here (nor in the mean time to fix)
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'patching', N'mean_days_to_fix', N'', N'', AVG(CONVERT(float, DATEDIFF(hour, s.FirstDetected, s.ClosedAt)) / 24.0), COUNT(DISTINCT s.CiId), COUNT_BIG(*),
                  CASE WHEN COUNT_BIG(*) > 0 THEN 1 ELSE 0 END, CASE WHEN COUNT_BIG(*) = 0 THEN N'no vulnerability was fixed in the last ' + CONVERT(nvarchar(10), @kfMttr) + N' days' END
FROM sidata.CiFindingState AS s WHERE s.FindingKey LIKE N'CVE-%' AND s.ClosedAt > DATEADD(day, -@kfMttr, @t) AND s.ClosedAt <= @t AND s.CloseReason = N'remediated';

-- ==== (2) EXPOSURE ================================================================================================
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'exposure', N'tier0_very_high_high', N'', N'', COUNT(DISTINCT CASE WHEN x.Cls IN ('vh', 'h') THEN d.CiId END), COUNT(DISTINCT CASE WHEN x.Cls IN ('vh', 'h') THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId WHERE d.Tier = 0 AND d.Active = 1;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'exposure', N'internet_very_high_cve', N'', N'', COUNT(DISTINCT CASE WHEN x.Cls = 'vh' AND x.Cve IS NOT NULL THEN d.CiId END), COUNT(DISTINCT CASE WHEN x.Cls = 'vh' AND x.Cve IS NOT NULL THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId WHERE d.Internet = 1 AND d.Active = 1;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'exposure', N'end_of_support', CASE WHEN GROUPING(CASE WHEN d.Typ = N'Server' THEN N'Servers' ELSE N'Other devices' END) = 1 THEN N'(all)' ELSE CASE WHEN d.Typ = N'Server' THEN N'Servers' ELSE N'Other devices' END END, N'',
                  COUNT(DISTINCT CASE WHEN x.Eos = 1 THEN d.CiId END), COUNT(DISTINCT CASE WHEN x.Eos = 1 THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId WHERE d.Class = N'device' AND d.Active = 1
GROUP BY GROUPING SETS ((CASE WHEN d.Typ = N'Server' THEN N'Servers' ELSE N'Other devices' END), ());

-- ==== (3) COVERAGE ================================================================================================
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'coverage', N'not_onboarded', N'', N'', SUM(CASE WHEN ISNULL(Onboarded, N'') <> N'onboarded' THEN 1 ELSE 0 END), SUM(CASE WHEN ISNULL(Onboarded, N'') <> N'onboarded' THEN 1 ELSE 0 END), COUNT(*), 1, NULL
FROM #d WHERE Class = N'device' AND Active = 1;
-- #855 W11 / #858 (owner 2026-10-21: "another filter can easily be unonboarded"): the active devices not onboarded, split by
-- Defender's onboarding status -- can be onboarded (the actionable part), unsupported, insufficient info, offboarded, and
-- unknown (no status) -- each linked to the CI list's Onboarding filter; the total above stays the sum of the parts
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'coverage', N'not_onboarded_status', s.Dim1, N'', COUNT(*), COUNT(*), (SELECT COUNT(*) FROM #d WHERE Class = N'device' AND Active = 1), 1, NULL
FROM (SELECT CASE WHEN ISNULL(Onboarded, N'') IN (N'can_be_onboarded', N'unsupported', N'insufficient_info', N'offboarded') THEN Onboarded ELSE N'unknown' END AS Dim1
      FROM #d WHERE Class = N'device' AND Active = 1 AND ISNULL(Onboarded, N'') <> N'onboarded') AS s
GROUP BY s.Dim1;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'coverage', N'not_seen_30d', N'', N'', SUM(CONVERT(int, NotSeen)), SUM(CONVERT(int, NotSeen)), COUNT(*), 1, NULL FROM #d WHERE Class = N'device';
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'coverage', N'azure_vm_no_agent', N'', N'', SUM(CASE WHEN HasMde = 0 THEN 1 ELSE 0 END), SUM(CASE WHEN HasMde = 0 THEN 1 ELSE 0 END), COUNT(*), 1, NULL FROM #d WHERE AzureVm = 1 AND Active = 1;

-- ==== (4) IDENTITY ================================================================================================
IF EXISTS (SELECT 1 FROM #d WHERE Class = N'identity' AND AssetType = N'User' AND Mfa IS NOT NULL)
    INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'identity', N'users_without_mfa', N'', N'', SUM(CASE WHEN Mfa = 0 THEN 1 ELSE 0 END), SUM(CASE WHEN Mfa = 0 THEN 1 ELSE 0 END), COUNT(*), 1, NULL
    FROM #d WHERE Class = N'identity' AND AssetType = N'User' AND ISNULL(Enabled, 1) = 1 AND Active = 1 AND Mfa IS NOT NULL;
ELSE INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'identity', N'users_without_mfa', N'', N'', NULL, NULL, NULL, 0, N'no user carries an MFA registration state (the identity profile reads it from Entra ID)');
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'identity', N'tier0_identities_at_risk', N'', N'', COUNT(DISTINCT CASE WHEN x.Cls IN ('vh', 'h') THEN d.CiId END), COUNT(DISTINCT CASE WHEN x.Cls IN ('vh', 'h') THEN d.CiId END), COUNT(DISTINCT d.CiId), 1, NULL
FROM #d AS d LEFT JOIN #fd AS x ON x.CiId = d.CiId WHERE d.Class = N'identity' AND d.Tier = 0 AND d.Active = 1;
IF EXISTS (SELECT 1 FROM #d WHERE Class = N'identity' AND Privileged = 1 AND LastSignIn IS NOT NULL)
    INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'identity', N'stale_admins', N'', N'', SUM(CASE WHEN LastSignIn < DATEADD(day, -@kfStale, @t) THEN 1 ELSE 0 END), SUM(CASE WHEN LastSignIn < DATEADD(day, -@kfStale, @t) THEN 1 ELSE 0 END), COUNT(*), 1, NULL
    FROM #d WHERE Class = N'identity' AND Privileged = 1 AND ISNULL(Enabled, 1) = 1 AND Active = 1 AND LastSignIn IS NOT NULL;
ELSE INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'identity', N'stale_admins', N'', N'', NULL, NULL, NULL, 0, N'no privileged account carries a last sign-in time (the identity profile reads it from Entra ID sign-in activity)');

-- ==== (5) CLOUD ===================================================================================================
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) SELECT N'cloud', N'high_recommendations', LEFT(ISNULL(d.Sub, N'(no subscription)'), 128), N'', COUNT_BIG(*), COUNT(DISTINCT d.CiId), NULL, 1, NULL
FROM #fd AS x JOIN #d AS d ON d.CiId = x.CiId WHERE d.Class = N'cloud_resource' AND x.Cls IN ('vh', 'h')
GROUP BY LEFT(ISNULL(d.Sub, N'(no subscription)'), 128);

-- SI:STEP patches
$patches
-- SI:STEP protection
$protection

-- SI:STEP write
-- #855 the marker: these figures count active assets only and remediated as fixed (a collection without it is figured again)
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'meta', N'active_assets_only', N'', N'', 1, NULL, NULL, 1, NULL);
-- #860 the marker: the grace is by kind (patch / other), the composite keys are resolved (a collection without it is figured again)
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'meta', N'grace_by_kind', N'', N'', 1, NULL, NULL, 1, NULL);
-- #859 the windows these figures were worked out with (the labels say the value in force for THIS collection)
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
VALUES (N'meta', N'window', N'recent_days', N'', @kfRecent, NULL, NULL, 1, NULL), (N'meta', N'window', N'mttr_days', N'', @kfMttr, NULL, NULL, 1, NULL),
       (N'meta', N'window', N'stale_admin_days', N'', @kfStale, NULL, NULL, 1, NULL);
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note)
SELECT N'meta', N'window', N'cve_age_band', CONVERT(nvarchar(10), Days), Days, NULL, NULL, 1, NULL FROM #ageBand;
INSERT #kf (Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note) VALUES (N'meta', N'onboarding_by_status', N'', N'', 1, NULL, NULL, 1, NULL);

BEGIN TRAN;
DELETE FROM sidata.KeyFigure WHERE CollectionId = @c;
INSERT sidata.KeyFigure (CollectionId, Block, Figure, Dim1, Dim2, Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients)
SELECT @c, Block, Figure, LEFT(Dim1, 200), LEFT(Dim2, 120), Value, Assets, Total, Available, Note, Items, VeryHigh, Servers, Clients FROM #kf;
DECLARE @n INT = @@ROWCOUNT;
UPDATE sidata.Collection SET KeyFiguresAt = SYSUTCDATETIME() WHERE CollectionId = @c;
COMMIT;
SELECT @n;
"@
}

function Get-SIProtectionScoreParams {
    <#
        PURE. The key-figure SQL's parameters: the protection score's settings (ONE reader for both editions:
        Get-SIProtectionScoreSettings in engine\_shared\SI-ProtectionScore.ps1) and the figures' windows (#859, ONE reader:
        Get-SIKeyFigureWindowSettings).
    #>
    param($Settings)
    if (-not (Get-Command -Name Get-SIProtectionScoreSettings -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-ProtectionScore.ps1'))
    }
    $c = Get-SIProtectionScoreSettings -Settings $Settings
    $w = Get-SIKeyFigureWindowSettings -Settings $Settings
    $inv = [Globalization.CultureInfo]::InvariantCulture
    [ordered]@{
        Sevs = (ConvertTo-Json -InputObject @($c.Severities) -Compress)
        W0 = ([double]$c.Weights[0]).ToString($inv); W1 = ([double]$c.Weights[1]).ToString($inv); W2 = ([double]$c.Weights[2]).ToString($inv); W3 = ([double]$c.Weights[3]).ToString($inv)
        GraceDevice = [string]$c.Grace.device; GraceIdentity = [string]$c.Grace.identity
        GraceCloud = [string]$c.Grace.cloud_resource; GracePublicIp = [string]$c.Grace.public_ip
        OtherGraceDevice = [string]$c.OtherGrace.device; OtherGraceIdentity = [string]$c.OtherGrace.identity
        OtherGraceCloud = [string]$c.OtherGrace.cloud_resource; OtherGracePublicIp = [string]$c.OtherGrace.public_ip
        RecentDays = $w.RecentDays.ToString($inv); MttrDays = $w.MeanTimeToFixDays.ToString($inv); StaleAdminDays = $w.StaleAdminDays.ToString($inv)
        CveAgeBands = (ConvertTo-Json -InputObject @($w.CveAgeBands) -Compress)
    }
}

# #859 (owner 2026-10-21: "do we have static values in the code ?" / "why not use the settings values (customer specific)"):
# every window a key figure counts over is a setting of the install, today's value as its shipped default.
$script:SIKeyFigureWindowDefaults = [ordered]@{
    SI_KeyFigures_RecentDays        = 30          # "opened / fixed in the last N days"
    SI_KeyFigures_MeanTimeToFixDays = 90          # "mean time to fix (days, last N days)"
    SI_KeyFigures_StaleAdminDays    = 90          # "privileged accounts without a sign-in for N days"
    SI_KeyFigures_CveAgeBands       = '30,60,90'  # "age of open CVE findings: older than N days", one band per number
}

function Get-SIKeyFigureWindowSettings {
    <#
        PURE. THE reader of the key figures' windows (#859), from -Settings (a dictionary: the update passes the install's own)
        or the globals (the data sync loads the config and the Settings page's values): @{ RecentDays; MeanTimeToFixDays;
        StaleAdminDays; CveAgeBands (ascending, distinct, 1..3650) }. A missing or invalid value = its default
        ($script:SIKeyFigureWindowDefaults); a band list with no valid number = the default bands.
    #>
    param($Settings)
    $val = {
        param($n)
        if ($Settings -is [System.Collections.IDictionary]) { if ($Settings.Contains($n)) { return $Settings[$n] }; return $null }
        Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue
    }
    $days = {
        param($n)
        $x = 0; $v = & $val $n
        if ($null -ne $v -and [int]::TryParse(([string]$v).Trim(), [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$x) -and $x -ge 1 -and $x -le 3650) { return $x }
        [int]$script:SIKeyFigureWindowDefaults[$n]
    }
    $bandsOf = {
        param($raw)
        $out = New-Object System.Collections.Generic.List[int]
        foreach ($p in @(([string]$raw) -split '[,;\s]+')) { $x = 0; if ($p -ne '' -and [int]::TryParse($p, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$x) -and $x -ge 1 -and $x -le 3650 -and -not $out.Contains($x)) { $out.Add($x) } }
        , @($out | Sort-Object)
    }
    $rawBands = & $val 'SI_KeyFigures_CveAgeBands'
    if ($rawBands -is [System.Array]) { $rawBands = (@($rawBands) | ForEach-Object { "$_" }) -join ',' }
    $bands = & $bandsOf $rawBands
    if ($bands.Count -eq 0) { $bands = & $bandsOf $script:SIKeyFigureWindowDefaults['SI_KeyFigures_CveAgeBands'] }
    @{
        RecentDays        = (& $days 'SI_KeyFigures_RecentDays')
        MeanTimeToFixDays = (& $days 'SI_KeyFigures_MeanTimeToFixDays')
        StaleAdminDays    = (& $days 'SI_KeyFigures_StaleAdminDays')
        CveAgeBands       = [int[]]$bands
    }
}
function Get-SIDataKeyFiguresSteps {
    <#
        PURE. The key-figure script (Get-SIDataKeyFiguresSql) cut at its '-- SI:STEP <name>' lines: @{ Prologue; Steps =
        [ordered] name -> text }. The prologue is the declarations every step needs (@c, @t, the windows, @kfLo / @kfHi);
        the step 'findings' reads one key range of the collection's findings (@kfLo < FindingId <= @kfHi).
    #>
    param([int]$CatchUpDays = 30)
    $all = Get-SIDataKeyFiguresSql -CatchUpDays $CatchUpDays
    $parts = [regex]::Split($all, '(?m)^-- SI:STEP (\w+)\s*$')
    $head = $parts[0] -replace '(?m)^SET (NOCOUNT|XACT_ABORT) ON;\s*$', ''
    $steps = [ordered]@{}
    for ($i = 1; $i -lt $parts.Count; $i += 2) { $steps[$parts[$i]] = $parts[$i + 1] }
    [pscustomobject]@{ Prologue = $head.Trim(); Steps = $steps }
}

function ConvertTo-SIKeyFigureParamDeclare {
    <#
        PURE. The parameters of the key-figure script as T-SQL declarations (DECLARE @Name nvarchar(max) = N'value';) -- a step
        runs as a plain batch, because a parameterised command runs in sp_executesql and drops the #temp tables the next step
        reads. Names are identifiers only; every value is a quoted N'' string (quotes doubled), as the script converts each one.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Params)
    $lines = foreach ($k in @($Params.Keys)) {
        if ([string]$k -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw ("key figures: '{0}' is not a parameter name" -f $k) }
        $v = $Params[$k]
        if ($null -eq $v) { "DECLARE @$k nvarchar(max) = NULL;" } else { "DECLARE @$k nvarchar(max) = N'" + ([string]$v).Replace("'", "''") + "';" }
    }
    ($lines -join "`n")
}

function Invoke-SIDataKeyFiguresStepped {
    <#
        THE KEY FIGURES OF ONE COLLECTION AT ANY SIZE (owner 2026-10-22: "i accept no limits ... this must work for customers
        with 50 mio objects"): the same script as Get-SIDataKeyFiguresSql, run as its steps on ONE connection (the seam's mode
        'session'), each its own command with no time limit, with a progress line per step -- and the collection's findings
        read into the working set one key range at a time (a clustered-key seek on (CollectionId, FindingId)), the range
        sized from the measured seconds of the one before (aim -TargetSeconds a range; never a fixed row count). The result
        is identical to the one-statement run (the same text, the same order). Answers the number of figure rows.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][System.Collections.IDictionary]$Params, [int]$CatchUpDays = 30,
          [scriptblock]$Log, [double]$TargetSeconds = 20, [long]$FirstSpan = 200000)
    if (-not $Log) { $Log = { param($l, $m) } }
    $plan = Get-SIDataKeyFiguresSteps -CatchUpDays $CatchUpDays
    $decl = ConvertTo-SIKeyFigureParamDeclare -Params $Params
    $cid = [string]$Params['CollectionId']
    $batchOf = {
        param([string]$Text, [long]$Lo, [long]$Hi)
        $pro = $plan.Prologue -replace 'DECLARE @kfLo bigint = \d+, @kfHi bigint = \d+;', ('DECLARE @kfLo bigint = {0}, @kfHi bigint = {1};' -f $Lo, $Hi)
        "SET NOCOUNT ON;`nSET XACT_ABORT ON;`n$decl`n$pro`n$Text"
    }
    $onSession = {
        param($Run)
        $clock = [Diagnostics.Stopwatch]::StartNew(); $sw = [Diagnostics.Stopwatch]::new()
        $null = & $Run (& $batchOf $plan.Steps['setup'] 0 ([long]::MaxValue)) 'nonquery'
        # the collection's finding ids: two seeks on the clustered key, never a count of the rows
        $rg = @(& $Run ("SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = CONVERT(int, N'{0}');" -f ([int]$cid)) 'reader') | Select-Object -First 1
        $lo = $null; $hi = $null
        if ($rg) { $lo = $rg.Lo; $hi = $rg.Hi; if ($lo -is [System.DBNull]) { $lo = $null }; if ($hi -is [System.DBNull]) { $hi = $null } }
        if ($null -ne $lo -and $null -ne $hi) {
            $from = [long]$lo - 1; $top = [long]$hi; $span = [Math]::Max(1L, $FirstSpan); $said = [Diagnostics.Stopwatch]::StartNew()
            while ($from -lt $top) {
                $to = [long][Math]::Min([double]$top, [double]$from + $span)
                $sw.Restart()
                $null = & $Run (& $batchOf $plan.Steps['findings'] $from $to) 'nonquery'
                $sec = [Math]::Max(0.05, $sw.Elapsed.TotalSeconds)
                $from = $to
                # the next range from the measured pace (at most twice / half the last one, so one slow range never swings it)
                $span = [long][Math]::Max(1, [Math]::Round($span * [Math]::Min(2.0, [Math]::Max(0.5, $TargetSeconds / $sec))))
                if ($said.Elapsed.TotalSeconds -ge 60 -or $from -ge $top) {
                    & $Log 'INFO' ("key figures : collection {0} -- findings read {1:N0}% ({2:N0} s so far)" -f $cid, (100.0 * ($from - [long]$lo + 1) / [Math]::Max(1, ($top - [long]$lo + 1))), $clock.Elapsed.TotalSeconds)
                    $said.Restart()
                }
            }
        }
        $n = 0L
        foreach ($name in @($plan.Steps.Keys)) {
            if ($name -in 'setup', 'findings') { continue }
            $sw.Restart()
            if ($name -eq 'write') { $n = [long](& $Run (& $batchOf $plan.Steps[$name] 0 ([long]::MaxValue)) 'scalar') }
            else { $null = & $Run (& $batchOf $plan.Steps[$name] 0 ([long]::MaxValue)) 'nonquery' }
            & $Log 'INFO' ("key figures : collection {0} -- {1} done in {2:N1} s ({3:N0} s so far)" -f $cid, $name, $sw.Elapsed.TotalSeconds, $clock.Elapsed.TotalSeconds)
        }
        $n
    }
    [long](& $Invoke $null $null 'session' $onSession)
}

function Invoke-SIDataKeyFigures {
    <#
    .SYNOPSIS  Writes the key figures of the newest complete collections that have none (newest first). Never throws.
    .NOTES     -Keep: how many of the newest pending collections get figures in one run (the trend reads every one that has
               them; older ones follow on the next runs). A collection without them: the Executive pages say "being prepared".
               NO TIME LIMIT ON THE WORK (owner 2026-10-22): a seam that runs a session (SISqlSession: the data sync's and the
               update's) works each collection out in steps with progress (Invoke-SIDataKeyFiguresStepped), no command time
               limit. -BudgetSeconds never stops a collection that has started: it only says when the OLDER pending
               collections are left to the next run (resume in parts -- the newest is always done first).
    #>
    # -Settings: the protection score's settings (a dictionary; none = the globals, as the data sync loads them) -- the update
    # passes the install's own when it figures the collections again (Invoke-SIContainerUpdate.ps1 step 9g)
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 600, $Settings = $null)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (([int](& $Invoke (Get-SIDataKeyFiguresSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'INFO' 'key figures : the database does not have the key figures table yet (the updater adds it) -- the Executive overview and report say they are being prepared.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke (Get-SIDataUnfiguredSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if ($DryRun) {
            & $Log 'INFO' ("key figures : {0} collection(s) would get their key figures; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0 } }
        $days = 30; if ($global:SI_PatchCycle_CatchUpDays -and [int]$global:SI_PatchCycle_CatchUpDays -gt 0) { $days = [int]$global:SI_PatchCycle_CatchUpDays }
        $sql = Get-SIDataKeyFiguresSql -CatchUpDays $days
        $clock = [Diagnostics.Stopwatch]::StartNew(); $done = 0; $rows = [long]0
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            $cid = $(if ($p -is [System.Collections.IDictionary]) { $p['CollectionId'] } else { $p.CollectionId })
            $ps = Get-SIProtectionScoreParams -Settings $Settings; $ps['CollectionId'] = [string][int]$cid
            if ($Invoke.PSObject.Properties['SISqlSession'] -and $Invoke.SISqlSession) {
                $rows += Invoke-SIDataKeyFiguresStepped -Invoke $Invoke -Params $ps -CatchUpDays $days -Log $Log
            } else {
                $rows += [long](& $Invoke $sql $ps 'scalar')
            }
            $done++
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("key figures : {0} collection(s) got their key figures ({1} figure row(s))" -f $done, $rows)
        if ($left -gt 0) { & $Log 'INFO' ("key figures : {0} older collection(s) follow on the next run(s)" -f $left) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Rows = $rows; Pending = $left }
    } catch {
        & $Log 'WARN' ("key figures : not completed this run -- {0}. Tried again on the next run; the Executive pages show the last complete set." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}
