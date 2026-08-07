using System.Text;
using System.Text.RegularExpressions;

namespace SIAnalyzer.Core.Kql;

/// <summary>Result of the read-only KQL guardrail check.</summary>
public sealed record GuardrailResult(bool Allowed, IReadOnlyList<string> Reasons, IReadOnlyList<string> Tables);

/// <summary>
/// The read-only KQL guardrail - the SINGLE gate every prestaged AND AI-generated query
/// must pass before it is submitted to Log Analytics. It rejects:
///   * control commands (any statement starting with '.'),
///   * destructive / mutating / external-reach operators,
///   * cross-cluster / cross-database / cross-workspace reach
///     (cluster()/database()/workspace()/app()/table()),
///   * whole-workspace scans (union *, unscoped search, find),
///   * any table in a SOURCE position outside the canonical SI allow-list,
///   * ungrounded / empty queries.
///
/// AUDIT #6 (2026-08-05) - this is a SOURCE WHITELIST, not a mention scan.
/// The original port of the PowerShell <c>Test-SiKqlReadOnly</c> decided "which tables does
/// this query touch" by regex-extracting every table-shaped identifier ANYWHERE in the text
/// and requiring at least one of them to be on the allow-list. That is not a whitelist, and
/// it was bypassable four different ways (all verified against the shipped code):
///   * <c>SI_RiskAnalysis_Summary_CL | union *</c> - one allowed mention, then read everything;
///   * a mention inside a <c>//</c> comment or a string literal grounded any query, e.g.
///     <c>// SI_RiskAnalysis_Summary_CL</c> + <c>SigninLogs | take 5</c>;
///   * tables that are not <c>*_CL</c> and not one of the five hardcoded Defender names
///     (SigninLogs, SecurityEvent, AuditLogs, ...) matched no pattern at all, so they were
///     neither allow-listed nor rejected - they were invisible;
///   * <c>workspace('other').X</c> / <c>app('other').X</c> reached a DIFFERENT workspace;
///     only cluster() and database() were banned.
/// So the gate now: strips comments and string literals FIRST, then walks the token stream and
/// validates every identifier that lands in a source position (statement start, the RHS of a
/// <c>let</c>, each <c>union</c> operand, the <c>join</c> operand, and inside a
/// <c>toscalar()</c>/<c>materialize()</c> sub-pipeline). An identifier in a source position that
/// is neither a <c>let</c>-defined name nor on the allow-list is REJECTED - it no longer has to
/// look like a table name to be caught. Fail-closed: anything the walker cannot account for in a
/// source position is rejected rather than ignored.
///
/// This is still a text-level control over a language the gate does not fully parse. It is
/// deliberately fail-closed, but "no known bypass" is not "provably complete" - treat it as one
/// layer, not as the reason the query identity may hold broad workspace permissions.
/// </summary>
public static class KqlGuardrail
{
    /// <summary>
    /// The canonical SI table allow-list - the ONLY tables a generated or prestaged
    /// query may read (RA Profile tables + ExposureGraph + the read-only Defender/Graph
    /// hunting tables the engine already consumes). Matches the PS allow-list 1:1.
    /// </summary>
    public static readonly IReadOnlyList<string> AllowedTables = new[]
    {
        // RA output tables - the SCORED findings (RiskScoreTotal, SecuritySeverity,
        // CriticalityTierLevel, RiskFactor_*). This is where the exec rollup + worklist
        // source their numbers; the Profile_CL tables below carry asset ATTRIBUTES only
        // (Tier, DisplayName, Hostname/Upn, ...) and do NOT contain RiskScoreTotal.
        SiTables.RiskAnalysisSummary,   // SI_RiskAnalysis_Summary_CL
        SiTables.RiskAnalysisDetailed,  // SI_RiskAnalysis_Detailed_CL
        // Asset-profile attribute tables (one flat row per asset, per snapshot).
        SiTables.EndpointProfile,
        SiTables.IdentityProfile,
        SiTables.AzureProfile,
        SiTables.PublicIpProfile,
        "SI_VulnerabilityPIP_CL",
        // Read-only Defender/Graph hunting tables the engine already consumes.
        "ExposureGraphNodes",
        "ExposureGraphEdges",
        "DeviceInfo",
        "DeviceTvmSoftwareVulnerabilities",
        "IdentityInfo",
    };

    // Destructive / mutating / external-reach operators (case-insensitive). These
    // never appear in a legitimate read-only SI analytics query. Ported verbatim
    // from the PS $bannedOperators list.
    private static readonly string[] BannedOperators =
    {
        "set-or-replace", "set-or-append", "create-or-alter",
        @"\.set\b", @"\.append\b", @"\.create\b", @"\.drop\b", @"\.alter\b", @"\.delete\b",
        @"\.ingest\b", @"\.purge\b", @"\.rename\b", @"\.move\b", @"\.replace\b",
        @"\bexternaldata\b", @"\bexternal_table\b", @"\bevaluate\s+http_request\b",
        @"\bevaluate\s+http_request_post\b", @"\binto\s+table\b",
    };

    // Functions that resolve a data source by NAME AT RUNTIME, i.e. outside anything a static
    // allow-list can see. cluster()/database() were already banned; workspace()/app() reach a
    // DIFFERENT Log Analytics workspace and table() resolves a table from a string expression.
    private static readonly (string Name, string Reason)[] ReachFunctions =
    {
        ("cluster",        "Cross-cluster reference not allowed: cluster(...)"),
        ("database",       "Cross-database reference not allowed: database(...)"),
        ("workspace",      "Cross-workspace reference not allowed: workspace(...)"),
        ("app",            "Cross-application reference not allowed: app(...)"),
        ("table",          "Dynamic table reference not allowed: table(...) - name the table directly."),
        ("external_table", "External table reference not allowed: external_table(...)"),
    };

    // union with a wildcard source list: 'union *', 'union A, *', 'union SI_*',
    // 'union withsource=T *'. Bounded by | and ; so a later 'a*b' cannot false-positive.
    private static readonly Regex WildcardUnionPattern = new(
        @"\bunion\b[^|;]*\*", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // search/find scan EVERY table in the workspace unless bound to a source. 'T | search "x"'
    // is bound (it filters T) and stays allowed; a statement that STARTS with search, a
    // 'search in (...)' source list, and find in any position are all whole-workspace reads.
    private static readonly Regex UnscopedSearchPattern = new(
        @"(?:^|;)\s*search\b", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex SearchInPattern = new(
        @"\bsearch\s+in\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex FindPattern = new(
        @"(?:^|\||;)\s*find\b", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex LetNamePattern = new(
        @"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", RegexOptions.Compiled);

    // Functions whose ARGUMENT is itself a pipeline, so the identifier inside is a source.
    private static readonly HashSet<string> SubPipelineFunctions =
        new(StringComparer.OrdinalIgnoreCase) { "toscalar", "materialize", "view" };

    // Operators that occupy a source position but read no table - they generate rows.
    private static readonly HashSet<string> RowGenerators =
        new(StringComparer.OrdinalIgnoreCase) { "print", "range", "datatable", "evaluate", "externaldata" };

    /// <summary>Check a query. Returns Allowed=false with reasons on any violation.</summary>
    public static GuardrailResult Check(string? query)
    {
        var reasons = new List<string>();
        var raw = query ?? "";

        if (string.IsNullOrWhiteSpace(raw))
        {
            return new GuardrailResult(false, new[] { "Query is empty." }, Array.Empty<string>());
        }

        // 0. Blank out comments and string literals BEFORE anything else. Everything below reads
        //    the sanitized text, so a table name in a comment cannot ground a query and a banned
        //    word inside a string literal cannot trip a ban.
        var q = Sanitize(raw);

        // 1. Control commands - any statement beginning with '.' (.set/.create/.drop/...).
        foreach (var rawLine in q.Split('\n'))
        {
            var line = rawLine.Trim().TrimEnd('\r').Trim();
            if (line.StartsWith('.'))
            {
                reasons.Add($"Control command not allowed: '{line}'");
            }
        }

        // 2. Destructive / mutating / external operators.
        foreach (var op in BannedOperators)
        {
            var m = Regex.Match(q, op, RegexOptions.IgnoreCase);
            if (m.Success)
            {
                reasons.Add($"Disallowed operator: '{m.Value.Trim()}'");
            }
        }

        // 3. Runtime-resolved / cross-scope sources.
        foreach (var (name, reason) in ReachFunctions)
        {
            if (Regex.IsMatch(q, $@"\b{name}\s*\(", RegexOptions.IgnoreCase))
            {
                reasons.Add(reason);
            }
        }

        // 4. Whole-workspace scans.
        if (WildcardUnionPattern.IsMatch(q))
        {
            reasons.Add("Wildcard union source not allowed: every union operand must be an allow-listed table.");
        }
        if (UnscopedSearchPattern.IsMatch(q) || SearchInPattern.IsMatch(q))
        {
            reasons.Add("Unscoped 'search' not allowed - it scans every table. Pipe it from an allow-listed table instead.");
        }
        if (FindPattern.IsMatch(q))
        {
            reasons.Add("'find' not allowed - it scans every table in the workspace.");
        }

        // 5. SOURCE allow-list. Walk the token stream and validate every identifier that lands
        //    in a source position - not every identifier that merely appears somewhere.
        var letNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in LetNamePattern.Matches(q))
        {
            letNames.Add(m.Groups[1].Value);
        }

        var sources = new List<string>();
        var offList = new List<string>();
        WalkSources(Tokenize(q), letNames, sources, offList, reasons);

        if (offList.Count > 0)
        {
            reasons.Add($"Table(s) not on the read-only allow-list: {string.Join(", ", offList)}");
        }
        if (sources.Count == 0)
        {
            reasons.Add("No recognised SI/Defender table referenced -- query rejected as ungrounded.");
        }

        var distinct = reasons.Distinct().ToList();
        return new GuardrailResult(distinct.Count == 0, distinct, sources);
    }

    /// <summary>
    /// Replace the CONTENT of comments and string literals with spaces, preserving length and
    /// line breaks so line-based checks and reported text still line up with the original.
    /// Handles <c>//</c> line comments, <c>"..."</c> / <c>'...'</c> (with backslash escapes),
    /// verbatim <c>@"..."</c>, and KQL's triple-backtick multi-line literals.
    /// </summary>
    private static string Sanitize(string q)
    {
        var sb = new StringBuilder(q.Length);
        var i = 0;
        while (i < q.Length)
        {
            var c = q[i];

            if (c == '/' && i + 1 < q.Length && q[i + 1] == '/')
            {
                while (i < q.Length && q[i] != '\n') { sb.Append(' '); i++; }
                continue;
            }

            if (c == '`' && i + 2 < q.Length && q[i + 1] == '`' && q[i + 2] == '`')
            {
                sb.Append("   ");
                i += 3;
                while (i < q.Length && !(q[i] == '`' && i + 2 < q.Length && q[i + 1] == '`' && q[i + 2] == '`'))
                {
                    sb.Append(q[i] == '\n' ? '\n' : ' ');
                    i++;
                }
                if (i < q.Length) { sb.Append("   "); i += 3; }
                continue;
            }

            if (c == '@' && i + 1 < q.Length && (q[i + 1] == '"' || q[i + 1] == '\''))
            {
                var verbatimQuote = q[i + 1];
                sb.Append("  ");
                i += 2;
                while (i < q.Length && q[i] != verbatimQuote) { sb.Append(q[i] == '\n' ? '\n' : ' '); i++; }
                if (i < q.Length) { sb.Append(' '); i++; }
                continue;
            }

            if (c == '"' || c == '\'')
            {
                sb.Append(' ');
                i++;
                while (i < q.Length && q[i] != c)
                {
                    if (q[i] == '\\' && i + 1 < q.Length) { sb.Append("  "); i += 2; continue; }
                    sb.Append(q[i] == '\n' ? '\n' : ' ');
                    i++;
                }
                if (i < q.Length) { sb.Append(' '); i++; }
                continue;
            }

            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    /// <summary>Split sanitized KQL into identifiers, numbers and single punctuation chars.</summary>
    private static List<string> Tokenize(string q)
    {
        var tokens = new List<string>();
        var i = 0;
        while (i < q.Length)
        {
            var c = q[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }

            if (char.IsLetter(c) || c == '_')
            {
                var start = i;
                while (i < q.Length && (char.IsLetterOrDigit(q[i]) || q[i] == '_')) i++;
                tokens.Add(q[start..i]);
                continue;
            }

            if (char.IsDigit(c))
            {
                var start = i;
                while (i < q.Length && (char.IsLetterOrDigit(q[i]) || q[i] == '.')) i++;
                tokens.Add(q[start..i]);
                continue;
            }

            tokens.Add(c.ToString());
            i++;
        }
        return tokens;
    }

    private static bool IsIdent(string token) =>
        token.Length > 0 && (char.IsLetter(token[0]) || token[0] == '_');

    /// <summary>
    /// Walk the tokens tracking whether the next identifier occupies a SOURCE position, and
    /// validate the ones that do. Source positions: query start, after ';', the RHS of
    /// 'let x =', each operand of 'union', the operand of 'join', and the argument of a
    /// sub-pipeline function. Everything else (column names, function arguments, literals) is
    /// never checked, which is why 'summarize max(CollectionTime)' does not trip the gate.
    /// </summary>
    private static void WalkSources(
        List<string> tokens, HashSet<string> letNames,
        List<string> sources, List<string> offList, List<string> reasons)
    {
        const string wildcardReason =
            "Wildcard table source not allowed - name each allow-listed table explicitly.";

        var expectSource = true;
        var depth = 0;
        var unionDepth = -1;   // paren depth of an open union operand list; -1 = not in one

        var i = 0;
        while (i < tokens.Count)
        {
            var t = tokens[i];

            if (t == "(")
            {
                depth++;
                i++;
                continue;   // if a source was expected it still is - '(' opens a sub-pipeline
            }
            if (t == ")")
            {
                depth--;
                if (unionDepth > depth) unionDepth = -1;
                expectSource = false;
                i++;
                continue;
            }
            if (t == ";")
            {
                expectSource = true;
                unionDepth = -1;
                i++;
                continue;
            }
            if (t == "|")
            {
                if (unionDepth == depth) unionDepth = -1;
                i++;
                if (i < tokens.Count && IsIdent(tokens[i]))
                {
                    var op = tokens[i];
                    i++;
                    if (string.Equals(op, "union", StringComparison.OrdinalIgnoreCase))
                    {
                        expectSource = true;
                        unionDepth = depth;
                        continue;
                    }
                    if (string.Equals(op, "join", StringComparison.OrdinalIgnoreCase))
                    {
                        expectSource = true;
                        continue;
                    }
                }
                expectSource = false;
                continue;
            }
            if (t == "," && unionDepth == depth)
            {
                expectSource = true;
                i++;
                continue;
            }

            if (expectSource)
            {
                if (t == "*")
                {
                    reasons.Add(wildcardReason);
                    expectSource = false;
                    i++;
                    continue;
                }

                if (IsIdent(t))
                {
                    // 'let name =' - the RHS is the source position, not 'let'.
                    if (string.Equals(t, "let", StringComparison.OrdinalIgnoreCase))
                    {
                        i++;
                        if (i < tokens.Count && IsIdent(tokens[i])) i++;
                        if (i < tokens.Count && tokens[i] == "=") i++;
                        continue;
                    }

                    // 'union' can also open a statement rather than follow a pipe.
                    if (string.Equals(t, "union", StringComparison.OrdinalIgnoreCase))
                    {
                        unionDepth = depth;
                        i++;
                        continue;
                    }

                    // Operator modifiers that precede the operand: kind=inner, withsource=T,
                    // isfuzzy=true, hint.strategy=shuffle. Skip them; still expecting a source.
                    if (TrySkipModifier(tokens, i, out var afterModifier))
                    {
                        i = afterModifier;
                        continue;
                    }

                    if (SubPipelineFunctions.Contains(t))
                    {
                        i++;
                        if (i < tokens.Count && tokens[i] == "(") { depth++; i++; }
                        continue;   // the inner expression is the source
                    }

                    if (RowGenerators.Contains(t))
                    {
                        expectSource = false;
                        i++;
                        continue;
                    }

                    // A real source reference: a let-defined name, an allow-listed table, or a
                    // rejection. Note there is no "looks like a table" test - anything here is one.
                    if (!letNames.Contains(t))
                    {
                        var canonical = AllowedTables.FirstOrDefault(
                            a => string.Equals(a, t, StringComparison.OrdinalIgnoreCase));
                        if (canonical is null)
                        {
                            if (!offList.Contains(t)) offList.Add(t);
                        }
                        else if (!sources.Contains(canonical))
                        {
                            sources.Add(canonical);
                        }
                    }
                    i++;
                    if (i < tokens.Count && tokens[i] == "*")   // 'union SI_*'
                    {
                        reasons.Add(wildcardReason);
                        i++;
                    }
                    expectSource = false;
                    continue;
                }

                // A number or punctuation where a table was expected - reads nothing.
                expectSource = false;
                i++;
                continue;
            }

            // Not a source position: the only thing still interesting is a sub-pipeline nested
            // inside an expression, e.g. 'extend x = toscalar(SigninLogs | count)'.
            if (IsIdent(t) && SubPipelineFunctions.Contains(t)
                && i + 1 < tokens.Count && tokens[i + 1] == "(")
            {
                depth++;
                expectSource = true;
                i += 2;
                continue;
            }

            i++;
        }
    }

    /// <summary>
    /// Match an operator modifier at <paramref name="i"/> - <c>ident[.ident]* = value</c> - and
    /// report the index just past it. Used so 'join kind=leftanti _before' still validates
    /// '_before' as the operand rather than 'kind'.
    /// </summary>
    private static bool TrySkipModifier(List<string> tokens, int i, out int next)
    {
        next = i;
        var j = i + 1;
        while (j + 1 < tokens.Count && tokens[j] == "." && IsIdent(tokens[j + 1])) j += 2;
        if (j >= tokens.Count || tokens[j] != "=") return false;
        j++;                                   // '='
        if (j < tokens.Count) j++;             // the value
        next = j;
        return true;
    }
}
