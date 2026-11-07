using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// EVERY VIEW IS FAST BY DEFAULT (owner 2026-11-05: "every views must be fast" / "that is default logic" / "fix for all,
// no exceptions, i cannot list them all"). The web app's read statements are fixed texts in its code. This catalog finds
// every one of them by reflection -- a NEW view is in it the moment it is written, nobody keeps a list -- so that:
//   * the plan guard (tests: ViewPlanGuardLocalSqlTests) asks a real SQL Server for each statement's plan and fails when
//     one reads documents (a scan of a table that carries a JSON document, or documents read for more than a page);
//   * the web app names a slow read in its log by the statement's name (DataAccess/SlowReadExecutor.cs).
// =====================================================================================================================

/// One read statement of the web app: where it is written (Type.Member) and its text.
public sealed record ViewStatement(string Name, string Text);

public static class ViewStatements
{
    private static readonly Regex LeadingComments = new(@"\A(?:\s+|--[^\n]*\n?|/\*.*?\*/)*", RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex Spaces = new(@"\s+", RegexOptions.CultureInvariant);

    /// PURE. Whether a text is a whole read statement (SELECT / WITH after leading comments; refused by nothing in
    /// <see cref="SqlGuard"/>; a FROM in it) -- never a fragment that is composed into a longer statement.
    public static bool IsRead(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = LeadingComments.Replace(text, "");
        if (!(t.StartsWith("SELECT", StringComparison.OrdinalIgnoreCase) || t.StartsWith("WITH", StringComparison.OrdinalIgnoreCase))) return false;
        if (t.IndexOf("FROM", StringComparison.OrdinalIgnoreCase) < 0) return false;
        try { SqlGuard.AssertReadOnly(t); } catch (InvalidOperationException) { return false; }
        return true;
    }

    /// PURE. The text as a lookup key: whitespace collapsed, trimmed.
    public static string Key(string text) => Spaces.Replace(text ?? "", " ").Trim();

    /// Every read statement written as a string constant or a static read-only string in the assemblies, once per text.
    public static IReadOnlyList<ViewStatement> From(params Assembly[] assemblies)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<ViewStatement>();
        foreach (var asm in assemblies.Distinct())
        {
            Type?[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }
            foreach (var type in types)
            {
                if (type is null || type.IsDefined(typeof(CompilerGeneratedAttribute), false) || type.ContainsGenericParameters) continue;
                foreach (var f in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly))
                {
                    if (f.FieldType != typeof(string) || !(f.IsLiteral || f.IsInitOnly) || f.IsDefined(typeof(CompilerGeneratedAttribute), false)) continue;
                    string? text;
                    try { text = f.IsLiteral ? f.GetRawConstantValue() as string : f.GetValue(null) as string; }
                    catch (Exception) { continue; }   // a type whose static set-up needs the app: not a statement source
                    if (!IsRead(text) || !seen.Add(Key(text!))) continue;
                    list.Add(new ViewStatement(NameOf(type) + "." + f.Name, text!));
                }
            }
        }
        return list.OrderBy(s => s.Name, StringComparer.Ordinal).ToList();
    }

    private static string NameOf(Type t) => t.DeclaringType is null ? t.Name : NameOf(t.DeclaringType) + "." + t.Name;
}
