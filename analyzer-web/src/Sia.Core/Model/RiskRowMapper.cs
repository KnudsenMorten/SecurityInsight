using Sia.Core.Kql;

namespace Sia.Core.Model;

/// <summary>
/// Maps a tabular KQL result (column names + a row of cell values) into a <see cref="RiskRow"/>
/// using the REAL SI RA-Summary schema. Shared by the live Log Analytics data source and the
/// AnalyzerService grounding path so column resolution + the RiskFactor_*_Detailed-over-numeric
/// preference live in ONE place (and are unit-testable without Azure).
///
/// RiskFactor mapping (engine reality): the plain-language driver text lives in
/// RiskFactor_*_Detailed; the bare RiskFactor_* columns are numeric factors. We surface the
/// _Detailed text to humans; only if it is absent/blank do we fall back to the numeric column
/// (rendered as a string) so a row is never left with an empty "why".
/// </summary>
public static class RiskRowMapper
{
    public static RiskRow FromCells(IReadOnlyList<string> columns, IReadOnlyList<object?> cells)
    {
        int Idx(string name)
        {
            for (var i = 0; i < columns.Count; i++)
            {
                if (string.Equals(columns[i], name, StringComparison.OrdinalIgnoreCase)) return i;
            }
            return -1;
        }

        string Detail(string detailedCol, string numericCol)
        {
            var text = S(cells, Idx(detailedCol));
            if (!string.IsNullOrWhiteSpace(text)) return text;
            // Fall back to the numeric factor only if it carries signal (> 0); a bare "0"
            // is noise, not a human-readable reason.
            var num = S(cells, Idx(numericCol));
            return string.IsNullOrWhiteSpace(num) || num == "0" ? "" : num;
        }

        return new RiskRow
        {
            SecurityDomain         = S(cells, Idx(SiTables.Cols.SecurityDomain)),
            ConfigurationName      = S(cells, Idx(SiTables.Cols.ConfigurationName)),
            ConfigurationId        = S(cells, Idx(SiTables.Cols.ConfigurationId)),
            CriticalityTier        = I(cells, Idx(SiTables.Cols.CriticalityTier)),
            CriticalityTierLevel   = S(cells, Idx(SiTables.Cols.CriticalityTierLevel)),
            SecuritySeverity       = S(cells, Idx(SiTables.Cols.SecuritySeverity)),
            RiskScoreTotal         = D(cells, Idx(SiTables.Cols.RiskScoreTotal)),
            RiskScoreTotalWeighted = D(cells, Idx(SiTables.Cols.RiskScoreTotalWeighted)),
            RiskFactorConsequence  = Detail(SiTables.Cols.RiskFactorConsequenceDetailed, SiTables.Cols.RiskFactorConsequence),
            RiskFactorProbability  = Detail(SiTables.Cols.RiskFactorProbabilityDetailed, SiTables.Cols.RiskFactorProbability),
            CollectionTime         = T(cells, Idx(SiTables.Cols.CollectionTime)),
        };
    }

    private static string S(IReadOnlyList<object?> r, int i) => i >= 0 && i < r.Count ? r[i]?.ToString() ?? "" : "";
    private static int I(IReadOnlyList<object?> r, int i) =>
        i >= 0 && i < r.Count && int.TryParse(r[i]?.ToString(), out var v) ? v : 0;
    private static double D(IReadOnlyList<object?> r, int i) =>
        i >= 0 && i < r.Count &&
        double.TryParse(r[i]?.ToString(), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : 0;
    private static DateTimeOffset T(IReadOnlyList<object?> r, int i) =>
        i >= 0 && i < r.Count && DateTimeOffset.TryParse(r[i]?.ToString(), out var v) ? v : DateTimeOffset.MinValue;
}
