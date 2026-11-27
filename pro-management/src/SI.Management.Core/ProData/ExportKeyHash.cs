namespace SI.Management.Core.ProData;

/// <summary>
/// #1418 (a)(b) the keys of every row an export reads, in one value: how many rows, and the sum of each key's 64-bit hash
/// (the first 8 bytes of SHA-256 over the key as text). Order-free and held in SQL Server -- no key is read into the web app.
/// Two reads that agree hold the same keys (a row added while another is removed changes the sum, never only the count).
/// </summary>
public sealed record ExportKeyHash(long Rows, string Sum)
{
    /// The value of one answer row (<see cref="ExportKeyHashSql.Columns"/>); null = no row.
    public static ExportKeyHash? Of(IReadOnlyDictionary<string, object?>? row)
    {
        if (row is null) return null;
        var n = row.TryGetValue("KeyRows", out var r) && r is not null and not DBNull ? Convert.ToInt64(r, System.Globalization.CultureInfo.InvariantCulture) : 0L;
        var s = row.TryGetValue("KeyHash", out var h) && h is not null and not DBNull ? Convert.ToString(h, System.Globalization.CultureInfo.InvariantCulture) ?? "" : "";
        return new ExportKeyHash(n, s);
    }
}

/// <summary>#1418 (a)(b) the SELECT list of a key-hash read over one key expression (a NULL key is not counted in the sum).</summary>
public static class ExportKeyHashSql
{
    public static string Columns(string keyExpression) =>
        "COUNT_BIG(*) AS KeyRows, CONVERT(nvarchar(64), SUM(CONVERT(decimal(38, 0), CONVERT(bigint, SUBSTRING(HASHBYTES('SHA2_256', CONVERT(nvarchar(4000), "
        + keyExpression + ")), 1, 8))))) AS KeyHash";
}
