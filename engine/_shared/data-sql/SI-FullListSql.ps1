#Requires -Version 5.1
<#
    SecurityInsight -- A LIST STORED CUT TO ITS COLUMN IS READ IN FULL (REQUIREMENTS #1403, review of 3.1.51; owner "data quality
    is key. trust" / "no data drop").

    A finding's affected product / vendor / version lists are stored in NVARCHAR(400) columns, its affected software in
    NVARCHAR(2000), its product scope in NVARCHAR(4000) -- each cut to its column. A reader that names those values (the task
    build, the duplicate check, the recommendation fold, the vulnerable items' product scope) reads them through
    Get-SIDataFullListSql: a value shorter than its column as stored; a value that FILLS its column (DATALENGTH -- trailing
    spaces count, LEN would not) in full from the finding's own document (OPENJSON ... WITH nvarchar(max): never NULL past
    4,000 characters, as JSON_VALUE is); a full value that cannot be read (no document) without its last item, which may be
    cut short -- never a name or a version cut in half.
    PowerShell 5.1. PURE (returns T-SQL text).
#>

function Get-SIDataJsonObjectTestSql {
    <# PURE. The document is a JSON OBJECT: its first character that is not white space (tab, line feed, carriage return, space) is
       '{' and it is JSON -- the same test the derive's one parse makes (SI-DataSql.ps1), so both read the same rows. #>
    param([Parameter(Mandatory)][string]$Json)
    "SUBSTRING($Json, PATINDEX(N'%[^' + CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) + N']%', $Json), 1) = N'{' AND ISJSON($Json) = 1"
}

function Get-SIDataFullListSql {
    <#
        PURE. The T-SQL of one list value read in full.
          -Column   the stored column (e.g. f.AffectedProduct)
          -Bytes    its width in bytes (NVARCHAR(400) = 800): a value of that DATALENGTH is taken as cut
          -Keys     the document's keys that hold the whole value, in order (the first not empty wins)
          -Json     the document (default f.DetailJson); a document that is not a JSON object is no document
          -NullReadsFull  a NULL column is read from the document too (a writer that left a long value NULL)
    #>
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*\.\[?[A-Za-z_][A-Za-z0-9_]*\]?$')][string]$Column,
          [Parameter(Mandatory)][int]$Bytes,
          [Parameter(Mandatory)][ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')][string[]]$Keys,
          [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*\.\[?[A-Za-z_][A-Za-z0-9_]*\]?$')][string]$Json = 'f.DetailJson',
          [switch]$NullReadsFull)
    $with = @(for ($i = 0; $i -lt $Keys.Count; $i++) { "[k$i] nvarchar(max) N'$." + $Keys[$i] + "'" }) -join ', '
    $pick = if ($Keys.Count -eq 1) { 'NULLIF(jx.[k0], N'''')' } else { 'COALESCE(' + (@(for ($i = 0; $i -lt $Keys.Count; $i++) { "NULLIF(jx.[k$i], N'')" }) -join ', ') + ')' }
    $full = "(SELECT TOP (1) $pick FROM OPENJSON(CASE WHEN $(Get-SIDataJsonObjectTestSql $Json) THEN $Json END) WITH ($with) AS jx)"
    $minus = "CASE WHEN CHARINDEX(N';', $Column) > 0 THEN LEFT($Column, DATALENGTH($Column) / 2 - CHARINDEX(N';', REVERSE($Column))) END"
    $short = if ($NullReadsFull) { "$Column IS NOT NULL AND DATALENGTH($Column) < $Bytes" } else { "$Column IS NULL OR DATALENGTH($Column) < $Bytes" }
    "CASE WHEN $short THEN $Column ELSE COALESCE($full, $minus) END"
}

function Get-SIDataFullTextSql {
    <# PURE. #1403 the WHOLE text of one document key (nvarchar(max), never NULL past 4,000 characters); a document that is not a JSON object = NULL. #>
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*$')][string]$Key,
          [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]*\.\[?[A-Za-z_][A-Za-z0-9_]*\]?$')][string]$Json = 'f.DetailJson')
    "(SELECT TOP (1) jx.[v] FROM OPENJSON(CASE WHEN $(Get-SIDataJsonObjectTestSql $Json) THEN $Json END) WITH ([v] nvarchar(max) N'$.$Key') AS jx)"
}
