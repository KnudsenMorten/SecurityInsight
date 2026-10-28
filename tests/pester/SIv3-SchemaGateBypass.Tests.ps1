#Requires -Version 5.1
<#
    THE ADDITIVE-ONLY SCHEMA GATE CANNOT BE WALKED AROUND BY FORMATTING (#128).

    Test-SISchemaIsAdditive scanned ONE LINE at a time, so ordinary SQL formatting defeated it: a
    statement split across lines, DELETE without FROM (optional in T-SQL), a /* */ block comment, a
    bracketed name with a space, and verbs it never listed (DROP VIEW/PROCEDURE/FUNCTION, MERGE). Each
    case below was accepted as additive by the pre-fix gate. The additive controls -- including
    `ON DELETE CASCADE` foreign keys and destructive words inside comments or string literals -- must
    still pass, or the gate teaches people to route around it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
}

Describe 'destructive SQL is refused however it is formatted' {
    It '<Name> is NOT additive' -ForEach @(
        @{ Name = 'UPDATE split across lines';      Sql = "UPDATE dbo.Assets`r`nSET Tier = 0" }
        @{ Name = 'DELETE without FROM';            Sql = 'DELETE dbo.Assets WHERE 1 = 1' }
        @{ Name = 'DELETE TOP';                     Sql = 'DELETE TOP (100) FROM dbo.Assets' }
        @{ Name = 'DROP VIEW';                      Sql = 'DROP VIEW dbo.vAssets' }
        @{ Name = 'DROP PROCEDURE';                 Sql = 'DROP PROCEDURE dbo.usp_Load' }
        @{ Name = 'DROP FUNCTION';                  Sql = 'DROP FUNCTION dbo.fn_Tier' }
        @{ Name = 'MERGE';                          Sql = "MERGE dbo.Assets AS t USING src AS s ON t.Id = s.Id`nWHEN MATCHED THEN DELETE;" }
        @{ Name = 'ALTER COLUMN on a bracketed name with a space'; Sql = 'ALTER TABLE [My Assets] ALTER COLUMN Name nvarchar(10)' }
        @{ Name = 'ALTER COLUMN split across lines'; Sql = "ALTER TABLE dbo.Assets`n    ALTER COLUMN Name nvarchar(10)" }
        @{ Name = 'a destructive line hidden AFTER a block comment'; Sql = "/* harmless */ DROP TABLE dbo.Assets" }
        @{ Name = 'sp_rename via EXECUTE and schema prefix'; Sql = "EXECUTE sys.sp_rename 'dbo.Assets.Name', 'Nm', 'COLUMN'" }
    ) {
        (Test-SISchemaIsAdditive -Sql $Sql).IsAdditive | Should -BeFalse
    }

    It 'the finding reports the line the statement STARTS on' {
        $r = Test-SISchemaIsAdditive -Sql "CREATE TABLE a (x int);`n`nUPDATE a`nSET x = 1;"
        @($r.Findings)[0].Line | Should -Be 3
    }
}

Describe 'additive SQL still passes' {
    It '<Name> IS additive' -ForEach @(
        @{ Name = 'CREATE TABLE';                         Sql = 'CREATE TABLE dbo.New (Id int NOT NULL)' }
        @{ Name = 'ALTER TABLE ADD';                      Sql = 'ALTER TABLE dbo.Assets ADD Owner nvarchar(200) NULL' }
        @{ Name = 'FK with ON DELETE CASCADE';            Sql = 'ALTER TABLE dbo.Child ADD CONSTRAINT FK_C FOREIGN KEY (PId) REFERENCES dbo.P(Id) ON DELETE CASCADE ON UPDATE CASCADE' }
        @{ Name = 'destructive words inside a comment';   Sql = "-- DROP TABLE dbo.Assets`n/* UPDATE x SET y */`nCREATE INDEX IX_A ON dbo.Assets(Name)" }
        @{ Name = 'destructive words inside a string';    Sql = "INSERT INTO dbo.Log (Msg) VALUES ('we never DELETE or DROP TABLE anything')" }
        @{ Name = 'CREATE STATISTICS';                    Sql = 'CREATE STATISTICS st_Name ON dbo.Assets(Name)' }
    ) {
        $r = Test-SISchemaIsAdditive -Sql $Sql
        $r.IsAdditive | Should -BeTrue -Because (@($r.Findings | ForEach-Object { $_.Why }) -join '; ')
    }
}
