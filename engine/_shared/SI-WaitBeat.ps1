#Requires -Version 5.1
<#
    SecurityInsight -- THE NAMED WAIT BEAT (#1310, framework 8.18 "a named wait beat during one external call is allowed",
    Invardia 2026-11-23). One external call (one SQL statement, which has no time limit on purpose) can run for longer than
    15 minutes and write nothing; the run monitor then takes a working step for dead (SUP-2026-00674, a large install 2026-11-22).

    While ONE call runs, a timer (System.Threading.Timer, compiled once per process) beats -- first after -FirstSeconds,
    then every -EverySeconds, never more often than every 5 minutes in production:
      * one line on the console: "[wait] waiting on <what> since <time>Z (<n> min so far) -- one call, still running" --
        it names what it waits on and since when, never a generic "alive";
      * when asked (-ConnectionString / -Execution), this execution's progress mark (cfg.StepProgress LastUtc, the same
        mark Write-SIStepProgress moves -- its phase, done and total are left as they are, so a queue worker's report
        record keeps its counts and only its time moves, as #1274's beat).
    The timer is made when the call starts and disposed when it returns or throws (Stop-SIWaitBeat, in a finally): it never
    outlives its call. It beats only that the call is still running -- the long-run warning (si-flow-1203) still fires on
    the step's time. No server view is read (no sys.dm_exec_requests), no new right.
    Scope-independent (#836): the C# source comes from a FUNCTION, the type is found by its NAME, a compile that failed is
    remembered for the process in $global:SI_WaitBeatOff and said once (the call then runs exactly as without a beat).
    NEVER throws. pwsh 7 and Windows PowerShell 5.1.
#>

function Get-SIWaitBeatSource {
    <# The beat's C# source. A FUNCTION, never a $script: variable (#836). #>
    @'
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Globalization;
using System.Threading;

namespace SecurityInsight.Wait
{
    public sealed class WaitBeat : IDisposable
    {
        private readonly object _gate = new object();
        private Timer _timer;
        private bool _done;
        private readonly Type _connType;
        private readonly string _cs, _token, _markSql, _exec, _job;
        private readonly bool _console;
        public readonly string What;
        public readonly DateTime SinceUtc;
        public int Beats;
        public int Marks;
        public string LastError = "";
        public readonly List<string> Lines = new List<string>();

        public WaitBeat(string what, int firstMs, int everyMs, bool console, Type connType, string connectionString, string token, string markSql, string execution, string job)
        {
            What = what; SinceUtc = DateTime.UtcNow; _console = console;
            _connType = connType; _cs = connectionString; _token = token; _markSql = markSql; _exec = execution; _job = job;
            _timer = new Timer(Fire, null, Math.Max(1, firstMs), Math.Max(1, everyMs));
        }

        public bool Stopped { get { lock (_gate) { return _done && _timer == null; } } }

        private void Fire(object state)
        {
            string line;
            lock (_gate)
            {
                if (_done) return;
                Beats++;
                int min = (int)Math.Floor((DateTime.UtcNow - SinceUtc).TotalMinutes);
                line = string.Format(CultureInfo.InvariantCulture, "[wait] waiting on {0} since {1:HH:mm:ss}Z ({2} min so far) -- one call, still running", What, SinceUtc, min);
                Lines.Add(line);
            }
            if (_console) { try { Console.Out.WriteLine(line); Console.Out.Flush(); } catch { } }
            if (_connType == null || string.IsNullOrEmpty(_cs) || string.IsNullOrEmpty(_exec) || string.IsNullOrEmpty(_markSql)) return;
            try
            {
                using (DbConnection cn = (DbConnection)Activator.CreateInstance(_connType, _cs))
                {
                    if (!string.IsNullOrEmpty(_token)) { var p = _connType.GetProperty("AccessToken"); if (p != null) p.SetValue(cn, _token, null); }
                    cn.Open();
                    using (DbCommand cmd = cn.CreateCommand())
                    {
                        cmd.CommandText = _markSql;
                        cmd.CommandTimeout = 30;   // limit-ok: the beat's own progress mark -- a slow mark is skipped, never the call it beats for
                        DbParameter a = cmd.CreateParameter(); a.ParameterName = "@Execution"; a.Value = _exec; cmd.Parameters.Add(a);
                        DbParameter b = cmd.CreateParameter(); b.ParameterName = "@Job"; b.Value = (object)_job ?? DBNull.Value; cmd.Parameters.Add(b);
                        cmd.ExecuteNonQuery();
                    }
                }
                lock (_gate) { Marks++; }
            }
            catch (Exception e) { lock (_gate) { LastError = e.Message; } }
        }

        public void Dispose()
        {
            Timer t;
            lock (_gate) { _done = true; t = _timer; }
            if (t != null)
            {
                // waits for a beat under way (its mark), so nothing of it runs after the call has returned
                using (var w = new ManualResetEvent(false)) { if (t.Dispose(w)) { w.WaitOne(15000); } }
            }
            lock (_gate) { _timer = null; }
        }
    }
}
'@
}

function Get-SIWaitBeatType {
    <# The compiled beat ([SecurityInsight.Wait.WaitBeat]), built once per process; $null where it cannot be (said once). #>
    if ($global:SI_WaitBeatOff) { return $null }
    $t = 'SecurityInsight.Wait.WaitBeat' -as [type]
    if ($null -ne $t) { return $t }
    try {
        Add-Type -TypeDefinition (Get-SIWaitBeatSource) -Language CSharp -ErrorAction Stop
        $t = 'SecurityInsight.Wait.WaitBeat' -as [type]
        if ($null -eq $t) { throw 'the compiled type was not found' }
        return $t
    } catch {
        $why = ((([string]$_.Exception.Message) -split "`n")[0]).Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
        $global:SI_WaitBeatOff = $why
        try { Write-Host ('       a long database call will not say it is still running in this process (its wait beat could not be built: {0}) -- the work runs as before' -f $why) } catch { }
        return $null
    }
}

function Get-SIWaitBeatWhat {
    <# PURE. What one SQL call waits on, in words: the database, the mode and the start of the statement (white space
       folded, at most 120 characters). A statement's text carries no values -- they travel as parameters. #>
    param([string]$Database, [string]$Mode, [string]$Sql)
    $m = if ($Mode -eq 'session') { 'a session of several statements' } elseif ($Mode) { $Mode } else { 'nonquery' }
    $s = [regex]::Replace(([string]$Sql -replace '(?m)--[^\r\n]*$', ''), '\s+', ' ').Trim()
    $s = [regex]::Replace($s, '^(SET NOCOUNT ON;\s*)', '')
    if ($s.Length -gt 120) { $s = $s.Substring(0, 117) + '...' }
    if ($s) { return ('the database {0} ({1}): {2}' -f $Database, $m, $s) }
    'the database {0} ({1})' -f $Database, $m
}

function Start-SIWaitBeat {
    <#
        The beat for ONE call (see the header). -What: what the call waits on (Get-SIWaitBeatWhat for SQL). -FirstSeconds /
        -EverySeconds: at least 300 each in production (8.18: at most every 5 minutes); -EveryMs / -FirstMs for tests.
        The mark: -ConnectionString, -AccessToken, -ConnectionType (default System.Data.SqlClient.SqlConnection), -Execution
        (default this container job's execution), -Job; none of them = lines only. -Quiet: no console line (tests).
        Returns the beat, or $null when it cannot be made (the call runs as without it). NEVER throws.
    #>
    param([Parameter(Mandatory)][string]$What, [int]$FirstSeconds = 300, [int]$EverySeconds = 300, [int]$FirstMs = 0, [int]$EveryMs = 0,
          [string]$ConnectionString, [string]$AccessToken, [type]$ConnectionType, [string]$Execution = [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME,
          [string]$Job = [string]$env:CONTAINER_APP_JOB_NAME, [switch]$Quiet)
    try {
        $t = Get-SIWaitBeatType
        if ($null -eq $t) { return $null }
        if ($FirstMs -le 0) { $FirstMs = [Math]::Max(300, $FirstSeconds) * 1000 }
        if ($EveryMs -le 0) { $EveryMs = [Math]::Max(300, $EverySeconds) * 1000 }
        $markSql = ''; $ct = $null
        if ($ConnectionString -and "$Execution".Trim()) {
            $ct = $(if ($ConnectionType) { $ConnectionType } else { 'System.Data.SqlClient.SqlConnection' -as [type] })
            if (Get-Command -Name Get-SIStepProgressMarkSql -ErrorAction SilentlyContinue) { $markSql = Get-SIStepProgressMarkSql }
            if (-not "$Job".Trim()) { $Job = ([string]$Execution -replace '-[a-z0-9]+$', '') }
        }
        return (New-Object -TypeName $t.FullName -ArgumentList @($What, [int]$FirstMs, [int]$EveryMs, (-not [bool]$Quiet), $ct, [string]$ConnectionString, [string]$AccessToken, [string]$markSql, [string]$Execution, [string]$Job))
    } catch { return $null }
}

function Stop-SIWaitBeat {
    <# Ends a beat (Start-SIWaitBeat) when its call has returned or thrown: the timer is disposed and a beat under way is
       waited for. Returns @{ Beats; Marks; Lines; Stopped; LastError } or $null (nothing to end). NEVER throws. #>
    param($Beat)
    if ($null -eq $Beat) { return $null }
    try { $Beat.Dispose() } catch { }
    try { [pscustomobject]@{ Beats = [int]$Beat.Beats; Marks = [int]$Beat.Marks; Lines = @($Beat.Lines); Stopped = [bool]$Beat.Stopped; LastError = [string]$Beat.LastError } } catch { $null }
}
