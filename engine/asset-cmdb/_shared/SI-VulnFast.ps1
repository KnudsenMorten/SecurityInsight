#Requires -Version 5.1
<#
    SI v3 -- THE VULNERABILITY STEP'S PER-FINDING WORK, COMPILED (2026-11-16, the step's speed).

    A large install's two page passes cost ~0.6 ms per finding (862,707 findings: 7,622 s and 12,338 s), and ~85 % of a page
    pass was PowerShell's own cost per operation -- a scriptblock call per field read, a hashtable per row, a pipeline over a
    page's whole desired set -- not SQL. The work that runs once PER FINDING is done here by a small C# helper, compiled once
    per process with Add-Type (.NET only: no module, no package), exactly as the lean rows are (SI-VulnSync.ps1,
    Get-SIVulnLeanType). The PowerShell functions keep their names, parameters and outputs; their bodies call the helper.

    WHAT THE HELPER DOES -- and the rule that keeps every result the SAME as before:
      * it reads a row's fields, copies rows, builds the desired entries and filters a page's lists the way PowerShell does
        (a dictionary's entry, else the object's property; [string] by PowerShell's own conversion, LanguagePrimitives; truth
        by LanguagePrimitives.IsTrue; the same dictionary types with the same comparers, filled in the same order);
      * every DECISION over a value stays in PowerShell: the finding key (Get-SIVulnFindingKey), the fields of a row's
        multi-value columns (Get-SIVulnRowNames and the rules over them), the finding type (Get-SIVulnFindingType), the
        affected software and the CI key (Get-SICiKey) are the PowerShell functions themselves, called ONCE PER DISTINCT
        INPUT from the helper's memo (each is a pure function of its input -- the memo the step already had, #850);
      * a shape the helper does not handle exactly (a null element where the old pipeline's handling of it is not certain,
        a value that is not text where text is compared, a set that is not a HashSet) answers $null, and the PowerShell
        body runs as before.
    Where the helper cannot be built (Windows PowerShell, application control blocking the compiler) or
    $global:SI_VulnFastOff is set, every function runs its PowerShell body exactly as before.
    Proof: tests\pester\SIv3-VulnFastSame.Tests.ps1 (each function, old body vs new, deep equality) and
    SIv3-VulnFastPagesSame.Tests.ps1 (the release before vs this one on real SQL, run after run).
    This file ships in both editions: SI-VulnDesired.ps1 (the free data sync loads it) loads it.
#>

function Get-SIVulnFastSource {
    # C# 5 (Windows PowerShell's compiler reads it too, though only pwsh builds it). The namespace is named after a hash of
    # this text (Get-SIVulnFastType), so a changed helper is a new type, never the one an earlier load left in the process.
    @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Management.Automation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace SecurityInsight.VulnFast.@@NS@@ {
    public static class Fast {
        // ---- PowerShell's own semantics, one value at a time -------------------------------------------------------------
        // the object PowerShell's -is and [string] look at (a PSObject's base, unless it is a PSCustomObject)
        public static object Base(object v) {
            PSObject p = v as PSObject;
            if (p != null && !(p.BaseObject is PSCustomObject)) return p.BaseObject;
            return v;
        }
        // [string]$v
        public static string Str(object v) {
            if (v == null) return "";
            string s = v as string; if (s != null) return s;
            PSObject p = v as PSObject;
            if (p != null) { s = p.BaseObject as string; if (s != null) return s; }
            object r = LanguagePrimitives.ConvertTo(v, typeof(string), CultureInfo.InvariantCulture);
            return r == null ? "" : (string)r;
        }
        // an item PowerShell reads one member of as $_.Name (null, a dictionary, an object -- never a list, whose member read
        // would be every element's)
        static bool Plain(object x) { object b = Base(x); return x == null || b is string || b is IDictionary || !(b is IEnumerable); }
        static bool AllPlain(object[] items) { if (items != null) foreach (object x in items) if (!Plain(x)) return false; return true; }
        // $v as a condition
        public static bool IsTrue(object v) { return LanguagePrimitives.IsTrue(v); }
        // $o.$n (a dictionary's entry when it has one, else the object's property, else $null)
        public static object Member(object o, string n) {
            if (o == null) return null;
            IDictionary d = Base(o) as IDictionary;
            if (d != null && d.Contains(n)) return d[n];
            PSPropertyInfo pi = PSObject.AsPSObject(o).Properties[n];
            return pi == null ? null : pi.Value;
        }
        // ConvertTo-SIVulnDesired's $val: a dictionary's $r[$n], else the property's value when the object has it, else $null
        static object Val(IDictionary d, PSObject p, string n) {
            if (d != null) return d[n];
            PSPropertyInfo pi = p.Properties[n];
            return pi == null ? null : pi.Value;
        }
        // the memo key of ConvertTo-SIVulnDesired (#850): exact text values in order; null when a value is not text
        static string MemoKey(StringBuilder sb, char kind, object[] vals) {
            sb.Clear(); sb.Append(kind).Append('|');
            for (int i = 0; i < vals.Length; i++) {
                object x = vals[i];
                if (x == null) { sb.Append("~;"); continue; }
                string s = Base(x) as string;
                if (s == null) return null;
                sb.Append(s.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(s);
            }
            return sb.ToString();
        }
        static PSObject ToCustomObject(OrderedDictionary h) {
            PSObject o = new PSObject();
            foreach (DictionaryEntry e in h) o.Properties.Add(new PSNoteProperty((string)e.Key, e.Value));
            return o;
        }

        // ---- one lean row maker (New-SIVulnRowMaker's object) and ConvertTo-SIVulnRow over it --------------------------------
        sealed class Maker {
            string[] names; Type t; ConstructorInfo ctor; MethodInfo intern; object pool;
            public Maker(object mk) {
                PSObject p = PSObject.AsPSObject(mk);
                names = (string[])LanguagePrimitives.ConvertTo(p.Properties["Names"].Value, typeof(string[]), CultureInfo.InvariantCulture);
                t = Base(p.Properties["Type"].Value) as Type;
                Type pt = Base(p.Properties["PoolType"].Value) as Type;
                pool = Base(p.Properties["Pool"].Value);
                if (t != null) ctor = t.GetConstructor(new Type[] { typeof(object[]) });
                if (pt != null) intern = pt.GetMethod("Intern");
            }
            public object Make(object[] vals) {
                if (vals == null) vals = new object[0];
                if (t != null && vals.Length == names.Length) {
                    try {
                        if (intern != null) vals = (object[])intern.Invoke(null, new object[] { pool, vals });
                        if (ctor != null) return ctor.Invoke(new object[] { vals });
                    } catch { }
                }
                PSObject o = new PSObject();
                for (int i = 0; i < names.Length; i++) o.Properties.Add(new PSNoteProperty(names[i], i < vals.Length ? vals[i] : null));
                return o;
            }
        }

        // ---- ConvertTo-SIVulnKeySpaceRows -----------------------------------------------------------------------------------
        // ciKey: [string](Get-SICiKey -AssetId $a -KeyMap $KeyMap).Key, once per distinct asset id; newMaker: New-SIVulnRowMaker
        // -Names, once per distinct property list ($null: no lean rows -- PSCustomObjects)
        public static object[] KeySpaceRows(object[] rows, Func<string, string> ciKey, Func<string[], object> newMaker) {
            List<object> output = new List<object>();
            if (rows == null) return output.ToArray();
            Dictionary<string, string> keys = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, Maker> makers = new Dictionary<string, Maker>(StringComparer.OrdinalIgnoreCase);
            foreach (object r in rows) {
                if (r == null) continue;
                OrderedDictionary h = new OrderedDictionary(StringComparer.OrdinalIgnoreCase);
                IDictionary d = Base(r) as IDictionary;
                if (d != null) { foreach (object k in new ArrayList(d.Keys)) h[Str(k)] = d[k]; }
                else { foreach (PSPropertyInfo p in PSObject.AsPSObject(r).Properties) h[p.Name] = p.Value; }
                string aid = Str(h["AssetId"]);
                h["SI_AssetId"] = aid;
                string key;
                if (!keys.TryGetValue(aid, out key)) { key = ciKey(aid) ?? ""; keys[aid] = key; }
                h["AssetId"] = key;
                if (newMaker == null) { output.Add(ToCustomObject(h)); continue; }
                string[] names = new string[h.Count]; h.Keys.CopyTo(names, 0);
                string mk = string.Join("\n", names);
                Maker m;
                if (!makers.TryGetValue(mk, out m)) { m = new Maker(newMaker(names)); makers[mk] = m; }
                object[] vals = new object[h.Count]; h.Values.CopyTo(vals, 0);
                output.Add(m.Make(vals));
            }
            return output.ToArray();
        }

        // ---- ConvertTo-SIVulnDesired ----------------------------------------------------------------------------------------
        static readonly string[] FieldCols = { "Reports", "ReportName", "Domains", "SecurityDomain", "Components", "si_component", "SubCis", "si_servicenow_subci", "OsFamilies", "si_os_family", "PatchCycles", "si_patch_cycle" };
        // counts: [0] without an asset id, [1] without a finding id, [2] bookkeeping
        public static object[] Desired(object[] rows, bool hasKeyMap, Func<string, string> findingKey, Func<object[], object> derive,
                                       Func<string, string, string, string> findingType, Func<object, object> affected, Func<string, string> ciKey, int[] counts) {
            List<object> output = new List<object>();
            int noId = 0, noFinding = 0, bookkeeping = 0;
            Dictionary<string, string> kMemo = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, object> fMemo = new Dictionary<string, object>(StringComparer.Ordinal);
            Dictionary<string, string> tMemo = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, object[]> aMemo = new Dictionary<string, object[]>(StringComparer.Ordinal);
            Dictionary<string, string> cMemo = new Dictionary<string, string>(StringComparer.Ordinal);
            StringBuilder sb = new StringBuilder();
            if (rows != null) foreach (object r in rows) {
                if (r == null) continue;
                IDictionary d = Base(r) as IDictionary;
                PSObject p = d == null ? PSObject.AsPSObject(r) : null;
                if (string.IsNullOrWhiteSpace(Str(Val(d, p, "AssetId")))) { noId++; continue; }
                string cidText = Str(Val(d, p, "Cve"));
                string key;
                if (!kMemo.TryGetValue(cidText, out key)) { key = findingKey(cidText) ?? ""; kMemo[cidText] = key; }
                if (key.Length == 0) { noFinding++; continue; }
                object[] raw = new object[FieldCols.Length];
                for (int i = 0; i < raw.Length; i++) raw[i] = Val(d, p, FieldCols[i]);
                string mk = MemoKey(sb, 'F', raw);
                object fld = null;
                if (mk == null || !fMemo.TryGetValue(mk, out fld)) { fld = Base(derive(raw)); if (mk != null) fMemo[mk] = fld; }
                if (IsTrue(Member(fld, "Reports")) && !IsTrue(Member(fld, "Real"))) { bookkeeping++; continue; }
                object domain = Member(fld, "Domain");
                object report = Member(fld, "Report");
                string aid = Str(Val(d, p, "SI_AssetId"));
                string corr = Str(Val(d, p, "AssetId"));
                if (aid.Length == 0) {
                    aid = corr;
                    if (hasKeyMap) { string c; if (!cMemo.TryGetValue(aid, out c)) { c = ciKey(aid) ?? ""; cMemo[aid] = c; } corr = c; }
                }
                string title = Str(Val(d, p, "Title")).Trim(); if (title.Length > 400) title = title.Substring(0, 400);
                string tk = MemoKey(sb, 'T', new object[] { key, domain, report });
                string ftype;
                if (tk == null || !tMemo.TryGetValue(tk, out ftype)) { ftype = findingType(key, Str(domain), Str(report)); if (tk != null) tMemo[tk] = ftype; }
                Hashtable e = new Hashtable(15, StringComparer.OrdinalIgnoreCase);
                e.Add("CorrelationId", corr); e.Add("AssetId", aid); e.Add("Cve", key); e.Add("Severity", Str(Val(d, p, "Severity")));
                e.Add("AssetName", Str(Val(d, p, "AssetName"))); e.Add("CiSysId", ""); e.Add("RiskScore", Str(Val(d, p, "RiskScore")));
                e.Add("FindingType", ftype); e.Add("Title", title); e.Add("Report", report); e.Add("Domain", domain);
                e.Add("Component", Member(fld, "Component")); e.Add("SubCi", Member(fld, "SubCi")); e.Add("OsFamily", Member(fld, "OsFamily")); e.Add("PatchCycle", Member(fld, "PatchCycle"));
                object affv = Val(d, p, "F_si_affected_product");
                if (affv != null) {
                    string ak = MemoKey(sb, 'A', new object[] { affv });
                    object[] aff = null;
                    if (ak == null || !aMemo.TryGetValue(ak, out aff)) { aff = (object[])Base(affected(affv)); if (ak != null) aMemo[ak] = aff; }
                    e["Affected"] = (object[])aff.Clone();
                }
                output.Add(e);
            }
            counts[0] = noId; counts[1] = noFinding; counts[2] = bookkeeping;
            return output.ToArray();
        }

        // ---- Resolve-SIVulnDesiredAlias (dictionary rows; anything else: null, the PowerShell body runs) -----------------------
        sealed class Slot { public object Row; public bool Alias; public Slot(object r, bool a) { Row = r; Alias = a; } }
        public static object[] DesiredAlias(object[] desired, Hashtable alias, int[] counts) {
            if (desired == null) desired = new object[0];
            foreach (object x in desired) {
                if (x == null) continue;
                IDictionary dx = Base(x) as IDictionary;
                if (dx == null || dx.Contains("Keys")) return null;
            }
            int resolved = 0, merged = 0;
            OrderedDictionary byKey = new OrderedDictionary(StringComparer.OrdinalIgnoreCase);
            foreach (object d0 in desired) {
                if (d0 == null) continue;
                object d = d0;
                IDictionary dd = (IDictionary)Base(d0);
                string id = Str(dd["CorrelationId"]).Trim();
                bool wasAlias = false;
                if (id.Length > 0 && alias != null && alias.Count > 0 && alias.ContainsKey(id.ToLowerInvariant())) {
                    string now = Str(alias[id.ToLowerInvariant()]);
                    if (now.Length > 0 && !string.Equals(now, id, StringComparison.OrdinalIgnoreCase)) {
                        Hashtable c = new Hashtable(0, StringComparer.OrdinalIgnoreCase);
                        foreach (object k in new ArrayList(dd.Keys)) c[k] = dd[k];
                        c["CorrelationId"] = now;
                        d = c; dd = c; id = now; wasAlias = true; resolved++;
                    }
                }
                string bk = id.ToLowerInvariant() + "|" + Str(dd["Cve"]).Trim().ToUpperInvariant();
                if (id.Length == 0) bk = "#" + byKey.Count.ToString(CultureInfo.InvariantCulture);
                if (!byKey.Contains(bk)) { byKey[bk] = new Slot(d, wasAlias); continue; }
                merged++;
                if (((Slot)byKey[bk]).Alias && !wasAlias) byKey[bk] = new Slot(d, false);
            }
            List<object> output = new List<object>(byKey.Count);
            foreach (object s in byKey.Values) output.Add(((Slot)s).Row);
            counts[0] = resolved; counts[1] = merged;
            return output.ToArray();
        }

        // ---- a page's lists (the vulnerability step's pages) ---------------------------------------------------------------------------
        // @($items | Where-Object { [$_ -and] [-not] $set.Contains(([string]$_.CorrelationId).Trim()) }) -- null: not handled here
        public static object[] SelectByKey(object[] items, object set, bool keepIn, bool truthy) {
            HashSet<string> hs = set as HashSet<string>;
            if (hs == null || !AllPlain(items)) return null;
            if (items == null) items = new object[0];
            if (!truthy) foreach (object x in items) if (x == null) return null;
            List<object> output = new List<object>(items.Length);
            foreach (object x in items) {
                if (truthy && !IsTrue(x)) continue;
                if (hs.Contains(Str(Member(x, "CorrelationId")).Trim()) == keepIn) output.Add(x);
            }
            return output.ToArray();
        }
        // @($items | Where-Object { $set.Contains(([string]$_.CorrelationId).Trim()) }).Count -- -1: not handled here
        public static long CountByKey(object[] items, object set) {
            HashSet<string> hs = set as HashSet<string>;
            if (hs == null || !AllPlain(items)) return -1;
            if (items == null) return 0;
            long n = 0;
            foreach (object x in items) { if (x == null) return -1; if (hs.Contains(Str(Member(x, "CorrelationId")).Trim())) n++; }
            return n;
        }
        // @($items | Where-Object { $_.State -notmatch '(?i)^closed' }).Count -- -1: not handled here
        static readonly Regex Closed = new Regex("(?i)^closed", RegexOptions.IgnoreCase);
        public static long CountNotClosed(object[] items) {
            if (items == null) return 0;
            if (!AllPlain(items)) return -1;
            long n = 0;
            foreach (object x in items) {
                if (x == null) return -1;
                object v = Member(x, "State");
                if (v == null) { n++; continue; }
                string s = Base(v) as string;
                if (s == null) return -1;
                if (!Closed.IsMatch(s)) n++;
            }
            return n;
        }
        // Resolve-SIVulnAssetId -Id $id -Alias $alias
        public static string ResolveAssetId(string id, Hashtable alias) {
            if (string.IsNullOrWhiteSpace(id) || alias == null || alias.Count == 0) return id;
            string k = id.Trim().ToLowerInvariant();
            if (alias.ContainsKey(k)) return Str(alias[k]);
            return id;
        }
        // @(@($desired | ForEach-Object { $_.CorrelationId }) + @($actual | ForEach-Object { Resolve-SIVulnAssetId -Id ([string]$_.CorrelationId) -Alias $alias }) | Where-Object { $_ } | Select-Object -Unique)
        // -- null: not handled here (a CorrelationId that is not text, a null element)
        public static object[] PageIds(object[] desired, object[] actual, Hashtable alias) {
            if (!AllPlain(desired) || !AllPlain(actual)) return null;
            List<string> all = new List<string>();
            if (desired != null) foreach (object d in desired) {
                if (d == null) return null;
                object v = Member(d, "CorrelationId");
                if (v == null) continue;
                string s = Base(v) as string;
                if (s == null) return null;
                all.Add(s);
            }
            if (actual != null) foreach (object a in actual) {
                if (a == null) return null;
                all.Add(ResolveAssetId(Str(Member(a, "CorrelationId")), alias));
            }
            return Unique(all);
        }
        // Select-Object -Unique over text: the first of each, compared as PowerShell compares text (culture, case-sensitive)
        static object[] Unique(List<string> all) {
            HashSet<string> seen = new HashSet<string>(StringComparer.Create(CultureInfo.CurrentCulture, false));
            List<object> output = new List<object>();
            foreach (string s in all) { if (string.IsNullOrEmpty(s)) continue; if (seen.Add(s)) output.Add(s); }
            return output.ToArray();
        }
        // @($assets | Where-Object { $_ -and [string]$_.AssetId } | ForEach-Object { [string]$_.AssetId } | Select-Object -Unique)
        public static object[] PresentAssets(object[] assets) {
            if (!AllPlain(assets)) return null;
            List<string> all = new List<string>();
            if (assets != null) foreach (object a in assets) {
                if (!IsTrue(a)) continue;
                string s = Str(Member(a, "AssetId"));
                if (s.Length == 0) continue;
                all.Add(s);
            }
            return Unique(all);
        }
        // the page's own CI keys (#850)
        public static bool AddPageKeys(HashSet<string> pids, object[] desired, object[] actual, object[] assets, Hashtable alias) {
            if (!AllPlain(desired) || !AllPlain(actual) || !AllPlain(assets)) return false;
            if (desired != null) foreach (object d in desired) { object v = Member(d, "CorrelationId"); if (IsTrue(v)) pids.Add(Str(v).Trim()); }
            if (actual != null) foreach (object a in actual) { if (!IsTrue(a)) continue; object v = Member(a, "CorrelationId"); if (IsTrue(v)) pids.Add(ResolveAssetId(Str(v).Trim(), alias)); }
            if (assets != null) foreach (object s in assets) { if (!IsTrue(s)) continue; object v = Member(s, "AssetId"); if (IsTrue(v)) pids.Add(Str(v).Trim()); }
            return true;
        }
    }
}
'@
}

function Get-SIVulnFastType {
    <#
        The compiled helper type, or $null (then every caller runs its PowerShell body, exactly as before). Built once per
        process (pwsh 7; Windows PowerShell keeps the PowerShell bodies, as it keeps PSCustomObject rows). Found by its NAME
        (a hash of the source), so a scope that did not load this file finds it too. -Reason: the build error when it failed.
    #>
    param([switch]$Reason)
    if ($Reason) { return [string]$global:SI_VulnFastError }
    if ($PSVersionTable.PSEdition -ne 'Core' -or $global:SI_VulnFastOff -or $global:SI_VulnFastBroken) { return $null }
    $src = Get-SIVulnFastSource
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($src))) -replace '-', '').Substring(0, 20) } finally { $sha.Dispose() }
    $name = 'SecurityInsight.VulnFast.H' + $h + '.Fast'
    $t = $name -as [type]
    if ($null -ne $t) { return $t }
    try { Add-Type -TypeDefinition $src.Replace('@@NS@@', 'H' + $h) -Language CSharp -ErrorAction Stop }
    catch { $global:SI_VulnFastBroken = $true; $global:SI_VulnFastError = $_.Exception.Message; return $null }
    $name -as [type]
}

# ---- the page's lists (Invoke-SIVulnLoop.ps1): each answers what its PowerShell line answered, as ONE array (never unrolled) --
function Select-SIVulnDesiredByKey {
    <#
        PURE. @($Items | Where-Object { [$_ -and] [-not] $Set.Contains(([string]$_.CorrelationId).Trim()) }) -- -In keeps the
        items whose key IS in the set (else the ones that are not), -Truthy leaves out an item that is $null / empty first.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items = @(), $Set, [switch]$In, [switch]$Truthy)
    $fx = Get-SIVulnFastType
    if ($null -ne $fx) { $r = $fx::SelectByKey([object[]]$Items, $Set, [bool]$In, [bool]$Truthy); if ($null -ne $r) { return , $r } }
    if ($Truthy) {
        if ($In) { return , @($Items | Where-Object { $_ -and $Set.Contains(([string]$_.CorrelationId).Trim()) }) }
        return , @($Items | Where-Object { $_ -and -not $Set.Contains(([string]$_.CorrelationId).Trim()) })
    }
    if ($In) { return , @($Items | Where-Object { $Set.Contains(([string]$_.CorrelationId).Trim()) }) }
    , @($Items | Where-Object { -not $Set.Contains(([string]$_.CorrelationId).Trim()) })
}

function Measure-SIVulnDesiredByKey {
    <# PURE. @($Items | Where-Object { $Set.Contains(([string]$_.CorrelationId).Trim()) }).Count #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items = @(), $Set)
    $fx = Get-SIVulnFastType
    if ($null -ne $fx) { $n = $fx::CountByKey([object[]]$Items, $Set); if ($n -ge 0) { return [int]$n } }
    @($Items | Where-Object { $Set.Contains(([string]$_.CorrelationId).Trim()) }).Count
}

function Measure-SIVulnOpenRecords {
    <# PURE. @($Records | Where-Object { $_.State -notmatch '(?i)^closed' }).Count #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Records = @())
    $fx = Get-SIVulnFastType
    if ($null -ne $fx) { $n = $fx::CountNotClosed([object[]]$Records); if ($n -ge 0) { return [int]$n } }
    @($Records | Where-Object { $_.State -notmatch '(?i)^closed' }).Count
}

function Get-SIVulnPageAssetIds {
    <#
        PURE. The CI keys a plan reads (Get-SIVulnAssetStates -AssetIds): the desired findings' keys, then the records' keys
        as they are NOW (Resolve-SIVulnAssetId) -- non-empty, the first of each:
        @(@($Desired | ForEach-Object { $_.CorrelationId }) + @($Actual | ForEach-Object { Resolve-SIVulnAssetId -Id ([string]$_.CorrelationId) -Alias $Alias }) | Where-Object { $_ } | Select-Object -Unique)
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Desired = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Actual = @(), [hashtable]$Alias)
    $fx = Get-SIVulnFastType
    if ($null -ne $fx) { $r = $fx::PageIds([object[]]$Desired, [object[]]$Actual, $Alias); if ($null -ne $r) { return , $r } }
    , @(@($Desired | ForEach-Object { $_.CorrelationId }) + @($Actual | ForEach-Object { Resolve-SIVulnAssetId -Id ([string]$_.CorrelationId) -Alias $Alias }) | Where-Object { $_ } | Select-Object -Unique)
}

function Get-SIVulnPresentAssetIds {
    <# PURE. The asset ids a snapshot's assets carry, the first of each: @($Assets | Where-Object { $_ -and [string]$_.AssetId } | ForEach-Object { [string]$_.AssetId } | Select-Object -Unique) #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Assets = @())
    $fx = Get-SIVulnFastType
    if ($null -ne $fx) { $r = $fx::PresentAssets([object[]]$Assets); if ($null -ne $r) { return , $r } }
    , @($Assets | Where-Object { $_ -and [string]$_.AssetId } | ForEach-Object { [string]$_.AssetId } | Select-Object -Unique)
}

function Add-SIVulnPageKeys {
    <# PURE (over -Keys). #850 a page's own CI keys into -Keys: its findings' keys, its records' keys as they are NOW, its assets' ids. #>
    param([Parameter(Mandatory)]$Keys, [AllowNull()][AllowEmptyCollection()][object[]]$Desired = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Actual = @(),
          [AllowNull()][AllowEmptyCollection()][object[]]$Assets = @(), [hashtable]$Alias)
    $fx = Get-SIVulnFastType
    if ($null -ne $fx -and $Keys -is [System.Collections.Generic.HashSet[string]]) { if ($fx::AddPageKeys($Keys, [object[]]$Desired, [object[]]$Actual, [object[]]$Assets, $Alias)) { return } }
    foreach ($d in @($Desired)) { if ($d.CorrelationId) { [void]$Keys.Add(([string]$d.CorrelationId).Trim()) } }
    foreach ($a in $Actual) { if ($a -and $a.CorrelationId) { [void]$Keys.Add((Resolve-SIVulnAssetId -Id ([string]$a.CorrelationId).Trim() -Alias $Alias)) } }
    foreach ($sa in $Assets) { if ($sa -and $sa.AssetId) { [void]$Keys.Add(([string]$sa.AssetId).Trim()) } }
}
