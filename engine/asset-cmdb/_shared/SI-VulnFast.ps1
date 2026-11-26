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

        // =================================================================================================================
        // #1320 THE PAGE FOLD (Add-SIVulnSnapshotRows / Complete-SIVulnSnapshot) AND THE COMPARE OF WHAT CHANGED
        // =================================================================================================================
        // ---- the fold reads a row as PowerShell does: a table of name -> text ('' for a missing / null / DBNull value) --------
        // a value whose text PowerShell would build from its parts (a list) is not read here
        static bool PlainValue(object x) { if (x == null) return true; object b = Base(x); return b == null || b is string || b is DBNull || !(b is IEnumerable); }
        static string Text(object x) { if (x == null) return ""; object b = Base(x); if (b == null || b is DBNull) return ""; return Str(x); }
        // a text a PowerShell -eq / -ne '' could read as empty although it is not (characters a culture compare ignores): such a
        // page is folded by PowerShell itself
        static bool OddEmpty(string s) {
            if (s == null || s.Length == 0) return false;
            bool ascii = true;
            foreach (char c in s) { if (c < ' ' || c > '~') { ascii = false; break; } }
            if (ascii) return false;
            return string.Compare(s, "", CultureInfo.InvariantCulture, CompareOptions.IgnoreCase) == 0 || string.Compare(s, "", CultureInfo.CurrentCulture, CompareOptions.IgnoreCase) == 0;
        }
        // $num of Add-SIVulnSnapshotRows
        static bool NumOf(string s, out double d) { d = 0; string t = s.Trim(); return t.Length > 0 && double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out d); }
        // $int: [int][Math]::Truncate($d) -- ok = false where PowerShell's [int] would throw (out of range, not a number)
        static object TierOf(string s, out bool ok) {
            ok = true; double d;
            if (!NumOf(s, out d)) return null;
            double t = Math.Truncate(d);
            if (double.IsNaN(t) || t < int.MinValue || t > int.MaxValue) { ok = false; return null; }
            return (int)t;
        }
        static string Cell(Hashtable r, string n) { object v = r[n]; return v == null ? "" : (string)v; }
        // the row table ($r): a copy of -template (PowerShell's own @{}, so the same key comparer), or null when the row is not
        // read here (a key that is not text, a list value, a text a culture compare reads as empty)
        static Hashtable RowTable(object r0, Hashtable template) {
            Hashtable r = (Hashtable)template.Clone();
            IDictionary d = Base(r0) as IDictionary;
            if (d != null) {
                IDictionaryEnumerator en = d.GetEnumerator();
                while (en.MoveNext()) {
                    string k = en.Key as string; object v = en.Value;
                    if (k == null || !PlainValue(v)) return null;
                    string t = Text(v); if (OddEmpty(t)) return null;
                    r[k] = t;
                }
                return r;
            }
            foreach (PSPropertyInfo p in PSObject.AsPSObject(r0).Properties) {
                object v; try { v = p.Value; } catch { return null; }
                if (!PlainValue(v)) return null;
                string t = Text(v); if (OddEmpty(t)) return null;
                r[p.Name] = t;
            }
            return r;
        }

        // Add-SIVulnSnapshotRows over the SAME accumulator ($Acc.Groups / Order / Assets / AssetOrder): returns the rows folded,
        // or -1 when the page is not folded here -- then NOTHING of the accumulator was changed and the PowerShell body folds it.
        // MEMORY AND SAFETY (stability review 2026-11-23): pass 1 checks every row and keeps nothing (no table per row); pass 2
        // reads one row at a time into a page-local overlay -- new groups and assets, and a COPY of an existing group or an
        // existing asset's tier before it changes -- inside one try: any error there leaves the accumulator untouched (-1). Only
        // then is the overlay put in (dictionary sets and list adds).
        public static long FoldRows(Dictionary<string, object> groups, List<string> order, Dictionary<string, object> assets, List<string> assetOrder,
                                    object[] rows, string edition, string[] scopeKeys, object[] scopeCols, Hashtable template) {
            if (rows == null) return 0;
            if (scopeKeys == null) scopeKeys = new string[0];
            if (scopeCols == null) scopeCols = new object[0];
            // pass 1: every row read as the fold reads it (nothing kept)
            for (int i = 0; i < rows.Length; i++) {
                if (rows[i] == null) continue;
                if (Base(rows[i]) is DBNull) return -1;
                Hashtable t0 = RowTable(rows[i], template);
                if (t0 == null) return -1;
                bool ok; TierOf(Cell(t0, "CriticalityTier"), out ok);
                if (!ok) return -1;
            }
            string ed = edition + ".";
            long n = 0;
            // the overlay of this page
            Dictionary<string, object> newGroups = new Dictionary<string, object>(StringComparer.Ordinal), copies = new Dictionary<string, object>(StringComparer.Ordinal);
            List<string> newOrder = new List<string>();
            Dictionary<string, object> newAssets = new Dictionary<string, object>(StringComparer.Ordinal), tierOf = new Dictionary<string, object>(StringComparer.Ordinal);
            List<string> newAssetOrder = new List<string>();
            try {
                for (int i = 0; i < rows.Length; i++) {
                    object r0 = rows[i]; if (r0 == null) continue;
                    Hashtable r = RowTable(r0, template);
                    if (r == null) return -1;
                    bool ok; object tier = TierOf(Cell(r, "CriticalityTier"), out ok);
                    if (!ok) return -1;
                    n++;
                    string aid = Cell(r, "AssetId");
                    // the snapshot's assets: every row with an asset id, whatever its finding
                    if (aid.Length != 0) {
                        object a;
                        if (newAssets.TryGetValue(aid, out a)) {
                            if (tier != null) { PSPropertyInfo tp = ((PSObject)a).Properties["Tier"]; if (tp.Value == null || (int)tier < (int)tp.Value) tp.Value = tier; }
                        } else if (assets.TryGetValue(aid, out a)) {
                            if (tier != null) {
                                object cur;
                                if (!tierOf.TryGetValue(aid, out cur)) { PSPropertyInfo tp = PSObject.AsPSObject(a).Properties["Tier"]; cur = tp.Value == null ? null : (object)Convert.ToInt32(Base(tp.Value), CultureInfo.InvariantCulture); }
                                if (cur == null || (int)tier < (int)cur) cur = tier;
                                tierOf[aid] = cur;
                            }
                        } else {
                            PSObject ao = new PSObject(); ao.Properties.Add(new PSNoteProperty("AssetId", aid)); ao.Properties.Add(new PSNoteProperty("Tier", tier));
                            newAssets[aid] = ao; newAssetOrder.Add(aid);
                        }
                    }
                    string cid = Cell(r, "ConfigurationId");
                    if (cid.Length == 0) continue;
                    string sv = Cell(r, "SolutionVersion");
                    if (sv.Length != 0 && !sv.StartsWith(ed, StringComparison.OrdinalIgnoreCase)) continue;
                    string k = aid + "\0" + cid;
                    object go; IDictionary g;
                    if (newGroups.TryGetValue(k, out go) || copies.TryGetValue(k, out go)) g = (IDictionary)go;
                    else if (groups.TryGetValue(k, out go)) {
                        // a group an earlier call made: changed only as a copy, put in at the end
                        Hashtable old = Base(go) as Hashtable; if (old == null) return -1;
                        Hashtable c = (Hashtable)old.Clone();
                        foreach (string ln in new string[] { "Domains", "Components", "SubCis", "OsFamilies", "PatchCycles", "Reports" }) c[ln] = new List<string>((List<string>)Base(old[ln]));
                        Hashtable of = Base(old["F"]) as Hashtable; if (of == null) return -1;
                        Hashtable cf = (Hashtable)of.Clone();
                        foreach (string sf in scopeKeys) cf[sf] = new List<string>((List<string>)Base(of[sf]));
                        c["F"] = cf;
                        copies[k] = c; g = c;
                    } else {
                        Hashtable h = (Hashtable)template.Clone();
                        h["AssetId"] = aid; h["Cve"] = cid; h["Severity"] = ""; h["AssetName"] = ""; h["Title"] = ""; h["RiskScore"] = null; h["Tier"] = null;
                        h["Domains"] = new List<string>(); h["Components"] = new List<string>(); h["SubCis"] = new List<string>();
                        h["OsFamilies"] = new List<string>(); h["PatchCycles"] = new List<string>(); h["Reports"] = new List<string>();
                        Hashtable f = (Hashtable)template.Clone();
                        foreach (string sf in scopeKeys) f[sf] = new List<string>();
                        h["F"] = f;
                        newGroups[k] = h; newOrder.Add(k); g = h;
                    }
                    if (Str(g["Severity"]).Length == 0) g["Severity"] = Cell(r, "SecuritySeverity");
                    if (Str(g["AssetName"]).Length == 0) g["AssetName"] = Cell(r, "AssetName");
                    if (Str(g["Title"]).Length == 0) g["Title"] = Cell(r, "ConfigurationName");
                    double rs;
                    if (NumOf(Cell(r, "RiskScoreTotal"), out rs)) { object cur = g["RiskScore"]; if (cur == null || rs > Convert.ToDouble(Base(cur), CultureInfo.InvariantCulture)) g["RiskScore"] = rs; }
                    if (tier != null) { object cur = g["Tier"]; if (cur == null || (int)tier < Convert.ToInt32(Base(cur), CultureInfo.InvariantCulture)) g["Tier"] = tier; }
                    ((List<string>)Base(g["Domains"])).Add(Cell(r, "SecurityDomain")); ((List<string>)Base(g["Components"])).Add(Cell(r, "si_component"));
                    ((List<string>)Base(g["SubCis"])).Add(Cell(r, "si_servicenow_subci")); ((List<string>)Base(g["OsFamilies"])).Add(Cell(r, "si_os_family"));
                    ((List<string>)Base(g["PatchCycles"])).Add(Cell(r, "si_patch_cycle"));
                    string rep = Cell(r, "AssetDetectedInReportName"); if (rep.Length == 0) rep = Cell(r, "ReportName");
                    ((List<string>)Base(g["Reports"])).Add(rep);
                    // the scope fields: a typed read carries the field already coalesced ('@<field>'); else coalesced here
                    IDictionary fd = (IDictionary)Base(g["F"]);
                    IDictionary d0 = Base(r0) as IDictionary;
                    PSObject p0 = d0 == null ? PSObject.AsPSObject(r0) : null;
                    for (int j = 0; j < scopeKeys.Length; j++) {
                        string sf = scopeKeys[j]; string at = "@" + sf;
                        object pre = null; bool has = false;
                        if (d0 != null) { if (d0.Contains(at)) { has = true; pre = d0[at]; } }
                        else { PSPropertyInfo pp = p0.Properties[at]; if (pp != null) pre = pp.Value; }
                        string v;
                        if (pre != null || has) v = Text(pre);
                        else {
                            v = "";
                            string[] cols = j < scopeCols.Length ? scopeCols[j] as string[] : null;
                            if (cols != null) foreach (string c in cols) { v = Cell(r, c); if (v.Length != 0) break; }
                        }
                        ((List<string>)Base(fd[sf])).Add(v);
                    }
                }
            } catch { return -1; }
            // put in: nothing above touched the accumulator
            foreach (KeyValuePair<string, object> kv in copies) groups[kv.Key] = kv.Value;
            foreach (string k in newOrder) { groups[k] = newGroups[k]; order.Add(k); }
            foreach (KeyValuePair<string, object> kv in tierOf) PSObject.AsPSObject(assets[kv.Key]).Properties["Tier"].Value = kv.Value;
            foreach (string a in newAssetOrder) { assets[a] = newAssets[a]; assetOrder.Add(a); }
            return n;
        }
        // ConvertTo-SIVulnSnapshotSet of one list: a list of plain text (printable ASCII, nothing JSON escapes) with at most one
        // distinct non-blank value is written here ('[]' / '["v"]'); any other list is ConvertTo-SIVulnSnapshotSet's own answer
        // (-setOf, once per distinct list of the call)
        static string SetText(object listObj, Func<object, object> setOf, Dictionary<string, string> memo, StringBuilder sb) {
            List<string> vals = Base(listObj) as List<string>;
            if (vals == null) return Str(setOf(listObj));
            string one = null; bool plain = true, many = false;
            foreach (string v in vals) {
                if (v == null) { plain = false; break; }
                foreach (char c in v) { if (c < ' ' || c > '~' || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' || c == '\'') { plain = false; break; } }
                if (!plain) break;
                if (v.Trim().Length == 0) continue;
                if (one == null) one = v; else if (!string.Equals(one, v, StringComparison.Ordinal)) many = true;
            }
            if (plain && !many) return one == null ? "[]" : "[\"" + one + "\"]";
            sb.Clear(); sb.Append(vals.Count.ToString(CultureInfo.InvariantCulture)).Append('|');
            foreach (string v in vals) { if (v == null) sb.Append("~;"); else sb.Append(v.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(v); }
            string key = sb.ToString(), hit;
            if (!memo.TryGetValue(key, out hit)) { hit = Str(setOf(vals)); memo[key] = hit; }
            return hit;
        }

        // Complete-SIVulnSnapshot over the accumulator: { Rows (one per group, in order), Assets (in order) }; the accumulator
        // is emptied as it is read. -t: the snapshot time already in UTC.
        public static object[] FoldComplete(Dictionary<string, object> groups, List<string> order, Dictionary<string, object> assets, List<string> assetOrder,
                                            string[] scopeKeys, DateTime t, Func<object, object> setOf) {
            if (scopeKeys == null) scopeKeys = new string[0];
            Dictionary<string, string> memo = new Dictionary<string, string>(StringComparer.Ordinal);
            StringBuilder sb = new StringBuilder();
            object[] rowsOut = new object[order.Count];
            for (int i = 0; i < order.Count; i++) {
                IDictionary g = (IDictionary)Base(groups[order[i]]);
                PSObject o = new PSObject();
                o.Properties.Add(new PSNoteProperty("AssetId", g["AssetId"]));
                o.Properties.Add(new PSNoteProperty("Cve", g["Cve"]));
                o.Properties.Add(new PSNoteProperty("SnapshotTime", t));
                o.Properties.Add(new PSNoteProperty("Severity", g["Severity"]));
                o.Properties.Add(new PSNoteProperty("AssetName", g["AssetName"]));
                o.Properties.Add(new PSNoteProperty("Title", g["Title"]));
                object rsv = g["RiskScore"];
                o.Properties.Add(new PSNoteProperty("RiskScore", rsv == null ? "" : Str(rsv)));
                o.Properties.Add(new PSNoteProperty("Tier", g["Tier"]));
                o.Properties.Add(new PSNoteProperty("Domains", SetText(g["Domains"], setOf, memo, sb)));
                o.Properties.Add(new PSNoteProperty("Components", SetText(g["Components"], setOf, memo, sb)));
                o.Properties.Add(new PSNoteProperty("SubCis", SetText(g["SubCis"], setOf, memo, sb)));
                o.Properties.Add(new PSNoteProperty("OsFamilies", SetText(g["OsFamilies"], setOf, memo, sb)));
                o.Properties.Add(new PSNoteProperty("PatchCycles", SetText(g["PatchCycles"], setOf, memo, sb)));
                o.Properties.Add(new PSNoteProperty("Reports", SetText(g["Reports"], setOf, memo, sb)));
                IDictionary fd = (IDictionary)Base(g["F"]);
                foreach (string sf in scopeKeys) o.Properties.Add(new PSNoteProperty("F_" + sf, SetText(fd[sf], setOf, memo, sb)));
                rowsOut[i] = o;
            }
            object[] assetsOut = new object[assetOrder.Count];
            for (int i = 0; i < assetOrder.Count; i++) { object a; assets.TryGetValue(assetOrder[i], out a); assetsOut[i] = a; }
            groups.Clear(); order.Clear(); assets.Clear(); assetOrder.Clear();
            return new object[] { rowsOut, assetsOut };
        }

        // one text per item (every property: its name, the value's type and text) -- what the shadow compares the two folds by
        public static string[] Canon(object[] items) {
            if (items == null) return new string[0];
            string[] o = new string[items.Length];
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < items.Length; i++) {
                object x = items[i];
                if (x == null) { o[i] = "~"; continue; }
                sb.Clear();
                foreach (PSPropertyInfo p in PSObject.AsPSObject(x).Properties) {
                    object v = p.Value; object b = v == null ? null : Base(v);
                    string s = b == null ? "" : (b is DateTime ? ((DateTime)b).ToString("o", CultureInfo.InvariantCulture) + "/" + ((DateTime)b).Kind.ToString() : Str(v));
                    sb.Append(p.Name).Append('=').Append(b == null ? "~" : b.GetType().FullName).Append(':').Append(s.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(s).Append(';');
                }
                o[i] = sb.ToString();
            }
            return o;
        }

        // ---- THE COMPARE OF WHAT CHANGED: one page's plan input split before New-SIVulnSyncPlan ----------------------------
        static readonly Regex ClosedOrResolved = new Regex("(?i)^closed|^resolved", RegexOptions.IgnoreCase);
        static bool IsClosed(object a) { return ClosedOrResolved.IsMatch(Str(Member(a, "State"))); }
        // New-SIVulnSyncPlan's $keyOf (a desired finding) and $actualKeyOf (a record: its CI key NOW, through -AssetAlias)
        static string DKey(object d) { return Str(Member(d, "CorrelationId")).Trim().ToLowerInvariant() + "|" + Str(Member(d, "Cve")).Trim().ToUpperInvariant(); }
        static string AKey(object a, Hashtable alias) {
            string id = Str(Member(a, "CorrelationId")).Trim(); string k = id.ToLowerInvariant();
            string now = (alias != null && alias.Count > 0 && alias.ContainsKey(k)) ? Str(alias[k]) : id;
            return now.Trim().ToLowerInvariant() + "|" + Str(Member(a, "Cve")).Trim().ToUpperInvariant();
        }
        static bool Aliased(object a, Hashtable alias) { return alias != null && alias.Count > 0 && alias.ContainsKey(Str(Member(a, "CorrelationId")).Trim().ToLowerInvariant()); }
        static bool Keyed(object o) { return !string.IsNullOrWhiteSpace(Str(Member(o, "CorrelationId"))) && !string.IsNullOrWhiteSpace(Str(Member(o, "Cve"))); }
        // Get-SIVulnSentFieldChanges' $has + $get
        static bool HasField(object o, string n, out object v) {
            v = null; if (o == null) return false;
            IDictionary d = Base(o) as IDictionary;
            if (d != null) { if (!d.Contains(n)) return false; v = d[n]; return true; }
            PSPropertyInfo p = PSObject.AsPSObject(o).Properties[n];
            if (p == null) return false;
            v = p.Value; return true;
        }
        // the plan's open records it owns ($openActual): keyed, and no Source, a blank one, or this source (-eq)
        static bool OwnedOpen(object a, string source, bool exact) {
            if (!Keyed(a) || IsClosed(a)) return false;
            if (PSObject.AsPSObject(a).Properties["Source"] == null) return true;
            string s = Str(Member(a, "Source"));
            if (string.IsNullOrWhiteSpace(s)) return true;
            if (exact) return string.Equals(s, source, StringComparison.Ordinal);
            return LanguagePrimitives.Equals(s, source, true, CultureInfo.InvariantCulture);
        }

        // THE UNCHANGED PAIRS of a page: a desired finding and the ONE record its key matches, where New-SIVulnSyncPlan can only
        // decide "still reported, nothing sent changed" (a "seen" refresh): the key once on each side, the record open, owned,
        // not under a previous id, not counted absent, not released, and every field the close-loop sends the same (trimmed,
        // case-sensitive; an empty desired value keeps the stored one). Returns { rest desired, rest records, the pairs as the
        // plan's own update items (Desired, Actual, Changes = -noChanges, Changed = false), the pairs' CI keys }, or null when
        // a list is not read here (then the page is planned whole). Anything in doubt stays in the rest -- never a guess.
        public static object[] SplitUnchanged(object[] desired, object[] actual, Hashtable alias, string source, string[] released, string[] sent, object noChanges) {
            if (desired == null) desired = new object[0];
            if (actual == null) actual = new object[0];
            if (!AllPlain(desired) || !AllPlain(actual)) return null;
            Dictionary<string, int> dN = new Dictionary<string, int>(StringComparer.Ordinal), dAt = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < desired.Length; i++) {
                object d = desired[i]; if (d == null || !Keyed(d)) continue;
                string k = DKey(d); int c; dN.TryGetValue(k, out c); dN[k] = c + 1; dAt[k] = i;
            }
            Dictionary<string, int> aN = new Dictionary<string, int>(StringComparer.Ordinal), aAt = new Dictionary<string, int>(StringComparer.Ordinal);
            for (int i = 0; i < actual.Length; i++) {
                object a = actual[i]; if (a == null) continue;
                string k = AKey(a, alias); int c; aN.TryGetValue(k, out c); aN[k] = c + 1; aAt[k] = i;
            }
            HashSet<string> rel = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (released != null) foreach (string r in released) { if (r != null) { rel.Add(r); rel.Add(r.Trim()); } }
            bool[] dOut = new bool[desired.Length], aOut = new bool[actual.Length];
            List<object> pairs = new List<object>(); List<string> seen = new List<string>();
            foreach (KeyValuePair<string, int> kv in dN) {
                if (kv.Value != 1) continue;
                int ac; if (!aN.TryGetValue(kv.Key, out ac) || ac != 1) continue;
                object d = desired[dAt[kv.Key]], a = actual[aAt[kv.Key]];
                if (Aliased(a, alias) || !OwnedOpen(a, source, true)) continue;
                object ar;
                if (HasField(a, "AbsentRuns", out ar)) { int n; if (int.TryParse(Str(ar), out n) && n > 0) continue; }
                if (rel.Count > 0) { string sys = Str(Member(a, "SysId")); if (rel.Contains(sys) || rel.Contains(sys.Trim())) continue; }
                bool same = true;
                if (sent != null) foreach (string f in sent) {
                    object dv; HasField(d, f, out dv);
                    string now = Str(dv).Trim(); if (now.Length == 0) continue;
                    object bv; if (!HasField(a, f, out bv)) continue;
                    if (!string.Equals(Str(bv).Trim(), now, StringComparison.Ordinal)) { same = false; break; }
                }
                if (!same) continue;
                dOut[dAt[kv.Key]] = true; aOut[aAt[kv.Key]] = true;
                PSObject u = new PSObject();
                u.Properties.Add(new PSNoteProperty("Desired", d)); u.Properties.Add(new PSNoteProperty("Actual", a));
                u.Properties.Add(new PSNoteProperty("Changes", noChanges)); u.Properties.Add(new PSNoteProperty("Changed", false));
                pairs.Add(u); seen.Add(Str(Member(d, "CorrelationId")).Trim());
            }
            List<object> rd = new List<object>(desired.Length - pairs.Count), ra = new List<object>(actual.Length - pairs.Count);
            for (int i = 0; i < desired.Length; i++) if (!dOut[i]) rd.Add(desired[i]);
            for (int i = 0; i < actual.Length; i++) if (!aOut[i]) ra.Add(actual[i]);
            return new object[] { rd.ToArray(), ra.ToArray(), pairs.ToArray(), seen.ToArray() };
        }

        static IEnumerable Items(object o, string n) {
            object v = Member(o, n); if (v == null) return new object[0];
            object b = Base(v); if (b is string || b is IDictionary) return new object[] { b };
            IEnumerable e = b as IEnumerable; return e ?? new object[] { b };
        }
        // THE CLOSE RULE'S CHECK: the open records of the page whose key is not among the page's desired findings -- from the FULL
        // lists, keys only -- against the records the plan judged absent (closes, held, counted, a held close set). Returns
        // { absent by keys, absent by the plan, only by keys, only by the plan }; both last 0 = the plan's closes rest on every key.
        public static long[] CloseCheck(object[] desired, object[] actual, Hashtable alias, string source, object plan) {
            HashSet<string> dk = new HashSet<string>(StringComparer.Ordinal);
            if (desired != null) foreach (object d in desired) { if (d != null && Keyed(d)) dk.Add(DKey(d)); }
            HashSet<string> full = new HashSet<string>(StringComparer.Ordinal), byPlan = new HashSet<string>(StringComparer.Ordinal);
            if (actual != null) foreach (object a in actual) { if (a == null || !OwnedOpen(a, source, false)) continue; string k = AKey(a, alias); if (!dk.Contains(k)) full.Add(k); }
            foreach (object a in Items(plan, "ToClose")) { if (a == null) continue; string k = AKey(a, alias); if (!dk.Contains(k)) byPlan.Add(k); }
            foreach (object h in Items(plan, "Held")) { object a = Member(h, "Record"); if (a == null) continue; string k = AKey(a, alias); if (!dk.Contains(k)) byPlan.Add(k); }
            foreach (object c in Items(plan, "ToCount")) { object a = Member(c, "Record"); if (a == null) continue; string k = AKey(a, alias); if (!dk.Contains(k)) byPlan.Add(k); }
            foreach (object a in Items(plan, "HeldCloses")) { if (a == null) continue; string k = AKey(a, alias); if (!dk.Contains(k)) byPlan.Add(k); }
            long onlyFull = 0, onlyPlan = 0;
            foreach (string k in full) if (!byPlan.Contains(k)) onlyFull++;
            foreach (string k in byPlan) if (!full.Contains(k)) onlyPlan++;
            return new long[] { full.Count, byPlan.Count, onlyFull, onlyPlan };
        }

        // ---- what a plan would DO and SEND, one line per action (sorted): the shadow compares two plans by these ----------
        static void Field(StringBuilder sb, object v) {
            string s;
            if (v == null) s = "~";
            else { object b = Base(v); if (b is DBNull) s = "~dbnull"; else if (b is DateTime) s = ((DateTime)b).ToString("o", CultureInfo.InvariantCulture); else s = Str(v); }
            sb.Append(s.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(s).Append('|');
        }
        // one line: kind|identity|name=<len>:<value>|... -- the identity is an id (the record's SysId; for an open, which has no
        // record yet, a hash of its finding key; for the summary the count's name), never a value, so a DIFFERENCE can be said
        // as kind + identity + the NAMES of the fields that differ (PlanDiff) and no customer value leaves the process
        static string Line(string kind, object id, string names, params object[] vals) {
            if (vals == null) vals = new object[] { null };   // (one null argument arrives as a null params array)
            string[] ns = names.Split(',');
            StringBuilder sb = new StringBuilder(kind); sb.Append('|').Append(Str(id).Replace("|", "/")).Append('|');
            for (int i = 0; i < vals.Length; i++) { sb.Append(i < ns.Length ? ns[i] : ("f" + i.ToString(CultureInfo.InvariantCulture))).Append('='); Field(sb, vals[i]); }
            return sb.ToString();
        }
        static string KeyHash(string key) {
            using (System.Security.Cryptography.SHA256 h = System.Security.Cryptography.SHA256.Create()) {
                byte[] b = h.ComputeHash(Encoding.UTF8.GetBytes(key));
                StringBuilder sb = new StringBuilder("key#");
                for (int i = 0; i < 8; i++) sb.Append(b[i].ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }
        // a line's identity (kind|id) and its fields: name -> the value's text (kept in memory only)
        static string LineId(string line) { int a = line.IndexOf('|'); if (a < 0) return line; int b = line.IndexOf('|', a + 1); return b < 0 ? line : line.Substring(0, b); }
        static Dictionary<string, string> LineFields(string line) {
            Dictionary<string, string> f = new Dictionary<string, string>(StringComparer.Ordinal);
            string id = LineId(line); int p = id.Length + 1;
            while (p < line.Length) {
                int eq = line.IndexOf('=', p); if (eq < 0) break;
                string name = line.Substring(p, eq - p);
                int colon = line.IndexOf(':', eq + 1); if (colon < 0) break;
                int len; if (!int.TryParse(line.Substring(eq + 1, colon - eq - 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out len)) break;
                if (colon + 1 + len > line.Length) break;
                f[name] = line.Substring(colon + 1, len);
                p = colon + 1 + len + 1;
            }
            return f;
        }
        // THE SHADOW'S DIFFERENCE, said without a value: two plans' lines (-full, -cs) -> one text per identity that differs:
        // "<kind>|<id>|<the names of the differing fields>" (or "only in the full plan" / "only in the changed set" / "<n> line(s) /
        // <m> line(s)" when the same identity is not one line on each side). Ids and field names only, never a value.
        public static string[] PlanDiff(string[] full, string[] cs) {
            Dictionary<string, List<string>> a = new Dictionary<string, List<string>>(StringComparer.Ordinal), b = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            List<string> order = new List<string>();
            foreach (string l in full ?? new string[0]) { string k = LineId(l); List<string> x; if (!a.TryGetValue(k, out x)) { x = new List<string>(); a[k] = x; if (!b.ContainsKey(k)) order.Add(k); } x.Add(l); }
            foreach (string l in cs ?? new string[0]) { string k = LineId(l); List<string> x; if (!b.TryGetValue(k, out x)) { x = new List<string>(); b[k] = x; if (!a.ContainsKey(k)) order.Add(k); } x.Add(l); }
            List<string> o = new List<string>();
            foreach (string k in order) {
                List<string> x, y; a.TryGetValue(k, out x); b.TryGetValue(k, out y);
                if (x == null) { o.Add(k + "|only in the changed set"); continue; }
                if (y == null) { o.Add(k + "|only in the full plan"); continue; }
                List<string> xs = new List<string>(x), ys = new List<string>(y); xs.Sort(StringComparer.Ordinal); ys.Sort(StringComparer.Ordinal);
                bool same = xs.Count == ys.Count; if (same) for (int i = 0; i < xs.Count; i++) if (!string.Equals(xs[i], ys[i], StringComparison.Ordinal)) { same = false; break; }
                if (same) continue;
                if (xs.Count != 1 || ys.Count != 1) { o.Add(k + "|" + xs.Count.ToString(CultureInfo.InvariantCulture) + " line(s) in the full plan, " + ys.Count.ToString(CultureInfo.InvariantCulture) + " in the changed set"); continue; }
                Dictionary<string, string> fx = LineFields(xs[0]), fy = LineFields(ys[0]);
                List<string> names = new List<string>();
                foreach (KeyValuePair<string, string> kv in fx) { string v; if (!fy.TryGetValue(kv.Key, out v) || !string.Equals(v, kv.Value, StringComparison.Ordinal)) names.Add(kv.Key); }
                foreach (string n in fy.Keys) if (!fx.ContainsKey(n)) names.Add(n);
                o.Add(k + "|" + string.Join(",", names.ToArray()));
            }
            return o.ToArray();
        }
        // THE SHADOW'S FOLD DIFFERENCE, said without a value: item by item, property by property -> "<index>:<the names of the
        // properties that differ>" (a property on one side only counts; a missing item is "<index>:missing").
        public static string[] FoldDiff(object[] a, object[] b) {
            if (a == null) a = new object[0]; if (b == null) b = new object[0];
            List<string> o = new List<string>();
            int m = Math.Max(a.Length, b.Length);
            for (int i = 0; i < m; i++) {
                if (i >= a.Length || i >= b.Length || a[i] == null || b[i] == null) { if (!(i < a.Length && i < b.Length && a[i] == null && b[i] == null)) o.Add(i.ToString(CultureInfo.InvariantCulture) + ":missing"); continue; }
                List<string> pa = new List<string>(), names = new List<string>();
                Dictionary<string, string> tb = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (PSPropertyInfo p in PSObject.AsPSObject(b[i]).Properties) tb[p.Name] = Canon(new object[] { PropOnly(p) })[0];
                foreach (PSPropertyInfo p in PSObject.AsPSObject(a[i]).Properties) {
                    pa.Add(p.Name); string t; string ta = Canon(new object[] { PropOnly(p) })[0];
                    if (!tb.TryGetValue(p.Name, out t) || !string.Equals(t, ta, StringComparison.Ordinal)) names.Add(p.Name);
                }
                foreach (string n in tb.Keys) if (!pa.Contains(n)) names.Add(n);
                // the same properties in another order is a difference too
                if (names.Count == 0) { int j = 0; foreach (PSPropertyInfo p in PSObject.AsPSObject(b[i]).Properties) { if (j >= pa.Count || p.Name != pa[j]) { names.Add("(property order)"); break; } j++; } }
                if (names.Count > 0) o.Add(i.ToString(CultureInfo.InvariantCulture) + ":" + string.Join(",", names.ToArray()));
            }
            return o.ToArray();
        }
        static PSObject PropOnly(PSPropertyInfo p) { PSObject x = new PSObject(); x.Properties.Add(new PSNoteProperty(p.Name, p.Value)); return x; }
        static string ChangesText(object ch) {
            if (ch == null) return "~";
            IDictionary d = Base(ch) as IDictionary; if (d == null) return Str(ch);
            StringBuilder sb = new StringBuilder();
            foreach (DictionaryEntry e in d) {
                sb.Append(Str(e.Key)).Append('=');
                object v = e.Value == null ? null : Base(e.Value);
                IEnumerable l = v as IEnumerable;
                if (l != null && !(v is string)) { foreach (object x in l) sb.Append(Str(x)).Append('>'); } else sb.Append(Str(e.Value));
                sb.Append(';');
            }
            return sb.ToString();
        }
        public static string[] PlanLines(object plan) {
            List<string> o = new List<string>();
            foreach (object d in Items(plan, "ToOpen")) { if (d == null) continue; o.Add(Line("open", KeyHash(DKey(d)), "CorrelationId,CiSysId,AssetName,Cve,Severity,AssetId,FindingType,Title,Report,Component,SubCi,OsFamily,PatchCycle", Member(d, "CorrelationId"), Member(d, "CiSysId"), Member(d, "AssetName"), Member(d, "Cve"), Member(d, "Severity"), Member(d, "AssetId"), Member(d, "FindingType"), Member(d, "Title"), Member(d, "Report"), Member(d, "Component"), Member(d, "SubCi"), Member(d, "OsFamily"), Member(d, "PatchCycle"))); }
            foreach (object p in Items(plan, "ToReopen")) { if (p == null) continue; object a = Member(p, "Actual"), d = Member(p, "Desired"); o.Add(Line("reopen", Member(a, "SysId"), "State,CloseReason,Cve", Member(a, "State"), Member(a, "CloseReason"), Member(d, "Cve"))); }
            foreach (object p in Items(plan, "ToUpdate")) {
                if (p == null) continue; object a = Member(p, "Actual"), d = Member(p, "Desired");
                o.Add(Line("update", Member(a, "SysId"), "CorrelationId,AssetName,AbsentRuns,Cve,Severity,AssetId,FindingType,Title,Report,Component,SubCi,OsFamily,PatchCycle,Changed,Changes",
                           Member(a, "CorrelationId"), Member(a, "AssetName"), Member(a, "AbsentRuns"), Member(d, "Cve"), Member(d, "Severity"), Member(d, "AssetId"), Member(d, "FindingType"), Member(d, "Title"), Member(d, "Report"),
                           Member(d, "Component"), Member(d, "SubCi"), Member(d, "OsFamily"), Member(d, "PatchCycle"), Member(p, "Changed"), ChangesText(Member(p, "Changes"))));
            }
            foreach (object a in Items(plan, "ToClose")) { if (a == null) continue; o.Add(Line("close", Member(a, "SysId"), "CorrelationId,Cve,State,CloseReason,CloseWhy,AbsentCount,AbsentRuns,AssetState,Corroborated", Member(a, "CorrelationId"), Member(a, "Cve"), Member(a, "State"), Member(a, "CloseReason"), Member(a, "CloseWhy"), Member(a, "AbsentCount"), Member(a, "AbsentRuns"), Member(a, "AssetState"), Member(a, "Corroborated"))); }
            foreach (object c in Items(plan, "ToCount")) { if (c == null) continue; object a = Member(c, "Record"); o.Add(Line("count", Member(a, "SysId"), "Cve,AbsentRuns,Snapshot,New,Reason", Member(a, "Cve"), Member(c, "AbsentRuns"), Member(c, "Snapshot"), Member(c, "New"), Member(c, "Reason"))); }
            foreach (object h in Items(plan, "Held")) { if (h == null) continue; object a = Member(h, "Record"); o.Add(Line("held", Member(a, "SysId"), "CorrelationId,Cve,AssetState,Reason", Member(a, "CorrelationId"), Member(a, "Cve"), Member(h, "AssetState"), Member(h, "Reason"))); }
            foreach (object a in Items(plan, "HeldCloses")) { if (a == null) continue; o.Add(Line("heldclose", Member(a, "SysId"), "CloseReason", Member(a, "CloseReason"))); }
            object s = Member(plan, "Summary");
            if (s != null) foreach (PSPropertyInfo p in PSObject.AsPSObject(s).Properties) o.Add(Line("summary", p.Name, "Value", p.Value));
            o.Add(Line("halt", "run", "Halted,HaltGuard,HaltReason,HaltHeld", Member(plan, "Halted"), Member(plan, "HaltGuard"), Member(plan, "HaltReason"), Member(plan, "HaltHeld")));
            o.Sort(StringComparer.Ordinal);
            return o.ToArray();
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

# =====================================================================================================================
#  #1320 (SCALE-2 #1314) THE CLOSE-LOOP COMPARES ONLY WHAT CHANGED, ITS PAGE FOLD COMPILED -- the setting
#  SI_VulnLoop_ChangedSet: on (the default) | off (every page planned whole, exactly as before) | shadow (troubleshooting).
#    * THE FOLD: Add-SIVulnSnapshotRows / Complete-SIVulnSnapshot -- ~85 % of a page pass -- run in the compiled helper over
#      the SAME accumulator (the same dictionaries, comparers, values and order); a page the helper does not read exactly (a
#      list value, a text a culture compare reads as empty, a tier PowerShell's [int] would refuse) is folded by PowerShell.
#      A set of more than one distinct value (PowerShell sorts it with its culture) is ConvertTo-SIVulnSnapshotSet's answer.
#    * THE CHANGED SET: per page, a desired finding and the ONE record its key matches, where the plan can only decide "still
#      reported, nothing sent changed", go past New-SIVulnSyncPlan: they are added to its result as the same "seen" refresh
#      (the same item, the same payload, the same counts) -- only new, changed, reopened and absent findings are planned.
#      CLOSES come only from the full KEY-to-KEY compare: every open record of the page against every desired key (keys only,
#      compiled); the plan's absent records must be exactly those, else the page is planned whole (and said).
#    * THE GUARDS decide once, centrally, on the FULL totals: the pairs are added to what the pages measured (desired, open,
#      still desired) exactly as the plan would have counted them; Get-SIVulnPagedGuardDecision is unchanged.
#    * SHADOW: each page is planned both ways -- the changed set in plan-only mode first, then the full plan, which is what is
#      applied -- and the two are compared: every planned action and what it sends (open / update / seen / reopen / close /
#      count / held, per record), the guards' totals and decision, and the two folds. A difference = a WARNING on the run
#      record (the data-problem report); nothing of the changed set is sent.
# =====================================================================================================================
function Get-SIVulnChangedSetMode {
    <# SI_VulnLoop_ChangedSet: 'on' (the default -- not set, or any other value) | 'off' (every page planned whole, as before
       2026-11-23) | 'shadow' (troubleshooting: both ways, compared; it doubles the plan work). On and shadow need the compiled
       helper: without it (Windows PowerShell, application control) the mode is off and the PowerShell path runs. #>
    $v = ([string]$global:SI_VulnLoop_ChangedSet).Trim().ToLowerInvariant()
    if ($v -eq 'off') { return 'off' }
    if ($v -ne 'shadow') { $v = 'on' }
    if ($null -eq (Get-SIVulnFastType)) { return 'off' }
    $v
}

function Get-SIVulnChangedSetSentFields {
    <# PURE. The fields the close-loop sends on a still-reported record -- SI-VulnSync.ps1's $script:SIVulnSentFields (held to
       it by SIv3-VulnLoopChangedSet.Tests.ps1). #>
    @('Severity', 'Title', 'FindingType', 'Report', 'AssetId', 'Component', 'SubCi', 'OsFamily', 'PatchCycle')
}

function Reset-SIVulnChangedSetTally {
    <# What one connector's run of the changed set counted: the unchanged pairs per pass, the pages planned whole after the key
       check, the pages compared (shadow) and every difference by kind with a few examples. #>
    param([string]$Connector = '')
    $global:SI_VulnChangedSetTally = [pscustomobject]@{
        Connector = $Connector; MeasurePairs = 0L; ApplyPairs = 0L; Pages = 0L; WholePages = 0L; NotSplit = 0L; WholeRun = $false
        ShadowPages = 0L; FoldPages = 0L; FoldRefused = 0L; Diff = 0L; Kinds = [ordered]@{}; Samples = (New-Object System.Collections.Generic.List[string])
    }
    $global:SI_VulnChangedSetTally
}

function Get-SIVulnChangedSetTally {
    if ($null -eq $global:SI_VulnChangedSetTally) { $null = Reset-SIVulnChangedSetTally }
    $global:SI_VulnChangedSetTally
}

function Add-SIVulnChangedSetDiff {
    <# One difference (or -Count of them) of a kind, with an example (the first 10 are kept). #>
    param([Parameter(Mandatory)][string]$Kind, [long]$Count = 1, [string]$Sample = '')
    if ($Count -le 0) { return }
    $t = Get-SIVulnChangedSetTally
    $t.Diff += $Count
    if ($t.Kinds.Contains($Kind)) { $t.Kinds[$Kind] = [long]$t.Kinds[$Kind] + $Count } else { $t.Kinds[$Kind] = $Count }
    if ($Sample -and $t.Samples.Count -lt 10) { $t.Samples.Add(('{0}: {1}' -f $Kind, $(if ($Sample.Length -gt 300) { $Sample.Substring(0, 300) + '...' } else { $Sample }))) }
}

function Invoke-SIVulnFoldRows {
    <# Add-SIVulnSnapshotRows in the compiled helper, over -Acc itself: the rows folded, or -1 (not handled -- nothing changed). #>
    param([Parameter(Mandatory)]$Acc, [AllowEmptyCollection()][object[]]$Rows = @())
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return -1L }
    $keys = [string[]]@($Acc.Scope.Keys)
    $cols = [object[]]@(foreach ($k in $Acc.Scope.Keys) { , [string[]]@($Acc.Scope[$k]) })
    [long]$fx::FoldRows($Acc.Groups, $Acc.Order, $Acc.Assets, $Acc.AssetOrder, [object[]]$Rows, [string]$Acc.Edition, $keys, $cols, @{})
}

function Complete-SIVulnFoldCompiled {
    <# Complete-SIVulnSnapshot in the compiled helper: @{ Rows; Assets } exactly as the PowerShell body gives them, or $null. #>
    param([Parameter(Mandatory)]$Acc, [Parameter(Mandatory)][datetime]$SnapshotTime)
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return $null }
    $t = [datetime]::SpecifyKind($SnapshotTime, [DateTimeKind]::Utc)
    $setOf = [Func[object, object]] { param($v) ConvertTo-SIVulnSnapshotSet -Values $v }
    $r = $fx::FoldComplete($Acc.Groups, $Acc.Order, $Acc.Assets, $Acc.AssetOrder, [string[]]@($Acc.Scope.Keys), $t, $setOf)
    [pscustomobject]@{ Rows = [object[]]$r[0]; Assets = [object[]]$r[1] }
}

function Compare-SIVulnFoldRows {
    <# SHADOW: the PowerShell fold (-Old) and the compiled one (-New) of one page, row for row and asset for asset (every
       property, its type and its text, in order). Returns the differences (each also counted as 'fold'). The example names the
       item's position and the NAMES of the properties that differ -- never a value (Fast.FoldDiff; the values stay in memory). #>
    param([Parameter(Mandatory)]$Old, [Parameter(Mandatory)]$New)
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return 0L }
    $t = Get-SIVulnChangedSetTally; $t.FoldPages++
    $n = 0L; $first = ''
    foreach ($pair in @(@('row', @($Old.Rows), @($New.Rows)), @('asset', @($Old.Assets), @($New.Assets)))) {
        $d = $fx::FoldDiff([object[]]$pair[1], [object[]]$pair[2])
        $n += $d.Length
        if ($d.Length -and -not $first) { $first = ('{0} {1}' -f $pair[0], $d[0]) }
    }
    if ($n) { Add-SIVulnChangedSetDiff -Kind 'fold' -Count $n -Sample $first }
    $n
}

function Split-SIVulnUnchanged {
    <#
        PURE. One page's plan input split (the compiled helper, Fast.SplitUnchanged): @{ Desired (the rest); Actual (the rest);
        Pairs (the unchanged pairs as the plan's own "seen" update items); SeenKeys (their CI keys) }, or $null when the lists
        are not read here (then the page is planned whole).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Desired = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Actual = @(), [hashtable]$AssetAlias = @{},
          [string]$Source = 'SecurityInsight', [AllowNull()][AllowEmptyCollection()][string[]]$Released = @())
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return $null }
    # the plan's own empty change map (one read-only map shared by every unchanged record)
    $none = if (Get-Command -Name Get-SIVulnSentFieldChanges -ErrorAction SilentlyContinue) { Get-SIVulnSentFieldChanges -Desired @{} -Actual @{} } else { ([ordered]@{}).AsReadOnly() }
    $r = $fx::SplitUnchanged([object[]]$Desired, [object[]]$Actual, $AssetAlias, $Source, [string[]]@($Released), [string[]](Get-SIVulnChangedSetSentFields), $none)
    if ($null -eq $r) { return $null }
    [pscustomobject]@{ Desired = [object[]]$r[0]; Actual = [object[]]$r[1]; Pairs = [object[]]$r[2]; SeenKeys = [string[]]$r[3] }
}

function Complete-SIVulnChangedSetPlan {
    <#
        PURE (over -Plan). The unchanged pairs of -Split put back into a plan of the rest, as the full plan would have them: the
        "seen" update items appended (not in a -Measure pass, which writes nothing), and every count the plan keeps for them --
        Summary Desired / Actual / Seen, and the guards' measure Desired / OpenActual / StillDesired.
    #>
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Split, [switch]$Measure)
    $n = [long]@($Split.Pairs).Count
    if ($n -eq 0) { return }
    if (-not $Measure) { $Plan.ToUpdate.AddRange([object[]]$Split.Pairs) }
    $s = $Plan.Summary
    $s.Desired = [int]$s.Desired + $n; $s.Actual = [int]$s.Actual + $n; $s.Seen = [int]$s.Seen + $n
    if ($Plan.PSObject.Properties['Measure'] -and $null -ne $Plan.Measure) {
        $m = $Plan.Measure; $m.Desired = [long]$m.Desired + $n; $m.OpenActual = [long]$m.OpenActual + $n; $m.StillDesired = [long]$m.StillDesired + $n
    }
}

function Test-SIVulnChangedSetCloses {
    <# THE CLOSE RULE: the plan's absent records against the full KEY-to-KEY compare of the page (Fast.CloseCheck). $true when
       they are exactly the same keys. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Desired = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Actual = @(), [hashtable]$AssetAlias = @{},
          [string]$Source = 'SecurityInsight', [Parameter(Mandatory)]$Plan)
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return $false }
    $c = $fx::CloseCheck([object[]]$Desired, [object[]]$Actual, $AssetAlias, $Source, $Plan)
    ($c[2] -eq 0 -and $c[3] -eq 0)
}

function Get-SIVulnPlanLines {
    <# PURE. What a plan would DO and SEND, one sorted line per action (Fast.PlanLines). #>
    param([Parameter(Mandatory)]$Plan)
    $fx = Get-SIVulnFastType
    if ($null -eq $fx) { return , [string[]]@() }
    , [string[]]$fx::PlanLines($Plan)
}

function Compare-SIVulnPlanLines {
    <# PURE. Two plans' lines (-Old: the full plan, -New: the changed set) -> @{ Diff; Kinds (action -> lines on one side only);
       Sample }. #>
    param([AllowEmptyCollection()][string[]]$Old = @(), [AllowEmptyCollection()][string[]]$New = @())
    $count = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    foreach ($l in $Old) { $c = 0; [void]$count.TryGetValue($l, [ref]$c); $count[$l] = $c + 1 }
    foreach ($l in $New) { $c = 0; [void]$count.TryGetValue($l, [ref]$c); $count[$l] = $c - 1 }
    $kinds = [ordered]@{}; $diff = 0L; $sample = ''
    foreach ($kv in $count.GetEnumerator()) {
        if ($kv.Value -eq 0) { continue }
        $k = $kv.Key.Substring(0, [Math]::Max(0, $kv.Key.IndexOf('|')))
        $d = [long][Math]::Abs($kv.Value); $diff += $d
        if ($kinds.Contains($k)) { $kinds[$k] = [long]$kinds[$k] + $d } else { $kinds[$k] = $d }
    }
    # the example: the action, the record's id (or its finding key's hash) and the NAMES of the fields that differ -- the lines
    # carry customer values (asset names, titles, finding ids), which never reach the run record (Fast.PlanDiff)
    if ($diff -gt 0) {
        $fx = Get-SIVulnFastType
        $pd = if ($null -ne $fx) { @($fx::PlanDiff([string[]]$Old, [string[]]$New)) } else { @() }
        if ($pd.Count) { $p3 = $pd[0].Split([char]'|', 3); $sample = ('{0} {1}: {2}' -f $p3[0], $(if ($p3.Count -gt 1) { $p3[1] } else { '' }), $(if ($p3.Count -gt 2) { $p3[2] } else { '' })) }
        else { $sample = ('{0} line(s) differ' -f $diff) }
    }
    [pscustomobject]@{ Diff = $diff; Kinds = $kinds; Sample = $sample }
}

function Invoke-SIVulnChangedSetPage {
    <#
        ONE PAGE'S PLAN with the changed set (-CsMode 'on' | 'shadow'). -CsPlanOf { param($Desired, $Actual, $SeenKeys) } is the
        loop's own New-SIVulnSyncPlan call (every other argument as the full plan has it). Returns @{ Plan (the plan to use);
        CsMeasure (shadow, a measure pass: the changed set's measure, for the guards' totals compared) }.
          on      the rest is planned, the unchanged pairs are put back (Complete-SIVulnChangedSetPlan); the absent records are
                  checked against the full key compare -- a difference (or a split that cannot be made) = the page planned whole.
          shadow  the changed set first, in plan-only mode (its actions and payload read at once), then the full plan -- the one
                  used; the two compared (Compare-SIVulnPlanLines), every difference counted.
        (Every name here starts with Cs / cs_: -CsPlanOf runs in this function's scope chain and must see the loop's own names.)
    #>
    param([Parameter(Mandatory)][string]$CsMode, [Parameter(Mandatory)][scriptblock]$CsPlanOf, [AllowNull()][AllowEmptyCollection()][object[]]$CsDesired = @(),
          [AllowNull()][AllowEmptyCollection()][object[]]$CsActual = @(), [AllowNull()][AllowEmptyCollection()][string[]]$CsSeen = @(), [hashtable]$CsAlias = @{},
          [AllowNull()][AllowEmptyCollection()][string[]]$CsReleased = @(), [switch]$CsMeasure, [string]$CsSource = 'SecurityInsight')
    # (the counts of pages are the second pass's: the pass that plans what is applied)
    $cs_t = Get-SIVulnChangedSetTally
    if (-not $CsMeasure) { $cs_t.Pages++ }
    $cs_split = $null
    if (-not ($CsMode -eq 'on' -and $cs_t.WholeRun)) { $cs_split = Split-SIVulnUnchanged -Desired $CsDesired -Actual $CsActual -AssetAlias $CsAlias -Source $CsSource -Released $CsReleased }
    if ($null -eq $cs_split -and -not $CsMeasure) { $cs_t.NotSplit++ }
    $cs_whole = { & $CsPlanOf $CsDesired $CsActual $CsSeen }
    $cs_plan = $null; $cs_ok = $false
    if ($null -ne $cs_split) {
        $cs_seen2 = [string[]]@(@($CsSeen) + @($cs_split.SeenKeys) | Where-Object { $_ })
        $cs_plan = & $CsPlanOf $cs_split.Desired $cs_split.Actual $cs_seen2
        # the close rule: the absent records rest on every key (never on the changed set) -- a halted plan closes nothing
        $cs_ok = [bool]$cs_plan.Halted -or (Test-SIVulnChangedSetCloses -Desired $CsDesired -Actual $CsActual -AssetAlias $CsAlias -Source $CsSource -Plan $cs_plan)
        if (-not $cs_ok) { Add-SIVulnChangedSetDiff -Kind 'close-keys' -Sample ('{0} desired, {1} record(s) on the page' -f @($CsDesired).Count, @($CsActual).Count) }
        Complete-SIVulnChangedSetPlan -Plan $cs_plan -Split $cs_split -Measure:$CsMeasure
    }
    if ($CsMode -eq 'on') {
        if ($null -ne $cs_split -and $cs_ok) {
            $cs_n = [long]@($cs_split.Pairs).Count
            if ($CsMeasure) { $cs_t.MeasurePairs += $cs_n } else { $cs_t.ApplyPairs += $cs_n }
            return [pscustomobject]@{ Plan = $cs_plan; CsMeasure = $null }
        }
        if ($null -ne $cs_split) {
            # the key check failed: this page is planned whole, and -- found in the first pass -- the second pass plans every
            # page whole (its measure is what the guards decided on)
            if ($CsMeasure) { $cs_t.WholeRun = $true } else { $cs_t.WholePages++ }
        }
        return [pscustomobject]@{ Plan = (& $cs_whole); CsMeasure = $null }
    }
    # shadow: the changed set was planned first (plan only); its lines are read before the full plan touches the records
    $cs_t.ShadowPages++
    $cs_lines = $null; $cs_meas = $null
    if ($null -ne $cs_plan) { if ($CsMeasure) { $cs_meas = $cs_plan.Measure } else { $cs_lines = Get-SIVulnPlanLines -Plan $cs_plan } }
    $cs_full = & $cs_whole
    if ($null -eq $cs_plan) { return [pscustomobject]@{ Plan = $cs_full; CsMeasure = $(if ($CsMeasure) { $cs_full.Measure } else { $null }) } }
    if ($CsMeasure) { $cs_t.MeasurePairs += [long]@($cs_split.Pairs).Count }
    else {
        $cs_t.ApplyPairs += [long]@($cs_split.Pairs).Count
        $cs_cmp = Compare-SIVulnPlanLines -Old (Get-SIVulnPlanLines -Plan $cs_full) -New $cs_lines
        foreach ($cs_k in @($cs_cmp.Kinds.Keys)) { Add-SIVulnChangedSetDiff -Kind ('plan ' + $cs_k) -Count ([long]$cs_cmp.Kinds[$cs_k]) -Sample $cs_cmp.Sample }
    }
    [pscustomobject]@{ Plan = $cs_full; CsMeasure = $cs_meas }
}

function Compare-SIVulnChangedSetMeasure {
    <# SHADOW, after the first pass: the guards' totals of the full path (-Full) and of the changed set (-Cs), key by key, and the
       decision each gives (-Decide { param($measure) } -> Get-SIVulnPagedGuardDecision). Counts every difference. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Full, [Parameter(Mandatory)][System.Collections.IDictionary]$Cs, [scriptblock]$Decide)
    $n = 0L
    foreach ($k in @($Full.Keys)) {
        $a = [long]$Full[$k]; $b = $(if ($Cs.Contains($k)) { [long]$Cs[$k] } else { 0L })
        if ($a -ne $b) { $n++; Add-SIVulnChangedSetDiff -Kind 'guard totals' -Sample ('{0}: {1} (full) / {2} (changed set)' -f $k, $a, $b) }
    }
    if ($Decide) {
        $da = & $Decide ([pscustomobject]$Full); $db = & $Decide ([pscustomobject]$Cs)
        $ta = '{0}|{1}|{2}|{3}' -f [bool]$da.Halted, [string]$da.HaltGuard, [string]$da.HaltReason, [long]$da.HaltHeld
        $tb = '{0}|{1}|{2}|{3}' -f [bool]$db.Halted, [string]$db.HaltGuard, [string]$db.HaltReason, [long]$db.HaltHeld
        # (the reason text is compared, never written: the sample is the guard, halted or not, and the count it held)
        if ($ta -ne $tb) { $n++; Add-SIVulnChangedSetDiff -Kind 'guard decision' -Sample ('{0}|{1}|{2} (full) / {3}|{4}|{5} (changed set)' -f [bool]$da.Halted, [string]$da.HaltGuard, [long]$da.HaltHeld, [bool]$db.Halted, [string]$db.HaltGuard, [long]$db.HaltHeld) }
    }
    $n
}
