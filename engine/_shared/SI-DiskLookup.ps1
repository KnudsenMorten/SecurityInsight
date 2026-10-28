#Requires -Version 5.1
<#
    #726 A TENANT-SIZED LOOKUP ON DISK (owner 2026-10-16: "fix the streaming code for identity now" / "same method across all
    cust"). The identity collection joins every user and service principal to lookups built from the whole tenant -- the
    Exposure Graph identity index (one entry per Entra-linked node, several keys each), the MFA registration rows. Held as
    hashtables of objects they were the identity producer's memory at the large ring-2 tenant (index ~2 GB, MFA ~0.4 GB).

    SecurityInsight.DiskLookup keeps each entry in a local file and only the KEYS in memory (key -> where the entry starts).
    An entry is written as PowerShell's own serialization (CliXml, ConvertTo-SIDiskLookupText) and read back with it -- TYPE
    FAITHFUL: a string stays a string (an ISO date or '/Date(...)/' text is NOT turned into a date, as ConvertFrom-Json would),
    a date stays a date, a number keeps its type, a list stays a list. A caller that reads `$map[$key]`,
    `$map.ContainsKey($key)` or `$map.Count` works unchanged. Every tenant uses it; nothing chooses by size.
      New-SIDiskLookup -Name <what>          a new, empty lookup (a file under the temp folder; removed by Dispose)
      ConvertTo-SIDiskLookupText <object>    the text an entry is kept as
      $l.Append(<text>)                      writes one entry, returns where it starts
      $l.SetKey(<key>, <at>)                 the key reads that entry (a later SetKey of the same key replaces it)
      $l.TryAddKey(<key>, <at>)              only when the key is not there yet ($true when added)
      $l.Put(<key>, <text>)                  Append + SetKey
      $l[<key>] / GetText(<key>)             the entry (a fresh copy) / its text; $null when the key is not there
    Keys compare case-insensitively, like the hashtables they replace. PowerShell 5.1 and 7.
#>

if (-not ('SecurityInsight.DiskLookup' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
namespace SecurityInsight {
    public sealed class DiskLookup : IDisposable {
        private FileStream _fs;
        private readonly Dictionary<string, long> _idx = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private readonly UTF8Encoding _enc = new UTF8Encoding(false);
        // the entry reader (set once, below, to PowerShell's deserializer): an entry reads back as the object it was
        public static Func<string, object> Reader;
        public string Path { get; private set; }
        public long Entries { get; private set; }
        public DiskLookup(string path) {
            Path = path;
            _fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read, 65536, FileOptions.DeleteOnClose);
        }
        public long Append(string text) {
            byte[] b = _enc.GetBytes(text ?? "");
            long at = _fs.Seek(0, SeekOrigin.End);
            _fs.Write(BitConverter.GetBytes(b.Length), 0, 4);
            _fs.Write(b, 0, b.Length);
            Entries++;
            return at;
        }
        public void SetKey(string key, long at) { if (key != null) _idx[key] = at; }
        public bool TryAddKey(string key, long at) { if (key == null || _idx.ContainsKey(key)) return false; _idx[key] = at; return true; }
        public long Put(string key, string text) { long at = Append(text); SetKey(key, at); return at; }
        public bool ContainsKey(string key) { return key != null && _idx.ContainsKey(key); }
        public bool Contains(string key) { return ContainsKey(key); }
        public int Count { get { return _idx.Count; } }
        public ICollection<string> Keys { get { return _idx.Keys; } }
        public string GetText(string key) {
            long at;
            if (key == null || !_idx.TryGetValue(key, out at)) return null;
            _fs.Seek(at, SeekOrigin.Begin);
            byte[] lb = new byte[4]; ReadAll(lb);
            byte[] b = new byte[BitConverter.ToInt32(lb, 0)]; ReadAll(b);
            return _enc.GetString(b);
        }
        private void ReadAll(byte[] b) { int o = 0; while (o < b.Length) { int n = _fs.Read(b, o, b.Length - o); if (n <= 0) throw new EndOfStreamException(Path); o += n; } }
        public object this[string key] {
            get {
                string t = GetText(key);
                if (t == null) return null;
                if (Reader == null) throw new InvalidOperationException("SecurityInsight.DiskLookup: no reader set");
                return Reader(t);
            }
        }
        public void Dispose() { if (_fs != null) { _fs.Dispose(); _fs = null; } _idx.Clear(); }
    }
}
'@
}
# #727 THE AZURE RECORDS STREAM TOO (owner 2026-10-16: "tenants can have millions of azure obj"). Two more shapes, same rule
# (each entry on disk, only the keys in memory -- or, for the groups, one small number per key):
#   SecurityInsight.DiskTextLookup  a TEXT per key ($l[<key>] reads it, $l[<key>] = <text> writes it): the Azure record
#                                   index of the producer, the capture's child -> parent map, the Azure context's scope and
#                                   backup sets. No serialization: the entry IS the text.
#   SecurityInsight.KeyGroups       which keys belong together (union / find): an Azure resource and every child resource
#                                   listed on it -- the hand-over folds a child into its parent one GROUP at a time.
if (-not ('SecurityInsight.DiskTextLookup' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
namespace SecurityInsight {
    public sealed class DiskTextLookup : IDisposable {
        private FileStream _fs;
        private readonly Dictionary<string, long> _idx = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        private readonly UTF8Encoding _enc = new UTF8Encoding(false);
        public string Path { get; private set; }
        public long Entries { get; private set; }
        public DiskTextLookup(string path) {
            Path = path;
            _fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.Read, 65536, FileOptions.DeleteOnClose);
        }
        public long Put(string key, string text) {
            if (key == null) return -1;
            byte[] b = _enc.GetBytes(text ?? "");
            long at = _fs.Seek(0, SeekOrigin.End);
            _fs.Write(BitConverter.GetBytes(b.Length), 0, 4);
            _fs.Write(b, 0, b.Length);
            Entries++;
            _idx[key] = at;
            return at;
        }
        public bool ContainsKey(string key) { return key != null && _idx.ContainsKey(key); }
        public bool Contains(string key) { return ContainsKey(key); }
        public int Count { get { return _idx.Count; } }
        public ICollection<string> Keys { get { return _idx.Keys; } }
        public string GetText(string key) {
            long at;
            if (key == null || !_idx.TryGetValue(key, out at)) return null;
            _fs.Seek(at, SeekOrigin.Begin);
            byte[] lb = new byte[4]; ReadAll(lb);
            byte[] b = new byte[BitConverter.ToInt32(lb, 0)]; ReadAll(b);
            return _enc.GetString(b);
        }
        private void ReadAll(byte[] b) { int o = 0; while (o < b.Length) { int n = _fs.Read(b, o, b.Length - o); if (n <= 0) throw new EndOfStreamException(Path); o += n; } }
        public string this[string key] { get { return GetText(key); } set { Put(key, value); } }
        public void Dispose() { if (_fs != null) { _fs.Dispose(); _fs = null; } _idx.Clear(); }
    }
    public sealed class KeyGroups {
        private readonly Dictionary<string, int> _idx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly List<int> _up = new List<int>();
        private readonly List<string> _keys = new List<string>();
        private int Id(string k) { int i; if (!_idx.TryGetValue(k, out i)) { i = _keys.Count; _idx[k] = i; _keys.Add(k); _up.Add(i); } return i; }
        private int Root(int i) { while (_up[i] != i) { _up[i] = _up[_up[i]]; i = _up[i]; } return i; }
        public void Union(string a, string b) {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return;
            int ra = Root(Id(a)), rb = Root(Id(b));
            if (ra == rb) return;
            if (ra < rb) _up[rb] = ra; else _up[ra] = rb;
        }
        // the group's key (the first key the group met); a key that was never joined is its own group
        public string Find(string k) { int i; if (k == null || !_idx.TryGetValue(k, out i)) return k; return _keys[Root(i)]; }
        public int Count { get { return _keys.Count; } }
    }
}
'@
}

function New-SIDiskTextLookup {
    <# A new, empty on-disk TEXT lookup (#727). -Name says what it holds (part of the file name). #>
    param([Parameter(Mandatory)][string]$Name, [string]$Directory = '')
    if (-not $Directory) { $Directory = [IO.Path]::GetTempPath() }
    New-Object SecurityInsight.DiskTextLookup ([IO.Path]::Combine($Directory, ('si-lookup-{0}-{1}.txt' -f ($Name -replace '[^A-Za-z0-9-]', ''), [guid]::NewGuid().ToString('N'))))
}

if ($null -eq [SecurityInsight.DiskLookup]::Reader) {
    [SecurityInsight.DiskLookup]::Reader = [Func[string, object]] { param([string]$Text) [System.Management.Automation.PSSerializer]::Deserialize($Text) }
}

function ConvertTo-SIDiskLookupText {
    <# PURE. The text one lookup entry is kept as: PowerShell's own serialization, deep enough for a whole entry. #>
    param([AllowNull()]$InputObject)
    [System.Management.Automation.PSSerializer]::Serialize($InputObject, 20)
}

function New-SIDiskLookup {
    <# A new, empty on-disk lookup (#726). -Name says what it holds (part of the file name). #>
    param([Parameter(Mandatory)][string]$Name, [string]$Directory = '')
    if (-not $Directory) { $Directory = [IO.Path]::GetTempPath() }
    New-Object SecurityInsight.DiskLookup ([IO.Path]::Combine($Directory, ('si-lookup-{0}-{1}.bin' -f ($Name -replace '[^A-Za-z0-9-]', ''), [guid]::NewGuid().ToString('N'))))
}

function Remove-SIDiskLookup {
    <# Lets a lookup go: a disk lookup's file is removed; anything else is left to the collector. Never throws. #>
    param($Lookup)
    try { if ($Lookup -is [System.IDisposable]) { $Lookup.Dispose() } } catch { }
}
