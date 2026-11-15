#Requires -Version 7.0
<#
    THE PAGE KEEPS THE PLATFORM'S SIGN-IN FRESH, WITH NO LOOP (#1263, framework AUTH-MODERN-1).

    With Microsoft's built-in sign-in the web app checks the ID token's expiry strictly, so the page refreshes the
    platform's session itself: wwwroot/js/auth-refresh.js wraps fetch() -- /.auth/refresh before the token's exp and ONCE on
    a 401 (the fetch repeated once), one navigation to the sign-in when the refresh fails (at most once per 5 minutes).

    This suite RUNS the script with node in a sandbox (a fake fetch, location, timers and session storage; nothing reaches a
    network) and checks what it does. Offline. Needs node on the test machine; without it the suite FAILS.
#>
Describe 'auth-refresh.js: refresh before expiry, once on a 401, never a loop' {
    BeforeAll {
        $script:Node = (Get-Command -Name node -ErrorAction SilentlyContinue | Select-Object -First 1)
        $script:Script = Join-Path $PSScriptRoot ('..{0}..{0}pro-management{0}src{0}SI.Management.Web{0}wwwroot{0}js{0}auth-refresh.js' -f [IO.Path]::DirectorySeparatorChar)
        $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('si-authrefresh-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:Work -Force
        $harness = Join-Path $script:Work 'harness.cjs'
        Set-Content -LiteralPath $harness -Encoding utf8NoBOM -Value @'
const vm = require("vm"), fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
const NOW = Date.parse("2026-11-15T12:00:00Z");
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const flush = async () => { for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r)); };

function page(o) {
  const calls = [], assigns = [], timers = [], store = {};
  const idToken = "h." + b64({ exp: Math.floor((NOW + o.expInMs) / 1000) }) + ".s";
  const resp = s => ({ status: s, ok: s >= 200 && s < 300, json: async () => null });
  const fetch = async (input) => {
    const u = typeof input === "string" ? input : input.url;
    calls.push(u);
    if (u === "/.auth/me") return { status: 200, ok: true, json: async () => [{ id_token: idToken }] };
    if (u === "/.auth/refresh") return resp(o.refreshOk ? 200 : 401);
    return resp(o.status(u, calls.filter(c => c === u).length));
  };
  const path = o.path || "/Findings";
  const ctx = {
    fetch, URL, JSON, Array, Number, String, Math, isNaN, Promise,
    location: { pathname: path, search: "?a=1", href: "https://si.example.test" + path + "?a=1", origin: "https://si.example.test", assign: u => assigns.push(u) },
    sessionStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
    document: { visibilityState: "visible", addEventListener() {} },
    setTimeout: (f, ms) => { timers.push(ms); return timers.length; }, clearTimeout() {},
    Date: { now: () => NOW, parse: Date.parse },
    atob: s => Buffer.from(s, "base64").toString("binary"),
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  return { ctx, calls, assigns, timers, n: u => calls.filter(c => c === u).length };
}

const out = {};
(async () => {
  // 1. a 401, the refresh works, the repeat answers 200: one refresh, the fetch twice, no navigation
  let p = page({ expInMs: 60 * 60000, refreshOk: true, status: (u, n) => n === 1 ? 401 : 200 });
  await flush();
  let r = await p.ctx.fetch("/api/x"); await flush();
  out.retryOnce = { status: r.status, fetches: p.n("/api/x"), refreshes: p.n("/.auth/refresh"), navigations: p.assigns.length };

  // 2. always 401, the refresh works: the fetch exactly twice, one refresh, the 401 handed back, no navigation
  p = page({ expInMs: 60 * 60000, refreshOk: true, status: () => 401 });
  await flush();
  r = await p.ctx.fetch("/api/x"); await flush();
  out.stillUnauthorized = { status: r.status, fetches: p.n("/api/x"), refreshes: p.n("/.auth/refresh"), navigations: p.assigns.length };

  // 3. the refresh fails: one navigation to the sign-in (back to this page); a second 401 on the same page navigates no more
  p = page({ expInMs: 60 * 60000, refreshOk: false, status: () => 401 });
  await flush();
  r = await p.ctx.fetch("/api/x"); await flush();
  const first = p.assigns.slice();
  await p.ctx.fetch("/api/y"); await flush();
  out.reloginOnce = { status: r.status, fetches: p.n("/api/x"), refreshes: p.n("/.auth/refresh"), navigations: p.assigns.length, url: first[0] || "" };

  // 4. three 401s at once: ONE refresh for all of them
  p = page({ expInMs: 60 * 60000, refreshOk: true, status: (u, n) => n === 1 ? 401 : 200 });
  await flush();
  await Promise.all([p.ctx.fetch("/api/a"), p.ctx.fetch("/api/b"), p.ctx.fetch("/api/c")]); await flush();
  out.oneRefreshInFlight = { refreshes: p.n("/.auth/refresh") };

  // 5. another site's 401 and the platform's own paths: never refreshed
  p = page({ expInMs: 60 * 60000, refreshOk: true, status: () => 401 });
  await flush();
  await p.ctx.fetch("https://elsewhere.example.test/x"); await p.ctx.fetch("/.auth/me/x"); await flush();
  out.crossOrigin = { refreshes: p.n("/.auth/refresh") };

  // 6. proactive: 2 minutes left = refresh at load; an hour left = a timer for 5 minutes before exp, no refresh yet
  p = page({ expInMs: 2 * 60000, refreshOk: true, status: () => 200 });
  await flush();
  out.proactiveSoon = { refreshes: p.n("/.auth/refresh") };
  p = page({ expInMs: 60 * 60000, refreshOk: true, status: () => 200 });
  await flush();
  out.proactiveLater = { refreshes: p.n("/.auth/refresh"), timer: p.timers[0] || 0 };

  // 7. a refresh that does not move the exp: at most one more proactive refresh, then the 401 path takes over
  p = page({ expInMs: 60000, refreshOk: true, status: () => 200 });
  await flush(); await flush();
  out.noProactiveLoop = { refreshes: p.n("/.auth/refresh") };

  // 8. a magic-link session: the script does nothing (fetch is not wrapped)
  p = page({ expInMs: 60000, refreshOk: true, status: () => 401, path: "/MagicLink/s/Findings" });
  await flush();
  r = await p.ctx.fetch("/MagicLink/s/api/x"); await flush();
  out.magicLink = { status: r.status, calls: p.calls.length, refreshes: p.n("/.auth/refresh") };

  console.log(JSON.stringify(out));
})().catch(e => { console.error(e && e.stack || e); process.exit(1); });
'@
        $script:Result = $null
        if ($script:Node) {
            $raw = & $script:Node.Source $harness $script:Script 2>&1
            $script:Exit = $LASTEXITCODE
            $script:Raw = @($raw | ForEach-Object { "$_" }) -join "`n"
            if ($script:Exit -eq 0) { $script:Result = ($script:Raw.Trim().Split("`n")[-1]) | ConvertFrom-Json }
        }
    }
    AfterAll { if ($script:Work -and (Test-Path -LiteralPath $script:Work)) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'node is on this machine and the script ran in the sandbox' {
        $script:Node | Should -Not -BeNullOrEmpty -Because 'this suite runs auth-refresh.js with node; install node on the test machine so the script runs'
        $script:Exit | Should -Be 0 -Because $script:Raw
        $script:Result | Should -Not -BeNullOrEmpty
    }

    It 'a 401 refreshes once and repeats the fetch once' {
        $r = $script:Result.retryOnce
        $r.status | Should -Be 200; $r.fetches | Should -Be 2; $r.refreshes | Should -Be 1; $r.navigations | Should -Be 0
    }

    It 'a 401 after the refresh is handed back -- never a second refresh or repeat' {
        $r = $script:Result.stillUnauthorized
        $r.status | Should -Be 401; $r.fetches | Should -Be 2; $r.refreshes | Should -Be 1; $r.navigations | Should -Be 0
    }

    It 'a failed refresh navigates to the sign-in ONCE, back to the same page' {
        $r = $script:Result.reloginOnce
        $r.status | Should -Be 401; $r.fetches | Should -Be 1; $r.navigations | Should -Be 1
        $r.url | Should -Be ('/.auth/login/aad?post_login_redirect_uri=' + [uri]::EscapeDataString('/Findings?a=1'))
    }

    It 'concurrent 401s share one refresh' { $script:Result.oneRefreshInFlight.refreshes | Should -Be 1 }

    It "another site's 401 and the platform's own paths are never refreshed" { $script:Result.crossOrigin.refreshes | Should -Be 0 }

    It 'refreshes before expiry: at once with < 5 minutes left, else a timer for 5 minutes before exp' {
        $script:Result.proactiveSoon.refreshes | Should -Be 1
        $script:Result.proactiveLater.refreshes | Should -Be 0
        $script:Result.proactiveLater.timer | Should -Be (55 * 60 * 1000)
    }

    It 'a refresh that does not move the expiry does not loop' { $script:Result.noProactiveLoop.refreshes | Should -BeLessOrEqual 2 }

    It 'does nothing in a magic-link session' {
        $r = $script:Result.magicLink
        $r.status | Should -Be 401; $r.calls | Should -Be 1; $r.refreshes | Should -Be 0
    }
}
