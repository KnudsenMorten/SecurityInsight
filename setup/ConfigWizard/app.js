/* =============================================================================
   SecurityInsight v2.2  --  Config Wizard
   app.js -- wizard state machine + page rendering + snippet generation.
   No frameworks, no build, runs straight off file://.
   ============================================================================= */
'use strict';

// ---------------------------------------------------------------------------
// PAGE REGISTRY -- one entry per left-rail item.
//   id     : DOM data-page selector
//   label  : rail text
//   active : false => "Coming soon" placeholder, can't be next-target
// ---------------------------------------------------------------------------
const PAGES = [
  { id: 'welcome',   label: 'Welcome',                active: true  },
  { id: 'tenant',    label: 'Tenant identity',        active: true  },
  { id: 'workspace', label: 'Workspace + ingestion',  active: true  },
  { id: 'output',    label: 'Output sinks',           active: false },
  { id: 'cmdb',      label: 'CMDB integration',       active: false },
  { id: 'apptag',    label: 'App / service tagging',  active: false },
  { id: 'raexcl',    label: 'RA exclusions',          active: false },
  { id: 'assettag',  label: 'Asset exclusion tags',   active: false },
  { id: 'shodan',    label: 'Shodan attack surface',  active: false },
  { id: 'advanced',  label: 'Advanced overrides',     active: false },
  { id: 'review',    label: 'Review & generate',      active: false },
];
// Note: registry holds 11 entries (Welcome + 10 numbered steps). The numbered
// "Step N of 10" labels in the page bodies count from "Tenant identity" onward.

const STORAGE_KEY = 'si.v22.wizard.state.v1';

// ---------------------------------------------------------------------------
// STATE -- single source of truth, mirrored to localStorage on every change.
// ---------------------------------------------------------------------------
const state = {
  currentPage: 'welcome',
  visited: { welcome: true },     // page id -> true once user has navigated to it
  data: {                         // user-entered values, keyed by data-key attr
    spnMode:     'createNew',     // 'createNew' | 'useExisting'
    credType:    'kvSecret',      // 'kvSecret' (= secret) | 'certThumb' (= cert)
    credStorage: 'KeyVault',      // 'KeyVault' | 'LocalCertStore' | 'Inline' (createNew only)
  },
};

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      Object.assign(state, parsed);
      // Ensure required nested objects exist after restore
      state.visited = state.visited || { welcome: true };
      state.data    = state.data    || {};
      if (!state.data.spnMode)     state.data.spnMode     = 'createNew';
      if (!state.data.credType)    state.data.credType    = 'kvSecret';
      if (!state.data.credStorage) state.data.credStorage = 'KeyVault';
    }
  } catch (e) {
    console.warn('Wizard: localStorage restore failed --', e);
  }
}
function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); }
  catch (e) { console.warn('Wizard: localStorage save failed --', e); }
}

// ---------------------------------------------------------------------------
// VALIDATORS -- inline error messages live in <span class="err" data-err="...">
// ---------------------------------------------------------------------------
const GUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HEX40_RE = /^[0-9a-fA-F]{40}$/;
const KV_RE   = /^[a-z][a-z0-9-]{1,22}[a-z0-9]$/;       // 3-24, leading letter

const validators = {
  tenantId:        v => !!v && GUID_RE.test(v),
  appId:           v => !!v && GUID_RE.test(v),
  subscriptionId:  v => !!v && GUID_RE.test(v),
  spnDisplayName:  v => !!v && /^[A-Za-z0-9][A-Za-z0-9 \-_.]{2,}$/.test(v),
  kvName:          v => !!v && KV_RE.test(v),
  secretName:      v => !!v && v.length > 0,
  certThumbprint:  v => !!v && HEX40_RE.test(v.replace(/\s/g, '')),
  workspaceName:   v => !!v && v.length > 0,
  workspaceRg:     v => !!v && v.length > 0,
  dceName:         v => !!v && v.length > 0,
  dceRg:           v => !!v && v.length > 0,
};

function isFieldValid(key) {
  const v = state.data[key];
  const fn = validators[key];
  if (!fn) return true;
  return fn(v == null ? '' : String(v));
}

// Per-page list of required keys -- used to mark a page as "done" in the rail
// and to gate the Next button.
const PAGE_REQS = {
  welcome:   [],
  tenant:    ['tenantId', 'appId'].concat(/* credType-dependent, added dynamically */),
  workspace: ['subscriptionId', 'workspaceName', 'workspaceRg', 'dceName', 'dceRg'],
};

function tenantRequiredKeys() {
  // Required fields branch by SPN mode:
  //   createNew  -> tenantId + spnDisplayName (+ kvName when CredStorage=KeyVault)
  //   useExisting -> tenantId + appId + cred-block fields
  if (state.data.spnMode === 'createNew') {
    const base = ['tenantId', 'spnDisplayName'];
    if (state.data.credStorage === 'KeyVault') return base.concat(['kvName']);
    // LocalCertStore + Inline don't need an additional input; cred is generated locally / returned inline.
    return base;
  }
  // useExisting (legacy / power-user path)
  const base = ['tenantId', 'appId'];
  if (state.data.credType === 'certThumb') return base.concat(['certThumbprint']);
  return base.concat(['kvName', 'secretName']);
}

function isPageDone(pageId) {
  if (pageId === 'welcome') return !!state.visited.welcome;
  let reqs;
  if (pageId === 'tenant')    reqs = tenantRequiredKeys();
  else if (pageId === 'workspace') reqs = PAGE_REQS.workspace;
  else                        reqs = PAGE_REQS[pageId] || [];
  if (reqs.length === 0) return false;
  return reqs.every(isFieldValid);
}

// ---------------------------------------------------------------------------
// SNIPPET GENERATORS -- each page that emits config has its own builder.
// All snippets are rendered with simple syntax highlighting via <span> wraps.
// ---------------------------------------------------------------------------

// Wrap PowerShell snippet text in <span class="cmt|var|str"> tokens.
// Cheap-but-readable -- not a real tokenizer, deliberately conservative.
function highlightPs(raw) {
  // Escape HTML first
  let s = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  // Trailing comments (after a closing single-quote + whitespace) -- match BEFORE
  // the string rule so the trailing '# default' tag on a default-value line wins.
  s = s.replace(/('\s+)(#[^\n]*)$/gm, '$1<span class="cmt">$2</span>');
  // Full-line comments (# to end-of-line) -- preserve leading whitespace
  s = s.replace(/^(\s*)(#.*)$/gm, '$1<span class="cmt">$2</span>');
  // Single-quoted strings
  s = s.replace(/('[^']*')/g, '<span class="str">$1</span>');
  // $global:Foo variables
  s = s.replace(/(\$global:[A-Za-z_][A-Za-z0-9_]*)/g, '<span class="var">$1</span>');
  return s;
}

function psQuote(v) {
  if (v == null) return "''";
  return "'" + String(v).replace(/'/g, "''") + "'";
}

// Resolve the value for a state key, preferring (in order):
//   1. user-typed value in state.data
//   2. the input's data-default attribute (real wizard default)
//   3. the supplied <fallback> placeholder token (e.g. '<sub-guid>')
// Returns { quoted, isDefault } so the snippet can mark default lines visibly.
function resolveValue(key, fallback) {
  const v = state.data[key];
  const el = document.querySelector('input[data-key="' + key + '"]');
  const def = el ? el.getAttribute('data-default') : null;
  if (v != null && v !== '') {
    // Defaults are pre-seeded into state, so flag isDefault when the
    // user-visible value still matches the recommended default.
    return { quoted: psQuote(v), isDefault: (def != null && v === def) };
  }
  if (def) return { quoted: psQuote(def), isDefault: true };
  return { quoted: psQuote(fallback), isDefault: false };
}

// Build a '$global:Var = <value>' line, padded to <pad> so multiple lines
// align, with a trailing '# default' marker when the value came from the
// input's data-default attribute (so customers see WHAT they get if they
// leave the field untouched).
function assignLine(varName, key, fallback, pad) {
  const r = resolveValue(key, fallback);
  const head = '$global:' + varName + ' '.repeat(Math.max(1, (pad || 0) - varName.length)) + '= ' + r.quoted;
  return r.isDefault ? head + '   # default' : head;
}

// Tenant page snippet: branches by SPN mode.
//   createNew  -> shows the "wizard will create on Apply" template; AppId / cred
//                 are placeholders the wizard's /api/apply endpoint fills in.
//   useExisting -> classic snippet using the existing AppId + cred details.
function buildTenantSnippet() {
  const d = state.data;
  const lines = [];
  lines.push('# ----------------------------------------------------------------------------');
  lines.push('# SecurityInsight v2.2 -- Tenant identity (Layer 5: LauncherConfig.custom.ps1)');
  lines.push('# Generated by Setup-SecurityInsight -Wizard.');
  lines.push('# ----------------------------------------------------------------------------');
  lines.push('');

  if (d.spnMode === 'createNew') {
    lines.push('# --- Tenant ----------------------------------------------------------------');
    lines.push(assignLine('SpnTenantId', 'tenantId', '<tenant-guid>', 14));
    lines.push('');
    lines.push('# --- SPN to be CREATED on Apply --------------------------------------------');
    lines.push('# The wizard\'s /api/apply endpoint runs New-SISpn:');
    lines.push('#   - Creates Entra app registration "' + (resolveValue('spnDisplayName', '<spn-display-name>').raw) + '"');
    const credKindHuman = (d.credType === 'certThumb') ? 'Self-signed certificate' : 'Client secret';
    lines.push('#   - Generates credential : ' + credKindHuman);
    lines.push('#   - Stores credential in : ' + (d.credStorage || 'KeyVault'));
    if (d.credStorage === 'KeyVault') {
      lines.push('#   - Key Vault            : ' + (resolveValue('kvName', '<kv-name>').raw));
    }
    lines.push('#   - Grants Microsoft Graph permissions + admin consent');
    lines.push('#   - Grants RBAC at root MG: Reader + Tag Contributor');
    lines.push('# After Apply, $global:SI_SPN_AppId / SI_SPN_Secret (or _CertThumbprint)');
    lines.push('# are written to config\\SecurityInsight.custom.ps1 automatically.');
    lines.push('# To trigger Apply directly:');
    lines.push('#   Invoke-RestMethod -Method POST http://localhost:8766/api/apply -ContentType application/json -Body $stateJson');
    return lines.join('\n');
  }

  // useExisting (legacy / power-user path)
  lines.push('# --- Tenant + service principal --------------------------------------------');
  lines.push(assignLine('SpnTenantId', 'tenantId', '<tenant-guid>',     14));
  lines.push(assignLine('SpnClientId', 'appId',    '<app-client-guid>', 14));
  lines.push('');
  if (d.credType === 'certThumb') {
    lines.push('# --- Credential: certificate thumbprint (recommended for production) ------');
    lines.push(assignLine('SpnCertificateThumbprint', 'certThumbprint', '<40-hex-chars>', 26));
  } else {
    lines.push('# --- Credential: secret stored in Azure Key Vault -------------------------');
    lines.push(assignLine('SpnKeyVaultName', 'kvName',     '<kv-name>',     18));
    lines.push(assignLine('SpnSecretName',   'secretName', '<secret-name>', 18));
  }
  return lines.join('\n');
}

// Workspace page snippet: cumulative -- includes tenant block too so the
// customer can copy ONE block and have it all.
function buildWorkspaceSnippet() {
  const d = state.data;
  const lines = [];
  lines.push(buildTenantSnippet());
  lines.push('');
  lines.push('# --- Subscription + Log Analytics workspace ----------------------------');
  lines.push(assignLine('SubscriptionId',         'subscriptionId', '<sub-guid>',       25));
  lines.push(assignLine('WorkspaceName',          'workspaceName',  '<workspace-name>', 25));
  lines.push(assignLine('WorkspaceResourceGroup', 'workspaceRg',    '<workspace-rg>',   25));
  lines.push('');
  lines.push('# --- Data Collection Endpoint ------------------------------------------');
  lines.push(assignLine('DceName',          'dceName', '<dce-name>', 18));
  lines.push(assignLine('DceResourceGroup', 'dceRg',   '<dce-rg>',   18));
  return lines.join('\n');
}

const SNIPPET_BUILDERS = {
  tenant:    buildTenantSnippet,
  workspace: buildWorkspaceSnippet,
};

function renderPreviews() {
  // Re-render the snippet on every keystroke for the active page (cheap).
  const builder = SNIPPET_BUILDERS[state.currentPage];
  if (!builder) return;
  const target = document.getElementById('preview-' + state.currentPage);
  if (!target) return;
  target.innerHTML = highlightPs(builder());
}

// ---------------------------------------------------------------------------
// RAIL RENDERING -- 11 entries with status badges.
// Badges: ✓ done · ● current · ○ pending · ⊘ coming-soon
// ---------------------------------------------------------------------------
function renderRail() {
  const ul = document.getElementById('rail-nav');
  ul.innerHTML = '';
  PAGES.forEach((p, idx) => {
    const li = document.createElement('li');
    li.dataset.page = p.id;
    li.className = '';
    let badgeChar;
    if (!p.active) {
      li.classList.add('soon', 'disabled');
      badgeChar = '\u2298';                 // ⊘ coming soon
    } else if (p.id === state.currentPage) {
      li.classList.add('current');
      badgeChar = '\u25CF';                 // ● current
    } else if (isPageDone(p.id)) {
      li.classList.add('done');
      badgeChar = '\u2713';                 // ✓ done
    } else {
      badgeChar = '\u25CB';                 // ○ pending
    }
    const num = (idx === 0) ? '' : String(idx);
    li.innerHTML = '<span class="num">' + num + '</span>' +
                   '<span class="badge">' + badgeChar + '</span>' +
                   '<span class="label">' + p.label + '</span>';
    if (p.active) {
      li.addEventListener('click', () => goToPage(p.id));
    }
    ul.appendChild(li);
  });
}

// ---------------------------------------------------------------------------
// PAGE NAVIGATION
// ---------------------------------------------------------------------------
function goToPage(id) {
  const target = PAGES.find(p => p.id === id);
  if (!target || !target.active) return;
  state.currentPage = id;
  state.visited[id] = true;
  saveState();
  renderApp();
  // Scroll the main content area to top so we don't land mid-page.
  document.querySelector('.main').scrollTo({ top: 0, behavior: 'instant' });
}

// "Next" only walks active pages -- skips placeholder Coming-Soon items.
function nextPage() {
  const activeIds = PAGES.filter(p => p.active).map(p => p.id);
  const i = activeIds.indexOf(state.currentPage);
  if (i >= 0 && i < activeIds.length - 1) goToPage(activeIds[i + 1]);
}
function prevPage() {
  const activeIds = PAGES.filter(p => p.active).map(p => p.id);
  const i = activeIds.indexOf(state.currentPage);
  if (i > 0) goToPage(activeIds[i - 1]);
}

// ---------------------------------------------------------------------------
// PAGE / FORM RENDERING
// ---------------------------------------------------------------------------
function renderProgress() {
  const idx = PAGES.findIndex(p => p.id === state.currentPage);
  const total = PAGES.length;
  document.getElementById('progress-text').textContent =
    'Page ' + (idx + 1) + ' of ' + total + '  \u00B7  ' + (PAGES[idx] ? PAGES[idx].label : '');
  document.getElementById('progress-fill').style.width =
    (((idx + 1) / total) * 100).toFixed(1) + '%';
}

function renderNavButtons() {
  const activeIds = PAGES.filter(p => p.active).map(p => p.id);
  const i = activeIds.indexOf(state.currentPage);
  const back = document.getElementById('btn-back');
  const next = document.getElementById('btn-next');
  back.disabled = (i <= 0);
  // No more active pages after current => disable next
  const noMore = (i < 0) || (i >= activeIds.length - 1);
  next.disabled = noMore;
  next.textContent = noMore ? 'End of scaffold' : 'Next \u2192';
}

function showCurrentPageOnly() {
  document.querySelectorAll('.page').forEach(el => {
    el.hidden = (el.dataset.page !== state.currentPage);
  });
}

// Hydrate every input on the current page from state.data, attach change
// listeners, and run validators.
function hydrateForms() {
  // Text inputs
  document.querySelectorAll('input[data-key]').forEach(input => {
    const key = input.dataset.key;
    // First-touch default seeding: if the field has a data-default and the
    // user has never written to it (state is null/undefined, NOT empty
    // string -- empty means they cleared it deliberately), seed the state
    // and the input value from data-default so the recommended value is
    // visible and "accept defaults = just click Next" works.
    const def = input.getAttribute('data-default');
    if (state.data[key] == null && def) {
      state.data[key] = def;
      saveState();
    }
    if (state.data[key] != null) input.value = state.data[key];
    if (!input._wired) {
      input.addEventListener('input', () => {
        state.data[key] = input.value.trim();
        validateField(input);
        saveState();
        renderPreviews();
        renderRail();   // status badges may flip
        renderNavButtons();
      });
      input._wired = true;
    }
    validateField(input);
  });

  // Toggle groups (radio-style)
  document.querySelectorAll('[data-toggle-key]').forEach(group => {
    const key = group.dataset.toggleKey;
    group.querySelectorAll('label[data-val]').forEach(lbl => {
      const val = lbl.dataset.val;
      const checked = (state.data[key] === val);
      lbl.classList.toggle('checked', checked);
      const radio = lbl.querySelector('input[type="radio"]');
      if (radio) radio.checked = checked;
      if (!lbl._wired) {
        lbl.addEventListener('click', () => {
          state.data[key] = val;
          saveState();
          hydrateForms();
          syncCredBlocks();
          renderPreviews();
          renderRail();
          renderNavButtons();
        });
        lbl._wired = true;
      }
    });
  });

  syncCredBlocks();
}

// Show/hide the SPN-mode / cred-type / cred-storage blocks on the Tenant page.
//   data-spn-mode-block      = 'createNew' | 'useExisting'
//   data-cred-block          = 'kvSecret'  | 'certThumb'   (legacy = useExisting cred block)
//   data-cred-storage-block  = 'KeyVault'  | 'LocalCertStore' | 'Inline'  (createNew only)
//
// Compound visibility: an element is shown only if ALL its data-* filters match the
// current state. This lets the HTML mark e.g. "createNew + KeyVault" with two attrs
// and we only show it when both are active.
function syncCredBlocks() {
  // Defensive: ensure the three driver fields are populated. Old localStorage
  // from pre-v2.2.106 sessions may be missing them, which breaks the visibility
  // pass below (every conditional would compare to undefined and pass-through).
  if (!state.data.spnMode)     state.data.spnMode     = 'createNew';
  if (!state.data.credType)    state.data.credType    = 'kvSecret';
  if (!state.data.credStorage) state.data.credStorage = 'KeyVault';
  // Auto-correct illegal credType x credStorage combos so a hidden radio is
  // never the active selection. LocalCertStore is cert-only; Inline is
  // secret-only. KeyVault works for both. When the user flips credType, we
  // silently snap credStorage back to KeyVault if the current pick became
  // invalid.
  if (state.data.credType === 'kvSecret'  && state.data.credStorage === 'LocalCertStore') state.data.credStorage = 'KeyVault';
  if (state.data.credType === 'certThumb' && state.data.credStorage === 'Inline')         state.data.credStorage = 'KeyVault';
  const elsMode = document.querySelectorAll('[data-spn-mode-block]');
  elsMode.forEach(b => {
    const wantMode    = b.dataset.spnModeBlock;
    const wantCred    = b.dataset.credBlock;
    const wantStorage = b.dataset.credStorageBlock;
    let hide = false;
    if (wantMode    && wantMode    !== state.data.spnMode)     hide = true;
    if (wantCred    && wantCred    !== state.data.credType)    hide = true;
    if (wantStorage && wantStorage !== state.data.credStorage) hide = true;
    b.hidden = hide;
  });
  // Legacy single-attr blocks (cred-block only, no spn-mode) -- keep working.
  const credOnly = document.querySelectorAll('[data-cred-block]:not([data-spn-mode-block])');
  credOnly.forEach(b => { b.hidden = (b.dataset.credBlock !== state.data.credType); });
  // Cred-storage-only blocks (rare).
  const storageOnly = document.querySelectorAll('[data-cred-storage-block]:not([data-spn-mode-block])');
  storageOnly.forEach(b => { b.hidden = (b.dataset.credStorageBlock !== state.data.credStorage); });
}

function validateField(input) {
  const key = input.dataset.key;
  if (!validators[key]) return;
  // Empty + not-yet-required => no error styling (don't yell at the customer
  // before they've typed anything, but mark as invalid so badges work).
  const val = (input.value || '').trim();
  const errEl = document.querySelector('.err[data-err="' + key + '"]');
  if (val === '') {
    input.classList.remove('invalid');
    if (errEl) errEl.classList.remove('show');
    return;
  }
  const ok = validators[key](val);
  input.classList.toggle('invalid', !ok);
  if (errEl) errEl.classList.toggle('show', !ok);
}

// ---------------------------------------------------------------------------
// MASTER RENDER
// ---------------------------------------------------------------------------
function renderApp() {
  showCurrentPageOnly();
  hydrateForms();
  renderPreviews();
  renderRail();
  renderProgress();
  renderNavButtons();
}

// ---------------------------------------------------------------------------
// COPY-TO-CLIPBOARD -- buttons with data-copy="<elementId>"
// ---------------------------------------------------------------------------
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg || 'Copied to clipboard.';
  t.classList.add('show');
  clearTimeout(showToast._tid);
  showToast._tid = setTimeout(() => t.classList.remove('show'), 1800);
}

async function copyById(id) {
  const el = document.getElementById(id);
  if (!el) return;
  // Use textContent to strip the syntax-highlight <span> wrappers.
  const text = el.textContent;
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard.');
  } catch (e) {
    // Fallback for file:// + older browsers (clipboard API often blocked there).
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showToast('Copied to clipboard.'); }
    catch (_) { showToast('Copy failed -- select + Ctrl+C manually.'); }
    document.body.removeChild(ta);
  }
}

// ---------------------------------------------------------------------------
// INIT
// ---------------------------------------------------------------------------
function init() {
  loadState();

  // Wire the hero buttons on the Welcome page.
  document.getElementById('btn-start').addEventListener('click', () => goToPage('tenant'));
  document.getElementById('btn-reset').addEventListener('click', () => {
    if (!confirm('Reset every wizard answer and clear localStorage?')) return;
    localStorage.removeItem(STORAGE_KEY);
    // Reset the in-memory state too -- mutating in place because consts above
    // hold references to these objects.
    state.currentPage = 'welcome';
    state.visited = { welcome: true };
    Object.keys(state.data).forEach(k => delete state.data[k]);
    state.data.credType = 'kvSecret';
    // Clear input element values manually -- hydrateForms only writes when
    // state has a value; it doesn't blank stale DOM input.value.
    document.querySelectorAll('input[data-key]').forEach(i => { i.value = ''; });
    renderApp();
    showToast('All answers cleared.');
  });

  // Bottom-bar nav
  document.getElementById('btn-next').addEventListener('click', nextPage);
  document.getElementById('btn-back').addEventListener('click', prevPage);

  // Keyboard nav: Enter advances when current page is "done", but not when
  // focused inside a textarea or when the user is in the middle of typing in
  // an invalid field.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const tag = (e.target && e.target.tagName) || '';
    if (tag === 'TEXTAREA' || tag === 'BUTTON') return;
    if (isPageDone(state.currentPage)) {
      e.preventDefault();
      nextPage();
    }
  });

  // Copy buttons (delegated -- works for buttons in placeholder cards too).
  document.body.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy]');
    if (btn) copyById(btn.dataset.copy);
  });

  renderApp();
}

// Defer until DOM is parsed (script tag is at end of body but kept for safety).
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}


// ===========================================================================
// APPLY PAGE  (Step 10) -- POSTs the wizard's collected state to /api/apply,
// renders 3-phase progress (SPN -> Infrastructure -> Config file), shows the
// result (or error) in-page. The /api/apply backend is live since v2.2.105.
// ===========================================================================
function buildApplyState() {
    var d = state.data || {};
    var st = {
        tenantId:       d.tenantId       || '',
        subscriptionId: d.subscriptionId || '',
        spn: {
            displayName: d.spnMode === 'createNew' ? (d.spnDisplayName || 'sp-securityinsight') : null,
            credKind:    d.credType === 'certThumb' ? 'Cert' : 'Secret',
            credStorage: d.credStorage || 'Inline'
        },
        infra: {
            location:           d.location           || 'westeurope',
            resourceGroupName:  d.workspaceRg        || 'rg-securityinsight',
            workspaceName:      d.workspaceName      || 'log-platform-management-securityinsight',
            dceName:            d.dceName            || 'dce-securityinsight',
            storageAccountName: d.storageAccountName || ''
        }
    };
    if (d.kvName) {
        st.spn.keyVaultName = d.kvName;
        st.infra.keyVaultName = d.kvName;
    }
    if (d.smtpServer || d.mailTo) {
        st.smtp = {
            Server:   d.smtpServer || null,
            Port:     d.smtpPort   ? Number(d.smtpPort) : 587,
            UseSsl:   d.smtpUseSsl !== false,
            User:     d.smtpUser     || null,
            Password: d.smtpPassword || null,
            From:     d.smtpFrom     || null,
            MailTo:   (d.mailTo || '').split(/[,;\s]+/).filter(Boolean)
        };
    }
    if (d.openAiEndpoint) {
        st.openAi = {
            Endpoint:    d.openAiEndpoint,
            Deployment:  d.openAiDeployment || null,
            ApiKey:      d.openAiApiKey || null
        };
    }
    if (d.shodanApiKey) {
        st.shodan = { ApiKey: d.shodanApiKey };
    }
    if (d.cmdbEnabled) {
        st.cmdb = { Enabled: true, RefreshHours: d.cmdbRefreshHours ? Number(d.cmdbRefreshHours) : 24, CsvPath: d.cmdbCsvPath || null };
    }
    if (d.enableJsonSink) st.enableJsonSink = true;
    if (d.defenderWorkspaceResourceId) st.defenderWorkspaceResourceId = d.defenderWorkspaceResourceId;
    return st;
}

function renderApplySummary() {
    var d = state.data || {};
    var st = buildApplyState();
    var spnEl = document.getElementById('apply-summary-spn');
    if (spnEl) {
        if (d.spnMode === 'createNew') {
            spnEl.textContent =
                'Create SPN "' + st.spn.displayName + '" in tenant ' + (st.tenantId || '<TENANT-ID>') + '\n' +
                'Cred kind    : ' + st.spn.credKind + '\n' +
                'Cred storage : ' + st.spn.credStorage +
                (st.spn.keyVaultName ? ('\nKey Vault    : ' + st.spn.keyVaultName) : '');
        } else {
            spnEl.textContent = 'Use existing SPN ' + (d.appId || '<APP-ID>') + ' in tenant ' + (st.tenantId || '<TENANT-ID>');
        }
    }
    var inEl = document.getElementById('apply-summary-infra');
    if (inEl) {
        inEl.textContent =
            'Subscription : ' + (st.subscriptionId || '<SUB-ID>') + '\n' +
            'Location     : ' + st.infra.location + '\n' +
            'Workspace    : ' + st.infra.workspaceName + ' (RG ' + st.infra.resourceGroupName + ')\n' +
            'DCE          : ' + st.infra.dceName + '\n' +
            'Storage      : ' + (st.infra.storageAccountName || '<STORAGE-ACCT>') + '   <- RBAC-only, no shared key';
    }
    var cfgEl = document.getElementById('apply-summary-config');
    if (cfgEl) {
        var optional = [];
        if (st.smtp)     optional.push('SMTP');
        if (st.openAi)   optional.push('Azure OpenAI');
        if (st.shodan)   optional.push('Shodan');
        if (st.cmdb)     optional.push('CMDB');
        if (st.enableJsonSink) optional.push('JSON sink');
        cfgEl.textContent = 'Write config\\SecurityInsight.custom.ps1 (existing file backed up to *.bak.<timestamp>).\n' +
            'Optional sections: ' + (optional.length ? optional.join(', ') : 'none');
    }
    var pre = document.getElementById('preview-apply');
    if (pre) {
        var safeSt = JSON.parse(JSON.stringify(st));
        if (safeSt.smtp && safeSt.smtp.Password)   safeSt.smtp.Password = '***';
        if (safeSt.openAi && safeSt.openAi.ApiKey) safeSt.openAi.ApiKey = '***';
        if (safeSt.shodan && safeSt.shodan.ApiKey) safeSt.shodan.ApiKey = '***';
        pre.textContent = JSON.stringify(safeSt, null, 2);
    }
}

function setApplyPhase(phase, status) {
    var el = document.querySelector('.apply-phase[data-phase="' + phase + '"]');
    if (!el) return;
    el.dataset.status = status;
    var ic = el.querySelector('.apply-icon');
    var stEl = el.querySelector('.apply-status');
    if (ic) {
        ic.innerHTML = status === 'ok' ? '&#10003;'
                       : status === 'failed' ? '&#10007;'
                       : status === 'running' ? '&#9696;'
                       : '&#9711;';
    }
    if (stEl) stEl.textContent = status;
}

function setApplyStatePill(text, bg) {
    var p = document.getElementById('apply-state-pill');
    if (!p) return;
    p.textContent = text;
    if (bg) p.style.background = bg;
}

function _esc(s) {
    return String(s).replace(/[<&>]/g, function(c) { return c === '<' ? '&lt;' : c === '>' ? '&gt;' : '&amp;'; });
}

async function runApply() {
    var btn = document.getElementById('btn-apply');
    var progress = document.getElementById('apply-progress');
    var result = document.getElementById('apply-result');
    if (!btn || !progress || !result) return;
    btn.disabled = true;
    btn.textContent = 'Applying...';
    progress.style.display = 'block';
    result.innerHTML = '';
    setApplyPhase('spn', 'running');
    setApplyPhase('infra', 'pending');
    setApplyPhase('config', 'pending');
    setApplyStatePill('RUNNING', '#fff4e5');

    var payload = JSON.stringify(buildApplyState());
    var respText = '';
    try {
        var resp = await fetch('/api/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload
        });
        respText = await resp.text();
        var obj = null;
        try { obj = JSON.parse(respText); } catch (e) { /* keep raw */ }

        if (resp.ok && obj && obj.ok) {
            setApplyPhase('spn', 'ok');
            setApplyPhase('infra', 'ok');
            setApplyPhase('config', 'ok');
            setApplyStatePill('DONE', '#e8f5e9');
            var appId = (obj.spn && obj.spn.AppId) || '?';
            var wsId  = (obj.infra && obj.infra.WorkspaceResourceId) || '?';
            var cfgPath = (obj.configFile && obj.configFile.Path) || '?';
            var cfgBytes = (obj.configFile && obj.configFile.Bytes) || 0;
            var cfgSecs = (obj.configFile && obj.configFile.Sections) || [];
            result.innerHTML =
                '<div class="note" style="background:#e8f5e9;border-left-color:#2e7d32;">' +
                '<b>&#10003; Apply succeeded.</b><br>' +
                'SPN AppId: <code>' + _esc(appId) + '</code><br>' +
                'Workspace: <code>' + _esc(wsId) + '</code><br>' +
                'Config file: <code>' + _esc(cfgPath) + '</code> (' + cfgBytes + ' bytes)<br>' +
                'Sections written: ' + _esc(cfgSecs.join(', ') || '(none)') + '</div>';
        } else {
            var phase = (obj && obj.phase) || 'unknown';
            var err   = (obj && obj.error) || respText || ('HTTP ' + resp.status);
            var ps = (obj && obj.phaseStatus) || {};
            ['spn','infra','config'].forEach(function(p) {
                if (ps[p]) setApplyPhase(p, ps[p]);
                else if (p === phase) setApplyPhase(p, 'failed');
            });
            setApplyStatePill('FAILED', '#fdecea');
            result.innerHTML =
                '<div class="note warn"><b>&#10007; Apply failed at phase: ' + _esc(phase) + '</b><br>' +
                '<pre style="white-space:pre-wrap;font-size:12px;margin:8px 0;">' + _esc(err) + '</pre></div>';
        }
    } catch (e) {
        setApplyPhase('spn', 'failed');
        setApplyStatePill('FAILED', '#fdecea');
        result.innerHTML = '<div class="note warn"><b>&#10007; Apply failed (network)</b><br>' + _esc(e.message || e) + '</div>';
    } finally {
        btn.disabled = false;
        btn.innerHTML = '&#9658; Apply now';
    }
}

function wireApplyPage() {
    var btn = document.getElementById('btn-apply');
    if (btn && !btn._wired) {
        btn.addEventListener('click', runApply);
        btn._wired = true;
    }
    renderApplySummary();
}

// Re-render the apply summary every time the user lands on the review page.
var _origGoToPage = goToPage;
goToPage = function(id) {
    _origGoToPage(id);
    if (id === 'review') wireApplyPage();
};
