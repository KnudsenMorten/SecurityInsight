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
  { id: 'output',    label: 'Mail / SMTP',            active: true  },
  { id: 'cmdb',      label: 'CMDB integration',       active: true  },
  { id: 'apptag',    label: 'Azure OpenAI',           active: true  },
  { id: 'raexcl',    label: 'RA exclusions',          active: false },  // power-user; v2.2.112+
  { id: 'assettag',  label: 'Asset exclusion tags',   active: false },  // power-user; v2.2.112+
  { id: 'shodan',    label: 'Shodan attack surface',  active: true  },
  { id: 'advanced',  label: 'Output sinks + Defender', active: true  },
  { id: 'review',    label: 'Apply',                  active: true  },
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
    credType:    'kvSecret',      // 'kvSecret' (= secret) | 'certThumb' (= cert, recommended for production)
    credStorage: 'Inline',        // 'KeyVault' | 'LocalCertStore' | 'Inline' (auto-snapped to a valid combo for hostType + credType)
    hostType:    'win',           // 'win' | 'azureVMMI' | 'azureContainerMI' (drives valid auth options)
    // Optional-feature master toggles (each defaults OFF -- explicit opt-in)
    smtpMode:      'off',         // 'off' | 'anon' | 'auth'
    cmdbMode:      'off',         // 'off' | 'csv'
    openAiMode:    'off',         // 'off' | 'enabled'
    openAiResMode: 'useExisting', // 'useExisting' | 'createNew' (createNew is v2.2.112+)
    shodanMode:    'off',         // 'off' | 'enabled'
    defenderMode:  'off',         // 'off' | 'linked'
    enableJsonSink: false,        // bool -- adds 'JSON' to every SI_Sinks_<Engine>
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
      if (!state.data.credStorage) state.data.credStorage = 'Inline';
      if (!state.data.hostType)    state.data.hostType    = 'win';
      if (!state.data.smtpMode)     state.data.smtpMode     = 'off';
      if (!state.data.cmdbMode)     state.data.cmdbMode     = 'off';
      if (!state.data.openAiMode)   state.data.openAiMode   = 'off';
      if (!state.data.openAiResMode)state.data.openAiResMode= 'useExisting';
      if (!state.data.shodanMode)   state.data.shodanMode   = 'off';
      if (!state.data.defenderMode) state.data.defenderMode = 'off';
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
  kvName:               v => !!v && KV_RE.test(v),
  secretName:           v => !!v && v.length > 0,
  certThumbprint:       v => !!v && HEX40_RE.test(v.replace(/\s/g, '')),
  workspaceName:        v => !!v && v.length > 0,
  workspaceRg:          v => !!v && v.length > 0,
  dceName:              v => !!v && v.length > 0,
  dceRg:                v => !!v && v.length > 0,
  storageAccountName:   v => !!v && /^[a-z0-9]{3,24}$/.test(v),  // Azure storage account name rules
  storageResourceGroup: v => !!v && v.length > 0,
  storageContainer:     v => !!v && /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(v),
  location:             v => !!v && /^[a-z0-9]+[0-9]?$/.test(v),  // Azure region short-name (lowercase, no spaces)
  openAiResName:        v => !!v && /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/.test(v),
  openAiResRg:          v => !!v && v.length > 0,
  openAiSubscriptionId: v => !v || GUID_RE.test(v),  // optional -- empty = inherit Step 2's sub
  openAiLocation:       v => !!v && /^[a-z0-9]+[0-9]?$/.test(v),
  openAiNewDeployment:  v => !!v && v.length > 0,
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
  workspace: ['subscriptionId', 'location', 'workspaceName', 'workspaceRg', 'dceName', 'dceRg', 'storageAccountName', 'storageResourceGroup', 'storageContainer'],
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

// Compute the effective name for a Step-2 resource key, applying the optional
// state.data.namingSuffix. Used by the snippet builder + buildApplyState so
// the SAME name lands in both places.
//   key           -- state key (e.g. 'workspaceName')
//   opts.storage  -- true for storage account names: hyphens stripped, lowercased,
//                    truncated to 24 chars (Azure storage rules).
// Returns the suffixed name, or the bare base name if no suffix is set.
function nameWithSuffix(key, opts) {
  opts = opts || {};
  let base = state.data[key];
  if (base == null || base === '') {
    const el = document.querySelector('input[data-key="' + key + '"], select[data-key="' + key + '"]');
    base = el ? (el.getAttribute('data-default') || '') : '';
  }
  const sfx = (state.data.namingSuffix || '').trim();
  if (!sfx) return base;
  if (opts.storage) {
    const safe = sfx.replace(/[^a-z0-9]/gi, '').toLowerCase();
    return (base + safe).substring(0, 24);
  }
  return base + '-' + sfx;
}

// Like assignLine, but applies state.data.namingSuffix to the value.
function suffixedAssignLine(varName, key, fallback, pad, opts) {
  opts = opts || {};
  let val = nameWithSuffix(key, opts);
  if (!val) val = fallback;
  const head = '$global:' + varName + ' '.repeat(Math.max(1, (pad || 0) - varName.length)) + '= ' + psQuote(val);
  const def  = (document.querySelector('input[data-key="' + key + '"], select[data-key="' + key + '"]') || {}).getAttribute && document.querySelector('input[data-key="' + key + '"], select[data-key="' + key + '"]').getAttribute('data-default');
  const sfx  = (state.data.namingSuffix || '').trim();
  let tag = '';
  if (sfx) tag = '   # default+suffix';
  else if (def && state.data[key] === def) tag = '   # default';
  return head + tag;
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
  lines.push('# --- Subscription + Log Analytics workspace + ingestion ----------------');
  const sfx = (d.namingSuffix || '').trim();
  if (sfx) lines.push('# Naming suffix in effect: "-' + sfx + '" (applied to all default names below)');
  lines.push('$global:SI_PrestageInfra        = $true');
  lines.push(assignLine('SI_AzSubscriptionId',     'subscriptionId', '<sub-guid>',       30));
  lines.push(assignLine('SI_Location',             'location',       'westeurope',       30));
  lines.push(suffixedAssignLine('SI_WorkspaceName',         'workspaceName',  '<workspace-name>', 30));
  lines.push(suffixedAssignLine('SI_WorkspaceResourceGroup','workspaceRg',    '<workspace-rg>',   30));
  lines.push('# SI_WorkspaceResourceId is composed at config-load time from the parts above.');
  lines.push('$global:SI_WorkspaceResourceId  = "/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_WorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:SI_WorkspaceName)"');
  lines.push('');
  lines.push('# --- Data Collection Endpoint ------------------------------------------');
  lines.push(suffixedAssignLine('SI_DceName',          'dceName', '<dce-name>', 25));
  lines.push(suffixedAssignLine('SI_DceResourceGroup', 'dceRg',   '<dce-rg>',   25));
  lines.push(suffixedAssignLine('SI_DcrResourceGroup', 'dceRg',   '<dce-rg>',   25));
  lines.push('');
  lines.push('# --- Storage account (RBAC-only, no SI_StorageKey written) -------------');
  lines.push(suffixedAssignLine('SI_StorageAccount',       'storageAccountName',   '<storage-acct>',  25, { storage: true }));
  lines.push(suffixedAssignLine('SI_StorageResourceGroup', 'storageResourceGroup', '<storage-rg>',    25));
  lines.push(suffixedAssignLine('SI_ExportContainer',      'storageContainer',     'securityinsight', 25));
  lines.push('$global:ExportDestination       = "https://$($global:SI_StorageAccount).blob.core.windows.net/$($global:SI_ExportContainer)/"');
  return lines.join('\n');
}

// ---------- Optional-section snippet builders (pages 3-7) -----------------

function buildOutputSnippet() {
  const d = state.data;
  if (d.smtpMode === 'off' || !d.smtpMode) {
    return '# Mail mode is OFF -- nothing written.\n# (Engines run silent; LA + Excel still produced.)';
  }
  const lines = [];
  lines.push('# --- SMTP / mail (Layer 3) -----------------------------------------------');
  lines.push(assignLine('SmtpServer', 'smtpServer', '<smtp-host>', 14));
  lines.push(assignLine('SmtpPort',   'smtpPort',   '587',         14));
  lines.push('$global:SMTP_UseSSL    = $' + ((d.smtpUseSsl !== false) ? 'true' : 'false'));
  lines.push(assignLine('SMTPFrom',   'smtpFrom',   '<sender@example.com>', 14));
  if (d.smtpMode === 'auth') {
    lines.push(assignLine('SMTPUser',     'smtpUser',     '<smtp-login>', 14));
    lines.push(assignLine('SMTPPassword', 'smtpPassword', '<smtp-pass>',  14));
  } else {
    lines.push('# Anonymous relay -- no SMTPUser / SMTPPassword needed.');
  }
  const recipients = (d.mailTo || '').split(/[,;\s]+/).filter(Boolean);
  const recipPs = recipients.length ? '@(' + recipients.map(r => "'" + r.replace(/'/g, "''") + "'").join(', ') + ')' : "@('<your-inbox@example.com>')";
  lines.push('$global:MailTo         = ' + recipPs);
  return lines.join('\n');
}

function buildCmdbSnippet() {
  const d = state.data;
  if (d.cmdbMode !== 'csv') return '# CMDB mode is OFF -- nothing written.';
  const lines = [];
  lines.push('# --- CMDB CSV enrichment (Layer 3) ---------------------------------------');
  lines.push('$global:SI_EnableCmdbProvider     = $true');
  lines.push(assignLine('SI_CmdbCsvPath',             'cmdbCsvPath',     '<C:\\path\\to\\cmdb.csv>', 32));
  lines.push(assignLine('SI_CmdbRefreshIntervalHours','cmdbRefreshHours','24',                       32));
  return lines.join('\n');
}

function buildApptagSnippet() {
  // The "apptag" page is now Azure OpenAI in v2.2.111 -- the section ID
  // wasn't renamed to keep state-key compatibility.
  const d = state.data;
  if (d.openAiMode !== 'enabled') return '# OpenAI mode is OFF -- nothing written.';
  const lines = [];
  lines.push('# --- Azure OpenAI -- AI summary on RiskAnalysis runs (Layer 3) ----------');
  lines.push('$global:BuildSummaryByAI = $true');
  if (d.openAiResMode === 'createNew') {
    // Wizard backend (v2.2.112+) provisions the resource on Apply and writes
    // the endpoint + key directly. The custom config still needs the consumer
    // globals set so engines pick up the new deployment without a re-edit.
    const resName = d.openAiResName || 'oai-myorg-securityinsight';
    lines.push('# Resource will be CREATED on Apply by setup\\Validate-SIOpenAI.ps1:');
    lines.push('#   Resource    : ' + resName);
    lines.push('#   Resource RG : ' + (d.openAiResRg || 'rg-securityinsight-openai'));
    lines.push('#   Subscription: ' + (d.openAiSubscriptionId || '<inherits Step 2 sub>'));
    lines.push('#   Region      : ' + (d.openAiLocation || 'swedencentral'));
    lines.push('#   Model SKU   : ' + (d.openAiModel    || 'gpt-4o-mini'));
    lines.push('#   Deployment  : ' + (d.openAiNewDeployment || 'gpt-4o-mini'));
    lines.push('# Endpoint + key written to the lines below by the Apply backend:');
    lines.push("$global:OpenAI_endpoint   = 'https://" + resName + ".openai.azure.com/'");
    lines.push(assignLine('OpenAI_deployment', 'openAiNewDeployment', 'gpt-4o-mini',          22));
    lines.push("$global:OpenAI_apiVersion = '2025-01-01-preview'");
    lines.push("$global:OpenAI_apiKey     = '<written-by-apply-backend>'   # default");
  } else {
    lines.push(assignLine('OpenAI_endpoint',   'openAiEndpoint',   '<https://your-aoai.openai.azure.com/>', 22));
    lines.push(assignLine('OpenAI_deployment', 'openAiDeployment', 'gpt-4o-mini',                          22));
    lines.push(assignLine('OpenAI_apiVersion', 'openAiApiVersion', '2025-01-01-preview',                   22));
    lines.push(assignLine('OpenAI_apiKey',     'openAiApiKey',     '<your-aoai-key>',                      22));
  }
  lines.push(assignLine('MaxAiSpendPerRun', 'openAiMaxSpend', '3', 22));
  return lines.join('\n');
}

function buildShodanSnippet() {
  const d = state.data;
  if (d.shodanMode !== 'enabled') return '# Shodan mode is OFF -- nothing written.';
  const lines = [];
  lines.push('# --- Shodan attack-surface enrichment (Layer 3) -------------------------');
  lines.push(assignLine('SI_Shodan_ApiKey',     'shodanApiKey',     '<your-shodan-key>', 24));
  lines.push(assignLine('SI_Shodan_LicenseTier','shodanLicenseTier','freelance',         24));
  return lines.join('\n');
}

function buildAdvancedSnippet() {
  const d = state.data;
  const lines = [];
  let any = false;
  if (d.enableJsonSink) {
    lines.push('# --- JSON output sink for every engine (Layer 3) ------------------------');
    lines.push("$global:SI_Sinks_RiskAnalysis  = @('LA','Excel','JSON')");
    lines.push("$global:SI_Sinks_Endpoint      = @('LA','Excel','JSON')");
    lines.push("$global:SI_Sinks_Identity      = @('LA','Excel','JSON')");
    lines.push("$global:SI_Sinks_Azure         = @('LA','Excel','JSON')");
    lines.push("$global:SI_Sinks_PublicIP      = @('LA','Excel','JSON')");
    any = true;
  }
  if (d.defenderMode === 'linked') {
    if (any) lines.push('');
    lines.push('# --- Defender XDR workspace linkage (Layer 3) ---------------------------');
    lines.push(assignLine('SI_DefenderXdrWorkspaceResourceId', 'defenderWorkspaceResourceId', '</subscriptions/.../workspaces/...>', 38));
    any = true;
  }
  if (!any) return '# Output sinks: LA + Excel only. Defender XDR linkage: OFF.\n# (Defaults are fine for most customers.)';
  return lines.join('\n');
}

const SNIPPET_BUILDERS = {
  tenant:    buildTenantSnippet,
  workspace: buildWorkspaceSnippet,
  output:    buildOutputSnippet,
  cmdb:      buildCmdbSnippet,
  apptag:    buildApptagSnippet,
  shodan:    buildShodanSnippet,
  advanced:  buildAdvancedSnippet,
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
  // Checkbox inputs (handle BEFORE the generic text-input pass below so the
  // text branch's input.value.trim() doesn't see them as text).
  document.querySelectorAll('input[type="checkbox"][data-key]').forEach(cb => {
    const key = cb.dataset.key;
    if (state.data[key] != null) cb.checked = !!state.data[key];
    if (!cb._wired) {
      cb.addEventListener('change', () => {
        state.data[key] = !!cb.checked;
        saveState();
        renderPreviews();
        renderRail();
        renderNavButtons();
      });
      cb._wired = true;
    }
  });

  // Text + password inputs
  document.querySelectorAll('input[data-key]:not([type="checkbox"])').forEach(input => {
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

  // Dropdowns (e.g. host-type picker on the Tenant Identity page).
  document.querySelectorAll('select[data-key]').forEach(sel => {
    const key = sel.dataset.key;
    const def = sel.getAttribute('data-default');
    if (state.data[key] == null && def) {
      state.data[key] = def;
      saveState();
    }
    if (state.data[key] != null) sel.value = state.data[key];
    if (!sel._wired) {
      sel.addEventListener('change', () => {
        state.data[key] = sel.value;
        saveState();
        syncCredBlocks();
        renderPreviews();
        renderRail();
        renderNavButtons();
      });
      sel._wired = true;
    }
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
// Map of HTML data-attribute -> state key for compound visibility filters.
// Add new filters here only -- syncCredBlocks() iterates this map generically.
const VIS_FILTERS = {
  spnModeBlock:     'spnMode',
  credBlock:        'credType',
  credStorageBlock: 'credStorage',
  hostTypeBlock:    'hostType',
  smtpModeBlock:      'smtpMode',     // off | anon | auth
  cmdbModeBlock:      'cmdbMode',     // off | csv
  openAiModeBlock:    'openAiMode',   // off | enabled
  openAiResModeBlock: 'openAiResMode',// useExisting | createNew
  shodanModeBlock:    'shodanMode',   // off | enabled
  defenderModeBlock:  'defenderMode', // off | linked
};

// Valid storage options per (hostType, credType). Drives:
//   - which storage radio labels are visible (HTML data-host-type-block + data-cred-block)
//   - auto-snap for state.data.credStorage when current pick becomes invalid
const VALID_STORAGE_BY_HOST = {
  win:              ['LocalCertStore', 'Inline'],                 // no MI = no KV bootstrap
  azureVMMI:        ['LocalCertStore', 'Inline', 'KeyVault'],
  azureContainerMI: ['Inline', 'KeyVault'],                       // ephemeral container, no cert store
};
const VALID_STORAGE_BY_CRED = {
  kvSecret:  ['Inline', 'KeyVault'],
  certThumb: ['LocalCertStore', 'KeyVault'],
};

function snapCredStorage() {
  const ht = state.data.hostType;
  const ct = state.data.credType;
  const cs = state.data.credStorage;
  const allowed = (VALID_STORAGE_BY_HOST[ht] || []).filter(x => (VALID_STORAGE_BY_CRED[ct] || []).includes(x));
  if (!allowed.includes(cs)) {
    // Snap to the first allowed option (preferred order matches the host's valid list).
    state.data.credStorage = allowed[0] || 'Inline';
  }
}

function syncCredBlocks() {
  // Defensive: ensure every driver field is populated. Old localStorage
  // from pre-v2.2.106 sessions may be missing them, which breaks the visibility
  // pass below (every conditional would compare to undefined and pass-through).
  if (!state.data.spnMode)     state.data.spnMode     = 'createNew';
  if (!state.data.credType)    state.data.credType    = 'kvSecret';
  if (!state.data.credStorage) state.data.credStorage = 'Inline';
  if (!state.data.hostType)    state.data.hostType    = 'win';
  if (!state.data.smtpMode)     state.data.smtpMode     = 'off';
  if (!state.data.cmdbMode)     state.data.cmdbMode     = 'off';
  if (!state.data.openAiMode)   state.data.openAiMode   = 'off';
  if (!state.data.openAiResMode)state.data.openAiResMode= 'useExisting';
  if (!state.data.shodanMode)   state.data.shodanMode   = 'off';
  if (!state.data.defenderMode) state.data.defenderMode = 'off';
  // Auto-snap credStorage to a valid combo for the current hostType x credType
  // so a hidden radio is never the active selection.
  snapCredStorage();

  // Single-pass visibility for every element carrying any of our filter
  // attributes. Each filter value may be a single token ("createNew") or a
  // comma-separated whitelist ("azureVMMI,azureContainerMI"); the element is
  // visible only if EVERY filter the element declares matches state.
  const selector = Object.keys(VIS_FILTERS).map(a => '[data-' + a.replace(/([A-Z])/g, '-$1').toLowerCase() + ']').join(', ');
  document.querySelectorAll(selector).forEach(el => {
    let hide = false;
    for (const [attr, stateKey] of Object.entries(VIS_FILTERS)) {
      const want = el.dataset[attr];
      if (!want) continue;
      const wants = want.split(',').map(s => s.trim()).filter(Boolean);
      if (!wants.includes(state.data[stateKey])) { hide = true; break; }
    }
    el.hidden = hide;
  });
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
        hostType:       d.hostType       || 'win',
        spn: {
            displayName: d.spnMode === 'createNew' ? (d.spnDisplayName || 'sp-securityinsight') : null,
            credKind:    d.credType === 'certThumb' ? 'Cert' : 'Secret',
            credStorage: d.credStorage || 'Inline'
        },
        infra: {
            location:             d.location             || 'westeurope',
            resourceGroupName:    nameWithSuffix('workspaceRg')          || 'rg-securityinsight',
            workspaceName:        nameWithSuffix('workspaceName')        || 'log-platform-management-securityinsight',
            dceName:              nameWithSuffix('dceName')              || 'dce-securityinsight',
            dceResourceGroup:     nameWithSuffix('dceRg')                || nameWithSuffix('workspaceRg') || 'rg-securityinsight',
            storageAccountName:   nameWithSuffix('storageAccountName', { storage: true }) || '',
            storageResourceGroup: nameWithSuffix('storageResourceGroup') || nameWithSuffix('workspaceRg') || 'rg-securityinsight',
            storageContainer:     nameWithSuffix('storageContainer')     || 'securityinsight'
        },
        namingSuffix: d.namingSuffix || null
    };
    if (d.kvName) {
        st.spn.keyVaultName = d.kvName;
        st.infra.keyVaultName = d.kvName;
    }
    if (d.smtpMode && d.smtpMode !== 'off') {
        st.smtp = {
            Mode:     d.smtpMode,
            Server:   d.smtpServer || null,
            Port:     d.smtpPort   ? Number(d.smtpPort) : 587,
            UseSsl:   d.smtpUseSsl !== false,
            From:     d.smtpFrom   || null,
            MailTo:   (d.mailTo || '').split(/[,;\s]+/).filter(Boolean)
        };
        if (d.smtpMode === 'auth') {
            st.smtp.User     = d.smtpUser     || null;
            st.smtp.Password = d.smtpPassword || null;
        }
    }
    if (d.openAiMode === 'enabled' && d.openAiEndpoint) {
        st.openAi = {
            Endpoint:        d.openAiEndpoint,
            Deployment:      d.openAiDeployment || null,
            ApiKey:          d.openAiApiKey     || null,
            ApiVersion:      d.openAiApiVersion || '2024-08-01-preview',
            MaxSpendPerRun:  d.openAiMaxSpend ? Number(d.openAiMaxSpend) : null
        };
    }
    if (d.shodanMode === 'enabled' && d.shodanApiKey) {
        st.shodan = { ApiKey: d.shodanApiKey };
    }
    if (d.cmdbMode === 'csv') {
        st.cmdb = {
            Enabled:      true,
            RefreshHours: d.cmdbRefreshHours ? Number(d.cmdbRefreshHours) : 24,
            CsvPath:      d.cmdbCsvPath || null
        };
    }
    if (d.enableJsonSink) st.enableJsonSink = true;
    if (d.defenderMode === 'linked' && d.defenderWorkspaceResourceId) {
        st.defenderWorkspaceResourceId = d.defenderWorkspaceResourceId;
    }
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
                       : status === 'consent-pending' ? '&#9888;'   // amber warning triangle
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
            // SPN phase may report 'consent-pending' even when overall apply
            // succeeded -- the SPN was created and the perms requested, but a
            // Global Admin still has to click the consent URL. Reflect that
            // distinction in the per-phase pills + the result panel.
            var spnPhase = (obj.phaseStatus && obj.phaseStatus.spn) || 'ok';
            setApplyPhase('spn', spnPhase === 'consent-pending' ? 'consent-pending' : 'ok');
            setApplyPhase('infra', 'ok');
            setApplyPhase('config', 'ok');
            var consentStatus = (obj.spn && obj.spn.ConsentStatus) || 'granted';
            var pendingPerms  = (obj.spn && obj.spn.PendingPermissions) || [];
            var consentUrl    = (obj.spn && obj.spn.ConsentUrl) || '';
            if (consentStatus === 'granted') {
                setApplyStatePill('DONE', '#e8f5e9');
            } else {
                setApplyStatePill('CONSENT PENDING', '#fff8e1');
            }
            var appId = (obj.spn && obj.spn.AppId) || '?';
            var wsId  = (obj.infra && obj.infra.WorkspaceResourceId) || '?';
            var cfgPath = (obj.configFile && obj.configFile.Path) || '?';
            var cfgBytes = (obj.configFile && obj.configFile.Bytes) || 0;
            var cfgSecs = (obj.configFile && obj.configFile.Sections) || [];
            var html = '<div class="note" style="background:' + (consentStatus === 'granted' ? '#e8f5e9' : '#fff8e1') +
                       ';border-left-color:' + (consentStatus === 'granted' ? '#2e7d32' : '#f57c00') + ';">' +
                       '<b>' + (consentStatus === 'granted' ? '&#10003; Apply succeeded.' : '&#9888; Apply succeeded -- ADMIN CONSENT PENDING.') + '</b><br>' +
                       'SPN AppId: <code>' + _esc(appId) + '</code><br>' +
                       'Workspace: <code>' + _esc(wsId) + '</code><br>' +
                       'Config file: <code>' + _esc(cfgPath) + '</code> (' + cfgBytes + ' bytes)<br>' +
                       'Sections written: ' + _esc(cfgSecs.join(', ') || '(none)') + '</div>';
            // Surface the admin-consent URL prominently when not all perms were granted.
            // The operator hands this URL to a Global Admin who clicks it once; afterward
            // re-clicking 'Apply now' validates that consent landed (Apply is idempotent).
            if (consentStatus !== 'granted' && consentUrl) {
                html += '<div class="note warn" style="background:#fff8e1;border-left-color:#f57c00;margin-top:12px;">' +
                        '<b>Admin consent required for ' + pendingPerms.length + ' permission(s):</b><br>' +
                        '<code style="font-size:11px;display:block;margin:6px 0;">' + _esc(pendingPerms.join(', ')) + '</code>' +
                        '<b>How to resolve:</b><br>' +
                        '1. Send this URL to a <b>Global Administrator</b> (or anyone with the <b>Privileged Role Administrator</b> role on the app):<br>' +
                        '<a href="' + _esc(consentUrl) + '" target="_blank" rel="noopener" style="display:inline-block;margin:8px 0;padding:8px 14px;background:#1a3a5c;color:#fff;text-decoration:none;border-radius:6px;font-weight:600;">&#128279; Open admin-consent page</a><br>' +
                        '<code style="font-size:11px;word-break:break-all;color:#5a6a7a;">' + _esc(consentUrl) + '</code><br>' +
                        '2. After they click <b>Accept</b>, re-click <b>Apply now</b> above. The wizard re-validates each permission and updates this panel (Apply is idempotent &mdash; nothing is re-created).' +
                        '</div>';
            }
            result.innerHTML = html;
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
