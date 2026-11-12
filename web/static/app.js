'use strict';
// mintk web — the browser side. Plain DOM, no framework, no build step.
// Everything rendered from server data goes through textContent (never
// innerHTML), so a scope or principal can't inject markup.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const POLL_MS = 4000;
const LOG_KEEP = 30;

let S = null;            // last /api/state
let skew = 0;            // server clock − local clock, ms
let pending = null;      // label of the action this tab is running
let renderedKey = '';    // what the trees were last built from
const ttlDraft = new Map();     // cert scope → lifetime typed in the Certs tree
const grantDraft = new Map();   // secret scope → lifetime typed in Secrets
const manageDraft = new Map();  // scope → default lifetime being edited
const logEntries = [];

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
};
const collapsed = new Set(store.get('mintk.collapsed', []));
const mcollapsed = new Set(store.get('mintk.collapsed.manage', []));

// --- tiny DOM helper --------------------------------------------------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'disabled') el.disabled = !!v;
    else if (k === 'selected') el.selected = !!v;
    else if (k === 'depth') el.style.setProperty('--depth', v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// highlight wraps the filter matches in <mark>.
function highlight(text, q) {
  if (!q) return [text];
  const out = [];
  const lower = text.toLowerCase();
  let i = 0;
  for (;;) {
    const j = lower.indexOf(q, i);
    if (j < 0) break;
    if (j > i) out.push(text.slice(i, j));
    out.push(h('mark', { text: text.slice(j, j + q.length) }));
    i = j + q.length;
  }
  out.push(text.slice(i));
  return out;
}

// --- time -------------------------------------------------------------------

const now = () => Date.now() + skew;

function fmtDur(ms) {
  if (ms < 0) ms = 0;
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400), hh = Math.floor(s / 3600) % 24, mm = Math.floor(s / 60) % 60, ss = s % 60;
  const p = (n) => String(n).padStart(2, '0');
  if (d > 0) return `${d}d${p(hh)}h`;
  if (hh > 0) return `${hh}h${p(mm)}m`;
  if (mm > 0) return `${mm}m${p(ss)}s`;
  return `${ss}s`;
}

const isLive = (x) => x.expires && x.expires > now();

// "soon" = under 15 minutes or under 10% of the lifetime left.
function isSoon(from, exp) {
  const left = exp - now();
  return left < 15 * 60e3 || (from && left < (exp - from) * 0.1);
}

// --- API --------------------------------------------------------------------

async function api(path, body) {
  const opt = { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Mintk': '1' }, credentials: 'same-origin', cache: 'no-store' };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opt);
  } catch {
    setConn(false);
    throw new Error('mintk web is not reachable — is it still running?');
  }
  setConn(true);
  if (res.status === 401 && unlocked) {
    // The session ran out (or the server restarted) under an open page.
    showLocked(true);
    authScreen();
  }
  let data;
  try { data = await res.json(); } catch { data = { error: `${res.status} ${res.statusText}` }; }
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    err.data = data;
    throw err;
  }
  return data;
}

function setConn(ok) {
  const el = $('#conn');
  el.className = 'conn ' + (ok ? 'ok' : 'bad');
  el.title = ok ? 'connected to mintk web' : 'mintk web is not reachable';
}

let unlocked = false;

function showLocked(locked) {
  unlocked = !locked;
  $('#locked').hidden = !locked;
  $('#app').hidden = locked;
  $('#lock').hidden = locked;
  if (locked) {
    $('#busy').hidden = true;
    $('#config-error').hidden = true;
    $('#notes').replaceChildren();
  }
}

// --- login: a tap on a registered YubiKey (WebAuthn) ------------------------

const b64 = {
  enc(buf) {
    let s = '';
    for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  },
};

let authMode = null;   // 'unlock' | 'enroll' | 'none'
let autoTried = false; // ask for the tap by itself once per page load, not after a manual lock
let authBusy = false;

function lockError(msg) {
  const e = $('#lock-error');
  e.textContent = msg || '';
  e.hidden = !msg;
}

function webauthnError(e) {
  if (e && e.name === 'NotAllowedError') return 'Cancelled or timed out — press the button and tap the key.';
  if (e && e.name === 'InvalidStateError') return 'This key is already registered.';
  if (e && e.name === 'SecurityError') return `The browser refused WebAuthn here — open the page as http://localhost:${location.port}/.`;
  return (e && e.message) || String(e);
}

// authScreen decides what the locked page shows: unlock, first registration, or
// how to get an enrollment link.
async function authScreen() {
  let st;
  try {
    st = await api('/api/auth/status');
  } catch (e) {
    showLocked(true);
    $('#lock-title').textContent = 'Not reachable';
    $('#lock-text').textContent = e.message;
    $('#unlock-btn').hidden = true;
    return;
  }
  if (st.authed) {
    showLocked(false);
    refresh();
    return;
  }
  showLocked(true);
  lockError('');
  const btn = $('#unlock-btn');
  $('#enroll-row').hidden = !st.enrolling;
  if (st.enrolling) {
    authMode = 'enroll';
    $('#lock-title').textContent = 'Register your YubiKey';
    $('#lock-text').textContent = 'This one-time link registers a security key for this mintk. Name it if you like, press the button, and tap the key when it blinks.';
    btn.textContent = 'Register this YubiKey';
    btn.hidden = false;
  } else if (st.enrolled) {
    authMode = 'unlock';
    $('#lock-title').textContent = 'Locked';
    $('#lock-text').textContent = 'Tap your YubiKey to unlock.';
    btn.textContent = 'Unlock with YubiKey';
    btn.hidden = false;
    if (!autoTried && document.hasFocus()) {
      autoTried = true;
      unlock();
    }
  } else {
    authMode = 'none';
    $('#lock-title').textContent = 'No key registered yet';
    $('#lock-text').textContent = 'Run  mintk web enroll  in the terminal and open the one-time link it prints to register your YubiKey.';
    btn.hidden = true;
  }
}

async function unlock() {
  if (authBusy) return;
  authBusy = true;
  lockError('');
  $('#unlock-btn').disabled = true;
  $('#lock-text').textContent = 'Tap your YubiKey…';
  try {
    const o = await api('/api/auth/login/begin', {});
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: b64.dec(o.challenge),
      rpId: o.rp_id,
      allowCredentials: o.allow.map((id) => ({ type: 'public-key', id: b64.dec(id) })),
      userVerification: 'discouraged',
      timeout: 60000,
    } });
    const r = cred.response;
    await api('/api/auth/login/finish', {
      id: b64.enc(cred.rawId),
      client_data: b64.enc(r.clientDataJSON),
      authenticator_data: b64.enc(r.authenticatorData),
      signature: b64.enc(r.signature),
    });
    showLocked(false);
    refresh();
  } catch (e) {
    lockError(webauthnError(e));
    $('#lock-text').textContent = 'Tap your YubiKey to unlock.';
  } finally {
    authBusy = false;
    $('#unlock-btn').disabled = false;
  }
}

// registerKey creates a non-resident credential on a roaming key (the YubiKey,
// not Windows Hello / the platform) — touch only, nothing stored on the key.
async function registerKey(name) {
  const o = await api('/api/auth/register/begin', {});
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: b64.dec(o.challenge),
    rp: { id: o.rp_id, name: 'mintk' },
    user: { id: b64.dec(o.user_id), name: o.user_name, displayName: o.user_name },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'discouraged',
    },
    excludeCredentials: o.exclude.map((id) => ({ type: 'public-key', id: b64.dec(id) })),
    attestation: 'none',
    timeout: 120000,
  } });
  const r = cred.response;
  const pk = r.getPublicKey ? r.getPublicKey() : null;
  if (!pk) throw new Error('This browser does not hand over the key\'s public key — use a current Chrome, Edge, Firefox or Safari.');
  return api('/api/auth/register/finish', {
    id: b64.enc(cred.rawId),
    client_data: b64.enc(r.clientDataJSON),
    authenticator_data: b64.enc(r.getAuthenticatorData()),
    public_key: b64.enc(pk),
    alg: r.getPublicKeyAlgorithm(),
    name,
  });
}

async function enrollFirst() {
  if (authBusy) return;
  authBusy = true;
  lockError('');
  $('#unlock-btn').disabled = true;
  try {
    const r = await registerKey($('#enroll-name').value.trim());
    showLocked(false);
    refresh();
    toast(`Registered ${r.key} — unlocked`);
  } catch (e) {
    lockError(webauthnError(e));
  } finally {
    authBusy = false;
    $('#unlock-btn').disabled = false;
  }
}

async function lockNow() {
  try { await api('/api/auth/logout', {}); } catch { /* locking locally anyway */ }
  autoTried = true; // a manual lock shouldn't immediately ask for the tap again
  showLocked(true);
  authScreen();
}

// --- keys tab ---------------------------------------------------------------

function ago(ms) {
  const d = now() - ms;
  return d < 60e3 ? 'just now' : `${fmtDur(d)} ago`;
}

async function renderKeys() {
  let d;
  try { d = await api('/api/auth/keys'); } catch { return; }
  $('#keys-file').textContent = d.file;
  const only = d.keys.length === 1;
  $('#keys-list').replaceChildren(...d.keys.map((k) => h('div', { class: 'trow' },
    h('span', { class: 'dot' }),
    h('span', { class: 'name', text: k.name, title: k.name }),
    h('span', { class: 'principal', text: `${k.alg} · added ${new Date(k.created).toLocaleDateString()}` }),
    h('span', { class: 'status', text: k.last_used ? `used ${ago(k.last_used)}` : 'never used' }),
    h('span', { class: 'actions' },
      h('button', {
        class: 'ghost small', text: 'Remove', disabled: only,
        title: only ? 'The only key can’t be removed — register another one first' : '',
        onclick: () => removeKey(k),
      })))));
}

async function removeKey(k) {
  if (!confirm(`Remove ${k.name}? It will no longer unlock mintk web.`)) return;
  try {
    await api('/api/auth/keys/delete', { id: k.id });
    toast(`Removed ${k.name}`);
  } catch (e) {
    toast(e.message, true);
  }
  renderKeys();
}

async function refresh() {
  if (!unlocked) return;
  try {
    const st = await api('/api/state');
    skew = st.now - Date.now();
    S = st;
    showLocked(false);
    render();
  } catch { /* conn dot / locked screen already say why */ }
}

// runAction performs one card/file operation and records it in the activity log.
async function runAction(label, path, body, { okToast } = {}) {
  const busy = pending || (S && S.busy);
  if (busy) {
    toast(`Busy: ${busy}`, true);
    return false;
  }
  pending = label;
  render();
  let ok = false;
  try {
    const r = await api(path, body);
    ok = r.ok;
    addLog(label, r.ok, r.log, r.error);
    toast(r.ok ? (okToast || `${label}: done`) : `${label}: failed`, !r.ok);
  } catch (e) {
    addLog(label, false, (e.data && e.data.log) || '', e.message);
    toast(e.message, true);
  } finally {
    pending = null;
    await refresh();
  }
  return ok;
}

let toastTimer = 0;
function toast(msg, err) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (err ? ' err' : '');
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, err ? 5000 : 2500);
}

// --- actions ----------------------------------------------------------------

function mint(s) {
  const ttl = (ttlDraft.get(s.name) || '').trim();
  return runAction(`mint ${s.name}${ttl ? ' +' + ttl : ''}`, '/api/mint', { scope: s.name, ttl }, { okToast: `minted ${s.name}` })
    .then((ok) => { if (ok) ttlDraft.delete(s.name); });
}

function drop(s) {
  if (!confirm(`Forget ${s.name}? Removes it from the ssh-agent and deletes its key and cert.`)) return;
  runAction(`drop ${s.name}`, '/api/drop', { scope: s.name });
}

function grant(sec) {
  const ttl = (grantDraft.get(sec.name) || '').trim();
  return runAction(`grant ${sec.name}${ttl ? ' +' + ttl : ''}`, '/api/grant', { scope: sec.name, ttl }, { okToast: `granted ${sec.name}` })
    .then((ok) => { if (ok) grantDraft.delete(sec.name); });
}

function revoke(sec) {
  runAction(`revoke ${sec.name}`, '/api/revoke', { scope: sec.name });
}

// --- render -----------------------------------------------------------------

function render() {
  if (!S) return;
  $('#host').textContent = S.host || '';
  const mode = $('#mode');
  mode.hidden = !S.mode;
  mode.textContent = S.mode ? `mode: ${S.mode}` : '';
  document.title = S.host ? `mintk · ${S.host}` : 'mintk';

  const ce = $('#config-error');
  ce.hidden = !S.config_error;
  ce.textContent = S.config_error ? `Config error: ${S.config_error}` : '';
  $('#notes').replaceChildren(...(S.notes || []).map((n) => h('div', { class: 'banner note', text: n })));

  renderBusy();

  // Rebuild only when the data changed, so typing isn't disturbed by polls.
  const key = JSON.stringify([S.scopes, S.groups, S.secrets, S.config_error, !!(pending || S.busy), $('#filter').value]);
  if (key !== renderedKey) {
    renderedKey = key;
    preservingFocus(() => {
      renderLive();
      renderCertTree();
      renderSecrets();
      renderManage();
      renderCleanup();
    });
  }
  tick();
}

function renderBusy() {
  const label = pending || (S && S.busy);
  $('#busy').hidden = !label;
  if (label) {
    const since = !pending && S.busy_since ? ` · ${fmtDur(now() - S.busy_since)}` : '';
    $('#busy-text').textContent = `Working: ${label} — tap the YubiKey if it blinks, answer a PIN prompt if one opens${since}`;
  }
}

// preservingFocus rebuilds DOM but puts the caret back where it was, keyed by
// data-fk on inputs.
function preservingFocus(fn) {
  const a = document.activeElement;
  const fk = a && a.dataset ? a.dataset.fk : null;
  const sel = fk && 'selectionStart' in a ? [a.selectionStart, a.selectionEnd] : null;
  fn();
  if (!fk) return;
  const el = document.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
  if (el) {
    el.focus();
    if (sel) try { el.setSelectionRange(sel[0], sel[1]); } catch { /* select */ }
  }
}

const busyNow = () => !!(pending || (S && S.busy));

// countdown is a span the 1s tick keeps current.
function countdown(from, exp, idle = '—') {
  return h('span', { class: 'status', 'data-exp': exp || '', 'data-from': from || '', 'data-idle': idle, text: exp ? fmtDur(exp - now()) : idle });
}

function renderLive() {
  const items = [];
  for (const s of S.scopes) if (isLive(s)) items.push({ kind: 'cert', s, exp: s.expires, from: s.from });
  for (const s of S.secrets.scopes || []) if (isLive(s)) items.push({ kind: 'secret', s, exp: s.expires, from: s.from });
  items.sort((a, b) => a.exp - b.exp);
  $('#live-count').textContent = items.length ? `${items.length} active` : '';

  const list = $('#live-list');
  if (!items.length) {
    list.replaceChildren(h('div', { class: 'live-empty', text: 'Nothing live. Pick a scope below and mint.' }));
    return;
  }
  list.replaceChildren(...items.map((it) => {
    const s = it.s;
    const sub = it.kind === 'cert' ? `${s.principal}${s.group ? '  ·  /' + s.group : ''}` : `secret · ${s.format}`;
    const actions = it.kind === 'cert'
      ? [h('button', { class: 'ghost small', text: 'Re-mint', disabled: busyNow(), onclick: () => mint(s) }),
         h('button', { class: 'icon', text: '×', title: 'Forget: drop from the agent, delete key + cert', disabled: busyNow(), onclick: () => drop(s) })]
      : [h('button', { class: 'ghost small', text: 'Re-grant', disabled: busyNow(), onclick: () => grant(s) }),
         h('button', { class: 'icon', text: '×', title: 'Revoke now', disabled: busyNow(), onclick: () => revoke(s) })];
    return h('div', { class: 'live-card', 'data-exp': it.exp, 'data-from': it.from || '' },
      h('div', { class: 'row1' }, h('span', { class: 'kind', text: it.kind }), h('span', { class: 'name', text: s.name, title: s.name }), ...actions),
      h('div', { class: 'sub', text: sub, title: sub }),
      h('div', { class: 'remain', 'data-exp': it.exp, text: fmtDur(it.exp - now()) }),
      h('div', { class: 'bar' }, h('i', { 'data-bar': '1' })));
  }));
}

// --- the scope tree ---------------------------------------------------------

function buildTree(scopes, groups) {
  const root = { path: '', name: '', children: new Map(), scopes: [] };
  const ensure = (path) => {
    let node = root;
    if (!path) return node;
    let acc = '';
    for (const seg of path.split('/')) {
      acc = acc ? `${acc}/${seg}` : seg;
      if (!node.children.has(seg)) node.children.set(seg, { path: acc, name: seg, children: new Map(), scopes: [] });
      node = node.children.get(seg);
    }
    return node;
  };
  for (const g of groups) ensure(g);
  for (const s of scopes) ensure(s.group).scopes.push(s);
  const sortNode = (n) => {
    n.children = new Map([...n.children.entries()].sort((a, b) => a[0].localeCompare(b[0])));
    n.scopes.sort((a, b) => a.name.localeCompare(b.name));
    n.children.forEach(sortNode);
  };
  sortNode(root);
  return root;
}

function subtreeScopes(node) {
  const out = [...node.scopes];
  node.children.forEach((c) => out.push(...subtreeScopes(c)));
  return out;
}

function filterQuery() { return $('#filter').value.trim().toLowerCase(); }

function scopeMatches(s, q) {
  return !q || s.name.toLowerCase().includes(q) || s.principal.toLowerCase().includes(q) || (s.group || '').toLowerCase().includes(q);
}

// renderTree walks the group tree; scopeRow and groupExtra differ per tab.
function renderTree(container, { q = '', collapsedSet, persistKey, scopeRow, groupExtra, showEmpty = true }) {
  const root = buildTree(S.scopes, S.groups);
  const visible = [];
  const walk = (node, depth, into) => {
    node.children.forEach((child) => {
      const all = subtreeScopes(child);
      const matched = all.filter((s) => scopeMatches(s, q));
      if (q && !matched.length) return;
      if (!q && !all.length && !showEmpty) return;
      const live = all.filter(isLive).length;
      const isCollapsed = !q && collapsedSet.has(child.path);
      const g = h('div', { class: 'group' + (isCollapsed ? ' collapsed' : '') });
      const count = all.length ? `${all.length} scope${all.length === 1 ? '' : 's'}${live ? ` · ${live} live` : ''}` : 'empty';
      const row = h('div', {
        class: 'trow group-row', depth,
        onclick: () => {
          if (q) return;
          g.classList.toggle('collapsed');
          if (g.classList.contains('collapsed')) collapsedSet.add(child.path); else collapsedSet.delete(child.path);
          store.set(persistKey, [...collapsedSet]);
        },
      },
      h('span', { class: 'caret', text: '▾' }),
      h('span', {}, ...highlight(child.name + '/', q), '  ', h('span', { class: 'count', text: count })),
      groupExtra ? groupExtra(child, all) : h('span'));
      const kids = h('div', { class: 'children' });
      walk(child, depth + 1, kids);
      g.append(row, kids);
      into.append(g);
    });
    for (const s of node.scopes) {
      if (!scopeMatches(s, q)) continue;
      visible.push(s);
      into.append(scopeRow(s, depth, q));
    }
  };
  const frag = document.createDocumentFragment();
  walk(root, 0, frag);
  container.replaceChildren(frag);
  if (!container.children.length) {
    container.append(h('div', { class: 'tree-empty', text: S.scopes.length ? 'No scope matches the filter.' : 'No scopes configured yet — add one under “Manage scopes”.' }));
  }
  return visible;
}

let visibleCertScopes = [];

function renderCertTree() {
  const q = filterQuery();
  visibleCertScopes = renderTree($('#cert-tree'), {
    q, collapsedSet: collapsed, persistKey: 'mintk.collapsed', showEmpty: false,
    scopeRow: (s, depth) => {
      const live = isLive(s);
      return h('div', { class: 'trow scope' + (live ? ' live' : ''), depth, 'data-row-exp': s.expires || '', 'data-row-from': s.from || '' },
        h('span', { class: 'dot' }),
        h('span', { class: 'name', title: s.name }, ...highlight(s.name, q)),
        h('span', { class: 'principal', title: `principal: ${s.principal}` }, ...highlight(s.principal, q)),
        countdown(s.from, s.expires),
        h('input', {
          class: 'ttl', placeholder: s.ttl, value: ttlDraft.get(s.name) || '', 'data-fk': `ttl:${s.name}`,
          title: `Lifetime for this mint (default ${s.ttl})`, spellcheck: 'false', autocomplete: 'off',
          oninput: (e) => ttlDraft.set(s.name, e.target.value),
          onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); mint(s); } },
        }),
        h('span', { class: 'actions' },
          h('button', { text: live ? 'Re-mint' : 'Mint', disabled: busyNow(), onclick: () => mint(s) }),
          (s.has_key || live)
            ? h('button', { class: 'icon', text: '×', title: 'Forget: drop from the agent, delete key + cert', disabled: busyNow(), onclick: () => drop(s) })
            : h('span', { class: 'icon-spacer' })));
    },
  });
}

// --- secrets ----------------------------------------------------------------

function renderSecrets() {
  const body = $('#secrets-body');
  const sec = S.secrets || {};
  if (!sec.enabled) {
    body.replaceChildren(h('div', { class: 'banner note', text: sec.error
      ? `Secret grants are unavailable: ${sec.error}`
      : 'Secret grants are not configured (no secrets: section in the config). See docs/secrets.md.' }));
    return;
  }
  if (!sec.scopes.length) {
    body.replaceChildren(h('div', { class: 'banner note', text: 'No secrets yet. Create one in the terminal: mintk secret edit <name>' }));
    return;
  }
  const list = h('div', { class: 'tree secret-list' });
  for (const s of sec.scopes) {
    const live = isLive(s);
    list.append(h('div', { class: 'trow' + (live ? ' live' : ''), 'data-row-exp': s.expires || '', 'data-row-from': s.from || '' },
      h('span', { class: 'dot' }),
      h('span', { class: 'name', text: s.name }),
      h('span', { class: 'principal', text: s.format }),
      countdown(s.from, s.expires),
      h('input', {
        class: 'ttl', placeholder: s.ttl, value: grantDraft.get(s.name) || '', 'data-fk': `grant:${s.name}`,
        title: `Lifetime for this grant (default ${s.ttl})`, spellcheck: 'false', autocomplete: 'off',
        oninput: (e) => grantDraft.set(s.name, e.target.value),
        onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); grant(s); } },
      }),
      h('span', { class: 'actions' },
        h('button', { text: live ? 'Re-grant' : 'Grant', disabled: busyNow(), onclick: () => grant(s) }),
        live ? h('button', { class: 'icon', text: '×', title: 'Revoke now', disabled: busyNow(), onclick: () => revoke(s) }) : h('span'))));
  }
  body.replaceChildren(list);
}

// --- manage -----------------------------------------------------------------

function groupOptions(selected) {
  return [h('option', { value: '', text: '/ (root)', selected: !selected }),
    ...S.groups.map((g) => h('option', { value: g, text: '/' + g, selected: g === selected }))];
}

function renderManage() {
  const sel = $('#add-scope select[name=group]');
  const cur = sel.value;
  sel.replaceChildren(...groupOptions(cur));
  if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;

  renderTree($('#manage-tree'), {
    collapsedSet: mcollapsed, persistKey: 'mintk.collapsed.manage',
    groupExtra: (node, all) => h('span', { class: 'actions' },
      h('button', { class: 'ghost small', text: 'Add scope here', onclick: (e) => { e.stopPropagation(); addScopeHere(node.path); } }),
      h('button', { class: 'ghost small', text: 'Rename / move', disabled: busyNow(), onclick: (e) => { e.stopPropagation(); renameGroup(node.path); } }),
      h('button', {
        class: 'ghost small', text: 'Delete', disabled: busyNow() || all.length > 0 || node.children.size > 0,
        title: all.length || node.children.size ? 'Only an empty group can be deleted' : '',
        onclick: (e) => { e.stopPropagation(); deleteGroup(node.path); },
      })),
    scopeRow: (s, depth) => {
      const saveTTL = (el) => {
        const v = el.value.trim();
        if (!v || v === s.ttl) return;
        runAction(`${s.name}: default lifetime ${v}`, '/api/scopes/update', { name: s.name, ttl: v })
          .then((ok) => { if (ok) manageDraft.delete(s.name); });
      };
      return h('div', { class: 'trow scope' + (isLive(s) ? ' live' : ''), depth },
        h('span', { class: 'dot' }),
        h('span', { class: 'name', text: s.name, title: s.name }),
        h('span', { class: 'principal', text: s.principal, title: `principal: ${s.principal}` }),
        h('input', {
          class: 'ttl', value: manageDraft.has(s.name) ? manageDraft.get(s.name) : s.ttl, 'data-fk': `mttl:${s.name}`,
          title: 'Default lifetime — Enter to save', spellcheck: 'false', autocomplete: 'off',
          oninput: (e) => manageDraft.set(s.name, e.target.value),
          onkeydown: (e) => { if (e.key === 'Enter') { e.preventDefault(); saveTTL(e.target); } },
          onchange: (e) => saveTTL(e.target),
        }),
        h('select', {
          title: 'Group', disabled: busyNow(),
          onchange: (e) => runAction(`${s.name} → /${e.target.value}`, '/api/scopes/update', { name: s.name, group: e.target.value }),
        }, ...groupOptions(s.group)));
    },
  });
}

function addScopeHere(path) {
  const form = $('#add-scope');
  form.group.value = path;
  form.scope.focus();
  form.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function renameGroup(path) {
  const to = prompt(`New path for /${path} (moves everything under it):`, path);
  if (to === null || to.trim() === '' || to.trim() === path) return;
  runAction(`group /${path} → /${to.trim()}`, '/api/groups/rename', { from: path, to: to.trim() });
}

function deleteGroup(path) {
  if (!confirm(`Delete the empty group /${path}?`)) return;
  runAction(`delete group /${path}`, '/api/groups/delete', { path });
}

// --- cleanup ----------------------------------------------------------------

function renderCleanup() {
  const sec = S.secrets || {};
  const live = (sec.scopes || []).filter(isLive).length;
  $('#revoke-all-card').hidden = !sec.enabled;
  $('#revoke-all-text').textContent = `Wipes every live grant (${live} now) from tmpfs instead of waiting for its TTL.`;
  $('#clean-keys').disabled = busyNow();
  $('#revoke-all').disabled = busyNow();
}

// --- tick: countdowns between polls -----------------------------------------

function tick() {
  if (!S) return;
  let expired = false;
  for (const el of $$('[data-exp]')) {
    const exp = Number(el.dataset.exp);
    if (!exp) continue;
    const left = exp - now();
    if (left <= 0) expired = true;
    const from = Number(el.dataset.from) || 0;
    const soon = isSoon(from, exp);
    if (el.classList.contains('live-card')) {
      el.classList.toggle('soon', soon);
      const bar = $('[data-bar]', el);
      if (bar && from) bar.style.width = `${Math.max(0, Math.min(100, (left / (exp - from)) * 100))}%`;
      continue;
    }
    el.textContent = left > 0 ? fmtDur(left) : (el.dataset.idle || '—');
  }
  for (const row of $$('[data-row-exp]')) {
    const exp = Number(row.dataset.rowExp);
    row.classList.toggle('soon', !!exp && exp > now() && isSoon(Number(row.dataset.rowFrom) || 0, exp));
  }
  renderBusy();
  if (expired) refresh();
}

// --- activity log -----------------------------------------------------------

function addLog(label, ok, log, error) {
  logEntries.unshift({ t: new Date(), label, ok, log: log || '', error: error || '' });
  logEntries.length = Math.min(logEntries.length, LOG_KEEP);
  renderLog();
}

function renderLog() {
  const list = $('#log-list');
  if (!logEntries.length) {
    list.replaceChildren(h('div', { class: 'muted', text: 'Nothing yet. Output of mints, grants and edits shows up here.' }));
    return;
  }
  list.replaceChildren(...logEntries.map((e, i) => {
    const d = h('details', { class: 'log-entry ' + (e.ok ? 'ok' : 'err') },
      h('summary', {},
        h('span', { class: 'time', text: e.t.toLocaleTimeString() }),
        h('span', { class: 'label', text: e.label }),
        h('span', { class: 'st', text: e.ok ? 'ok' : 'failed' })),
      h('pre', {}, e.log, e.error ? h('div', { class: 'errline', text: (e.log ? '\n' : '') + e.error }) : null));
    if (i === 0 && (e.log || e.error)) d.open = true;
    return d;
  }));
}

// --- wiring -----------------------------------------------------------------

function selectTab(name) {
  for (const b of $$('.tabs button')) b.setAttribute('aria-selected', String(b.dataset.tab === name));
  for (const p of $$('[data-panel]')) p.hidden = p.dataset.panel !== name;
  store.set('mintk.tab', name);
  history.replaceState(null, '', '#' + name);
  if (name === 'keys' && unlocked) renderKeys();
}

const TABS = ['certs', 'secrets', 'scopes', 'cleanup', 'keys'];

function init() {
  for (const b of $$('.tabs button')) b.addEventListener('click', () => selectTab(b.dataset.tab));
  const fromHash = location.hash.slice(1);
  selectTab(TABS.includes(fromHash) ? fromHash : store.get('mintk.tab', 'certs'));
  window.addEventListener('hashchange', () => {
    const t = location.hash.slice(1);
    if (TABS.includes(t)) selectTab(t);
  });

  const filter = $('#filter');
  filter.dataset.fk = 'filter';
  filter.addEventListener('input', () => render());
  filter.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { filter.value = ''; render(); }
    if (e.key === 'Enter' && visibleCertScopes.length === 1) { e.preventDefault(); mint(visibleCertScopes[0]); }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      selectTab('certs');
      filter.focus();
    }
  });

  $('#expand-all').addEventListener('click', () => { collapsed.clear(); store.set('mintk.collapsed', []); renderedKey = ''; render(); });
  $('#collapse-all').addEventListener('click', () => {
    collapsed.clear();
    (S ? S.groups : []).forEach((g) => collapsed.add(g));
    store.set('mintk.collapsed', [...collapsed]);
    renderedKey = '';
    render();
  });

  $('#add-scope').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const name = f.scope.value.trim();
    const ok = await runAction(`add scope ${name}`, '/api/scopes/add', {
      name, principal: f.principal.value.trim() || name, ttl: f.ttl.value.trim(), group: f.group.value,
    });
    if (ok) { f.scope.value = ''; f.principal.value = ''; }
  });
  $('#add-group').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    const ok = await runAction(`add group ${f.path.value.trim()}`, '/api/groups/add', { path: f.path.value.trim() });
    if (ok) f.path.value = '';
  });

  $('#clean-keys').addEventListener('click', () => {
    if (confirm('Delete every minted session key and cert? Live certs stop working for new connections.')) {
      runAction('wipe minted identities', '/api/clean-keys', {});
    }
  });
  $('#revoke-all').addEventListener('click', () => {
    if (confirm('Revoke every live secret grant now?')) runAction('revoke all grants', '/api/revoke-all', {});
  });
  $('#log-clear').addEventListener('click', () => { logEntries.length = 0; renderLog(); });

  $('#unlock-btn').addEventListener('click', () => (authMode === 'enroll' ? enrollFirst() : unlock()));
  $('#enroll-name').addEventListener('keydown', (e) => { if (e.key === 'Enter') enrollFirst(); });
  $('#lock').addEventListener('click', lockNow);
  $('#add-key').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      const r = await registerKey(f.keyname.value.trim());
      toast(`Registered ${r.key}`);
      f.keyname.value = '';
    } catch (err) {
      toast(webauthnError(err), true);
    }
    renderKeys();
  });

  renderLog();
  authScreen();
  setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
  setInterval(tick, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
}

init();
