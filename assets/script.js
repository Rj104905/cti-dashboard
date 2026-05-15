'use strict';

const DATA_URL      = './data/cti_data.json';
const REFRESH_MS    = 5 * 60 * 1000;  // 5 min client-side refresh
const COUNTDOWN_SEC = 5 * 60;

let ctiData     = null;
let activeTab   = 'cisa_kev';
let sortState   = {};        // { col, dir } per tab
let countdownId = null;
let countSec    = COUNTDOWN_SEC;

// ── Source metadata ──────────────────────────────────────────────────────────
const SOURCES = {
  cisa_kev: {
    label: 'CISA KEV', icon: '🚨',
    desc: 'CISA Known Exploited Vulnerabilities Catalog — actively exploited CVEs that federal agencies must patch.',
    statId: 'stat-cisa', statusId: 'status-cisa',
    countFn: d => d.count ?? d.items?.length ?? 0,
    columns: [
      { key: 'id',          label: 'CVE ID',       mono: true,  w: '140px' },
      { key: 'vendor',      label: 'Vendor',                    w: '120px' },
      { key: 'product',     label: 'Product',                   w: '140px' },
      { key: 'date_added',  label: 'Date Added',   mono: true,  w: '110px' },
      { key: 'due_date',    label: 'Due Date',     mono: true,  w: '110px' },
      { key: 'name',        label: 'Vulnerability',             w: '220px' },
    ],
    renderCell(key, val, row) {
      if (key === 'id')
        return `<a class="link mono" href="https://nvd.nist.gov/vuln/detail/${val}" target="_blank">${val}</a>`;
      return cell(key, val, row);
    },
  },

  urlhaus: {
    label: 'URLhaus', icon: '🔗',
    desc: 'Abuse.ch URLhaus — malware distribution URLs reported by the community.',
    statId: 'stat-urlhaus', statusId: 'status-urlhaus',
    countFn: d => d.items?.length ?? 0,
    columns: [
      { key: 'host',     label: 'Host',    mono: true, w: '180px' },
      { key: 'url',      label: 'URL',     mono: true, w: '320px', trunc: true },
      { key: 'threat',   label: 'Threat',             w: '130px' },
      { key: 'status',   label: 'Status',             w: '90px' },
      { key: 'date_added', label: 'Reported',         w: '140px' },
      { key: 'tags',     label: 'Tags',               w: '160px' },
    ],
    renderCell(key, val, row) {
      if (key === 'status')
        return `<span class="status-${(val||'').toLowerCase()}">${val || '—'}</span>`;
      if (key === 'tags') return renderTags(val);
      if (key === 'url')
        return `<span class="mono truncate" style="max-width:300px" title="${esc(val)}">${esc(val)}</span>`;
      return cell(key, val, row);
    },
  },

  malwarebazaar: {
    label: 'MalwareBazaar', icon: '🦠',
    desc: 'Abuse.ch MalwareBazaar — malware sample repository with hashes and metadata.',
    statId: 'stat-malwarebazaar', statusId: 'status-malwarebazaar',
    countFn: d => d.items?.length ?? 0,
    columns: [
      { key: 'sha256',     label: 'SHA-256', mono: true, w: '200px', trunc: true },
      { key: 'file_name',  label: 'File Name',          w: '160px', trunc: true },
      { key: 'signature',  label: 'Signature',          w: '150px' },
      { key: 'file_type',  label: 'Type',               w: '120px' },
      { key: 'first_seen', label: 'First Seen',         w: '140px' },
      { key: 'tags',       label: 'Tags',               w: '160px' },
    ],
    renderCell(key, val, row) {
      if (key === 'sha256')
        return `<a class="link mono truncate" style="display:block;max-width:180px" href="https://bazaar.abuse.ch/sample/${val}/" target="_blank" title="${esc(val)}">${val.slice(0,16)}…</a>`;
      if (key === 'tags') return renderTags(val);
      return cell(key, val, row);
    },
  },

  threatfox: {
    label: 'ThreatFox', icon: '🎯',
    desc: 'Abuse.ch ThreatFox — Indicators of Compromise published in the last 24 hours.',
    statId: 'stat-threatfox', statusId: 'status-threatfox',
    countFn: d => d.items?.length ?? 0,
    columns: [
      { key: 'ioc',        label: 'IOC Value', mono: true, w: '240px', trunc: true },
      { key: 'type',       label: 'Type',                  w: '100px' },
      { key: 'threat',     label: 'Threat',                w: '120px' },
      { key: 'malware',    label: 'Malware',               w: '130px' },
      { key: 'confidence', label: 'Confidence',            w: '100px' },
      { key: 'first_seen', label: 'First Seen',            w: '140px' },
      { key: 'tags',       label: 'Tags',                  w: '140px' },
    ],
    renderCell(key, val, row) {
      if (key === 'type') return `<span class="ioc-type">${esc(val)}</span>`;
      if (key === 'confidence')
        return `<span class="confidence" title="${val}%"><span class="confidence-fill" style="width:${val}%"></span></span> ${val}%`;
      if (key === 'tags') return renderTags(val);
      if (key === 'ioc')
        return `<span class="mono truncate" style="max-width:220px" title="${esc(val)}">${esc(val)}</span>`;
      return cell(key, val, row);
    },
  },

  feodo: {
    label: 'Feodo C2', icon: '🕸',
    desc: 'Abuse.ch Feodo Tracker — active botnet command-and-control infrastructure IPs.',
    statId: 'stat-feodo', statusId: 'status-feodo',
    countFn: d => d.count ?? d.items?.length ?? 0,
    columns: [
      { key: 'ip',         label: 'IP Address', mono: true, w: '130px' },
      { key: 'port',       label: 'Port',       mono: true, w: '70px' },
      { key: 'malware',    label: 'Malware',               w: '130px' },
      { key: 'status',     label: 'Status',                w: '90px' },
      { key: 'country',    label: 'Country',               w: '90px' },
      { key: 'as_number',  label: 'ASN',        mono: true, w: '90px' },
      { key: 'first_seen', label: 'First Seen',            w: '130px' },
      { key: 'last_online',label: 'Last Online',           w: '130px' },
    ],
    renderCell(key, val, row) {
      if (key === 'status')
        return `<span class="status-${(val||'').toLowerCase()}">${val || '—'}</span>`;
      return cell(key, val, row);
    },
  },

  nvd: {
    label: 'NVD CVE', icon: '🔓',
    desc: 'NIST National Vulnerability Database — most recently published CVEs.',
    statId: 'stat-nvd', statusId: 'status-nvd',
    countFn: d => d.items?.length ?? 0,
    columns: [
      { key: 'id',          label: 'CVE ID',    mono: true, w: '140px' },
      { key: 'score',       label: 'CVSS',                  w: '70px' },
      { key: 'severity',    label: 'Severity',              w: '100px' },
      { key: 'vector',      label: 'Attack',                w: '100px' },
      { key: 'published',   label: 'Published', mono: true, w: '130px' },
      { key: 'description', label: 'Description',           w: '360px', trunc: true },
    ],
    renderCell(key, val, row) {
      if (key === 'id')
        return `<a class="link mono" href="https://nvd.nist.gov/vuln/detail/${val}" target="_blank">${val}</a>`;
      if (key === 'severity')
        return `<span class="sev sev-${val}">${val}</span>`;
      if (key === 'score')
        return `<strong style="color:${scoreColor(val)}">${val}</strong>`;
      if (key === 'description')
        return `<span class="truncate" style="max-width:350px" title="${esc(val)}">${esc(val)}</span>`;
      return cell(key, val, row);
    },
  },

  otx: {
    label: 'AlienVault OTX', icon: '👁',
    desc: 'AlienVault Open Threat Exchange — threat intelligence pulses from the community.',
    statId: 'stat-otx', statusId: 'status-otx',
    countFn: d => d.items?.length ?? 0,
    apiRequired: true,
    secretName: 'OTX_API_KEY',
    apiUrl: 'https://otx.alienvault.com',
    columns: [
      { key: 'name',       label: 'Pulse Name',            w: '240px', trunc: true },
      { key: 'adversary',  label: 'Adversary',             w: '120px' },
      { key: 'indicators', label: 'Indicators',            w: '90px' },
      { key: 'tlp',        label: 'TLP',                   w: '70px' },
      { key: 'created',    label: 'Created',  mono: true,  w: '140px' },
      { key: 'tags',       label: 'Tags',                  w: '200px' },
      { key: 'countries',  label: 'Targets',               w: '160px' },
    ],
    renderCell(key, val, row) {
      if (key === 'name')
        return `<a class="link" href="https://otx.alienvault.com/pulse/${row.id}" target="_blank" title="${esc(val)}">${esc(val).slice(0,80)}</a>`;
      if (key === 'tags')     return renderTags(val);
      if (key === 'countries') return renderTags(val);
      if (key === 'tlp') {
        const c = { white:'#ccc', green:var_low, amber:var_med, red:var_crit }[val?.toLowerCase()] || '#ccc';
        return `<span style="color:${c};font-weight:700;font-size:11px">TLP:${(val||'').toUpperCase()}</span>`;
      }
      return cell(key, val, row);
    },
  },

  virustotal: {
    label: 'VirusTotal', icon: '🔬',
    desc: 'VirusTotal threat analysis — multi-engine detection results.',
    statId: 'stat-vt', statusId: 'status-vt',
    countFn: d => d.items?.length ?? 0,
    apiRequired: true,
    secretName: 'VT_API_KEY',
    apiUrl: 'https://www.virustotal.com',
    columns: [
      { key: 'name',        label: 'Name / IOC',           w: '280px', trunc: true },
      { key: 'type',        label: 'Type',                 w: '80px' },
      { key: 'malicious',   label: 'Malicious',            w: '90px' },
      { key: 'suspicious',  label: 'Suspicious',           w: '90px' },
      { key: 'harmless',    label: 'Harmless',             w: '90px' },
      { key: 'tags',        label: 'Tags',                 w: '160px' },
    ],
    renderCell(key, val, row) {
      if (key === 'malicious')  return `<strong style="color:var(--crit)">${val}</strong>`;
      if (key === 'suspicious') return `<strong style="color:var(--med)">${val}</strong>`;
      if (key === 'tags')       return renderTags(val);
      if (key === 'name')
        return `<span class="mono truncate" style="max-width:260px" title="${esc(val)}">${esc(val)}</span>`;
      return cell(key, val, row);
    },
  },
};

// CSS variable helpers for inline use
const var_low  = '#22c55e';
const var_crit = '#ef4444';
const var_med  = '#eab308';

// ── Utilities ────────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function scoreColor(score) {
  const n = parseFloat(score);
  if (isNaN(n)) return '#888';
  if (n >= 9)   return var_crit;
  if (n >= 7)   return '#f97316';
  if (n >= 4)   return var_med;
  return var_low;
}

function renderTags(tags) {
  if (!Array.isArray(tags) || !tags.length) return '—';
  return `<div class="tag-list">${tags.slice(0,5).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div>`;
}

function cell(key, val, row) {
  if (val === null || val === undefined || val === '') return '<span style="color:var(--text-dim)">—</span>';
  const src = SOURCES[activeTab];
  const col = src.columns.find(c => c.key === key) || {};
  let s = esc(String(val));
  if (col.mono)  s = `<span class="mono">${s}</span>`;
  if (col.trunc) s = `<span class="truncate" title="${esc(String(val))}">${s}</span>`;
  return s;
}

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
  } catch { return iso; }
}

// ── Data loading ─────────────────────────────────────────────────────────────
async function loadData(showToast = false) {
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spinning');

  try {
    const r = await fetch(DATA_URL + '?_=' + Date.now());
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    ctiData = await r.json();
    updateStats();
    updateTicker();
    renderActiveTab();
    const genAt = ctiData.generated_at ? fmtDate(ctiData.generated_at) : '—';
    document.getElementById('last-updated').textContent = `Data: ${genAt} UTC`;
    if (showToast) toast('Threat data refreshed', 'ok');
  } catch (e) {
    console.error(e);
    if (showToast) toast(`Refresh failed: ${e.message}`, 'error');
  } finally {
    btn.classList.remove('spinning');
  }
}

// ── Stats bar ────────────────────────────────────────────────────────────────
function updateStats() {
  if (!ctiData?.sources) return;
  for (const [key, cfg] of Object.entries(SOURCES)) {
    const src = ctiData.sources[key];
    if (!src) continue;

    const statEl   = document.getElementById(cfg.statId);
    const statusEl = document.getElementById(cfg.statusId);
    const card     = statEl?.closest('.stat-card');

    if (src.status === 'ok') {
      statEl && (statEl.textContent = src.count ?? cfg.countFn(src));
      statusEl && (statusEl.className = 'stat-status ok');
      card?.classList.remove('loading');
    } else if (src.status === 'skipped') {
      statEl && (statEl.textContent = '—');
      statusEl && (statusEl.className = 'stat-status skipped');
      card?.classList.remove('loading');
    } else {
      statEl && (statEl.textContent = 'ERR');
      statusEl && (statusEl.className = 'stat-status error');
      card?.classList.remove('loading');
    }
  }
}

// ── Ticker ───────────────────────────────────────────────────────────────────
function updateTicker() {
  if (!ctiData?.sources) return;
  const items = [];

  const tf = ctiData.sources.threatfox;
  if (tf?.items) tf.items.slice(0,8).forEach(i => items.push(`[IOC] ${i.ioc} (${i.malware})`));

  const uh = ctiData.sources.urlhaus;
  if (uh?.items) uh.items.slice(0,6).forEach(i => items.push(`[URL] ${i.host} — ${i.threat}`));

  const mb = ctiData.sources.malwarebazaar;
  if (mb?.items) mb.items.slice(0,6).forEach(i => items.push(`[HASH] ${(i.sha256||'').slice(0,12)}… ${i.signature}`));

  const fe = ctiData.sources.feodo;
  if (fe?.items) fe.items.slice(0,5).forEach(i => items.push(`[C2] ${i.ip}:${i.port} (${i.malware})`));

  document.getElementById('ticker-content').textContent =
    items.length ? items.join('   ·   ') : 'No data — run the GitHub Actions workflow to populate.';
}

// ── Tab rendering ────────────────────────────────────────────────────────────
function renderActiveTab() {
  const src = ctiData?.sources?.[activeTab];
  const cfg = SOURCES[activeTab];
  const area = document.getElementById('table-area');
  const infoEl = document.getElementById('source-info');

  // Source info bar
  let infoParts = [`<strong>${cfg.label}</strong> — ${cfg.desc}`];
  if (cfg.apiRequired) {
    const status = src?.status === 'ok' ? '✓ Active' : 'No API key';
    infoParts.push(`<span class="badge api-required">API key required · ${status}</span>`);
  }
  if (src?.last_updated)
    infoParts.push(`<span style="margin-left:auto;color:var(--text-dim)">Updated ${fmtDate(src.last_updated)}</span>`);
  infoEl.innerHTML = infoParts.join(' ');

  if (!src) {
    area.innerHTML = `<div class="loading-spinner"><div class="spinner"></div><p>No data yet — trigger the GitHub Actions workflow.</p></div>`;
    return;
  }

  if (src.status === 'skipped') {
    area.innerHTML = noticeHtml('🔑', 'API Key Required',
      `Add <code>${cfg.secretName}</code> to your repository's GitHub Secrets:`,
      `Settings → Secrets and variables → Actions → New repository secret\nName: ${cfg.secretName}`,
      `Then re-run the workflow or wait for the next scheduled run.`);
    return;
  }

  if (src.status === 'error') {
    area.innerHTML = noticeHtml('⚠️', 'Fetch Error', `Could not load data from ${cfg.label}.`,
      src.error || 'Unknown error');
    return;
  }

  if (!src.items?.length) {
    area.innerHTML = noticeHtml('📭', 'No Items', 'The feed returned no items.');
    return;
  }

  renderTable(src.items, cfg);
}

function noticeHtml(icon, title, ...lines) {
  return `<div class="notice-card">
    <div class="notice-icon">${icon}</div>
    <h2>${esc(title)}</h2>
    ${lines.map(l => l.startsWith('Settings') || l.startsWith('Name:')
      ? `<code>${esc(l)}</code>` : `<p>${esc(l)}</p>`).join('')}
  </div>`;
}

// ── Table rendering ──────────────────────────────────────────────────────────
function renderTable(items, cfg) {
  const area = document.getElementById('table-area');
  const { col: sortCol, dir: sortDir } = sortState[activeTab] || {};

  let sorted = [...items];
  if (sortCol) {
    sorted.sort((a, b) => {
      const va = String(a[sortCol] ?? '');
      const vb = String(b[sortCol] ?? '');
      const cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
      return sortDir === 'asc' ? cmp : -cmp;
    });
  }

  const thead = cfg.columns.map(c => {
    let cls = '';
    if (c.key === sortCol) cls = sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc';
    return `<th class="${cls}" data-col="${c.key}" style="width:${c.w||'auto'}">
      ${esc(c.label)} <span class="sort-arrow"></span>
    </th>`;
  }).join('');

  const tbody = sorted.map(row => {
    const cells = cfg.columns.map(c => {
      const val = row[c.key];
      return `<td>${cfg.renderCell(c.key, val, row)}</td>`;
    }).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  area.innerHTML = `<table class="data-table">
    <thead><tr>${thead}</tr></thead>
    <tbody>${tbody}</tbody>
  </table>`;

  area.querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      const cur = sortState[activeTab] || {};
      sortState[activeTab] = {
        col,
        dir: cur.col === col && cur.dir === 'asc' ? 'desc' : 'asc',
      };
      renderActiveTab();
    });
  });
}

// ── Countdown ────────────────────────────────────────────────────────────────
function startCountdown() {
  clearInterval(countdownId);
  countSec = COUNTDOWN_SEC;
  countdownId = setInterval(() => {
    countSec--;
    if (countSec <= 0) {
      clearInterval(countdownId);
      loadData(true).then(startCountdown);
      return;
    }
    const m = String(Math.floor(countSec / 60)).padStart(1, '0');
    const s = String(countSec % 60).padStart(2, '0');
    document.getElementById('countdown').textContent = `${m}:${s}`;
  }, 1000);
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), 3500);
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Tab clicks
  document.getElementById('tab-nav').addEventListener('click', e => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeTab = btn.dataset.tab;
    if (ctiData) renderActiveTab();
  });

  // Refresh button
  document.getElementById('refresh-btn').addEventListener('click', () => {
    loadData(true).then(startCountdown);
  });

  // Initial load
  loadData().then(startCountdown);
});
