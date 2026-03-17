/**
 * Jercept Dashboard — frontend logic
 * Fetches data from GET /v1/dashboard and renders Charts.js visualisations.
 * Auto-refreshes every 30 seconds. Event feed auto-refreshes every 10 seconds.
 */

const API_BASE    = 'http://localhost:8000';  // Change to deployed URL in production
const STORAGE_KEY = 'csm_api_key';
const REFRESH_MS  = 30_000;
const FEED_MS     = 10_000;

// ── State ─────────────────────────────────────────────────────────────────────
let timelineChart = null;
let blockedChart  = null;
let feedTimer     = null;

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const key = loadApiKey();
  if (!key) {
    window.location.href = 'index.html';
    return;
  }
  maskKeyDisplay(key);
  fetchDashboard(key);
  setInterval(() => fetchDashboard(key), REFRESH_MS);
  startFeedTimer(key);
});

// ── API key helpers ───────────────────────────────────────────────────────────
function loadApiKey() {
  return localStorage.getItem(STORAGE_KEY) || '';
}
function maskKeyDisplay(key) {
  const el = document.getElementById('api-key-display');
  if (!el) return;
  const visible = key.slice(0, 12);
  el.textContent = visible + '••••••••';
}

// ── Main fetch ────────────────────────────────────────────────────────────────
async function fetchDashboard(apiKey) {
  try {
    const res = await fetch(`${API_BASE}/v1/dashboard?hours=24&limit=500`, {
      headers: { Authorization: `Bearer ${apiKey}` }
    });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderAll(data);
    setStatus(true);
    document.getElementById('last-refresh').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    setStatus(false);
    document.getElementById('last-refresh').textContent = 'Error — retrying…';
    console.warn('Dashboard fetch failed:', err);
  }
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderAll(data) {
  // Metric cards
  setText('m-total',   data.total_requests ?? '—');
  setText('m-blocked', data.blocked_attacks ?? '—');
  setText('m-rate',    (data.block_rate != null) ? data.block_rate.toFixed(1) + '%' : '—');
  setText('m-allowed', (data.total_requests != null && data.blocked_attacks != null)
    ? (data.total_requests - data.blocked_attacks) : '—');

  renderTimeline(data.attack_timeline || []);
  renderBlockedActions(data.top_blocked_actions || []);
  renderEventFeed(data.recent_events || []);
}

// ── Timeline Chart ────────────────────────────────────────────────────────────
function renderTimeline(timeline) {
  const labels   = timeline.map(p => p.hour.slice(11, 16));  // HH:MM
  const allowed  = timeline.map(p => p.allowed);
  const blocked  = timeline.map(p => p.blocked);

  const ctx = document.getElementById('timeline-chart').getContext('2d');
  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Allowed',
          data: allowed,
          borderColor: '#00d4aa',
          backgroundColor: 'rgba(0,212,170,0.08)',
          borderWidth: 2,
          pointRadius: 3,
          tension: 0.35,
          fill: true,
        },
        {
          label: 'Blocked',
          data: blocked,
          borderColor: '#ff4d5a',
          backgroundColor: 'rgba(255,77,90,0.08)',
          borderWidth: 2,
          pointRadius: 3,
          tension: 0.35,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          labels: { color: '#8b9ab5', font: { family: 'Inter' } }
        },
        tooltip: {
          backgroundColor: '#0f1420',
          borderColor: '#1e2a3f',
          borderWidth: 1,
          titleColor: '#e8eaf0',
          bodyColor: '#8b9ab5',
        }
      },
      scales: {
        x: {
          ticks: { color: '#4a5568', font: { size: 11 } },
          grid:  { color: '#1e2a3f' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#4a5568', font: { size: 11 } },
          grid:  { color: '#1e2a3f' },
        }
      }
    }
  });
}

// ── Blocked Actions Chart ─────────────────────────────────────────────────────
function renderBlockedActions(actions) {
  const labels = actions.map(a => a.action);
  const counts = actions.map(a => a.count);

  const ctx = document.getElementById('blocked-chart').getContext('2d');
  if (blockedChart) blockedChart.destroy();

  blockedChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Blocked attempts',
        data: counts,
        backgroundColor: 'rgba(255,77,90,0.25)',
        borderColor: '#ff4d5a',
        borderWidth: 1,
        borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f1420',
          borderColor: '#1e2a3f',
          borderWidth: 1,
          titleColor: '#e8eaf0',
          bodyColor: '#8b9ab5',
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: '#4a5568', font: { size: 11 } },
          grid:  { color: '#1e2a3f' },
        },
        y: {
          ticks: {
            color: '#8b9ab5',
            font: { size: 12, family: 'JetBrains Mono' }
          },
          grid: { display: false },
        }
      }
    }
  });
}

// ── Event Table ───────────────────────────────────────────────────────────────
function renderEventFeed(events) {
  const tbody = document.getElementById('event-tbody');
  const countEl = document.getElementById('event-count');
  if (!tbody) return;

  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="5">
      <div class="empty-state"><span>🛡️</span><p>No events yet — run an agent to see data</p></div>
    </td></tr>`;
    if (countEl) countEl.textContent = '';
    return;
  }

  if (countEl) countEl.textContent = `${events.length} events`;

  tbody.innerHTML = events.map(ev => {
    const time    = ev.ts ? new Date(ev.ts).toLocaleTimeString() : '—';
    const intent  = truncate(ev.raw_intent || '—', 36);
    const action  = ev.action || '—';
    const resource = truncate(ev.resource || '—', 24);
    const badge   = ev.permitted
      ? '<span class="badge allowed">✓ Allowed</span>'
      : '<span class="badge blocked">✗ Blocked</span>';
    const rowClass = ev.permitted ? '' : 'blocked-row';
    return `<tr class="${rowClass}">
      <td class="mono">${esc(time)}</td>
      <td>${esc(intent)}</td>
      <td class="mono">${esc(action)}</td>
      <td class="mono">${esc(resource)}</td>
      <td>${badge}</td>
    </tr>`;
  }).join('');
}

// ── Feed auto-refresh ─────────────────────────────────────────────────────────
function startFeedTimer(apiKey) {
  if (feedTimer) clearInterval(feedTimer);
  feedTimer = setInterval(() => fetchDashboard(apiKey), FEED_MS);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function truncate(str, len) {
  return str.length > len ? str.slice(0, len) + '…' : str;
}
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function setStatus(online) {
  const dot = document.getElementById('status-dot');
  if (!dot) return;
  dot.style.background   = online ? '#00d4aa' : '#ff4d5a';
  dot.style.boxShadow    = online ? '0 0 6px #00d4aa' : '0 0 6px #ff4d5a';
}
function logout() {
  localStorage.removeItem(STORAGE_KEY);
  window.location.href = 'index.html';
}
