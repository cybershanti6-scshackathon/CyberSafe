/**
 * CyberSure Scanner Client Library
 * =================================
 * Shared library for communicating with the MSME Cyber Auditor backend.
 * Provides: scanner listing, schema fetching, scan execution, and result rendering.
 *
 * Backend API (FastAPI, port 8000):
 *   GET  /api/health
 *   GET  /api/system-info
 *   GET  /api/scanners
 *   GET  /api/scanners/{id}
 *   POST /api/scanners/{id}/scan
 *   POST /api/scan-all
 *   POST /api/export-pdf
 */

const ScannerAPI = {
  BASE: '',  // Same origin — no CORS needed

  // ── Fetch helpers ────────────────────────────────────────────────
  async get(path) {
    const res = await fetch(`${this.BASE}${path}`);
    if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(`${this.BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `POST ${path} failed: ${res.status}`);
    }
    return res.json();
  },

  // ── API endpoints ────────────────────────────────────────────────
  async health() {
    return this.get('/api/health');
  },

  async systemInfo() {
    return this.get('/api/system-info');
  },

  async listScanners() {
    return this.get('/api/scanners');
  },

  async getScannerSchema(id) {
    return this.get(`/api/scanners/${id}`);
  },

  async runScan(scannerId, config = {}, targetType = null, target = null) {
    return this.post(`/api/scanners/${scannerId}/scan`, {
      config,
      target_type: targetType,
      target,
    });
  },

  async scanAll(config = {}, targetType = null, target = null) {
    return this.post('/api/scan-all', { config, target_type: targetType, target });
  },

  async exportPdf(results, title = 'Security Audit Report', target = '', scanType = '') {
    const res = await fetch(`${this.BASE}/api/export-pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ results, title, target, scan_type: scanType }),
    });
    if (!res.ok) throw new Error('PDF export failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

// ── Scanner Category Mapping ──────────────────────────────────────
// Maps page names to the scanner categories/IDs they use
const ScannerCategories = {
  rpp: ['RPP'],           // Password Policy scanners
  nes: ['NES'],           // Network & Email Security scanners
  web: ['WEB', 'WEB.1'],  // Web Security scanners
  devices: ['DEVICE', 'VENDOR', 'CISCO', 'FORTINET', 'JUNIPER'], // Device/Vendor scanners
};

// ── Form Rendering ────────────────────────────────────────────────
// Renders dynamic form fields from scanner input_fields schema
function renderScannerFields(container, fields, systemInfo) {
  container.innerHTML = '';
  const grid = document.createElement('div');
  grid.className = 'form-grid';

  fields.forEach(f => {
    // Skip auto-detect info fields
    if (f.name && f.name.startsWith('_auto')) {
      const banner = document.createElement('div');
      banner.className = 'full notice';
      banner.innerHTML = `<span class="material-symbols-outlined" style="vertical-align:middle;margin-right:6px">wifi</span> ${f.help_text || 'This scanner auto-detects your system — no input needed'}`;
      grid.appendChild(banner);
      return;
    }

    const group = document.createElement('div');
    group.className = 'field';

    const effectiveDefault = (f.name === 'target_type' && systemInfo?.recommended_target_type)
      ? systemInfo.recommended_target_type
      : f.default;

    if (f.field_type === 'boolean') {
      group.innerHTML = `
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
          <input type="checkbox" name="${f.name}" ${f.default ? 'checked' : ''} style="accent-color:var(--primary);width:18px;height:18px">
          <span>${f.label}</span>
        </label>
        ${f.help_text ? `<div class="muted" style="font-size:12px;margin-top:2px">${f.help_text}</div>` : ''}
      `;
    } else if (f.field_type === 'select') {
      const options = (f.options || []).map(o =>
        `<option value="${o}" ${o === effectiveDefault ? 'selected' : ''}>${o}</option>`
      ).join('');
      group.innerHTML = `
        <label>${f.label}</label>
        <select name="${f.name}">${options}</select>
        ${f.help_text ? `<div class="muted" style="font-size:12px;margin-top:2px">${f.help_text}</div>` : ''}
      `;
    } else if (f.field_type === 'number') {
      group.innerHTML = `
        <label>${f.label}</label>
        <input type="number" name="${f.name}" value="${f.default ?? ''}"
          ${f.min_value != null ? `min="${f.min_value}"` : ''}
          ${f.max_value != null ? `max="${f.max_value}"` : ''}>
        ${f.help_text ? `<div class="muted" style="font-size:12px;margin-top:2px">${f.help_text}</div>` : ''}
      `;
    } else {
      // text / textarea
      if (f.name === 'sample_hashes' || (f.placeholder && f.placeholder.includes('\n'))) {
        group.innerHTML = `
          <label>${f.label}</label>
          <textarea name="${f.name}" placeholder="${f.placeholder || ''}">${f.default ?? ''}</textarea>
          ${f.help_text ? `<div class="muted" style="font-size:12px;margin-top:2px">${f.help_text}</div>` : ''}
        `;
      } else {
        group.innerHTML = `
          <label>${f.label}</label>
          <input type="text" name="${f.name}" value="${f.default ?? ''}" placeholder="${f.placeholder || ''}">
          ${f.help_text ? `<div class="muted" style="font-size:12px;margin-top:2px">${f.help_text}</div>` : ''}
        `;
      }
    }

    grid.appendChild(group);
  });

  container.appendChild(grid);
}

// ── Collect form data into config object ──────────────────────────
function collectFormConfig(form) {
  const config = {};
  const formData = new FormData(form);
  for (const [key, value] of formData.entries()) {
    if (key === 'target_type' || key === 'target') continue; // handled separately
    const input = form.querySelector(`[name="${key}"]`);
    if (input) {
      if (input.type === 'checkbox') {
        config[key] = input.checked;
      } else if (input.type === 'number') {
        config[key] = value === '' ? null : Number(value);
      } else {
        config[key] = value;
      }
    }
  }
  return config;
}

// ── Result Rendering ──────────────────────────────────────────────
function renderScanResult(container, result) {
  if (!result || result.error) {
    container.innerHTML = `
      <div class="finding" style="border:none">
        <span class="severity critical">ERROR</span>
        <div><strong>Scan failed</strong><p class="muted">${result?.error || 'Unknown error occurred'}</p></div>
      </div>`;
    return;
  }

  const score = result.score || 0;
  const status = result.status?.value || (score >= 85 ? 'PASSED' : score >= 50 ? 'WARNING' : 'FAILED');
  const statusClass = status === 'PASSED' ? 'low' : status === 'WARNING' ? 'medium' : 'critical';
  const checks = result.checks || [];

  let html = `
    <div class="grid-4" style="margin-bottom:16px">
      <div class="card score-card">
        <span class="muted">Score</span>
        <div class="score" style="color:var(--${status === 'PASSED' ? 'success' : status === 'WARNING' ? 'warning' : 'danger'})">${score}/100</div>
        <div class="progress"><span style="width:${score}%"></span></div>
      </div>
      <div class="card score-card">
        <span class="muted">Status</span>
        <div class="score" style="font-size:22px"><span class="severity ${statusClass}">${status}</span></div>
      </div>
      <div class="card score-card">
        <span class="muted">Checks Passed</span>
        <div class="score">${checks.filter(c => c.passed).length}/${checks.length}</div>
      </div>
      <div class="card score-card">
        <span class="muted">Scanner</span>
        <div class="score" style="font-size:16px">${result.scanner_id || 'N/A'}</div>
      </div>
    </div>`;

  if (result.summary) {
    html += `<div class="card" style="margin-bottom:16px"><h3 style="margin:0 0 8px">Summary</h3><p class="muted">${result.summary}</p></div>`;
  }

  if (checks.length > 0) {
    html += `<div class="card"><h3 style="margin:0 0 12px">Check Results</h3>`;
    checks.forEach(c => {
      const severity = c.passed ? 'low' : (c.severity?.toLowerCase() || 'medium');
      const label = c.passed ? 'PASS' : (c.severity || 'FAIL');
      html += `
        <div class="finding">
          <span class="severity ${severity}">${label}</span>
          <div style="flex:1">
            <strong>${c.check_name || c.name || 'Check'}</strong>
            <p class="muted">${c.expected_value || ''} ${c.actual_value ? '→ ' + c.actual_value : ''}</p>
            ${c.remediation_command ? `<p class="muted" style="margin-top:4px;font-size:12px"><em>Remediation: ${c.remediation_command}</em></p>` : ''}
          </div>
        </div>`;
    });
    html += `</div>`;
  }

  if (result.remediation) {
    html += `
      <div class="card" style="margin-top:16px">
        <h3 style="margin:0 0 8px">Remediation</h3>
        <pre style="background:var(--surface-2);padding:14px;border-radius:12px;font-size:13px;overflow-x:auto;white-space:pre-wrap;margin:0">${result.remediation}</pre>
      </div>`;
  }

  container.innerHTML = html;
}

// ── Batch Result Rendering ────────────────────────────────────────
function renderBatchResults(container, results) {
  const entries = Object.entries(results);
  if (!entries.length) {
    container.innerHTML = '<div class="empty">No results to display.</div>';
    return;
  }

  let html = `<div class="grid-4" style="margin-bottom:16px">`;
  let totalScore = 0;
  let count = 0;

  entries.forEach(([id, r]) => {
    const score = r.score || 0;
    totalScore += score;
    count++;
    const status = r.error ? 'ERROR' : (score >= 85 ? 'PASS' : score >= 50 ? 'WARN' : 'FAIL');
    const statusClass = status === 'PASS' ? 'low' : status === 'WARN' ? 'medium' : 'critical';
    html += `
      <div class="card score-card">
        <span class="muted">${id}</span>
        <div class="score">${r.error ? '—' : score}</div>
        <span class="severity ${statusClass}" style="margin-top:8px">${status}</span>
      </div>`;
  });
  html += `</div>`;

  const avgScore = count > 0 ? Math.round(totalScore / count) : 0;
  html += `<div class="card" style="margin-bottom:16px">
    <h3 style="margin:0 0 8px">Overall Score: ${avgScore}/100</h3>
    <div class="progress"><span style="width:${avgScore}%"></span></div>
  </div>`;

  container.innerHTML = html;
}
