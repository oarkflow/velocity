const apiBase = window.location.origin;

function qs(sel, root=document) { return root.querySelector(sel); }
function qsa(sel, root=document){ return [...root.querySelectorAll(sel)]; }

function tokenHeader() {
  const t = localStorage.getItem('token');
  return t && !tokenExpired(t) ? {'Authorization': 'Bearer ' + t} : {};
}

function tokenExpired(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1] || ''));
    return payload.exp && payload.exp * 1000 <= Date.now();
  } catch (e) {
    return false;
  }
}

function hasToken() {
  const t = localStorage.getItem('token');
  if (!t) return false;
  if (tokenExpired(t)) {
    localStorage.removeItem('token');
    return false;
  }
  return true;
}

function showLogin() {
  localStorage.removeItem('token');
  qs('#file-manager').classList.add('hidden');
  qs('#login').classList.remove('hidden');
  qs('#auth-ui #user-info').classList.add('hidden');
  qs('#logout-btn').classList.add('hidden');
}

async function api(path, opts={}){
  opts.headers = Object.assign({}, tokenHeader(), opts.headers || {});
  const res = await fetch(apiBase + path, opts);
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch(e){}
  if (res.status === 401 && path !== '/auth/login') {
    showLogin();
  }
  return {ok:res.ok,status:res.status,body};
}

// Auth
qs('#login-form').addEventListener('submit', async (ev) =>{
  ev.preventDefault();
  const form = ev.target;
  const fd = new FormData(form);
  const payload = {username: fd.get('username'), password: fd.get('password')};
  const r = await api('/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  if (!r.ok){ alert(`Login failed: ${r.status} ${JSON.stringify(r.body)}`); return; }
  localStorage.setItem('token', r.body.token);
  qs('#login').classList.add('hidden');
  qs('#file-manager').classList.remove('hidden');
  qs('#auth-ui #user-info').textContent = r.body.user.username; qs('#auth-ui #user-info').classList.remove('hidden');
  qs('#logout-btn').classList.remove('hidden');
  // Load root directory
  loadDirectory('');
});

qs('#logout-btn').addEventListener('click', () => { localStorage.removeItem('token'); location.reload(); });

// File Manager
let currentPath = '';

async function loadDirectory(path) {
  currentPath = path;
  updateBreadcrumb(path);

  const r = await api('/api/objects?prefix=' + encodeURIComponent(path));
  const tbody = qs('#files-list');
  tbody.innerHTML = '';

  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-red-500">Error loading directory</td></tr>';
    return;
  }

  const objects = r.body.objects || [];
  const folders = new Set();
  const files = [];

  // Separate folders and files
  objects.forEach(obj => {
    const relativePath = obj.path.replace(path, '').replace(/^\//, '');
    if (relativePath.includes('/')) {
      const folder = relativePath.split('/')[0];
      folders.add(folder);
    } else {
      files.push(obj);
    }
  });

  // Add parent directory if not root
  if (path) {
    const tr = document.createElement('tr');
    tr.className = 'file-row file-row-clickable';
    tr.innerHTML = `
      <td>
        <div class="file-name-cell">
          <svg class="file-icon file-icon-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
          </svg>
          ..
        </div>
      </td>
      <td>Folder</td>
      <td>-</td>
      <td>-</td>
      <td></td>
    `;
    tr.addEventListener('click', () => {
      const parentPath = path.split('/').slice(0, -2).join('/') + (path.split('/').slice(0, -2).length > 0 ? '/' : '');
      loadDirectory(parentPath);
    });
    tbody.appendChild(tr);
  }

  // Add folders
  folders.forEach(folder => {
    const tr = document.createElement('tr');
    tr.className = 'file-row file-row-clickable';
    tr.innerHTML = `
      <td>
        <div class="file-name-cell">
          <svg class="file-icon file-icon-folder" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2H5a2 2 0 00-2-2z"></path>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5a2 2 0 012-2h4a2 2 0 012 2v2H8V5z"></path>
          </svg>
          ${decodeURIComponent(folder)}
        </div>
      </td>
      <td>Folder</td>
      <td>-</td>
      <td>-</td>
      <td>
        <button class="file-row-btn file-row-btn-danger" data-delete-folder="${folder}">Delete</button>
      </td>
    `;
    tr.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      loadDirectory(path + folder + '/');
    });
    tbody.appendChild(tr);
  });

  // Add files
  files.forEach(file => {
    const tr = document.createElement('tr');
    tr.className = 'file-row';
    const size = file.size ? (file.size >= 1024 ? (file.size/1024).toFixed(1) + ' KB' : file.size + ' B') : '-';
    const modified = file.modified_at ? new Date(file.modified_at).toLocaleString() : '-';
    const isImage = file.content_type && file.content_type.startsWith('image/');
    const fileName = decodeURIComponent(file.path).split('/').pop();

    tr.innerHTML = `
      <td>
        <div class="file-name-cell">
          <svg class="file-icon file-icon-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
          </svg>
          ${fileName}
        </div>
      </td>
      <td>${file.content_type || 'Unknown'}</td>
      <td>${size}</td>
      <td>${modified}</td>
      <td>
        <div class="file-row-actions">
          ${isImage ? '<button class="file-row-btn" data-preview="' + file.path + '">Preview</button>' : ''}
          <button class="file-row-btn" data-download="' + file.path + '">Download</button>
          <button class="file-row-btn file-row-btn-danger" data-delete="' + file.path + '">Delete</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function updateBreadcrumb(path) {
  const breadcrumb = qs('#breadcrumb');
  const parts = path.split('/').filter(p => p);
  let html = '<span class="cursor-pointer text-blue-500" data-path="">Root</span>';

  let currentPath = '';
  parts.forEach((part, index) => {
    currentPath += part + '/';
    html += ' / <span class="cursor-pointer text-blue-500" data-path="' + currentPath + '">' + part + '</span>';
  });

  breadcrumb.innerHTML = html;

  // Add click handlers
  breadcrumb.querySelectorAll('[data-path]').forEach(el => {
    el.addEventListener('click', () => {
      loadDirectory(el.dataset.path);
    });
  });
}

// Upload button
qs('#upload-btn').addEventListener('click', () => {
  qs('#upload-btn').closest('details')?.removeAttribute('open');
  qs('#upload-modal').classList.remove('hidden');
});

qs('#upload-cancel').addEventListener('click', () => {
  qs('#upload-modal').classList.add('hidden');
});

qs('#upload-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const fd = new FormData(form);
  const file = form.querySelector('input[type=file]').files[0];
  if (!file) {
    alert('Please select a file');
    return;
  }

  const uploadPath = currentPath + file.name;
  const uploadData = new FormData();
  uploadData.append('file', file);

  const r = await api('/api/objects/' + encodeURIComponent(uploadPath), {
    method: 'POST',
    body: uploadData
  });

  if (r.ok) {
    qs('#upload-modal').classList.add('hidden');
    loadDirectory(currentPath);
  } else {
    alert('Upload failed: ' + JSON.stringify(r.body));
  }
});

// New folder
qs('#new-folder-btn').addEventListener('click', () => {
  qs('#new-folder-btn').closest('details')?.removeAttribute('open');
  qs('#new-folder-modal').classList.remove('hidden');
});

qs('#new-folder-cancel').addEventListener('click', () => {
  qs('#new-folder-modal').classList.add('hidden');
});

qs('#new-folder-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const form = ev.target;
  const fd = new FormData(form);
  const folderName = fd.get('folder-name');
  if (!folderName) {
    alert('Please enter a folder name');
    return;
  }

  const folderPath = currentPath + folderName + '/';
  const r = await api('/api/folders/' + encodeURIComponent(folderPath), {
    method: 'POST'
  });

  if (r.ok) {
    qs('#new-folder-modal').classList.add('hidden');
    loadDirectory(currentPath);
  } else {
    alert('Failed to create folder: ' + JSON.stringify(r.body));
  }
});

// Refresh
qs('#refresh-btn').addEventListener('click', () => {
  loadDirectory(currentPath);
});

// Search
qs('#search-input').addEventListener('input', (ev) => {
  const query = ev.target.value.toLowerCase();
  const rows = qs('#files-list').querySelectorAll('tr');
  rows.forEach(row => {
    const name = row.querySelector('td:first-child').textContent.toLowerCase();
    if (name.includes(query)) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
});

// File actions
qs('#files-list').addEventListener('click', async (ev) => {
  const preview = ev.target.dataset.preview;
  const download = ev.target.dataset.download;
  const deleteFile = ev.target.dataset.delete;
  const deleteFolder = ev.target.dataset.deleteFolder;

  if (preview) {
    // preview uses the encoded path returned by the API directly (no double-encoding)
    const res = await fetch(apiBase + '/api/objects/' + preview, {
      headers: tokenHeader()
    });
    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      qs('#preview-img').src = url;
      qs('#preview-modal').classList.remove('hidden');
    } else {
      alert('Preview failed: ' + res.status);
    }
  }

  if (download) {
    const res = await fetch(apiBase + '/api/objects/' + download, {
      headers: tokenHeader()
    });
    if (res.ok) {
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = decodeURIComponent(download.split('/').pop());
      a.click();
    } else {
      alert('Download failed: ' + res.status);
    }
  }

  if (deleteFile) {
    if (confirm('Delete file ' + decodeURIComponent(deleteFile) + '?')) {
      const r = await api('/api/objects/' + deleteFile, { method: 'DELETE' });
      if (r.ok) {
        loadDirectory(currentPath);
      } else {
        alert('Delete failed: ' + JSON.stringify(r.body));
      }
    }
  }

  if (deleteFolder) {
    if (confirm('Delete folder ' + deleteFolder + '?')) {
      const r = await api('/api/folders/' + encodeURIComponent(currentPath + deleteFolder + '/'), { method: 'DELETE' });
      if (r.ok) {
        loadDirectory(currentPath);
      } else {
        alert('Delete folder failed: ' + JSON.stringify(r.body));
      }
    }
  }
});

qs('#preview-close').addEventListener('click', () => {
  qs('#preview-modal').classList.add('hidden');
  qs('#preview-img').src = '';
});

// Knowledge Graph
function escapeHTML(value) {
  return String(value || '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function splitCSV(value) {
  return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
}

function kgNumber(value, fallback=0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function renderJSON(value) {
  return `<pre class="kg-json">${escapeHTML(JSON.stringify(value || {}, null, 2))}</pre>`;
}

function queryTerms(query) {
  return String(query || '').toLowerCase().split(/[^a-z0-9_./-]+/).filter(term => term.length > 1);
}

function makeSnippet(text, query, size=520) {
  const raw = String(text || '').replace(/\s+/g, ' ').trim();
  if (!raw || raw.length <= size) return raw;
  const lower = raw.toLowerCase();
  let pos = -1;
  for (const term of queryTerms(query)) {
    pos = lower.indexOf(term);
    if (pos >= 0) break;
  }
  if (pos < 0) return raw.slice(0, size) + '...';
  const start = Math.max(0, pos - Math.floor(size * 0.35));
  const end = Math.min(raw.length, start + size);
  return `${start > 0 ? '... ' : ''}${raw.slice(start, end)}${end < raw.length ? ' ...' : ''}`;
}

function highlightQuery(text, query) {
  let html = escapeHTML(text);
  for (const term of queryTerms(query).sort((a, b) => b.length - a.length)) {
    const escaped = escapeHTML(term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    html = html.replace(new RegExp(`(${escaped})`, 'ig'), '<mark>$1</mark>');
  }
  return html;
}

function objectPathFromHit(hit) {
  return (hit.metadata && hit.metadata.path) || String(hit.source || '').replace(/^object:/, '');
}

function renderKGHits(hits, query='', emptyText='No results') {
  return hits.length ? hits.map(hit => `
    <article class="kg-hit" data-doc-id="${escapeHTML(hit.doc_id || '')}">
      <div class="kg-hit-head">
        <span class="kg-hit-title">${escapeHTML(hit.title || hit.source || hit.doc_id || hit.chunk_id)}</span>
        <span class="kg-pill">score ${Number(hit.score || 0).toFixed(4)}</span>
        ${hit.metadata?.content_type ? `<span class="kg-pill">${escapeHTML(hit.metadata.content_type)}</span>` : ''}
      </div>
      <div class="kg-hit-snippet">${highlightQuery(makeSnippet(hit.text || '', query), query)}</div>
      <div class="kg-hit-meta">
        <span>${escapeHTML(objectPathFromHit(hit) || hit.source || '-')}</span>
        <span>doc ${escapeHTML(hit.doc_id || '-')}</span>
      </div>
      <details class="kg-doc-details">
        <summary>Document details</summary>
        <div class="kg-doc-body">
          <div><strong>Title</strong>${escapeHTML(hit.title || '-')}</div>
          <div><strong>Source</strong>${escapeHTML(hit.source || '-')}</div>
          <div><strong>Content type</strong>${escapeHTML(hit.metadata?.content_type || hit.metadata?.resource_type || '-')}</div>
          <div><strong>Object ID</strong>${escapeHTML(hit.metadata?.object_id || '-')}</div>
          ${objectPathFromHit(hit) ? `<a class="kg-doc-link" href="/api/objects/${encodeURIComponent(objectPathFromHit(hit))}" target="_blank" rel="noopener">Open document</a>` : ''}
        </div>
      </details>
    </article>
  `).join('') : `<div class="text-gray-500">${emptyText}</div>`;
}

function setActiveTab(name) {
  if (!hasToken()) {
    showLogin();
    return;
  }
  const filesActive = name === 'files';
  qs('#files-panel').classList.toggle('hidden', !filesActive);
  qs('#kg-panel').classList.toggle('hidden', filesActive);
  qs('#tab-files').className = filesActive ? 'px-3 py-2 border-b-2 border-blue-600 text-blue-700 font-medium' : 'px-3 py-2 border-b-2 border-transparent text-gray-600 hover:text-blue-700';
  qs('#tab-kg').className = filesActive ? 'px-3 py-2 border-b-2 border-transparent text-gray-600 hover:text-blue-700' : 'px-3 py-2 border-b-2 border-blue-600 text-blue-700 font-medium';
  if (!filesActive) {
    loadKGDashboard();
  }
}

qs('#tab-files').addEventListener('click', () => setActiveTab('files'));
qs('#tab-kg').addEventListener('click', () => setActiveTab('kg'));

let lastKGGraphRequest = null;
let kgSyncRunning = false;

async function loadKGDashboard() {
  if (!hasToken()) return;
  const analytics = await api('/api/v1/kg/analytics');
  if (analytics.status === 401 || !hasToken()) return;

  const [status, rules, jobs, merges, relations] = await Promise.all([
    api('/api/v1/kg/sync/status'),
    api('/api/v1/kg/ner/rules'),
    api('/api/v1/kg/jobs?status=running'),
    api('/api/v1/kg/entities/merge?status=pending'),
    api('/api/v1/kg/relations/query', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({limit:20})})
  ]);
  if (analytics.ok) {
    qs('#kg-analytics').innerHTML = `
      <div>Documents: ${analytics.body.total_documents || 0}</div>
      <div>Chunks: ${analytics.body.total_chunks || 0}</div>
      <div>Entities: ${analytics.body.total_entities || 0}</div>
    `;
  }
  if (status.ok) {
    const body = status.body || {};
    kgSyncRunning = Boolean(body.running);
    qs('#kg-sync-status').innerHTML = `
      <div>Enabled: ${body.enabled ? 'yes' : 'no'}</div>
      <div>Running: ${body.running ? 'yes' : 'no'}</div>
      <div>Last error: ${escapeHTML(body.last_error || '-')}</div>
    `;
  }
  if (rules.ok) {
    renderKGRules(rules.body.rules || []);
  }
  if (jobs.ok) renderKGJobs(jobs.body.jobs || []);
  if (merges.ok) renderKGMerges(merges.body.proposals || []);
  if (relations.ok) renderKGRelations(relations.body.relations || []);
}

function renderKGRules(rules) {
  qs('#kg-rules').innerHTML = rules.length ? rules.slice(0, 40).map(rule => `
    <div class="border-b border-gray-200 py-1">
      <span class="font-medium">${escapeHTML(rule.type)}</span>
      <span class="text-gray-500">${Number(rule.confidence || 0).toFixed(2)}</span>
      <div class="text-xs text-gray-500 truncate">${escapeHTML(rule.pattern)}</div>
    </div>
  `).join('') : '<div class="text-gray-500">No rules loaded</div>';
}

qs('#kg-sync-btn').addEventListener('click', async () => {
  const r = await api('/api/v1/kg/sync', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      enabled: true,
      existing: true,
      sync_workers: 4,
      max_value_bytes: 67108864,
      resources: ['kv', 'object', 'secret', 'envelope', 'entity']
    })
  });
  if (!r.ok) {
    alert('KG sync failed: ' + JSON.stringify(r.body));
    return;
  }
  loadKGDashboard();
});

qs('#kg-rebuild-btn').addEventListener('click', async () => {
  const r = await api('/api/v1/kg/rebuild', {method:'POST'});
  if (!r.ok) {
    alert('KG rebuild failed: ' + JSON.stringify(r.body));
    return;
  }
  loadKGDashboard();
});

qs('#kg-object-probe-btn').addEventListener('click', () => {
  const form = qs('#kg-search-form');
  form.querySelector('[name=query]').value = 'OBJECT-CONTENT-0000100';
  form.querySelector('[name=limit]').value = '5';
  form.dispatchEvent(new Event('submit', {cancelable:true, bubbles:true}));
});

qs('#kg-search-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const query = String(fd.get('query') || '').trim();
  const limit = Number(fd.get('limit') || 10);
  if (!query) return;
  const payload = {
    query,
    limit,
    mode: String(fd.get('mode') || ''),
    match_mode: String(fd.get('match_mode') || ''),
    prefix_match: fd.get('prefix_match') === 'on',
    fuzzy: fd.get('fuzzy') === 'on',
    fuzzy_max_edits: fd.get('fuzzy') === 'on' ? 1 : 0,
    enable_graph: fd.get('enable_graph') === 'on',
    graph_depth: kgNumber(fd.get('graph_depth'), 2),
    enable_vector: fd.get('enable_vector') === 'on',
    min_score: kgNumber(fd.get('min_score'), 0)
  };
  if (!payload.mode) delete payload.mode;
  if (!payload.match_mode) delete payload.match_mode;
  if (!payload.min_score) delete payload.min_score;
  const search = await api('/api/v1/kg/search', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!search.ok) {
    alert('KG search failed: ' + JSON.stringify(search.body));
    return;
  }
  const hits = search.body.hits || [];
  qs('#kg-results').innerHTML = renderKGHits(hits, query, kgNoResultsMessage(query));
});

function kgNoResultsMessage(query) {
  const suffix = kgSyncRunning ? ' Indexing is still running, so newly uploaded files may appear in a moment.' : ' Try Broad match, check that the file was synced, or search a shorter phrase.';
  return `<div class="kg-empty"><strong>No results for "${escapeHTML(query)}"</strong>${suffix}</div>`;
}

qs('#kg-context-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = {
    query: String(fd.get('query') || '').trim(),
    limit: kgNumber(fd.get('limit'), 10),
    graph_depth: kgNumber(fd.get('depth'), 2),
    include_related: fd.get('include_related') === 'on',
    relation_types: splitCSV(fd.get('relation_types')),
    context_weight: 0.45,
    search_weight: 1
  };
  if (!payload.query) return;
  const r = await api('/api/v1/kg/context-search', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('Context search failed: ' + JSON.stringify(r.body));
    return;
  }
  const hits = r.body.hits || [];
  qs('#kg-context-results').innerHTML = hits.length ? hits.map(hit => `
    <div class="kg-hit">
      <div class="flex flex-wrap gap-2 items-center">
        <span class="font-medium">${escapeHTML(hit.title || hit.source || hit.doc_id)}</span>
        <span class="kg-pill">${escapeHTML(hit.match_kind || 'hit')}</span>
        <span class="kg-pill">final ${Number(hit.final_score || hit.score || 0).toFixed(4)}</span>
        <span class="kg-pill">context ${Number(hit.context_score || 0).toFixed(4)}</span>
      </div>
      <div class="text-gray-600 mt-1">${escapeHTML((hit.text || '').slice(0, 280))}</div>
      <div class="text-xs text-gray-500 mt-1">relations ${(hit.related_relations || []).length}</div>
    </div>
  `).join('') : '<div class="text-gray-500">No context hits</div>';
});

qs('#kg-materialize-btn').addEventListener('click', async () => {
  if (!lastKGGraphRequest) {
    alert('Run a KG search first.');
    return;
  }
  const r = await api('/api/v1/kg/resource-graph/materialize', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({resource_graph: lastKGGraphRequest, created_by: 'admin-ui'})
  });
  if (!r.ok) {
    alert('Materialize failed: ' + JSON.stringify(r.body));
    return;
  }
  qs('#kg-graph').insertAdjacentHTML('afterbegin', `<div class="text-indigo-700">Materialized ${r.body.created || 0}, skipped ${r.body.skipped || 0}</div>`);
  loadKGDashboard();
});

qs('#kg-import-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const connector = String(fd.get('connector') || 'local_file');
  const target = String(fd.get('target') || '').trim();
  const table = String(fd.get('table') || '').trim();
  const limit = Number(fd.get('limit') || 50);
  if (!target) return;
  const payload = {connector, limit};
  if (connector === 'url') payload.url = target; else payload.path = target;
  if (table) payload.table = table;
  const r = await api('/api/v1/kg/connectors/import', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('KG import failed: ' + JSON.stringify(r.body));
    return;
  }
  qs('#kg-import-result').textContent = `Imported ${r.body.imported || 0}, skipped ${r.body.skipped || 0}`;
  loadKGDashboard();
});

qs('#kg-query-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const seed = String(fd.get('seed') || '').trim();
  const seedSearch = String(fd.get('seed_search') || '').trim();
  const depth = Number(fd.get('depth') || 2);
  const payload = {depth};
  if (seed) payload.seed_ids = seed.split(',').map(s => s.trim()).filter(Boolean);
  if (seedSearch) payload.seed_search = seedSearch;
  const r = await api('/api/v1/kg/query', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('Graph query failed: ' + JSON.stringify(r.body));
    return;
  }
  qs('#kg-persistent-graph').innerHTML = renderRelationList(r.body.relations || [], 'No persistent relations found');
});

qs('#kg-path-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = {
    source: String(fd.get('source') || '').trim(),
    target: String(fd.get('target') || '').trim(),
    query: {depth: 8}
  };
  if (!payload.source || !payload.target) return;
  const r = await api('/api/v1/kg/algorithms/path', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  qs('#kg-algorithms').innerHTML = r.ok ? `
    <div class="kg-hit">
      <div class="font-medium">Shortest path</div>
      <div class="text-gray-600">${escapeHTML((r.body.nodes || []).join(' -> '))}</div>
      <div class="mt-2">${renderRelationList(r.body.relations || [], 'No path relations')}</div>
    </div>
  ` : `<div class="text-red-600">${escapeHTML(JSON.stringify(r.body))}</div>`;
});

qs('#kg-metrics-btn').addEventListener('click', async () => {
  const r = await api('/api/v1/kg/algorithms/metrics', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({})
  });
  qs('#kg-algorithms').innerHTML = r.ok ? renderJSON(r.body) : `<div class="text-red-600">${escapeHTML(JSON.stringify(r.body))}</div>`;
});

qs('#kg-components-btn').addEventListener('click', async () => {
  const r = await api('/api/v1/kg/algorithms/components', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({depth: 8, limit: 500})
  });
  const components = Array.isArray(r.body) ? r.body : (r.body.components || []);
  qs('#kg-algorithms').innerHTML = r.ok ? (components.length ? components.slice(0, 20).map((c, i) => `
    <div class="kg-hit">
      <div class="font-medium">Component ${i + 1}</div>
      <div class="text-gray-600">${escapeHTML((c || []).slice(0, 20).join(', '))}</div>
    </div>
  `).join('') : '<div class="text-gray-500">No components</div>') : `<div class="text-red-600">${escapeHTML(JSON.stringify(r.body))}</div>`;
});

qs('#kg-mutations-btn').addEventListener('click', async () => {
  const r = await api('/api/v1/kg/mutations?limit=50');
  const records = r.body.records || r.body.mutations || r.body || [];
  qs('#kg-algorithms').innerHTML = r.ok && Array.isArray(records) ? (records.length ? records.map(m => `
    <div class="kg-hit">
      <div class="font-medium">${escapeHTML(m.action || '')} ${escapeHTML(m.entity || m.entity_type || '')}</div>
      <div class="text-xs text-gray-500">${escapeHTML(m.entity_id || '')} ${escapeHTML(m.actor || '')}</div>
    </div>
  `).join('') : '<div class="text-gray-500">No mutations</div>') : renderJSON(r.body);
});

qs('#kg-relation-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = {
    source: String(fd.get('source') || '').trim(),
    target: String(fd.get('target') || '').trim(),
    relation_type: String(fd.get('type') || '').trim(),
    evidence: String(fd.get('evidence') || '').trim(),
    created_by: 'admin-ui'
  };
  if (!payload.source || !payload.target || !payload.relation_type) return;
  const r = await api('/api/v1/kg/relations', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('Create relation failed: ' + JSON.stringify(r.body));
    return;
  }
  ev.target.reset();
  loadKGDashboard();
});

qs('#kg-load-jobs-btn').addEventListener('click', loadKGJobs);

async function loadKGJobs() {
  if (!hasToken()) return;
  const r = await api('/api/v1/kg/jobs');
  if (r.ok) renderKGJobs(r.body.jobs || []);
}

function renderKGJobs(jobs) {
  qs('#kg-jobs').innerHTML = jobs.length ? jobs.slice(0, 30).map(job => `
    <div class="border-b border-gray-200 pb-2">
      <div class="font-medium">${escapeHTML(job.connector || job.job_id)} <span class="text-gray-500">${escapeHTML(job.status || '')}</span></div>
      <div class="text-xs text-gray-500">imported ${job.imported || 0}, skipped ${job.skipped || 0}</div>
      ${job.status === 'running' || job.status === 'pending' ? `<button data-job-cancel="${escapeHTML(job.job_id)}" class="mt-1 text-red-700 text-xs">Cancel</button>` : ''}
    </div>
  `).join('') : '<div class="text-gray-500">No jobs</div>';
  document.querySelectorAll('[data-job-cancel]').forEach(btn => btn.addEventListener('click', async () => {
    const id = btn.getAttribute('data-job-cancel');
    const r = await api(`/api/v1/kg/jobs/${encodeURIComponent(id)}/cancel`, {method:'POST'});
    if (!r.ok) alert('Cancel failed: ' + JSON.stringify(r.body));
    loadKGJobs();
  }));
}

qs('#kg-ontology-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  let payload;
  try {
    payload = JSON.parse(String(new FormData(ev.target).get('ontology') || '{}'));
  } catch (err) {
    qs('#kg-ontology-result').textContent = 'Invalid JSON';
    return;
  }
  const r = await api('/api/v1/kg/ontology', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  qs('#kg-ontology-result').textContent = r.ok ? `Applied ${r.body.name || 'ontology'}` : `Failed: ${JSON.stringify(r.body)}`;
});

qs('#kg-merge-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = {
    target_id: String(fd.get('target') || '').trim(),
    source_ids: String(fd.get('sources') || '').split(',').map(s => s.trim()).filter(Boolean),
    created_by: 'admin-ui'
  };
  if (!payload.target_id || !payload.source_ids.length) return;
  const r = await api('/api/v1/kg/entities/merge/propose', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('Merge proposal failed: ' + JSON.stringify(r.body));
    return;
  }
  ev.target.reset();
  loadKGMerges();
});

async function loadKGMerges() {
  const r = await api('/api/v1/kg/entities/merge?status=pending');
  if (r.ok) renderKGMerges(r.body.proposals || []);
}

function renderKGMerges(proposals) {
  qs('#kg-merges').innerHTML = proposals.length ? proposals.slice(0, 30).map(p => `
    <div class="border-b border-gray-200 pb-2">
      <div class="font-medium">${escapeHTML(p.target_id || '')}</div>
      <div class="text-xs text-gray-500">${escapeHTML((p.source_ids || []).join(', '))}</div>
      <button data-merge-approve="${escapeHTML(p.proposal_id)}" class="mt-1 text-blue-700 text-xs">Approve</button>
    </div>
  `).join('') : '<div class="text-gray-500">No pending merges</div>';
  document.querySelectorAll('[data-merge-approve]').forEach(btn => btn.addEventListener('click', async () => {
    const id = btn.getAttribute('data-merge-approve');
    const r = await api(`/api/v1/kg/entities/merge/${encodeURIComponent(id)}/approve`, {method:'POST'});
    if (!r.ok) alert('Approve failed: ' + JSON.stringify(r.body));
    loadKGMerges();
  }));
}

function renderKGRelations(relations) {
  qs('#kg-relations').innerHTML = renderRelationList(relations, 'No relations');
}

function renderRelationList(relations, emptyText) {
  return relations.length ? relations.map(rel => `
    <div class="border-b border-gray-200 pb-2">
      <div>${escapeHTML(rel.source)} -> ${escapeHTML(rel.target)}</div>
      <div class="text-gray-600">${escapeHTML(rel.relation_type)} ${Number(rel.confidence || 0).toFixed(2)} ${escapeHTML(rel.status || '')}</div>
      <div class="text-xs text-gray-500 truncate">${escapeHTML(rel.evidence || rel.relation_id || '')}</div>
    </div>
  `).join('') : `<div class="text-gray-500">${emptyText}</div>`;
}

qs('#kg-rule-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const payload = {
    type: String(fd.get('type') || '').trim(),
    pattern: String(fd.get('pattern') || '').trim(),
    confidence: Number(fd.get('confidence') || 0.75)
  };
  if (!payload.type || !payload.pattern) return;
  const r = await api('/api/v1/kg/ner/rules', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  if (!r.ok) {
    alert('KG rule failed: ' + JSON.stringify(r.body));
    return;
  }
  ev.target.reset();
  loadKGDashboard();
});

// Init
(function(){
  const t = localStorage.getItem('token');
  if (t){
    qs('#login').classList.add('hidden');
    qs('#file-manager').classList.remove('hidden');
    qs('#auth-ui #user-info').textContent = 'admin';
    qs('#auth-ui #user-info').classList.remove('hidden');
    qs('#logout-btn').classList.remove('hidden');
    loadDirectory('');
  }
})();
