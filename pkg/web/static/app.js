const apiBase = window.location.origin;

function qs(sel, root=document) { return root.querySelector(sel); }
function qsa(sel, root=document){ return [...root.querySelectorAll(sel)]; }

function tokenHeader() {
  const t = localStorage.getItem('token');
  return t ? {'Authorization': 'Bearer ' + t} : {};
}

async function api(path, opts={}){
  opts.headers = Object.assign({}, tokenHeader(), opts.headers || {});
  const res = await fetch(apiBase + path, opts);
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch(e){}
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
    tr.className = 'hover:bg-gray-100 cursor-pointer';
    tr.innerHTML = `
      <td class="py-2">
        <div class="flex items-center">
          <svg class="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
    tr.className = 'hover:bg-gray-100 cursor-pointer';
    tr.innerHTML = `
      <td class="py-2">
        <div class="flex items-center">
          <svg class="w-5 h-5 mr-2 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
        <button class="text-red-500 hover:text-red-700" data-delete-folder="${folder}">Delete</button>
      </td>
    `;
    tr.addEventListener('click', () => {
      loadDirectory(path + folder + '/');
    });
    tbody.appendChild(tr);
  });

  // Add files
  files.forEach(file => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-gray-100';
    const size = file.size ? (file.size >= 1024 ? (file.size/1024).toFixed(1) + ' KB' : file.size + ' B') : '-';
    const modified = file.modified_at ? new Date(file.modified_at).toLocaleString() : '-';
    const isImage = file.content_type && file.content_type.startsWith('image/');
    const fileName = decodeURIComponent(file.path).split('/').pop();

    tr.innerHTML = `
      <td class="py-2">
        <div class="flex items-center">
          <svg class="w-5 h-5 mr-2 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
          </svg>
          ${fileName}
        </div>
      </td>
      <td>${file.content_type || 'Unknown'}</td>
      <td>${size}</td>
      <td>${modified}</td>
      <td>
        ${isImage ? '<button class="text-blue-500 hover:text-blue-700 mr-2" data-preview="' + file.path + '">Preview</button>' : ''}
        <button class="text-green-500 hover:text-green-700 mr-2" data-download="' + file.path + '">Download</button>
        <button class="text-red-500 hover:text-red-700" data-delete="' + file.path + '">Delete</button>
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

function setActiveTab(name) {
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

async function loadKGDashboard() {
  const [analytics, status, rules] = await Promise.all([
    api('/api/v1/kg/analytics'),
    api('/api/v1/kg/sync/status'),
    api('/api/v1/kg/ner/rules')
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
    qs('#kg-sync-status').innerHTML = `
      <div>Enabled: ${body.enabled ? 'yes' : 'no'}</div>
      <div>Running: ${body.running ? 'yes' : 'no'}</div>
      <div>Last error: ${escapeHTML(body.last_error || '-')}</div>
    `;
  }
  if (rules.ok) {
    renderKGRules(rules.body.rules || []);
  }
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
    body: JSON.stringify({enabled:true, existing:true})
  });
  if (!r.ok) {
    alert('KG sync failed: ' + JSON.stringify(r.body));
    return;
  }
  loadKGDashboard();
});

qs('#kg-search-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const query = String(fd.get('query') || '').trim();
  const limit = Number(fd.get('limit') || 10);
  if (!query) return;
  const search = await api('/api/v1/kg/search', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({query, limit})
  });
  if (!search.ok) {
    alert('KG search failed: ' + JSON.stringify(search.body));
    return;
  }
  const hits = search.body.hits || [];
  qs('#kg-results').innerHTML = hits.length ? hits.map(hit => `
    <div class="border-b border-gray-200 pb-2">
      <div class="font-medium">${escapeHTML(hit.title || hit.source || hit.doc_id)}</div>
      <div class="text-gray-600">${escapeHTML((hit.text || '').slice(0, 260))}</div>
      <div class="text-xs text-gray-500">score ${Number(hit.score || 0).toFixed(4)}</div>
    </div>
  `).join('') : '<div class="text-gray-500">No results</div>';

  const graph = await api('/api/v1/kg/resource-graph', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({query, limit, depth:1})
  });
  if (graph.ok) {
    const edges = graph.body.edges || [];
    qs('#kg-graph').innerHTML = edges.length ? edges.map(edge => `
      <div class="border-b border-gray-200 pb-2">
        <div>${escapeHTML(edge.source)} -> ${escapeHTML(edge.target)}</div>
        <div class="text-gray-600">${escapeHTML(edge.relation_type)} ${Number(edge.confidence || 0).toFixed(2)}: ${escapeHTML(edge.evidence || '')}</div>
      </div>
    `).join('') : '<div class="text-gray-500">No inferred edges</div>';
  }
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
