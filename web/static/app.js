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
  if (!r.ok){ qs('#data-output').textContent = `Login failed: ${r.status} ${JSON.stringify(r.body)}`; return; }
  localStorage.setItem('token', r.body.token);
  qs('#login').classList.add('hidden');
  qs('#main-tabs').classList.remove('hidden');
  qs('#auth-ui #user-info').textContent = r.body.user.username; qs('#auth-ui #user-info').classList.remove('hidden');
  qs('#logout-btn').classList.remove('hidden');
  // show data tab and load keys/files
  const dataTab = qs('.tabs button[data-tab="data"]'); if (dataTab){ dataTab.click(); }
  loadKeys(0);
  refreshFiles();
});

qs('#logout-btn').addEventListener('click', () => { localStorage.removeItem('token'); location.reload(); });

// Tabs
qsa('.tabs button').forEach(b=> b.addEventListener('click', (ev)=>{
  const tab = b.dataset.tab;
  // active state
  qsa('.tabs button').forEach(x=> x.classList.remove('active'));
  b.classList.add('active');
  qsa('.panel').forEach(p=> p.classList.add('hidden'));
  qs(`#${tab}`).classList.remove('hidden');
}));

// Put
qs('#put-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const data = Object.fromEntries(new FormData(ev.target));
  const r = await api('/api/put', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data)});
  qs('#data-output').textContent = `Status: ${r.status}\n${JSON.stringify(r.body, null, 2)}`;
});

// Get / Delete
qs('#get-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const key = new FormData(ev.target).get('key');
  const r = await api('/api/get/' + encodeURIComponent(key));
  qs('#data-output').textContent = `Status: ${r.status}\n${JSON.stringify(r.body, null, 2)}`;
});
qs('#delete-key').addEventListener('click', async ()=>{
  const key = qs('#get-form input[name="key"]').value;
  if (!confirm(`Delete key ${key}?`)) return;
  const r = await api('/api/delete/' + encodeURIComponent(key), {method:'DELETE'});
  qs('#data-output').textContent = `Status: ${r.status}\n${JSON.stringify(r.body, null, 2)}`;
  // refresh key list
  loadKeys(currentKeysPage);
});

// Keys listing (pagination)
let currentKeysPage = 0;
async function loadKeys(page=0){
  const limit = parseInt(qs('#keys-limit').value, 10) || 10;
  const offset = page * limit;
  const r = await api(`/api/keys?limit=${limit}&offset=${offset}`);
  const tbody = qs('#keys-table tbody'); tbody.innerHTML='';
  if (!r.ok){ tbody.innerHTML = `<tr><td colspan="2">Error: ${r.status}</td></tr>`; return; }
  (r.body.keys || []).forEach(k=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${k}</code></td><td><button data-fill="${k}">Fill</button> <button data-get="${k}">Get</button> <button data-delete="${k}">Delete</button></td>`;
    tbody.appendChild(tr);
  });
  qs('#keys-prev').disabled = (page <= 0);
  qs('#keys-next').disabled = ((page+1)*limit >= (r.body.total || 0));
  currentKeysPage = page;
}
qs('#keys-prev').addEventListener('click', ()=>{ if (currentKeysPage>0) loadKeys(currentKeysPage-1); });
qs('#keys-next').addEventListener('click', ()=>{ loadKeys(currentKeysPage+1); });
qs('#keys-limit').addEventListener('change', ()=>{ loadKeys(0); });

// delegate actions
qs('#keys-table').addEventListener('click', async (ev)=>{
  const fill = ev.target.dataset.fill; const g = ev.target.dataset.get; const del = ev.target.dataset.delete;
  if (fill){ qs('#get-form input[name="key"]').value = fill; return; }
  if (g){ const r = await api('/api/get/' + encodeURIComponent(g)); qs('#data-output').textContent = `Status: ${r.status}\n${JSON.stringify(r.body, null, 2)}`; return; }
  if (del){ if (!confirm(`Delete key ${del}?`)) return; const r = await api('/api/delete/' + encodeURIComponent(del), {method:'DELETE'}); qs('#data-output').textContent = `Status: ${r.status}\n${JSON.stringify(r.body, null, 2)}`; loadKeys(currentKeysPage); }
});


// Files
async function refreshFiles(){
  const r = await api('/api/files');
  const tbody = qs('#files-table tbody'); tbody.innerHTML='';
  if (!r.ok){ qs('#files-output').textContent = `Error: ${r.status} ${JSON.stringify(r.body)}`; return; }
  (r.body.files || []).forEach(f=>{
    const tr = document.createElement('tr');
    const uploaded = f.uploaded_at ? new Date(f.uploaded_at).toLocaleString() : '';
    const size = typeof f.size === 'number' ? (f.size >= 1024 ? (f.size/1024).toFixed(1) + ' KB' : f.size + ' B') : '';
    // preview column (image types)
    const isImage = (f.content_type||'').startsWith('image/');
    const previewBtn = isImage ? `<button data-preview="${f.key}">Preview</button>` : '';
    const progressBar = `<div class="progress" data-prog="${f.key}"><i style="width:0%"></i></div>`;
    const regenBtn = isImage ? `<button data-regen="${f.key}">Regen</button>` : '';
    const thumbImg = f.thumbnail_url ? `<img class="thumb-preview" src="${f.thumbnail_url}" width="48" alt="thumb" />` : '';
    tr.innerHTML = `<td>${f.key || ''}</td><td>${f.filename||''}</td><td>${f.content_type||''}</td><td>${size}</td><td>${uploaded}</td><td>${thumbImg||previewBtn}</td><td>`+
      `${progressBar} ${regenBtn} <button data-download="${f.key}">Download</button> <button data-delete="${f.key}">Delete</button></td>`;
    tbody.appendChild(tr);
  });
}
qs('#refresh-files').addEventListener('click', refreshFiles);
qs('#regen-all-thumbs').addEventListener('click', async ()=>{
  if (!confirm('Regenerate all thumbnails? This may take some time.')) return;
  const headers = tokenHeader();
  const r = await fetch(apiBase + '/admin/thumbnails/regenerate', {method:'POST', headers});
  const txt = await r.text();
  qs('#files-output').textContent = `Status: ${r.status}\n${txt}`;
  refreshFiles();
});
qs('#files-table').addEventListener('click', async (ev)=>{
  const dl = ev.target.dataset.download; const del = ev.target.dataset.delete; const prev = ev.target.dataset.preview;
  if (dl){
    // download with progress
  }
  if (ev.target.classList && ev.target.classList.contains('thumb-preview')){
    const src = ev.target.src;
    qs('#preview-img').src = src; qs('#preview-modal').classList.remove('hidden'); return;
  }
  if (dl){
    // download with progress
    const key = dl;
    const url = apiBase + '/api/files/' + encodeURIComponent(key);
    const headers = tokenHeader();
    const resp = await fetch(url, {headers});
    if (!resp.ok){ qs('#files-output').textContent = `Download failed: ${resp.status}`; return; }
    const total = resp.headers.get('Content-Length');
    const reader = resp.body.getReader();
    const progEl = qs(`.progress[data-prog="${key}"] i`);
    const chunks = [];
    let received = 0;
    while(true){
      const {done, value} = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      if (total && progEl){ progEl.style.width = Math.floor((received/parseInt(total))*100) + '%'; }
    }
    const blob = new Blob(chunks);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = '';
    document.body.appendChild(a); a.click(); a.remove();
    if (progEl) setTimeout(()=>{ progEl.style.width='0%'; }, 800);
    return;
  }
  if (prev){
    // preview image — request server-side thumbnail for speed
    const key = prev;
    const url = apiBase + '/api/files/' + encodeURIComponent(key) + '/thumbnail';
    const headers = tokenHeader();
    const resp = await fetch(url, {headers});
    if (!resp.ok){ qs('#files-output').textContent = `Preview failed: ${resp.status}`; return; }
    const blob = await resp.blob();
    const urlObj = URL.createObjectURL(blob);
    qs('#preview-img').src = urlObj;
    qs('#preview-modal').classList.remove('hidden');
    return;
  }
  if (del){ if (!confirm(`Delete file ${del}?`)) return; const r = await api('/api/files/' + encodeURIComponent(del), {method:'DELETE'}); qs('#files-output').textContent = JSON.stringify(r.body, null, 2); refreshFiles(); }
  if (ev.target.dataset.regen){
    // regenerate single thumbnail (admin)
    const key = ev.target.dataset.regen;
    if (!confirm(`Regenerate thumbnail for ${key}?`)) return;
    const headers = tokenHeader();
    const r = await fetch(apiBase + '/admin/thumbnails/' + encodeURIComponent(key) + '/regenerate', {method:'POST', headers});
    const txt = await r.text();
    qs('#files-output').textContent = `Status: ${r.status}\n${txt}`;
    refreshFiles();
  }
});
qs('#preview-close').addEventListener('click', ()=>{ qs('#preview-img').src=''; qs('#preview-modal').classList.add('hidden'); });
  if (del){ if (!confirm(`Delete file ${del}?`)) return; const r = await api('/api/files/' + encodeURIComponent(del), {method:'DELETE'}); qs('#files-output').textContent = JSON.stringify(r.body, null, 2); refreshFiles(); }
});
qs('#preview-close').addEventListener('click', ()=>{ qs('#preview-img').src=''; qs('#preview-modal').classList.add('hidden'); });
qs('#upload-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const form = ev.target; const fd = new FormData(form);
  const overwrite = !!fd.get('overwrite');
  const key = fd.get('key');
  const file = form.querySelector('input[type=file]').files[0];
  if (!file){ alert('Choose a file'); return; }
  const up = new FormData(); up.append('file', file); if (key) up.append('key', key);
  const params = overwrite ? '?overwrite=true' : '';
  const t = tokenHeader();
  const r = await fetch(apiBase + '/api/files' + params, {method:'POST', headers: t, body: up});
  const txt = await r.text();
  let json = txt; try { json = JSON.parse(txt); } catch(e){}
  qs('#files-output').textContent = `Status: ${r.status}\n${JSON.stringify(json, null, 2)}`;
  refreshFiles();
});

// WAL
qs('#wal-refresh').addEventListener('click', async ()=>{
  const r = await api('/admin/wal'); qs('#wal-output').textContent = JSON.stringify(r.body, null, 2);
});
qs('#wal-rotate').addEventListener('click', async ()=>{
  if (!confirm('Force rotate WAL now?')) return;
  const r = await api('/admin/wal/rotate', {method:'POST'}); qs('#wal-output').textContent = JSON.stringify(r.body, null, 2);
});
qs('#wal-archives-refresh').addEventListener('click', async ()=>{
  const r = await api('/admin/wal/archives'); const tbody = qs('#wal-archives tbody'); tbody.innerHTML=''; (r.body.archives||[]).forEach(a=>{ const tr=document.createElement('tr'); tr.innerHTML = `<td>${a.name}</td><td>${a.size}</td><td>${a.mod_time}</td>`; tbody.appendChild(tr); });
});

// SSTable repair
qs('#sstable-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const path = new FormData(ev.target).get('path');
  const r = await api('/admin/sstable/repair', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({path})});
  qs('#sstable-output').textContent = JSON.stringify(r.body, null, 2);
});

// Init
(function(){
  const t = localStorage.getItem('token');
  if (t){
    qs('#login').classList.add('hidden');
    qs('#main-tabs').classList.remove('hidden');
    qs('#auth-ui #user-info').textContent = 'admin';
    qs('#auth-ui #user-info').classList.remove('hidden');
    qs('#logout-btn').classList.remove('hidden');
    // show data tab and load keys/files on load
    const dataTab = qs('.tabs button[data-tab="data"]'); if (dataTab){ dataTab.click(); }
    loadKeys(0);
    refreshFiles();
  }
})();
