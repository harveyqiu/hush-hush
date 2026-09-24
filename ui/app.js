'use strict';

// hush-hush admin UI. Plain browser JavaScript, no dependencies, no build.
// Rules this file keeps:
//   - All dynamic text goes through textContent (el()), never innerHTML.
//   - The admin token lives in memory plus sessionStorage (this tab only)
//     and is sent only as a bearer header to this origin.
//   - Secret values and new token plaintext exist only inside an open
//     dialog; closing it removes them from the DOM.

(() => {
  const TOKEN_KEY = 'hush_admin_token';
  const TAB_KEY = 'hush_tab';
  const IDLE_LIMIT_MS = 15 * 60 * 1000;
  const NAME_RE = /^[a-zA-Z0-9_.-]{1,128}$/;
  const AUDIT_ACTIONS = ['get', 'list', 'put', 'delete', 'other',
    'token_list', 'token_create', 'token_update', 'token_revoke', 'audit_read'];
  const AUDIT_RESULTS = ['allowed', 'denied', 'not_found', 'conflict',
    'unauthenticated', 'rate_limited', 'bad_request', 'error'];

  const $ = (id) => document.getElementById(id);
  let token = null;
  let secretsCache = [];
  let tokensCache = [];
  let lastActivity = Date.now();

  // ---------- small helpers ----------

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (k in node && typeof v !== 'string') node[k] = v;
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  const storage = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* private mode */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } },
  };

  const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '-');
  const splitList = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const joinList = (a) => (a && a.length ? a.join(', ') : '-');

  class ApiError extends Error {
    constructor(status, message, requestId) {
      super(message);
      this.status = status;
      this.requestId = requestId;
    }
  }

  function errText(e) {
    if (!(e instanceof ApiError)) return String(e && e.message ? e.message : e);
    const head = e.status ? `${e.status} ` : '';
    const rid = e.requestId ? `（请求 ID ${e.requestId}）` : '';
    return `${head}${e.message}${rid}`;
  }

  async function api(method, path, body) {
    const headers = { Authorization: `Bearer ${token}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
    } catch {
      throw new ApiError(0, '网络错误，服务不可达', '');
    }
    const rid = res.headers.get('X-Request-ID') || '';
    let data = null;
    if (res.status !== 204) {
      try { data = await res.json(); } catch { data = null; }
    }
    if (!res.ok) {
      let msg = (data && data.error) || res.statusText;
      if (res.status === 429) {
        const retry = res.headers.get('Retry-After');
        msg = `请求过于频繁${retry ? `，${retry} 秒后再试` : ''}`;
      }
      const err = new ApiError(res.status, msg, rid);
      if (res.status === 401 && token) logout('登录已失效（token 无效、已吊销或已过期）');
      throw err;
    }
    return data;
  }

  function banner(msg) {
    const b = $('banner');
    b.textContent = msg || '';
    b.hidden = !msg;
  }

  async function copy(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = '已复制';
    } catch {
      button.textContent = '复制失败，请手动选择';
    }
  }

  // ---------- dialog ----------

  const dialog = $('dialog');
  let dialogOk = null;

  // openDialog shows (or replaces the content of) the single modal.
  // onOk may return false to keep the dialog open; a thrown error is shown
  // inside the dialog.
  function openDialog({ title, body, okText = '确定', okClass = '', cancelText = '取消', hideCancel = false, onOk }) {
    $('dialog-title').textContent = title;
    $('dialog-body').replaceChildren(...body);
    $('dialog-error').hidden = true;
    const ok = $('dialog-ok');
    ok.textContent = okText;
    ok.className = okClass;
    ok.disabled = false;
    const cancel = $('dialog-cancel');
    cancel.textContent = cancelText;
    cancel.hidden = hideCancel;
    dialogOk = onOk || null;
    if (!dialog.open) dialog.showModal();
    const first = $('dialog-body').querySelector('input, textarea, select');
    if (first) first.focus();
  }

  function dialogError(msg) {
    const e = $('dialog-error');
    e.textContent = msg;
    e.hidden = !msg;
  }

  // Both buttons and Enter arrive as a submit of the dialog form.
  $('dialog-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (ev.submitter && ev.submitter.id === 'dialog-cancel') dialog.close();
    else runDialogOk();
  });

  async function runDialogOk() {
    const ok = $('dialog-ok');
    if (ok.disabled) return;
    if (!dialogOk) { dialog.close(); return; }
    ok.disabled = true;
    dialogError('');
    try {
      const keepOpen = (await dialogOk()) === false;
      if (!keepOpen) dialog.close();
    } catch (e) {
      dialogError(errText(e));
    } finally {
      ok.disabled = false;
    }
  }
  // Drop whatever the dialog showed (secret values, new tokens) on close.
  dialog.addEventListener('close', () => { $('dialog-body').replaceChildren(); dialogOk = null; });

  function field(label, input) { return el('label', {}, label, input); }

  function confirmByName({ title, warning, name, okText, run }) {
    const input = el('input', { autocomplete: 'off', spellcheck: 'false', placeholder: name });
    openDialog({
      title,
      body: [el('p', { class: 'warn', text: warning }), field(`输入 ${name} 以确认`, input)],
      okText,
      okClass: 'danger',
      onOk: async () => {
        if (input.value.trim() !== name) throw new Error('输入的名称不匹配');
        await run();
      },
    });
  }

  // ---------- login / session ----------

  function showLogin(msg) {
    $('app').hidden = true;
    $('login').hidden = false;
    const e = $('login-error');
    e.textContent = msg || '';
    e.hidden = !msg;
    $('login-token').focus();
  }

  function logout(msg) {
    token = null;
    storage.del(TOKEN_KEY);
    secretsCache = [];
    tokensCache = [];
    for (const id of ['secret-rows', 'token-rows', 'audit-rows']) $(id).replaceChildren();
    if (dialog.open) dialog.close();
    banner('');
    showLogin(msg);
  }

  async function login(candidate) {
    token = candidate;
    try {
      // An admin-only endpoint: proves the token is valid AND admin.
      await api('GET', '/v1/admin/tokens');
    } catch (e) {
      token = null;
      if (e.status === 401) return showLogin('token 无效、已吊销或已过期');
      if (e.status === 403) return showLogin('这个 token 不是 admin，不能使用管理界面');
      return showLogin(errText(e));
    }
    storage.set(TOKEN_KEY, candidate);
    lastActivity = Date.now();
    $('login').hidden = true;
    $('app').hidden = false;
    $('whoami').textContent = '已登录（admin）';
    switchTab(storage.get(TAB_KEY) || 'secrets');
  }

  $('login-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const v = $('login-token').value.trim();
    $('login-token').value = '';
    if (v) login(v);
  });
  $('logout').addEventListener('click', () => logout(''));

  for (const evt of ['click', 'keydown']) {
    document.addEventListener(evt, () => { lastActivity = Date.now(); }, { passive: true });
  }
  setInterval(() => {
    if (token && Date.now() - lastActivity > IDLE_LIMIT_MS) logout('长时间未操作，已自动退出');
  }, 30 * 1000);

  // ---------- tabs ----------

  function switchTab(name) {
    if (!['secrets', 'tokens', 'audit'].includes(name)) name = 'secrets';
    storage.set(TAB_KEY, name);
    for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === name);
    for (const t of ['secrets', 'tokens', 'audit']) $(`tab-${t}`).hidden = t !== name;
    banner('');
    if (name === 'secrets') loadSecrets();
    if (name === 'tokens') loadTokens();
    if (name === 'audit') loadAudit();
  }
  for (const b of document.querySelectorAll('.tab')) b.addEventListener('click', () => switchTab(b.dataset.tab));

  // ---------- secrets ----------

  async function loadSecrets() {
    try {
      const data = await api('GET', '/v1/secrets');
      secretsCache = data.secrets || [];
      renderSecrets();
      if (secretsCache.length >= 1000) banner('只显示前 1000 条 secret。');
    } catch (e) {
      banner(`加载 secret 失败：${errText(e)}`);
    }
  }

  function renderSecrets() {
    const q = $('secret-filter').value.trim().toLowerCase();
    const rows = secretsCache
      .filter((s) => !q || s.name.toLowerCase().includes(q))
      .map((s) => el('tr', {},
        el('td', { class: 'mono', text: s.name }),
        el('td', { text: fmtTime(s.created_at) }),
        el('td', { text: fmtTime(s.updated_at) }),
        el('td', { class: 'actions' },
          el('button', { class: 'link', text: '查看', onclick: () => viewSecret(s.name) }),
          el('button', { class: 'link', text: '修改', onclick: () => editSecret(s.name) }),
          el('button', { class: 'link danger', text: '删除', onclick: () => deleteSecret(s.name) }))));
    $('secret-rows').replaceChildren(...(rows.length ? rows
      : [el('tr', { class: 'dim' }, el('td', { colspan: '4', text: q ? '没有匹配的 secret' : '还没有 secret' }))]));
  }

  const secretPath = (name) => `/v1/secrets/${encodeURIComponent(name)}`;

  async function viewSecret(name) {
    let data;
    try {
      data = await api('GET', secretPath(name));
    } catch (e) {
      banner(`读取 ${name} 失败：${errText(e)}`);
      return;
    }
    const box = el('div', { class: 'secret-box', text: data.value });
    const copyBtn = el('button', { class: 'secondary', type: 'button', text: '复制' });
    copyBtn.addEventListener('click', () => copy(data.value, copyBtn));
    const body = [box, el('div', {}, copyBtn),
      el('p', { class: 'muted', text: `创建 ${fmtTime(data.created_at)} · 更新 ${fmtTime(data.updated_at)}` })];
    if (data.value.startsWith('hh2:')) {
      body.unshift(el('p', { class: 'warn', text: '这是 hush CLI 客户端加密（v2）的密文，需要对应的 vault 口令才能解密。' }));
    }
    openDialog({ title: name, body, okText: '关闭', hideCancel: true });
  }

  function secretForm(name) {
    const nameInput = el('input', { class: 'mono', autocomplete: 'off', spellcheck: 'false', value: name || '', placeholder: 'llm.openai' });
    if (name) nameInput.disabled = true;
    const valueInput = el('textarea', { autocomplete: 'off', spellcheck: 'false', placeholder: '值（最大 64 KiB）' });
    return { nameInput, valueInput };
  }

  async function putSecret(name, value) {
    if (!NAME_RE.test(name)) throw new Error('名称只能包含字母、数字和 _ . -，最长 128 个字符');
    if (!value) throw new Error('值不能为空');
    await api('PUT', secretPath(name), { value });
    await loadSecrets();
  }

  $('secret-new').addEventListener('click', () => {
    const { nameInput, valueInput } = secretForm('');
    openDialog({
      title: '新建 secret',
      body: [field('名称', nameInput), field('值', valueInput)],
      okText: '保存',
      onOk: async () => {
        const name = nameInput.value.trim();
        if (secretsCache.some((s) => s.name === name)) throw new Error(`${name} 已存在，请在列表中使用"修改"`);
        await putSecret(name, valueInput.value);
      },
    });
  });

  function editSecret(name) {
    const { nameInput, valueInput } = secretForm(name);
    openDialog({
      title: `修改 ${name}`,
      body: [field('名称', nameInput), field('新值（会覆盖旧值）', valueInput)],
      okText: '保存',
      onOk: () => putSecret(name, valueInput.value),
    });
  }

  function deleteSecret(name) {
    confirmByName({
      title: `删除 ${name}`,
      warning: '删除不可恢复。依赖这个 secret 的 agent 将读到 404。',
      name,
      okText: '删除',
      run: async () => {
        await api('DELETE', secretPath(name));
        await loadSecrets();
      },
    });
  }

  $('secret-filter').addEventListener('input', renderSecrets);
  $('secret-refresh').addEventListener('click', loadSecrets);

  // ---------- tokens ----------

  async function loadTokens() {
    try {
      const data = await api('GET', '/v1/admin/tokens');
      tokensCache = data.tokens || [];
      renderTokens();
    } catch (e) {
      banner(`加载 token 失败：${errText(e)}`);
    }
  }

  function renderTokens() {
    const rows = tokensCache.map((t) => {
      const isAdmin = t.role === 'admin';
      const active = t.status === 'active';
      return el('tr', { class: active ? '' : 'dim' },
        el('td', { class: 'mono', text: t.name }),
        el('td', { text: t.role }),
        el('td', { class: 'mono', text: isAdmin ? '（全部）' : joinList(t.prefixes) }),
        el('td', { class: 'mono', text: isAdmin ? '（全部，可覆盖/删除）' : joinList(t.write_prefixes) }),
        el('td', {}, el('span', { class: `pill ${t.status}`, text: t.status })),
        el('td', { text: t.expires_at ? fmtTime(t.expires_at) : '永不' }),
        el('td', { text: fmtTime(t.last_used_at) }),
        el('td', { class: 'actions' },
          !isAdmin && active ? el('button', { class: 'link', text: '改前缀', onclick: () => editToken(t) }) : null,
          active ? el('button', { class: 'link danger', text: '吊销', onclick: () => revokeToken(t.name) }) : null));
    });
    $('token-rows').replaceChildren(...(rows.length ? rows
      : [el('tr', { class: 'dim' }, el('td', { colspan: '8', text: '还没有 token' }))]));
  }

  // grantFields builds the read/write prefix inputs plus the "*" confirmation
  // checkbox, which only appears when the read prefixes are exactly "*".
  function grantFields(read, write) {
    const readInput = el('input', { class: 'mono', autocomplete: 'off', spellcheck: 'false', value: read, placeholder: 'llm. github.' });
    const writeInput = el('input', { class: 'mono', autocomplete: 'off', spellcheck: 'false', value: write, placeholder: '留空表示不能写，例如 crawler.' });
    const confirmAll = el('input', { type: 'checkbox' });
    const confirmRow = el('label', { class: 'warn' },
      el('span', {}, confirmAll, ' 我确认：前缀 * 允许读取全部 secret，包括以后新增的'));
    const sync = () => { confirmRow.hidden = readInput.value.trim() !== '*'; };
    readInput.addEventListener('input', sync);
    sync();
    return {
      nodes: [
        field('读前缀（空格或逗号分隔，必须以 . 或 _ 结尾）', readInput),
        field('写前缀（只能新建，不能覆盖或删除）', writeInput),
        confirmRow,
      ],
      read: () => splitList(readInput.value),
      write: () => splitList(writeInput.value),
      confirmed: () => confirmAll.checked,
      setDisabled(d) { readInput.disabled = d; writeInput.disabled = d; },
    };
  }

  function showNewToken(name, plaintext, warnings) {
    const box = el('div', { class: 'secret-box', text: plaintext });
    const copyBtn = el('button', { class: 'secondary', type: 'button', text: '复制' });
    copyBtn.addEventListener('click', () => copy(plaintext, copyBtn));
    openDialog({
      title: `token ${name} 已创建`,
      body: [
        el('p', { class: 'warn', text: '这是唯一一次显示明文。现在就把它交给对应的 agent 或存进密码管理器，关闭后无法再次查看。' }),
        box,
        el('div', {}, copyBtn),
        ...(warnings || []).map((w) => el('p', { class: 'warn', text: w })),
      ],
      okText: '我已保存',
      hideCancel: true,
      onOk: null,
    });
  }

  $('token-new').addEventListener('click', () => {
    const nameInput = el('input', { class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'agent-crawler' });
    const roleInput = el('select', {},
      el('option', { value: 'agent', text: 'agent（按前缀只读，可选只新建）' }),
      el('option', { value: 'admin', text: 'admin（全部读写删，可管理 token）' }));
    const expiresInput = el('input', { autocomplete: 'off', placeholder: '例如 90d、12h；留空表示永不过期' });
    const grants = grantFields('', '');
    roleInput.addEventListener('change', () => grants.setDisabled(roleInput.value === 'admin'));
    openDialog({
      title: '新建 token',
      body: [field('名称', nameInput), field('角色', roleInput), ...grants.nodes, field('有效期', expiresInput)],
      okText: '创建',
      onOk: async () => {
        const isAdmin = roleInput.value === 'admin';
        const body = {
          name: nameInput.value.trim(),
          role: roleInput.value,
          prefixes: isAdmin ? [] : grants.read(),
          write_prefixes: isAdmin ? [] : grants.write(),
          expires: expiresInput.value.trim(),
          confirm_all: !isAdmin && grants.confirmed(),
        };
        const res = await api('POST', '/v1/admin/tokens', body);
        await loadTokens();
        showNewToken(res.name, res.token, res.warnings);
        return false; // the dialog now shows the new token
      },
    });
  });

  function editToken(t) {
    const grants = grantFields((t.prefixes || []).join(' '), (t.write_prefixes || []).join(' '));
    openDialog({
      title: `修改 ${t.name} 的前缀`,
      body: [el('p', { class: 'muted', text: '两组前缀都会整体替换，下一次请求起生效。' }), ...grants.nodes],
      okText: '保存',
      onOk: async () => {
        const res = await api('PATCH', `/v1/admin/tokens/${encodeURIComponent(t.name)}`, {
          prefixes: grants.read(),
          write_prefixes: grants.write(),
          confirm_all: grants.confirmed(),
        });
        await loadTokens();
        if (res.warnings && res.warnings.length) banner(res.warnings.join(' '));
      },
    });
  }

  function revokeToken(name) {
    confirmByName({
      title: `吊销 ${name}`,
      warning: '吊销立即生效且不可撤销，使用这个 token 的 agent 下一次请求就会收到 401。',
      name,
      okText: '吊销',
      run: async () => {
        await api('DELETE', `/v1/admin/tokens/${encodeURIComponent(name)}`);
        await loadTokens();
      },
    });
  }

  $('token-refresh').addEventListener('click', loadTokens);

  // ---------- audit ----------

  const auditForm = $('audit-form');
  for (const a of AUDIT_ACTIONS) auditForm.elements.action.append(el('option', { value: a, text: a }));
  for (const r of AUDIT_RESULTS) auditForm.elements.result.append(el('option', { value: r, text: r }));

  async function loadAudit() {
    const params = new URLSearchParams();
    for (const [k, v] of new FormData(auditForm)) {
      if (String(v).trim()) params.set(k, String(v).trim());
    }
    try {
      const data = await api('GET', `/v1/admin/audit?${params}`);
      const rows = (data.records || []).map((r) => el('tr', {},
        el('td', { text: fmtTime(r.ts) }),
        el('td', { class: 'mono', text: r.token_name || '-' }),
        el('td', { text: r.action }),
        el('td', { class: 'mono', text: r.secret_name || '-' }),
        el('td', {}, el('span', { class: `pill ${r.result}`, text: r.result })),
        el('td', { class: 'mono', text: r.remote_addr || '-' }),
        el('td', { class: 'mono', text: r.request_id || '-' })));
      $('audit-rows').replaceChildren(...(rows.length ? rows
        : [el('tr', { class: 'dim' }, el('td', { colspan: '7', text: '没有匹配的记录' }))]));
    } catch (e) {
      banner(`查询审计日志失败：${errText(e)}`);
    }
  }

  auditForm.addEventListener('submit', (ev) => { ev.preventDefault(); loadAudit(); });

  // ---------- start ----------

  const saved = storage.get(TOKEN_KEY);
  if (saved) login(saved); else showLogin('');
})();
