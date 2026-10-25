'use strict';

(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const page = $('#page');
  const dialog = $('#dialog');
  const dialogContent = $('#dialog-content');
  const routes = ['overview', 'devices', 'users', 'keys', 'gateway', 'policy', 'audit'];
  const keyLifetimes = [['1 hour', 1], ['1 day', 24], ['7 days', 168], ['30 days', 720], ['90 days', 2160]];
  const isDefaultRoute = route => route === '0.0.0.0/0' || route === '::/0';
  const hostLabel = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  const ipv4Network = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
  const ipv6Network = /^[0-9a-f:]+\/(12[0-8]|1[01]\d|[1-9]?\d)$/i;

  const titles = { overview: 'Overview', devices: 'Devices', users: 'Users', keys: 'Device keys', gateway: 'Gateway', policy: 'Access policy', audit: 'Activity' };
  const state = { authenticated: false, canWrite: false, authMode: '', csrf: '', generation: 0, route: 'overview', epoch: 0, dirty: false, policy: '', revision: '', userId: '' };
  let dialogOrigin = null;
  let dialogLocked = false;
  let secretOpen = false;
  let notifyTimer;

  // Icons are local vector shapes. API values are always inserted as text.
  const shapes = {
    overview: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M3 14h7v7H3z', 'M14 14h7v7h-7z'],
    devices: ['M3 4h18v12H3z', 'M8 21h8', 'M12 16v5'],
    users: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M16 3a4 4 0 0 1 0 8', 'M22 21v-2a4 4 0 0 0-3-3.87', 'M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0'],
    keys: ['M14 10a5 5 0 1 0-4 4L21 3', 'M17 7l3 3', 'M14 10l3 3'],
    policy: ['M12 3l8 4v5c0 5-8 9-8 9s-8-4-8-9V7z', 'M9 12l2 2 4-4'],
    gateway: ['M4 12h11', 'M11 7l5 5-5 5', 'M20 4v16'],
    audit: ['M3 12h4l3-8 4 16 3-8h4'],
    refresh: ['M20 7v5h-5', 'M4 17v-5h5', 'M6.1 7a7 7 0 0 1 11.55-2.2L20 8', 'M4 16l2.35 3.2A7 7 0 0 0 17.9 17'],
    plus: ['M12 5v14', 'M5 12h14'],
    arrow: ['M5 12h14', 'M14 7l5 5-5 5'],
    search: ['M21 21l-4.5-4.5', 'M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0'],
    alert: ['M12 9v4', 'M12 17h.01', 'M10.3 4L2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0'],
    close: ['M6 6l12 12', 'M18 6L6 18'],
    copy: ['M9 9h12v12H9z', 'M5 15H3V3h12v2'],
    clock: ['M12 8v4l3 2', 'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0'],
    check: ['M5 12l4 4L19 6'],
    network: ['M12 3v6', 'M5 15v-3h14v3', 'M12 12V9', 'M9 3h6v6H9z', 'M2 15h6v6H2z', 'M16 15h6v6h-6z'],
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
    for (const d of shapes[name] || shapes.network) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      svg.append(path);
    }
    return svg;
  }

  function button(text, fn, style = '', iconName = '') {
    const node = el('button', 'button ' + style);
    node.type = 'button';
    if (iconName) node.append(icon(iconName));
    node.append(el('span', '', text));
    if (fn) node.addEventListener('click', fn);
    return node;
  }

  function badge(text, style = '') { return el('span', 'badge ' + style, text); }
  function writeButton(text, fn, style = '', iconName = '') {
    const node = button(text, event => { if (state.canWrite && fn) fn(event); }, style, iconName);
    node.disabled = !state.canWrite;
    if (!state.canWrite) node.title = 'Your role permits viewing only';
    return node;
  }
  function cell(content, className = '') {
    const node = el('td', className);
    if (content instanceof Node) node.append(content); else node.textContent = content == null || content === '' ? '—' : String(content);
    return node;
  }

  function friendlyDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()) || date.getFullYear() < 1971) return '—';
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
  }

  function ago(value) {
    if (!value) return 'Never seen';
    const date = new Date(value);
    if (Number.isNaN(date.getTime()) || date.getFullYear() < 1971) return 'Never seen';
    const seconds = Math.max(0, (Date.now() - date.getTime()) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' min ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hr ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + ' days ago';
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(date);
  }

  function expired(value) { return value && !Number.isNaN(Date.parse(value)) && Date.parse(value) < Date.now(); }
  function deviceName(device) { return device.name || device.hostname || 'Device ' + device.id; }
  function userName(user) { return user.displayName || user.email || user.name || 'User ' + user.id; }
  // In lists of people, the email tells two people with one name apart. Someone
  // who has not signed in since sign-ins brought emails is told apart by ID.
  function userLabel(user) {
    const name = userName(user), detail = user.email || (user.displayName ? user.name : '');
    return detail && detail !== name ? name + ' · ' + detail : name;
  }
  function deviceStatus(device) {
    if (device.expired) return badge('Expired', 'warning');
    const node = badge(device.online ? 'Online' : 'Offline', device.online ? 'success' : '');
    if (device.online) node.prepend(el('span', 'status-dot'));
    return node;
  }

  function notify(message, error = false) {
    const node = $('#notification');
    clearTimeout(notifyTimer);
    node.textContent = message;
    node.className = 'notification' + (error ? ' error' : '');
    node.hidden = false;
    notifyTimer = setTimeout(() => { node.hidden = true; node.textContent = ''; }, error ? 7000 : 4500);
  }

  async function api(path, options = {}) {
    const requestGeneration = state.generation;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    const headers = { Accept: 'application/json' };
    const method = options.method || 'GET';
    const changesState = method !== 'GET' && method !== 'HEAD';
    if (changesState && path.startsWith('/api/') && !['/api/login', '/api/logout'].includes(path) && !state.canWrite) throw new Error('Your role permits viewing only.');
    const recovery = changesState ? ' The operation may have completed. Inspect current state before retrying.' : ' Refresh to try again.';
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && path !== '/api/login') headers['X-CSRF-Token'] = state.csrf;
    try {
      const response = await fetch(path, { credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', method, headers, signal: controller.signal, ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}) });
      let data;
      try {
        data = await response.json();
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid response object');
      } catch {
        if (response.ok) throw new Error('The console received an invalid response.' + recovery);
        data = {};
      }
      if (!response.ok) {
        if (response.status === 401 && path !== '/api/login' && state.authenticated && requestGeneration === state.generation) signedOut('Your session has ended. Sign in again to continue.');
        const error = new Error(data.error || (response.status === 409 ? 'This item changed. Refresh and try again.' : 'The request could not be completed. Please try again.'));
        error.code = data.code || '';
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('The request timed out.' + (changesState ? recovery : ' Check your connection and try again.'));
      if (error instanceof TypeError) throw new Error('The connection was interrupted.' + (changesState ? recovery : ' Check your connection and try again.'));
      throw error;
    } finally { clearTimeout(timer); }
  }

  function signedOut(message = '') {
    state.authenticated = false;
    state.canWrite = false;
    state.generation++;
    state.csrf = '';
    state.epoch++;
    state.dirty = false;
    state.policy = '';
    state.revision = '';
    state.userId = '';
    closeDialog(true);
    page.replaceChildren();
    $('#app').hidden = true;
    $('#boot').hidden = true;
    $('#signin').hidden = false;
    $('#login-token').value = '';
    const error = $('#login-error');
    error.textContent = message;
    error.hidden = !message;
    $('#session-identity').textContent = '';
    if (state.authMode === 'token') $('#login-token').focus();
  }

  function signedIn(session) {
    if (session.authenticated !== true || typeof session.csrfToken !== 'string' || !session.csrfToken || session.permissions?.canRead !== true || typeof session.permissions.canWrite !== 'boolean') throw new Error('Could not establish your session. Sign in again to continue.');
    state.authenticated = true;
    state.canWrite = session.permissions.canWrite;
    $('#session-identity').textContent = (session.user?.name || 'Signed in') + ' · ' + (state.canWrite ? 'Administrator' : 'Read-only');
    state.generation++;
    state.csrf = session.csrfToken || '';
    $('#login-token').value = '';
    $('#signin').hidden = true;
    $('#boot').hidden = true;
    $('#app').hidden = false;
    loadRoute(routeFromLocation());
  }

  function routeFromLocation() {
    const route = location.hash.slice(1) || location.pathname.slice(1) || 'overview';
    return routes.includes(route) ? route : 'overview';
  }

  async function navigate(route, replace = false) {
    if (!routes.includes(route)) return;
    if (state.dirty && !(await confirmDiscard())) return;
    if (!state.authenticated) return;
    state.dirty = false;
    history[replace ? 'replaceState' : 'pushState'](null, '', '#' + route);
    loadRoute(route);
  }

  async function refresh() {
    if (state.dirty && !(await confirmDiscard())) return;
    state.dirty = false;
    loadRoute(state.route);
  }

  function heading(route, description, action = null) {
    const node = el('div', 'page-heading');
    const copy = el('div');
    if (route === 'overview') copy.append(el('span', 'eyebrow', 'YOUR PRIVATE NETWORK'));
    copy.append(el('h1', '', route === 'overview' ? 'A home for your connections.' : titles[route]), el('p', '', description));
    const actions = el('div', 'heading-actions');
    actions.append(button('Refresh', refresh, 'quiet', 'refresh'));
    if (action) actions.append(action);
    node.append(copy, actions);
    return node;
  }

  function panel(title, subtitle = '', action = null) {
    const node = el('section', 'panel');
    const header = el('div', 'panel-header');
    const copy = el('div');
    copy.append(el('h2', '', title));
    if (subtitle) copy.append(el('p', '', subtitle));
    header.append(copy);
    if (action) header.append(action);
    node.append(header);
    return node;
  }

  function table(headers, rows, label) {
    const wrap = el('div', 'table-wrap');
    const node = el('table');
    node.setAttribute('aria-label', label);
    const head = el('thead');
    const tr = el('tr');
    for (const title of headers) { const th = el('th', '', title); th.scope = 'col'; tr.append(th); }
    head.append(tr);
    const body = el('tbody');
    body.append(...rows);
    node.append(head, body);
    wrap.append(node);
    return wrap;
  }

  function identity(name, description, kind = 'devices') {
    const node = el('div', 'identity');
    const mark = el('span', 'identity-icon');
    mark.append(icon(kind));
    const text = el('div');
    text.append(el('div', 'identity-name', name));
    if (description) text.append(el('div', 'identity-detail', description));
    node.append(mark, text);
    return node;
  }

  function empty(title, description, kind, action = null) {
    const node = el('div', 'empty-state');
    const mark = el('div', 'empty-icon'); mark.append(icon(kind));
    node.append(mark, el('h2', '', title), el('p', '', description));
    if (action) node.append(action);
    return node;
  }

  function unavailable(error, retry = refresh) {
    const node = empty('Unable to load this information', error.message, 'alert', button('Try again', retry));
    node.classList.add('error-state');
    return node;
  }

  function loading(text = 'Loading your network…') {
    const node = el('div', 'loading-state');
    node.setAttribute('role', 'status');
    node.append(el('span', 'spinner'), el('span', '', text));
    return node;
  }

  function banner(text, kind = '') {
    const node = el('div', 'banner ' + kind); node.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    node.append(icon(kind === 'success' ? 'check' : 'alert'), el('span', '', text));
    return node;
  }

  function foot(text, kind = 'clock') { const node = el('div', 'panel-foot'); node.append(icon(kind), el('span', '', text)); return node; }
  function synced() { $('#sync-status').textContent = 'Updated ' + new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date()); }

  async function loadRoute(route) {
    const epoch = ++state.epoch;
    state.route = route;
    for (const node of $('#navigation').children) {
      if (node.dataset.route === route) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
    }
    $('#breadcrumb-title').textContent = titles[route];
    document.title = titles[route] + ' · Covee';
    $('#sync-status').textContent = 'Loading…';
    page.setAttribute('aria-busy', 'true');
    page.replaceChildren(heading(route, descriptions[route]), loading());
    try {
      await loaders[route](epoch);
      if (epoch === state.epoch && state.authenticated) synced();
    } catch (error) {
      if (epoch === state.epoch && state.authenticated) {
        page.replaceChildren(heading(route, descriptions[route]), unavailable(error));
        $('#sync-status').textContent = 'Update failed';
      }
    } finally { if (epoch === state.epoch) page.removeAttribute('aria-busy'); }
  }

  const current = (epoch) => epoch === state.epoch && state.authenticated;
  const descriptions = {
    overview: 'People, devices, and access. All in one place.',
    devices: 'See the devices in your network and manage their access.',
    users: 'The people who can enroll devices in your network.',
    keys: 'Keys that add servers and computers to your network.',
    gateway: 'Choose what your devices reach through the gateway, and who may.',
    policy: 'Choose which connections your network allows.',
    audit: 'A record of changes made through this console.',
  };

  function metric(label, value, detail, kind, status = false) {
    const node = el('div', 'metric');
    const labelNode = el('div', 'metric-label', label); labelNode.append(icon(kind));
    const detailNode = el('div', 'metric-detail');
    if (status) detailNode.append(el('span', 'status-dot'));
    detailNode.append(el('span', '', detail));
    node.append(labelNode, el('div', 'metric-value', value), detailNode);
    return node;
  }

  async function overview(epoch) {
    const [deviceResult, userResult, policyResult] = await Promise.allSettled([api('/api/devices'), api('/api/users'), api('/api/policy')]);
    if (!current(epoch)) return;
    const devices = deviceResult.status === 'fulfilled' ? deviceResult.value.devices || [] : null;
    const users = userResult.status === 'fulfilled' ? userResult.value.users || [] : null;
    const policy = policyResult.status === 'fulfilled' ? policyResult.value : null;
    const online = devices && devices.filter(d => d.online && !d.expired).length;
    const nodes = [heading('overview', descriptions.overview, writeButton('Enroll a device', () => createKey(users), 'primary', 'plus'))];
    if (!devices || !users || !policy) nodes.push(banner('Some network information is unavailable. Refresh to try again.', 'error'));
    const metrics = el('div', 'overview-grid');
    metrics.append(metric('Connected now', devices ? online : '—', devices ? online + ' online devices' : 'Device information unavailable', 'network', !!online), metric('Devices', devices ? devices.length : '—', devices ? devices.filter(d => d.expired).length + ' with expired access' : 'Device information unavailable', 'devices'), metric('People', users ? users.length : '—', users ? 'Registered network users' : 'User information unavailable', 'users'));
    nodes.push(metrics);
    const lower = el('div', 'overview-lower');
    const devicePanel = panel('Your devices', 'A look at your latest connections', button('View all', () => navigate('devices'), 'quiet small', 'arrow'));
    if (!devices) devicePanel.append(unavailable(deviceResult.reason));
    else if (!devices.length) devicePanel.append(empty('Your network starts here', 'Install the Covee app on a Mac or iPhone and sign in, or add a server.', 'devices', writeButton('Add a device', () => createKey(users), 'primary')));
    else {
      const latest = [...devices].sort((a, b) => (Date.parse(b.lastSeen) || 0) - (Date.parse(a.lastSeen) || 0)).slice(0, 6);
      devicePanel.append(deviceTable(latest, true));
      devicePanel.append(foot('Status is a snapshot of the last refresh.'));
    }
    const side = el('div', 'stack');
    const invite = el('section', 'callout-panel');
    const mark = el('div', 'callout-icon'); mark.append(icon('plus'));
    invite.append(mark, el('h2', '', 'Make room for another connection.'), el('p', '', 'Add a server, an exit node, or a machine that reaches a local network. Covee gives you the commands to run.'), writeButton('Add a device', () => createKey(users), '', 'arrow'));
    const policyPanel = panel('Access, on your terms');
    const policyBody = el('div', 'panel-body policy-summary');
    if (policy) {
      policyBody.append(el('p', '', 'Your network policy is available to review and edit. Changes take effect when you save.'));
      if (policy.updatedAt) policyBody.append(el('p', '', 'Last updated ' + friendlyDate(policy.updatedAt)));
      policyBody.append(button('Review policy', () => navigate('policy'), 'quiet small', 'policy'));
    } else policyBody.append(el('p', '', 'Policy information is currently unavailable.'), button('Try again', refresh, 'small'));
    policyPanel.append(policyBody);
    side.append(invite, policyPanel);
    lower.append(devicePanel, side);
    nodes.push(lower);
    page.replaceChildren(...nodes);
  }

  // A tagged device belongs to its tags rather than a person.
  function deviceOwner(device) {
    if (device.tags?.length && !device.userName) return device.tags.join(', ');
    return device.userName || 'User ' + device.userId;
  }

  function routeBadges(device) {
    const offered = device.availableRoutes || [];
    const approved = new Set(device.approvedRoutes || []);
    const out = [];
    const exit = offered.filter(isDefaultRoute);
    if (exit.length) out.push(exit.every(route => approved.has(route)) ? ['Exit node', 'success'] : ['Exit node: approve', 'warning']);
    const subnets = offered.filter(route => !isDefaultRoute(route));
    if (subnets.length) {
      const waiting = subnets.filter(route => !approved.has(route)).length;
      out.push(waiting ? ['Local networks: approve', 'warning'] : [subnets.length === 1 ? 'Local network' : subnets.length + ' local networks', 'success']);
    }
    return out;
  }

  function deviceTable(devices, compact = false) {
    const rows = devices.map(device => {
      const row = el('tr');
      const status = el('div', 'tag-list'); status.append(deviceStatus(device));
      if (!compact) for (const text of routeBadges(device)) status.append(badge(text[0], text[1]));
      row.append(cell(identity(deviceName(device), compact ? deviceOwner(device) : device.hostname)), cell(status));
      if (!compact) {
        row.append(cell(deviceOwner(device)));
        const ips = el('div', 'ip-list mono'); for (const ip of device.ips || []) ips.append(el('span', '', ip));
        row.append(cell(ips.childNodes.length ? ips : '—'));
      }
      row.append(cell(ago(device.lastSeen)));
      row.append(cell(button('Manage', () => manageDevice(device), 'quiet small'), 'action-cell'));
      return row;
    });
    return table(compact ? ['Device', 'Status', 'Last seen', 'Actions'] : ['Device', 'Status', 'Owner', 'Addresses', 'Last seen', 'Actions'], rows, 'Network devices');
  }

  async function devicesView(epoch) {
    const data = await api('/api/devices');
    if (!current(epoch)) return;
    const devices = data.devices || [];
    const section = panel('Network devices');
    const toolbar = el('div', 'toolbar');
    const search = el('div', 'search-box');
    const input = el('input'); input.type = 'search'; input.placeholder = 'Find a device, person, or address'; input.setAttribute('aria-label', 'Search devices');
    search.append(icon('search'), input);
    const count = el('span', 'result-count');
    toolbar.append(search, count);
    const results = el('div');
    function render() {
      const term = input.value.trim().toLowerCase();
      const filtered = devices.filter(d => [d.name, d.hostname, d.userName, ...(d.ips || []), ...(d.tags || [])].join(' ').toLowerCase().includes(term));
      count.textContent = filtered.length + ' of ' + devices.length + ' devices';
      if (filtered.length) results.replaceChildren(deviceTable(filtered));
      else if (term) results.replaceChildren(empty('No devices match your search', 'Try another name, owner, or address.', 'search'));
      else results.replaceChildren(empty('No devices yet', 'Install the Covee app on a Mac or iPhone, or add a server.', 'devices', writeButton('Add a device', () => createKey(), 'primary')));
    }
    input.addEventListener('input', render);
    render();
    section.append(toolbar, results, foot('Device status is a snapshot. Refresh to see new connections.'));
    page.replaceChildren(heading('devices', descriptions.devices, writeButton('Add a device', () => createKey(), 'primary', 'plus')), section);
  }

  async function usersView(epoch) {
    const data = await api('/api/users');
    if (!current(epoch)) return;
    const users = data.users || [];
    const section = panel('Network users', users.length + (users.length === 1 ? ' person' : ' people'));
    if (!users.length) section.append(empty('Start with a person', 'Add a user to give your devices an owner.', 'users', writeButton('Add your first user', createUser, 'primary')));
    else {
      const rows = users.map(user => {
        const row = el('tr');
        const actions = el('div', 'button-row');
        actions.append(writeButton('Create key', () => { state.userId = String(user.id); createKey(users); }, 'quiet small'), writeButton('Remove', () => confirmUserDelete(user), 'quiet small'));
        row.append(cell(identity(userName(user), user.email ? '' : user.name, 'users')), cell(user.email), cell(friendlyDate(user.createdAt)), cell(actions, 'action-cell'));
        return row;
      });
      section.append(table(['Person', 'Email', 'Added', 'Actions'], rows, 'Network users'));
    }
    page.replaceChildren(heading('users', descriptions.users, writeButton('Add user', createUser, 'primary', 'plus')), section);
  }

  async function keysView(epoch) {
    const data = await api('/api/users');
    if (!current(epoch)) return;
    const users = data.users || [];
    const section = panel('Device keys', 'Keys are listed by identifier. Their secrets are only shown when created.');
    const toolbar = el('div', 'toolbar');
    const selection = el('div', 'select-toolbar');
    const label = el('label', '', 'Keys belonging to'); label.htmlFor = 'key-owner';
    const select = userSelect(users, 'key-owner');
    const servers = el('option', '', 'Servers (tag-owned)'); servers.value = 'tags'; select.prepend(servers);
    if (users.some(u => String(u.id) === state.userId) || state.userId === 'tags') select.value = state.userId;
    state.userId = select.value;
    selection.append(label, select);
    toolbar.append(selection);
    const results = el('div');
    let keyEpoch = 0;
    async function render() {
      const run = ++keyEpoch;
      state.userId = select.value;
      results.replaceChildren(loading('Loading keys…'));
      try {
        const tagged = select.value === 'tags';
        const owner = tagged ? null : users.find(u => String(u.id) === select.value);
        const result = await api(tagged ? '/api/keys?owner=tags' : '/api/keys?userId=' + encodeURIComponent(select.value));
        if (!current(epoch) || run !== keyEpoch) return;
        const keys = result.keys || [];
        if (!keys.length) results.replaceChildren(empty(tagged ? 'No server keys' : 'No keys for this user', tagged ? 'Add a server to create one.' : 'Create a key to connect a computer for ' + userName(owner) + '.', 'keys', writeButton('Add a device', () => createKey(users), 'primary')));
        else {
          const rows = keys.map(key => {
            const row = el('tr');
            const status = expired(key.expiresAt) ? badge('Expired', 'warning') : key.used && !key.reusable ? badge('Used') : badge('Available', 'success');
            const kinds = el('div', 'tag-list'); kinds.append(badge(key.reusable ? 'Reusable' : 'Single use')); if (key.ephemeral) kinds.append(badge('Ephemeral'));
            const tags = el('div', 'tag-list'); for (const tag of key.tags || []) tags.append(badge(tag));
            const expireButton = writeButton('Expire', () => confirmKeyExpire(key, owner), 'quiet small'); expireButton.disabled = !state.canWrite || !!expired(key.expiresAt);
            row.append(cell('Key ' + key.id, 'mono'), cell(status), cell(kinds), cell(friendlyDate(key.expiresAt)), cell(tags.childNodes.length ? tags : '—'), cell(expireButton, 'action-cell'));
            return row;
          });
          results.replaceChildren(table(['Identifier', 'Status', 'Type', 'Expires', 'Tags', 'Actions'], rows, 'Device keys'));
        }
      } catch (error) { if (current(epoch) && run === keyEpoch) results.replaceChildren(unavailable(error, render)); }
    }
    select.addEventListener('change', render);
    section.append(toolbar, results, foot('Store new keys securely. Existing key secrets cannot be viewed here.', 'policy'));
    page.replaceChildren(heading('keys', descriptions.keys, writeButton('Add a device', () => createKey(users), 'primary', 'plus')), section);
    await render();
  }

  async function policyView(epoch) {
    const data = await api('/api/policy');
    if (!current(epoch)) return;
    state.policy = data.policy || '';
    state.revision = data.revision;
    state.dirty = false;
    const editor = el('textarea', 'policy-editor');
    editor.value = state.policy; editor.spellcheck = false; editor.setAttribute('aria-label', 'Network access policy'); editor.setAttribute('aria-describedby', 'policy-help');
    const status = el('span', 'policy-editor-status', 'No unsaved changes');
    editor.readOnly = !state.canWrite;
    const save = writeButton('Save policy', submit, 'primary', 'check'); save.disabled = true;
    if (!state.canWrite) status.textContent = 'Read-only access';
    const section = panel('Network policy', 'Comments and trailing commas are supported.', status);
    section.append(editor);
    section.append(foot(data.updatedAt ? 'Last updated ' + friendlyDate(data.updatedAt) : 'Save explicitly to apply your changes.'));
    const errors = el('div');
    const layout = el('div', 'policy-layout');
    const main = el('div'); main.append(errors, section);
    const help = el('aside', 'policy-note'); help.id = 'policy-help';
    const first = el('div'); first.append(el('h2', '', 'A deliberate change.'), el('p', '', 'Review your rules before saving. Changes to the policy can affect which devices are able to connect.'), el('p', '', 'The policy is checked when you save. Invalid changes are not applied.'));
    const second = el('div'); second.append(el('h2', '', 'Keep your draft.'), el('p', '', 'This editor does not save automatically. Changes through this console are checked for conflicts before saving.'), el('p', '', 'Copy your draft before refreshing after a conflict.'));
    // Tailscale SSH: servers running `tailscale set --ssh` let people in by their network identity.
    const sshRule = el('div', 'secret-box commands', '{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["autogroup:nonroot"]}');
    sshRule.tabIndex = 0;
    const sshStatus = el('span', 'copy-status');
    const third = el('div');
    third.append(el('h2', '', 'Sign in to servers without keys.'),
      el('p', '', 'A server that runs Tailscale with SSH turned on (tailscale set --ssh) lets people in by their network identity, with no key or password, from Covee on a Mac or iPhone. This rule, in the ssh list, lets everyone sign in to servers tagged tag:server as any user but root:'),
      sshRule, copyButton('Copy rule', sshRule, sshStatus, 'Copied.'), sshStatus);
    help.append(first, el('hr'), second, el('hr'), third);
    layout.append(main, help);
    editor.addEventListener('input', () => {
      if (!state.canWrite) return;
      state.dirty = editor.value !== state.policy;
      save.disabled = !state.dirty || save.dataset.conflict === 'true';
      status.textContent = state.dirty ? 'Unsaved changes' : 'No unsaved changes';
      status.classList.toggle('dirty', state.dirty);
    });
    async function submit() {
      if (!state.canWrite || !state.dirty || save.disabled) return;
      save.disabled = true; editor.disabled = true; save.querySelector('span').textContent = 'Saving…'; errors.replaceChildren();
      try {
        const result = await api('/api/policy', { method: 'PUT', body: { policy: editor.value, revision: state.revision } });
        if (!current(epoch)) return;
        state.policy = editor.value;
        if (result.revision !== undefined) state.revision = result.revision;
        state.dirty = false;
        status.textContent = 'All changes saved'; status.classList.remove('dirty');
        notify('Access policy saved.'); synced();
      } catch (error) {
        if (!current(epoch)) return;
        const conflict = error.status === 409;
        errors.append(banner(conflict ? 'The policy has changed since you opened it. Your draft is still here. Copy it, then refresh to review the current policy before saving again.' : error.message, 'error'));
        if (conflict) save.dataset.conflict = 'true';
      } finally {
        editor.disabled = false;
        save.querySelector('span').textContent = 'Save policy';
        save.disabled = !state.dirty || save.dataset.conflict === 'true';
      }
    }
    page.replaceChildren(heading('policy', descriptions.policy, save), layout);
  }

  async function auditView(epoch) {
    const data = await api('/api/audit');
    if (!current(epoch)) return;
    const events = data.events || [];
    const section = panel('Recent activity', 'The latest ' + events.length + ' console actions');
    if (!events.length) section.append(empty('A clean page', 'User, device, key, and policy changes will appear here.', 'audit'));
    else {
      const rows = events.map(event => {
        const row = el('tr');
        const actor = event.actor;
        const actorLabel = actor ? (actor.name || actor.subject || 'Unknown actor') + (actor.issuer ? ' · ' + actor.issuer + ' · ' + actor.subject : '') : 'Legacy record';
        row.append(cell(friendlyDate(event.time)), cell(actorLabel), cell(event.action), cell(event.target), cell(badge(event.outcome, event.outcome === 'success' ? 'success' : event.outcome === 'error' || event.outcome === 'failure' ? 'danger' : '')), cell(event.requestId, 'mono'));
        return row;
      });
      section.append(table(['Time', 'Actor', 'Action', 'Target', 'Outcome', 'Request'], rows, 'Recent console activity'));
    }
    section.append(foot('Activity covers changes made through this console.'));
    page.replaceChildren(heading('audit', descriptions.audit), section);
  }

  // The gateway: what members reach through the network's gateway device,
  // and which DNS names go to private resolvers. Every save sends the whole
  // settings with the revision they were loaded at.
  async function gatewayView(epoch) {
    const [data, people] = await Promise.all([api('/api/gateway'), api('/api/users').catch(() => null)]);
    if (!current(epoch)) return;
    const person = new Map();
    for (const user of people?.users || []) { person.set(user.name, user); if (user.email) person.set(user.email, user); }
    if (!data.enabled) {
      const section = panel('No gateway yet', 'A gateway lets your devices reach places only the server can, such as a cloud\u2019s private networks.');
      section.append(empty('This network has no gateway', 'Turn it on from the computer that manages the network with covee gateway <network>, then return here.', 'gateway'));
      page.replaceChildren(heading('gateway', descriptions.gateway), section);
      return;
    }
    state.gateway = data;
    const status = data.status || {};
    const settings = data.settings || { entries: [], dns: [] };
    const parts = [];
    const device = status.device;
    if (!device) parts.push(banner('The gateway device has not joined the network yet. Routes take effect once it has.', 'warning'));
    else if (!device.online) parts.push(banner('The gateway device is offline, so nothing reaches its destinations right now.', 'error'));
    if (status.problem) parts.push(banner(status.problem, 'error'));

    const routeState = new Map((status.routes || []).map(route => [route.route, route]));
    const hostState = new Map((status.hosts || []).map(host => [host.name, host]));
    const add = writeButton('Add destination', () => editGatewayEntry(null), 'primary', 'plus');
    const section = panel('Through the gateway', 'Traffic to these destinations goes through the gateway device; everything else goes directly.', add);
    if (!settings.entries.length) section.append(empty('Nothing goes through the gateway', 'Add address ranges such as 10.0.0.0/8, or host names such as db.example.com.', 'gateway'));
    else {
      const rows = settings.entries.map(entry => {
        const row = el('tr');
        const list = el('div', 'tag-list');
        for (const destination of entry.destinations) {
          const host = hostState.get(destination);
          let text = destination;
          if (host) text += host.addresses.length ? ' \u2192 ' + host.addresses.join(', ') : '';
          list.append(badge(text, 'wrap' + (host && host.problem ? ' warning' : '')));
          if (host && host.problem) list.append(el('span', 'field-hint', destination + ' ' + host.problem));
        }
        const mine = (status.routes || []).filter(route => (route.entries || []).includes(entry.id));
        const ready = mine.filter(route => route.approved).length;
        const routeBadge = !mine.length ? badge('No addresses yet', 'warning') : ready === mine.length ? badge('Active', 'success') : badge(ready + ' of ' + mine.length + ' active', 'warning');
        const who = entry.users && entry.users.length ? entry.users.map(name => person.has(name) ? userName(person.get(name)) : name).join(', ') : 'Everyone in the network';
        const actions = el('div', 'button-row');
        actions.append(writeButton('Edit', () => editGatewayEntry(entry), 'quiet small'), writeButton('Remove', () => removeGatewayEntry(entry), 'quiet small'));
        row.append(cell(entry.label), cell(list), cell(who), cell(routeBadge), cell(actions, 'action-cell'));
        return row;
      });
      section.append(table(['Name', 'Destinations', 'Who', 'Status', ''], rows, 'Destinations through the gateway'));
    }
    section.append(foot('Host names are looked up from the server every 5 minutes. Devices use these routes when the app\u2019s gateway setting is on.'));

    const dnsAdd = writeButton('Add domain', () => editGatewayDNS(null), '', 'plus');
    const dnsSection = panel('Private DNS', 'Names in these domains are answered by private resolvers, through the gateway.', dnsAdd);
    const dnsStatus = status.dns || {};
    if (dnsStatus.problem) dnsSection.append(banner('The server could not apply the DNS settings: ' + dnsStatus.problem, 'error'));
    else if (settings.dns.length && !dnsStatus.applied) dnsSection.append(banner('Waiting for the server to apply these DNS settings. It restarts the coordinator for a few seconds; devices stay connected.', 'warning'));
    if (!settings.dns.length) dnsSection.append(empty('No private DNS', 'Add a domain such as blob.core.windows.net with the resolver 168.63.129.16 to use private endpoints by name. Key Vault needs two: vault.azure.net and privatelink.vaultcore.azure.net.', 'gateway'));
    else {
      const rows = settings.dns.map(entry => {
        const row = el('tr');
        const actions = el('div', 'button-row');
        actions.append(writeButton('Edit', () => editGatewayDNS(entry), 'quiet small'), writeButton('Remove', () => removeGatewayDNS(entry), 'quiet small'));
        row.append(cell(entry.domain, 'mono'), cell(entry.resolvers.join(', '), 'mono'), cell(actions, 'action-cell'));
        return row;
      });
      dnsSection.append(table(['Domain', 'Resolvers', ''], rows, 'Private DNS domains'));
    }
    page.replaceChildren(heading('gateway', descriptions.gateway), ...parts, section, dnsSection);
  }

  // saveGateway sends the settings with one change applied.
  function saveGateway(change) {
    const settings = JSON.parse(JSON.stringify(state.gateway.settings));
    change(settings);
    return api('/api/gateway', { method: 'PUT', body: { entries: settings.entries, dns: settings.dns, revision: state.gateway.revision } });
  }

  function gatewayError(failure) {
    if (failure.status === 409) failure.message = 'The gateway settings changed since this page loaded. Close this, refresh, and try again.';
    throw failure;
  }

  async function editGatewayEntry(entry) {
    if (!state.canWrite) return;
    const { body, footer } = showDialog(entry ? 'Edit destination' : 'Add destination', 'Traffic to these addresses goes through the gateway device.');
    body.append(loading('Loading users\u2026'));
    footer.append(button('Cancel', () => closeDialog(), 'quiet'));
    let users = [];
    try { users = (await api('/api/users')).users || []; } catch (failure) { body.replaceChildren(banner(failure.message, 'error')); return; }
    const form = el('form'); form.id = 'gateway-form';
    const label = field(form, 'Name', 'label', 'text', 'For example: Azure private networks.'); label.maxLength = 64; label.value = entry ? entry.label : '';
    const wrap = el('div', 'field'); const destLabel = el('label', '', 'Destinations'); destLabel.htmlFor = 'field-destinations';
    const destinations = el('textarea'); destinations.id = 'field-destinations'; destinations.rows = 5; destinations.value = entry ? entry.destinations.join('\n') : '';
    wrap.append(destLabel, destinations, el('p', 'field-hint', 'One per line: an address range such as 10.20.0.0/16, an address such as 203.0.113.7, or a host name such as cluster0.abc.mongodb.net.'));
    form.append(wrap);
    const everyone = checkbox(form, 'Everyone in the network', 'everyone', 'Turn this off to choose people.');
    const people = el('div', 'route-section'); people.id = 'gateway-people';
    const chosen = new Set(entry ? entry.users : []);
    const boxes = users.map((user, index) => {
      const box = checkbox(people, userLabel(user), 'person-' + index);
      box.checked = chosen.has(user.name) || (user.email && chosen.has(user.email));
      box.dataset.name = user.name;
      return box;
    });
    form.append(people);
    everyone.checked = !entry || !entry.users || !entry.users.length;
    const sync = () => { people.hidden = everyone.checked; };
    everyone.addEventListener('change', sync); sync();
    const error = errorField(form); body.replaceChildren(form);
    const submit = writeButton(entry ? 'Save' : 'Add', null, 'primary'); submit.type = 'submit'; submit.setAttribute('form', form.id);
    footer.replaceChildren(button('Cancel', () => closeDialog(), 'quiet'), submit);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const list = destinations.value.split(/[\n,]+/).map(text => text.trim()).filter(Boolean);
      const picked = everyone.checked ? [] : boxes.filter(box => box.checked).map(box => box.dataset.name);
      if (!label.value.trim()) { error.textContent = 'Give the destination a name.'; error.hidden = false; return; }
      if (!list.length) { error.textContent = 'List at least one destination.'; error.hidden = false; return; }
      if (!everyone.checked && !picked.length) { error.textContent = 'Choose at least one person, or allow everyone.'; error.hidden = false; return; }
      const updated = { id: entry ? entry.id : '', label: label.value.trim(), destinations: list, users: picked };
      modalMutation(form, error, submit, () => saveGateway(settings => {
        if (entry) settings.entries = settings.entries.map(item => item.id === entry.id ? updated : item); else settings.entries.push(updated);
      }).catch(gatewayError), () => { closeDialog(); notify(entry ? 'Destination saved.' : 'Destination added.'); loadRoute(state.route); });
    });
    label.focus();
  }

  function removeGatewayEntry(entry) {
    review('Stop routing this through the gateway?', 'Devices will reach these destinations directly again, or not at all if they are private.', entry.label + ' \u00b7 ' + entry.destinations.join(', '), 'Remove',
      () => saveGateway(settings => { settings.entries = settings.entries.filter(item => item.id !== entry.id); }).catch(gatewayError), 'Destination removed.');
  }

  function editGatewayDNS(entry) {
    if (!state.canWrite) return;
    const { body, footer } = showDialog(entry ? 'Edit private DNS' : 'Add private DNS', 'Names in this domain are answered by these resolvers, through the gateway.');
    const form = el('form'); form.id = 'gateway-dns-form';
    const domain = field(form, 'Domain', 'domain', 'text', 'For example: blob.core.windows.net. Its subdomains are included. Key Vault needs vault.azure.net and privatelink.vaultcore.azure.net.'); domain.value = entry ? entry.domain : '';
    const resolvers = field(form, 'Resolvers', 'resolvers', 'text', 'Comma separated. Azure\u2019s private DNS is 168.63.129.16.'); resolvers.value = entry ? entry.resolvers.join(', ') : '168.63.129.16';
    const error = errorField(form); body.append(form);
    const submit = writeButton(entry ? 'Save' : 'Add', null, 'primary'); submit.type = 'submit'; submit.setAttribute('form', form.id);
    footer.append(button('Cancel', () => closeDialog(), 'quiet'), submit);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const updated = { domain: domain.value.trim().toLowerCase(), resolvers: resolvers.value.split(',').map(text => text.trim()).filter(Boolean) };
      if (!updated.domain || !updated.resolvers.length) { error.textContent = 'Enter a domain and at least one resolver.'; error.hidden = false; return; }
      modalMutation(form, error, submit, () => saveGateway(settings => {
        if (entry) settings.dns = settings.dns.map(item => item.domain === entry.domain ? updated : item); else settings.dns.push(updated);
      }).catch(gatewayError), () => { closeDialog(); notify('Private DNS saved. The server applies it within a minute.'); loadRoute(state.route); });
    });
    domain.focus();
  }

  function removeGatewayDNS(entry) {
    review('Stop using private DNS for this domain?', 'Its names will be answered by the devices\u2019 usual DNS again.', entry.domain, 'Remove',
      () => saveGateway(settings => { settings.dns = settings.dns.filter(item => item.domain !== entry.domain); }).catch(gatewayError), 'Private DNS removed.');
  }

  const loaders = { overview, devices: devicesView, users: usersView, keys: keysView, gateway: gatewayView, policy: policyView, audit: auditView };

  function showDialog(title, subtitle = '', explicit = false) {
    if (dialog.open) closeDialog(true);
    dialogOrigin = document.activeElement;
    dialogLocked = false;
    secretOpen = explicit;
    const header = el('div', 'dialog-header');
    const copy = el('div'); const heading = el('h2', '', title); heading.id = 'dialog-title'; copy.append(heading);
    if (subtitle) copy.append(el('p', '', subtitle));
    header.append(copy);
    if (!explicit) {
      const close = button('', () => closeDialog(), 'close-button'); close.className = 'close-button'; close.setAttribute('aria-label', 'Close dialog'); close.append(icon('close')); header.append(close);
    }
    const body = el('div', 'dialog-body');
    const footer = el('div', 'dialog-footer');
    dialogContent.replaceChildren(header, body, footer);
    dialog.showModal();
    return { body, footer };
  }

  function closeDialog(force = false) {
    if (dialogLocked && !force) return;
    dialogLocked = false;
    if (secretOpen) {
      for (const node of dialogContent.querySelectorAll('.secret-box')) node.textContent = '';
      window.getSelection()?.removeAllRanges();
    }
    secretOpen = false;
    dialog.close();
    // Destroy every DOM reference containing the one-time key secret.
    dialogContent.replaceChildren();
    if (dialogOrigin?.isConnected && state.authenticated) dialogOrigin.focus();
    dialogOrigin = null;
  }

  dialog.addEventListener('cancel', event => { event.preventDefault(); if (!dialogLocked && !secretOpen) closeDialog(); });

  function errorField(parent) { const node = el('p', 'form-error'); node.hidden = true; node.setAttribute('role', 'alert'); parent.append(node); return node; }
  function field(parent, labelText, name, type = 'text', hint = '') {
    const wrap = el('div', 'field'); const label = el('label', '', labelText); label.htmlFor = 'field-' + name;
    const input = el('input'); input.id = label.htmlFor; input.name = name; input.type = type;
    wrap.append(label, input);
    if (hint) { const desc = el('p', 'field-hint', hint); desc.id = 'hint-' + name; input.setAttribute('aria-describedby', desc.id); wrap.append(desc); }
    parent.append(wrap);
    return input;
  }

  function userSelect(users, id) {
    const select = el('select'); select.id = id;
    for (const user of users) { const option = el('option', '', userLabel(user)); option.value = String(user.id); select.append(option); }
    return select;
  }

  function checkbox(parent, text, name, hint) {
    const wrap = el('div', 'checkbox-field'); const input = el('input'); input.type = 'checkbox'; input.name = name; input.id = 'field-' + name;
    const label = el('label', '', text); label.htmlFor = input.id;
    if (hint) label.append(el('div', 'field-hint', hint));
    wrap.append(input, label); parent.append(wrap); return input;
  }

  async function modalMutation(form, error, submit, operation, done) {
    if (dialogLocked) return;
    const generation = state.generation;
    dialogLocked = true;
    const controls = [...dialogContent.querySelectorAll('button,input,select,textarea')];
    const disabled = controls.map(node => node.disabled);
    for (const node of controls) node.disabled = true;
    const text = submit.querySelector('span'); const original = text.textContent; text.textContent = 'Working…';
    error.hidden = true;
    try {
      const result = await operation();
      dialogLocked = false;
      if (state.authenticated && state.generation === generation) done(result);
    } catch (failure) {
      if (!state.authenticated || state.generation !== generation) return;
      error.textContent = failure.message; error.hidden = false;
    } finally {
      dialogLocked = false;
      controls.forEach((node, index) => { node.disabled = disabled[index]; });
      text.textContent = original;
    }
  }

  function createUser() {
    if (!state.canWrite) return;
    const { body, footer } = showDialog('Add a user', 'Give a person a place in your network.');
    const form = el('form'); form.id = 'user-form';
    const name = field(form, 'Username', 'name', 'text', 'A unique username for this network.'); name.required = true; name.autocomplete = 'off'; name.maxLength = 100;
    const displayName = field(form, 'Display name', 'displayName', 'text', 'Optional. The name shown in this console.'); displayName.autocomplete = 'name'; displayName.maxLength = 200;
    const email = field(form, 'Email', 'email', 'email', 'Optional.'); email.autocomplete = 'email'; email.maxLength = 320;
    const error = errorField(form); body.append(form);
    const submit = writeButton('Add user', null, 'primary'); submit.type = 'submit'; submit.setAttribute('form', form.id);
    footer.append(button('Cancel', () => closeDialog(), 'quiet'), submit);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const payload = { name: name.value.trim(), email: email.value.trim(), displayName: displayName.value.trim() };
      if (!payload.name) { name.setCustomValidity('Enter a username.'); name.reportValidity(); name.setCustomValidity(''); return; }
      modalMutation(form, error, submit, () => api('/api/users', { method: 'POST', body: payload }), () => { closeDialog(); notify('User added.'); loadRoute(state.route); });
    });
    name.focus();
  }

  function selectField(parent, labelText, id, options, hint = '') {
    const label = el('label', '', labelText); label.htmlFor = id;
    const select = el('select'); select.id = id;
    for (const [text, value] of options) { const option = el('option', '', text); option.value = String(value); select.append(option); }
    parent.append(label, select);
    if (hint) parent.append(el('p', 'field-hint', hint));
    return select;
  }

  // Add a device: a server owned by a tag (never expires) or a person's machine
  // that runs the standard Tailscale client, with the commands to join it.
  async function createKey(knownUsers) {
    if (!state.canWrite) return;
    const { body, footer } = showDialog('Add a device', 'Prepare a key and the commands that connect a machine to your network.');
    body.append(loading('Loading users…'));
    footer.append(button('Cancel', () => closeDialog(), 'quiet'));
    const titleNode = $('#dialog-title');
    let users = knownUsers;
    try { if (!users) users = (await api('/api/users')).users || []; }
    catch (error) { if (dialog.open && $('#dialog-title') === titleNode) body.replaceChildren(unavailable(error, () => createKey())); return; }
    if (!dialog.open || $('#dialog-title') !== titleNode || !state.authenticated) return;
    const form = el('form'); form.id = 'key-form';
    const kind = selectField(form, 'What are you adding?', 'new-key-kind', [['A server or other machine', 'server'], ["A person's computer", 'person']]);
    const kindHint = el('p', 'field-hint'); form.append(kindHint);
    const serverPart = el('div');
    const tags = field(serverPart, 'Tag', 'tags', 'text', 'The machine belongs to this tag instead of a person, for example tag:server. Separate several with commas.'); tags.value = 'tag:server'; tags.autocomplete = 'off'; tags.spellcheck = false;
    const allow = checkbox(serverPart, "Let everyone's devices reach it", 'allowMembers', 'Adds this rule to the access policy.'); allow.checked = true;
    const personPart = el('div'); personPart.hidden = true;
    let select = null;
    if (users.length) {
      const label = el('label', '', 'Belongs to'); label.htmlFor = 'new-key-owner';
      select = userSelect(users, label.htmlFor);
      if (users.some(user => String(user.id) === state.userId)) select.value = state.userId;
      personPart.append(label, select);
    } else personPart.append(el('p', 'field-hint', 'Add a user first: a person’s computer belongs to a user.'));
    personPart.append(el('p', 'field-hint', 'For Macs and iPhones, install the Covee app and sign in instead; no key is needed.'));
    form.append(serverPart, personPart);
    const name = field(form, 'Machine name', 'hostname', 'text', 'Optional. Lowercase letters, digits and hyphens.'); name.autocomplete = 'off'; name.spellcheck = false;
    const exitNode = checkbox(form, 'Offer it as an exit node', 'exitNode', 'Other devices can send their internet traffic through it, once you approve it.');
    const routes = field(form, 'Offer local networks', 'routes', 'text', 'Optional, for example 192.168.1.0/24. Your devices reach them through this machine once you approve them.'); routes.placeholder = '192.168.1.0/24'; routes.autocomplete = 'off'; routes.spellcheck = false;
    const lifetime = selectField(form, 'The key works for', 'new-key-lifetime', keyLifetimes, 'Only for joining. A server stays connected afterwards until you remove it.'); lifetime.value = '24';
    const reusable = checkbox(form, 'Several machines can use this key', 'reusable', 'Otherwise the key works once.');
    const ephemeral = checkbox(form, 'Remove the machine when it goes offline', 'ephemeral', 'For short-lived machines such as containers.');
    const error = errorField(form);
    function showKind() {
      const server = kind.value === 'server';
      serverPart.hidden = !server; personPart.hidden = server;
      kindHint.textContent = server ? 'It belongs to the network, not a person, and stays connected until you remove it.' : 'It belongs to a person and signs in again when the network’s device access period ends.';
    }
    kind.addEventListener('change', showKind); showKind();
    const submit = writeButton('Create key', null, 'primary'); submit.type = 'submit'; submit.setAttribute('form', form.id);
    body.replaceChildren(form); footer.replaceChildren(button('Cancel', () => closeDialog(), 'quiet'), submit);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const server = kind.value === 'server';
      const hostname = name.value.trim().toLowerCase();
      const networks = routes.value.split(/[\s,]+/).map(value => value.trim()).filter(Boolean);
      const problem = !server && !select ? 'Add a user first, or add a server instead.'
        : hostname && !hostLabel.test(hostname) ? 'Use lowercase letters, digits and hyphens for the machine name.'
        : networks.find(network => !ipv4Network.test(network) && !ipv6Network.test(network)) ? 'Write local networks like 192.168.1.0/24.' : '';
      if (problem) { error.textContent = problem; error.hidden = false; return; }
      const tagList = tags.value.split(',').map(tag => tag.trim()).filter(Boolean);
      const payload = server
        ? { tags: tagList, allowMembers: allow.checked, expiryHours: Number(lifetime.value), reusable: reusable.checked, ephemeral: ephemeral.checked }
        : { userId: select.value, expiryHours: Number(lifetime.value), reusable: reusable.checked, ephemeral: ephemeral.checked, tags: [] };
      if (!server) state.userId = select.value;
      const owner = server ? null : users.find(user => String(user.id) === select.value);
      modalMutation(form, error, submit, () => api('/api/keys', { method: 'POST', body: payload }), result => {
        loadRoute(state.route);
        showSecret(result.secret, owner, result.key, { controlURL: result.controlURL, hostname, exitNode: exitNode.checked, networks, tags: server ? tagList : [] });
      });
    });
    kind.focus();
  }

  // The commands for a Linux machine. They contain the key, so they are shown
  // in a secret box that is cleared with the dialog.
  function joinCommands(secret, join) {
    const flags = ['--login-server=' + (join.controlURL || 'https://YOUR-COORDINATOR'), '--auth-key=' + secret];
    if (join.hostname) flags.push('--hostname=' + join.hostname);
    if (join.exitNode) flags.push('--advertise-exit-node');
    if (join.networks.length) flags.push('--advertise-routes=' + join.networks.join(','));
    const lines = ['curl -fsSL https://tailscale.com/install.sh | sh'];
    if (join.exitNode || join.networks.length) {
      lines.push("echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-covee.conf", "echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-covee.conf", 'sudo sysctl -p /etc/sysctl.d/99-covee.conf');
    }
    lines.push('sudo tailscale up ' + flags.join(' '));
    return lines.join('\n');
  }

  function copyButton(text, box, status, done) {
    return button(text, async () => {
      try {
        // Read from the visible DOM so the secret is not retained by a closure.
        if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
        await navigator.clipboard.writeText(box.textContent);
        if (box.isConnected) status.textContent = done;
      } catch {
        if (!box.isConnected) return;
        const range = document.createRange(); range.selectNodeContents(box);
        const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); box.focus();
        status.textContent = 'Selected. Press ⌘C or Ctrl+C to copy.';
      }
    }, '', 'copy');
  }

  function showSecret(secret, user, key, join = null) {
    const owner = user ? 'For ' + userName(user) : join?.tags?.length ? 'For ' + join.tags.join(', ') : '';
    const { body, footer } = showDialog('Your device key is ready.', owner, true);
    if (typeof secret !== 'string' || !secret) {
      body.append(banner('The key was created, but its secret was not returned. Create another key if you need to add a device.', 'error'));
      footer.append(button('Close', () => closeDialog(), 'primary'));
      return;
    }
    body.append(el('div', 'secret-warning', 'Copy this now and store it securely. It will not be shown again after you close this window.'));
    const box = el('pre', 'secret-box', secret); box.tabIndex = 0; box.setAttribute('aria-label', 'New device key');
    body.append(box);
    const status = el('span', 'copy-status'); status.setAttribute('role', 'status');
    const actions = el('div', 'secret-actions'); actions.append(copyButton('Copy key', box, status, 'Copied to clipboard'), status); body.append(actions);
    if (key?.expiresAt) body.append(el('p', 'field-hint', 'The key works until ' + friendlyDate(key.expiresAt) + '.'));
    if (join) {
      body.append(el('h3', '', 'Run this on the Linux machine'));
      const commands = el('pre', 'secret-box commands', joinCommands(secret, join)); commands.tabIndex = 0; commands.setAttribute('aria-label', 'Commands that connect the machine');
      body.append(commands);
      const commandStatus = el('span', 'copy-status'); commandStatus.setAttribute('role', 'status');
      const commandActions = el('div', 'secret-actions'); commandActions.append(copyButton('Copy commands', commands, commandStatus, 'Commands copied'), commandStatus); body.append(commandActions);
      body.append(el('p', 'field-hint', 'This installs the open-source Tailscale client, which works with your network’s coordinator, and joins the machine.' + (join.exitNode || join.networks.length ? ' After it joins, approve its exit node or local networks under Devices → Manage.' : '')));
    }
    footer.append(button('I have saved the key', () => { for (const node of body.querySelectorAll('.secret-box')) node.textContent = ''; closeDialog(); notify('Device key created.'); }, 'primary'));
  }

  function review(title, description, target, action, operation, success) {
    if (!state.canWrite) return;
    const { body, footer } = showDialog(title);
    body.append(el('p', '', description), el('span', 'review-target', target));
    const error = errorField(body);
    const submit = button(action, () => modalMutation(null, error, submit, operation, () => { closeDialog(); notify(success); loadRoute(state.route); }), 'danger');
    footer.append(button('Cancel', () => closeDialog(), 'quiet'), submit);
  }

  function confirmUserDelete(user) {
    review('Remove this user?', 'Review the user you are removing. A user with registered devices may need those devices removed first.', userName(user) + ' · ' + user.name + ' · ID ' + user.id, 'Remove user', () => api('/api/users/' + encodeURIComponent(user.id), { method: 'DELETE' }), 'User removed.');
  }

  function confirmKeyExpire(key, user) {
    const body = user ? { userId: String(key.userId || user.id) } : { tagged: true };
    review('Expire this key?', 'This key will no longer add devices. Devices already added keep their access.', 'Key ' + key.id + ' · ' + (user ? userName(user) : (key.tags || []).join(', ')), 'Expire key', () => api('/api/keys/' + encodeURIComponent(key.id) + '/expire', { method: 'POST', body }), 'Key expired.');
  }

  function manageDevice(device) {
    const { body, footer } = showDialog('Manage device', deviceName(device));
    const form = el('form'); form.id = 'device-form';
    const name = field(form, 'Device name', 'deviceName'); name.value = deviceName(device); name.required = true; name.maxLength = 100; name.autocomplete = 'off';
    name.readOnly = !state.canWrite;
    const error = errorField(form); body.append(form, el('hr', 'detail-divider'));
    const facts = el('dl', 'detail-list');
    for (const [label, value] of [['Owner', deviceOwner(device)], ['Hostname', device.hostname], ['Addresses', (device.ips || []).join(', ')], ['Last seen', friendlyDate(device.lastSeen)], ['Access expires', friendlyDate(device.expiresAt)], ['Tags', (device.tags || []).join(', ')]]) { facts.append(el('dt', '', label), el('dd', '', value || '—')); }
    body.append(facts);
    if ((device.availableRoutes || []).length) body.append(routeSection(device));
    const danger = el('div', 'danger-zone');
    const expireButton = el('button', 'text-button danger', 'Expire device access'); expireButton.type = 'button'; expireButton.disabled = !state.canWrite || !!device.expired;
    expireButton.addEventListener('click', () => review('Expire this device?', 'The device will need to authenticate again to regain network access.', deviceName(device) + ' · ' + deviceOwner(device) + ' · ID ' + device.id, 'Expire device', () => api('/api/devices/' + encodeURIComponent(device.id) + '/expire', { method: 'POST', body: {} }), 'Device access expired.'));
    const remove = el('button', 'text-button danger', 'Remove device'); remove.type = 'button';
    remove.disabled = !state.canWrite;
    remove.addEventListener('click', () => review('Remove this device?', 'Remove this device from your network. It will need to enroll again to reconnect.', deviceName(device) + ' · ' + deviceOwner(device) + ' · ID ' + device.id, 'Remove device', () => api('/api/devices/' + encodeURIComponent(device.id), { method: 'DELETE' }), 'Device removed.'));
    danger.append(expireButton, remove); body.append(danger);
    const submit = writeButton('Save name', null, 'primary'); submit.type = 'submit'; submit.setAttribute('form', form.id);
    footer.append(button('Close', () => closeDialog(), 'quiet'), submit);
    form.addEventListener('submit', event => {
      event.preventDefault(); if (!state.canWrite) return; const value = name.value.trim();
      if (!value) { name.setCustomValidity('Enter a device name.'); name.reportValidity(); name.setCustomValidity(''); return; }
      modalMutation(form, error, submit, () => api('/api/devices/' + encodeURIComponent(device.id), { method: 'PATCH', body: { name: value } }), () => { closeDialog(); notify('Device renamed.'); loadRoute(state.route); });
    });
    name.focus();
  }

  // What a device offers: an exit node (both default routes) and local networks.
  // Approving lets it serve them; the policy decides who may use them.
  function routeSection(device) {
    const offered = device.availableRoutes || [];
    const approved = new Set(device.approvedRoutes || []);
    const section = el('div', 'route-section');
    section.append(el('h3', '', 'Exit node and local networks'));
    const choices = [];
    const exitRoutes = offered.filter(isDefaultRoute);
    if (exitRoutes.length) choices.push({ label: 'Exit node', hint: 'Devices can send their internet traffic through ' + deviceName(device) + '.', routes: exitRoutes });
    for (const route of offered.filter(route => !isDefaultRoute(route))) choices.push({ label: route, hint: 'Devices can reach this local network through ' + deviceName(device) + '.', routes: [route] });
    const boxes = choices.map((choice, index) => {
      const box = checkbox(section, choice.label, 'route-' + index, choice.hint);
      box.checked = choice.routes.every(route => approved.has(route));
      box.disabled = !state.canWrite;
      return box;
    });
    const allow = checkbox(section, "Let everyone's devices use what is approved", 'routeAccess', 'Adds the matching rule to the access policy.');
    allow.checked = true; allow.disabled = !state.canWrite;
    const error = errorField(section);
    const save = writeButton('Save approvals', null, 'small');
    save.addEventListener('click', () => {
      if (!state.canWrite) return;
      const routes = choices.flatMap((choice, index) => boxes[index].checked ? choice.routes : []);
      modalMutation(null, error, save, () => api('/api/devices/' + encodeURIComponent(device.id) + '/routes', { method: 'POST', body: { routes, allowMembers: allow.checked && routes.length > 0 } }), () => { closeDialog(); notify(routes.length ? 'Approvals saved.' : 'Approvals removed.'); loadRoute(state.route); });
    });
    section.append(save);
    return section;
  }

  function confirmDiscard() {
    return new Promise(resolve => {
      const { body, footer } = showDialog('Leave your policy draft?');
      body.append(el('p', '', 'Your policy has unsaved changes. Leaving this page will discard your draft.'));
      let resolved = false;
      const finish = value => {
        if (resolved) return;
        resolved = true;
        dialog.removeEventListener('cancel', cancel);
        closeDialog();
        if (value) state.dirty = false;
        resolve(value);
      };
      const keep = () => finish(false);
      const discard = () => finish(true);
      footer.append(button('Keep editing', keep), button('Discard draft', discard, 'danger'));
      const cancel = event => { event.preventDefault(); keep(); };
      dialog.addEventListener('cancel', cancel, { once: true });
      // The close icon also means keep editing.
      $('.close-button', dialogContent)?.addEventListener('click', () => finish(false), { once: true });
    });
  }

  async function logout() {
    if (state.dirty && !(await confirmDiscard())) return;
    const buttons = [$('#logout'), $('#mobile-logout')].filter(Boolean);
    buttons.forEach(node => { node.disabled = true; });
    try { await api('/api/logout', { method: 'POST', body: {} }); signedOut(); }
    catch (error) { if (state.authenticated) notify(error.message, true); }
    finally { buttons.forEach(node => { node.disabled = false; }); }
  }

  for (const route of routes) {
    const link = el('a', 'nav-link'); link.href = '#' + route; link.dataset.route = route;
    link.append(icon(route), el('span', '', titles[route]));
    link.addEventListener('click', event => { event.preventDefault(); navigate(route); });
    $('#navigation').append(link);
  }
  $('#sidebar-icon').append(icon('policy'));
  $('.sidebar > .brand').addEventListener('click', event => { event.preventDefault(); navigate('overview'); });
  const mobileLogout = button('Sign out', logout, 'quiet small'); mobileLogout.id = 'mobile-logout';
  $('.topbar-right').prepend(mobileLogout);
  $('#logout').addEventListener('click', logout);
  $('#oidc-login-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (state.authMode !== 'oidc') return;
    const submit = $('#oidc-login-form button');
    submit.disabled = true; $('#login-error').hidden = true;
    try {
      const result = await api('/auth/oidc/login', { method: 'POST', body: {} });
      const target = new URL(result.authorizationUrl);
      if (target.protocol !== 'https:') throw new Error('Sign-in configuration is unavailable.');
      location.assign(target.href);
    } catch (error) {
      $('#login-error').textContent = error.message; $('#login-error').hidden = false;
      submit.disabled = false;
    }
  });
  $('#login-form').addEventListener('submit', async event => {
    event.preventDefault();
    const input = $('#login-token');
    let token = input.value;
    if (!token) return;
    const submit = $('#login-form button');
    const original = submit.textContent;
    submit.disabled = true; input.disabled = true; submit.textContent = 'Signing in…'; $('#login-error').hidden = true;
    try {
      const pending = api('/api/login', { method: 'POST', body: { token } });
      input.value = ''; token = '';
      signedIn(await pending);
    } catch (error) {
      input.value = ''; $('#login-error').textContent = error.message; $('#login-error').hidden = false;
    } finally { token = ''; input.disabled = false; submit.disabled = false; submit.textContent = original; if (!state.authenticated) input.focus(); }
  });
  window.addEventListener('beforeunload', event => { if (state.dirty) { event.preventDefault(); event.returnValue = ''; } });
  window.addEventListener('popstate', async () => {
    const route = routeFromLocation();
    if (!state.authenticated) return;
    if (state.dirty && !(await confirmDiscard())) { history.pushState(null, '', '#' + state.route); return; }
    state.dirty = false; loadRoute(route);
  });

  api('/auth/config').then(config => {
    if (!['token', 'oidc'].includes(config.mode)) throw new Error('Sign-in configuration is unavailable. Refresh to try again.');
    state.authMode = config.mode;
    $('#login-form').hidden = config.mode !== 'token';
    $('#oidc-login-form').hidden = config.mode !== 'oidc';
    const brokered = config.mode === 'oidc' && typeof config.signinLabel === 'string' && config.signinLabel.length > 0 && config.signinLabel.length <= 100;
    $('#oidc-login-form button').textContent = brokered ? config.signinLabel : 'Sign in with Entra ID';
    $('#signin-description').textContent = config.mode === 'oidc' ? (brokered ? 'Choose your account on the next screen.' : 'Use your organization account to continue.') : 'Enter your administrator token to continue.';
    $('#signin-note').textContent = config.mode === 'oidc' ? (brokered ? 'Your network administrator controls which accounts can access this console.' : 'Your assigned app role controls what you can do.') : 'Use the token configured by your network administrator.';
    return api('/api/session');
  }).then(signedIn).catch(error => signedOut(error.status === 401 ? '' : error.message));
})();
