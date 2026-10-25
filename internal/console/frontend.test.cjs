// Dependency-free interaction tests for sensitive console behavior. This small
// DOM harness deliberately has no HTML parser or browser storage: rendering
// untrusted HTML or persisting credentials makes these tests fail.
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

class Element {
  constructor(tag, document) {
    this.tagName = tag.toUpperCase(); this.document = document;
    this.childNodes = []; this.parentNode = null; this.attributes = {};
    this.dataset = {}; this.listeners = {}; this.className = ''; this._text = ''; this._value = '';
    this.hidden = false; this.disabled = false; this.checked = false; this.open = false;
    this.classList = { toggle: (name, active) => { const classes = new Set(this.className.split(' ').filter(Boolean)); if (active) classes.add(name); else classes.delete(name); this.className = [...classes].join(' '); }, add: name => { this.className += ' ' + name; } };
  }
  set innerHTML(_) { throw new Error('HTML rendering is forbidden in this harness'); }
  get children() { return this.childNodes; }
  get isConnected() { return this === this.document.root || !!this.parentNode?.isConnected; }
  get textContent() { return this._text + this.childNodes.map(node => node.textContent).join(''); }
  set textContent(value) { this.childNodes.forEach(child => { child.parentNode = null; }); this.childNodes = []; this._text = String(value); }
  get value() { return this._value || (this.tagName === 'SELECT' ? this.childNodes[0]?.value || '' : ''); }
  set value(value) { this._value = String(value); }
  append(...nodes) { for (const node of nodes) { if (node.parentNode) node.parentNode.childNodes = node.parentNode.childNodes.filter(child => child !== node); node.parentNode = this; this.childNodes.push(node); } }
  prepend(node) { this.append(node); this.childNodes = [node, ...this.childNodes.filter(child => child !== node)]; }
  replaceChildren(...nodes) { this.childNodes.forEach(node => { node.parentNode = null; }); this.childNodes = []; this._text = ''; this.append(...nodes); }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  removeAttribute(key) { delete this.attributes[key]; }
  getAttribute(key) { return this.attributes[key]; }
  addEventListener(type, fn, options) { (this.listeners[type] ||= []).push({ fn, once: options?.once }); }
  removeEventListener(type, fn) { this.listeners[type] = (this.listeners[type] || []).filter(listener => listener.fn !== fn); }
  async dispatch(type) {
    for (const listener of [...this.listeners[type] || []]) {
      if (listener.once) this.removeEventListener(type, listener.fn);
      await listener.fn({ type, target: this, preventDefault() {} });
    }
  }
  focus() { this.document.activeElement = this; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  setCustomValidity() {}
  reportValidity() {}
  matches(selector) {
    if (selector.startsWith('#')) return this.id === selector.slice(1);
    if (selector.startsWith('.')) return this.className.split(' ').includes(selector.slice(1));
    return this.tagName === selector.toUpperCase();
  }
  querySelectorAll(selector) {
    const result = [];
    const parts = selector.replaceAll(' > ', ' ').split(' ');
    const final = parts.pop();
    const selectors = final.split(',');
    const visit = node => {
      for (const child of node.childNodes) {
        if (selectors.some(part => child.matches(part))) {
          let ancestor = child.parentNode; let match = true;
          for (const part of [...parts].reverse()) {
            while (ancestor && !ancestor.matches(part)) ancestor = ancestor.parentNode;
            if (!ancestor) { match = false; break; }
            ancestor = ancestor.parentNode;
          }
          if (match) result.push(child);
        }
        visit(child);
      }
    };
    visit(this); return result;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

const flush = async () => { for (let i = 0; i < 15; i++) await new Promise(resolve => setImmediate(resolve)); };

async function harness(route, respond, authMode = 'token') {
  const authConfig = typeof authMode === 'object' ? authMode : { mode: authMode };
  const selection = { node: null, removeAllRanges() { this.node = null; }, addRange(range) { this.node = range.node; } };
  const document = { activeElement: null, title: '', createElement(tag) { return new Element(tag, this); }, createElementNS(_, tag) { return new Element(tag, this); }, querySelector(selector) { return this.root.querySelector(selector); }, createRange() { return { selectNodeContents(node) { this.node = node; } }; } };
  document.root = new Element('body', document);
  const add = (tag, id, parent = document.root, className = '') => { const node = document.createElement(tag); node.id = id; node.className = className; parent.append(node); return node; };
  add('div', 'boot'); add('span', 'session-identity'); add('p', 'signin-description'); add('p', 'signin-note'); const oidcForm = add('form', 'oidc-login-form'); add('button', '', oidcForm).textContent = 'Sign in with Entra ID'; const signin = add('section', 'signin'); const login = add('form', 'login-form', signin); add('input', 'login-token', login); add('p', 'login-error', login); add('button', '', login).textContent = 'Open console';
  const app = add('div', 'app'); const sidebar = add('aside', '', app, 'sidebar'); add('a', '', sidebar, 'brand'); add('nav', 'navigation', sidebar); add('span', 'sidebar-icon', sidebar); add('button', 'logout', sidebar);
  const topbar = add('div', '', app, 'topbar-right'); add('span', 'sync-status', topbar); add('span', 'breadcrumb-title', app); add('div', 'page', app); add('div', 'notification');
  const dialog = add('dialog', 'dialog'); add('div', 'dialog-content', dialog);
  const location = { pathname: '/', hash: '#' + route, assign(url) { this.navigated = url; } };
  const requests = [];
  const context = { document, Node: Element, location, URL, Intl, Date, Error, TypeError, Number, String, Object, Array, Promise, setTimeout: (fn, ms) => { const timer = setTimeout(fn, ms); timer.unref(); return timer; }, clearTimeout, AbortController, navigator: {}, history: { pushState(_, __, hash) { location.hash = hash; }, replaceState(_, __, hash) { location.hash = hash; } }, window: { addEventListener() {}, getSelection() { return selection; } }, fetch: async (path, options) => { requests.push({ path, ...options }); const result = path === '/auth/config' ? { body: authConfig } : await respond(path, options); return { ok: (result.status || 200) < 400, status: result.status || 200, json: async () => { if (result.invalidJSON) throw new SyntaxError('Truncated response'); return Object.hasOwn(result, 'body') ? result.body : {}; } }; } };
  Object.defineProperty(context, 'localStorage', { get() { throw new Error('Persistent credential storage is forbidden'); } });
  Object.defineProperty(context, 'sessionStorage', { get() { throw new Error('Persistent credential storage is forbidden'); } });
  vm.runInNewContext(readFileSync(__dirname + '/assets/app.js', 'utf8'), context, { filename: 'app.js' });
  await flush();
  const findButton = text => document.root.querySelectorAll('button').find(node => node.textContent === text || node.querySelector('span')?.textContent === text);
  return { document, requests, findButton, flush, selection, location };
}

test('OIDC mode offers organization sign-in and hides the administrator token form', async () => {
  const h = await harness('overview', async path => {
    if (path === '/api/session') return { status: 401 };
    if (path === '/auth/oidc/login') return { body: { authorizationUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?state=fixture' } };
    throw new Error('Unexpected request ' + path);
  }, 'oidc');
  assert.equal(h.document.querySelector('#login-form').hidden, true);
  assert.equal(h.document.querySelector('#oidc-login-form').hidden, false);
  assert.ok(h.document.querySelector('#signin-description').textContent.includes('organization account'));
  assert.equal(h.requests.filter(r => r.path === '/api/login').length, 0);
  await h.document.querySelector('#oidc-login-form').dispatch('submit'); await h.flush();
  assert.ok(h.location.navigated.startsWith('https://login.microsoftonline.com/'));
  assert.equal(h.requests.find(r => r.path === '/auth/oidc/login').method, 'POST');
});

test('broker sign-in navigates through the shared provider chooser without token login', async () => {
  const h = await harness('overview', async path => {
    if (path === '/api/session') return { status: 401 };
    if (path === '/auth/oidc/login') return { body: { authorizationUrl: 'https://control.example.test/identity/authorize?client_id=console&state=fixture' } };
    throw new Error('Unexpected request ' + path);
  }, { mode: 'oidc', signinLabel: 'Continue to sign in' });
  assert.equal(h.document.querySelector('#login-form').hidden, true);
  assert.equal(h.document.querySelector('#oidc-login-form button').textContent, 'Continue to sign in');
  assert.ok(h.document.querySelector('#signin-description').textContent.includes('next screen'));
  await h.document.querySelector('#oidc-login-form').dispatch('submit'); await h.flush();
  assert.equal(h.location.navigated, 'https://control.example.test/identity/authorize?client_id=console&state=fixture');
  assert.equal(h.requests.filter(r => r.path === '/api/login').length, 0);
});

test('provider display text is rendered without creating markup', async () => {
  const label = '<img src=x onerror=alert(1)>';
  const h = await harness('overview', async path => {
    if (path === '/api/session') return { status: 401 };
    throw new Error('Unexpected request ' + path);
  }, { mode: 'oidc', signinLabel: label });
  const button = h.document.querySelector('#oidc-login-form button');
  assert.equal(button.textContent, label);
  assert.equal(button.querySelector('img'), null);
});

test('reader permissions disable user changes and show effective role', async () => {
  const h = await harness('users', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'reader-csrf', permissions: { canRead: true, canWrite: false }, user: { name: 'Reader Example' } } };
    if (path === '/api/users') return { body: { users: [{ id: '1', name: 'alice' }] } };
    throw new Error('Unexpected request ' + path);
  }, 'oidc');
  assert.ok(h.document.querySelector('#session-identity').textContent.includes('Reader Example · Read-only'));
  for (const label of ['Add user', 'Create key', 'Remove']) {
    assert.equal(h.findButton(label).disabled, true);
    await h.findButton(label).dispatch('click');
  }
  assert.equal(h.document.querySelector('#dialog').open, false);
  assert.equal(h.requests.filter(r => !['GET', 'HEAD'].includes(r.method)).length, 0);
});

test('reader policy is read-only and cannot create an editable draft', async () => {
  const h = await harness('policy', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'reader-csrf', permissions: { canRead: true, canWrite: false } } };
    if (path === '/api/policy') return { body: { policy: '{"acls":[]}', revision: 'revision-1' } };
    throw new Error('Unexpected request ' + path);
  }, 'oidc');
  const editor = h.document.querySelector('textarea');
  assert.equal(editor.readOnly, true);
  editor.value = 'changed'; await editor.dispatch('input');
  assert.equal(h.findButton('Save policy').disabled, true);
  await h.findButton('Save policy').dispatch('click');
  assert.equal(h.requests.filter(r => r.method === 'PUT').length, 0);
});

test('login clears the token, keeps authentication in cookies, and attaches CSRF to changes', async () => {
  let authenticated = false;
  const h = await harness('users', async (path, options) => {
    if (path === '/api/session') return { status: 401 };
    if (path === '/api/login') { authenticated = true; return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } }; }
    if (path === '/api/users' && options.method === 'POST') return { body: { user: { id: '2' } } };
    if (path === '/api/users') return { body: { users: [] } };
    throw new Error('Unexpected request ' + path);
  });
  const input = h.document.querySelector('#login-token'); input.value = 'admin-secret-fixture';
  await h.document.querySelector('#login-form').dispatch('submit'); await h.flush();
  assert.equal(authenticated, true);
  assert.equal(input.value, '');
  assert.equal(h.document.querySelector('#signin').hidden, true);
  await h.findButton('Add user').dispatch('click');
  h.document.querySelector('#field-name').value = 'alice';
  await h.document.querySelector('#user-form').dispatch('submit'); await h.flush();
  const request = h.requests.find(request => request.path === '/api/users' && request.method === 'POST');
  assert.equal(request.headers['X-CSRF-Token'], 'csrf-fixture');
  assert.equal(request.credentials, 'same-origin');
  assert.equal(request.mode, 'same-origin');
  assert.ok(!h.document.root.textContent.includes('admin-secret-fixture'));
});

test('enrollment secrets disappear on explicit dismissal and never appear in key lists', async () => {
  const user = { id: '1', name: 'alice' };
  const h = await harness('keys', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/users') return { body: { users: [user] } };
    if (path.startsWith('/api/keys?')) return { body: { keys: [{ id: '7', userId: '1', secret: 'must-never-be-listed', expiresAt: '2099-01-01T00:00:00Z' }] } };
    if (path === '/api/keys' && options.method === 'POST') return { body: { key: { id: '8' }, secret: 'one-time-secret-fixture' } };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(!h.document.root.textContent.includes('must-never-be-listed'));
  await h.findButton('Add a device').dispatch('click'); await h.flush();
  await h.document.querySelector('#key-form').dispatch('submit'); await h.flush();
  const dialog = h.document.querySelector('#dialog');
  assert.equal(dialog.open, true);
  assert.ok(dialog.textContent.includes('one-time-secret-fixture'));
  await h.findButton('Copy key').dispatch('click');
  assert.equal(h.selection.node?.textContent, 'one-time-secret-fixture');
  assert.ok(dialog.textContent.includes('Ctrl+C to copy'));
  await dialog.dispatch('cancel');
  assert.equal(dialog.open, true, 'Escape must not silently dismiss the only copy');
  await h.findButton('I have saved the key').dispatch('click');
  assert.equal(dialog.open, false);
  assert.equal(h.document.querySelector('#dialog-content').childNodes.length, 0);
  assert.ok(!h.document.root.textContent.includes('one-time-secret-fixture'));
});

test('a server key comes with join commands that are cleared with the dialog', async () => {
  let created = null;
  const h = await harness('devices', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { body: { devices: [] } };
    if (path === '/api/users') return { body: { users: [] } };
    if (path === '/api/keys' && options.method === 'POST') { created = JSON.parse(options.body); return { body: { key: { id: '9' }, secret: 'server-secret-fixture', controlURL: 'https://control.example.test' } }; }
    throw new Error('Unexpected request ' + path);
  });
  await h.findButton('Add a device').dispatch('click'); await h.flush();
  h.document.querySelector('#field-hostname').value = 'homeserver';
  h.document.querySelector('#field-exitNode').checked = true;
  h.document.querySelector('#field-routes').value = '192.168.1.0/24';
  await h.document.querySelector('#key-form').dispatch('submit'); await h.flush();
  assert.deepEqual(created.tags, ['tag:server']);
  assert.equal(created.allowMembers, true);
  assert.equal(created.userId, undefined, 'a server key belongs to its tag, not a person');
  const dialog = h.document.querySelector('#dialog');
  const commands = dialog.querySelectorAll('.secret-box')[1].textContent;
  for (const part of ['tailscale.com/install.sh', '--login-server=https://control.example.test', '--auth-key=server-secret-fixture', '--hostname=homeserver', '--advertise-exit-node', '--advertise-routes=192.168.1.0/24', 'net.ipv4.ip_forward = 1']) assert.ok(commands.includes(part), part);
  await h.findButton('I have saved the key').dispatch('click');
  assert.equal(dialog.open, false);
  assert.ok(!h.document.root.textContent.includes('server-secret-fixture'));
});

test('a mistyped local network is refused before any key is made', async () => {
  const h = await harness('devices', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { body: { devices: [] } };
    if (path === '/api/users') return { body: { users: [] } };
    throw new Error('Unexpected request ' + path + ' ' + options.method);
  });
  await h.findButton('Add a device').dispatch('click'); await h.flush();
  h.document.querySelector('#field-routes').value = '192.168.1.0';
  await h.document.querySelector('#key-form').dispatch('submit'); await h.flush();
  assert.ok(h.document.querySelector('#dialog').textContent.includes('Write local networks like 192.168.1.0/24.'));
  assert.ok(!h.requests.some(request => request.path === '/api/keys'));
});

test('a device offering an exit node and a local network can be approved', async () => {
  let approval = null;
  const device = { id: '4', name: 'homeserver', tags: ['tag:server'], ips: ['100.64.0.5'], availableRoutes: ['0.0.0.0/0', '::/0', '192.168.1.0/24'], approvedRoutes: [] };
  const h = await harness('devices', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { body: { devices: [device] } };
    if (path === '/api/devices/4/routes') { approval = JSON.parse(options.body); return { body: { device } }; }
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes('Exit node: approve'));
  assert.ok(h.document.root.textContent.includes('Local networks: approve'));
  assert.ok(h.document.root.textContent.includes('tag:server'), 'a tagged device shows its tag as the owner');
  await h.findButton('Manage').dispatch('click'); await h.flush();
  h.document.querySelector('#field-route-0').checked = true;
  h.document.querySelector('#field-route-1').checked = true;
  await h.findButton('Save approvals').dispatch('click'); await h.flush();
  assert.deepEqual(approval, { routes: ['0.0.0.0/0', '::/0', '192.168.1.0/24'], allowMembers: true });
});

test('policy conflict keeps the draft and blocks another stale save', async () => {
  const h = await harness('policy', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/policy' && options.method === 'PUT') return { status: 409, body: { code: 'revision_conflict', error: 'Policy changed' } };
    if (path === '/api/policy') return { body: { policy: '{"acls":[]}', revision: 'revision-1' } };
    throw new Error('Unexpected request ' + path);
  });
  const editor = h.document.querySelector('textarea'); editor.value = '// My draft\n{"acls":[]}'; await editor.dispatch('input');
  const save = h.findButton('Save policy'); assert.equal(save.disabled, false);
  await save.dispatch('click'); await h.flush();
  assert.equal(editor.value, '// My draft\n{"acls":[]}');
  assert.equal(save.disabled, true);
  editor.value += '\n'; await editor.dispatch('input');
  assert.equal(save.disabled, true, 'editing after a conflict must not re-enable a stale revision');
  assert.ok(h.document.root.textContent.includes('Your draft is still here'));
});

test('API-controlled device labels render as inert text', async () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const h = await harness('devices', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { body: { devices: [{ id: '1', name: hostile, ips: [], userName: 'alice' }] } };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes(hostile));
  assert.equal(h.document.root.querySelectorAll('img').length, 0);
});

test('an unavailable upstream is not presented as an empty network', async () => {
  const h = await harness('devices', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { status: 502, body: { error: 'Network service unavailable' } };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes('Unable to load this information'));
  assert.ok(h.document.root.textContent.includes('Network service unavailable'));
  assert.ok(!h.document.root.textContent.includes('No devices yet'));
});

test('logout removes secret material and authenticated page data', async () => {
  const h = await harness('keys', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/users') return { body: { users: [{ id: '1', name: 'alice' }] } };
    if (path.startsWith('/api/keys?')) return { body: { keys: [] } };
    if (path === '/api/keys' && options.method === 'POST') return { body: { key: { id: '8' }, secret: 'logout-secret-fixture' } };
    if (path === '/api/logout') return { body: {} };
    throw new Error('Unexpected request ' + path);
  });
  await h.findButton('Add a device').dispatch('click'); await h.flush();
  await h.document.querySelector('#key-form').dispatch('submit'); await h.flush();
  assert.ok(h.document.root.textContent.includes('logout-secret-fixture'));
  await h.document.querySelector('#logout').dispatch('click'); await h.flush();
  assert.equal(h.document.querySelector('#signin').hidden, false);
  assert.equal(h.document.querySelector('#page').childNodes.length, 0);
  assert.equal(h.document.querySelector('#dialog-content').childNodes.length, 0);
  assert.ok(!h.document.root.textContent.includes('logout-secret-fixture'));
});

test('a malformed successful inventory response is not displayed as an empty network', async () => {
  const h = await harness('devices', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') return { invalidJSON: true };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes('Unable to load this information'));
  assert.ok(h.document.root.textContent.includes('invalid response'));
  assert.ok(!h.document.root.textContent.includes('No devices yet'));
});

for (const failure of ['invalid JSON', 'network interruption', 'timeout']) {
  test('a mutation with ' + failure + ' reports an uncertain outcome without retrying', async () => {
    const h = await harness('users', async (path, options) => {
      if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
      if (path === '/api/users' && options.method === 'POST') {
        if (failure === 'invalid JSON') return { status: 201, invalidJSON: true };
        if (failure === 'network interruption') throw new TypeError('Network unavailable');
        const error = new Error('Aborted'); error.name = 'AbortError'; throw error;
      }
      if (path === '/api/users') return { body: { users: [] } };
      throw new Error('Unexpected request ' + path);
    });
    await h.findButton('Add user').dispatch('click');
    h.document.querySelector('#field-name').value = 'alice';
    await h.document.querySelector('#user-form').dispatch('submit'); await h.flush();
    assert.equal(h.document.querySelector('#dialog').open, true);
    assert.ok(h.document.querySelector('.form-error').textContent.includes('The operation may have completed. Inspect current state before retrying.'));
    assert.ok(!h.document.querySelector('#notification').textContent.includes('User added.'));
    assert.equal(h.requests.filter(request => request.path === '/api/users' && request.method === 'POST').length, 1);
  });
}

test('a delayed 401 from a previous session cannot sign out a new session', async () => {
  let finishOldRequest;
  let deviceRequests = 0;
  const h = await harness('devices', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-session-a', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/logout') return { body: {} };
    if (path === '/api/login') return { body: { authenticated: true, csrfToken: 'csrf-session-b', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/devices') {
      if (++deviceRequests === 1) return new Promise(resolve => { finishOldRequest = resolve; });
      return { body: { devices: [{ id: '2', name: 'Session B device', ips: [] }] } };
    }
    throw new Error('Unexpected request ' + path + ' ' + options.method);
  });
  await h.document.querySelector('#logout').dispatch('click');
  h.document.querySelector('#login-token').value = 'session-b-token';
  await h.document.querySelector('#login-form').dispatch('submit'); await h.flush();
  assert.ok(h.document.querySelector('#page').textContent.includes('Session B device'));
  finishOldRequest({ status: 401, body: { error: 'Expired old session' } }); await h.flush();
  assert.equal(h.document.querySelector('#signin').hidden, true);
  assert.equal(h.document.querySelector('#app').hidden, false);
  assert.ok(h.document.querySelector('#page').textContent.includes('Session B device'));
});

test('the gateway page explains how to turn the gateway on', async () => {
  const h = await harness('gateway', async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/gateway') return { body: { enabled: false } };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes('This network has no gateway'));
  assert.ok(h.document.root.textContent.includes('covee gateway'));
});

test('destinations through the gateway are listed, added and limited to people', async () => {
  const saved = [];
  const gateway = {
    enabled: true, revision: 'rev-1',
    settings: { entries: [{ id: 'azure', label: 'Azure private networks', destinations: ['10.20.0.0/16', 'kv.vault.azure.net'], users: [] }],
      dns: [{ domain: 'vault.azure.net', resolvers: ['168.63.129.16'] }] },
    status: { device: { id: '12', name: 'gateway', online: true }, problem: '',
      routes: [{ route: '10.20.0.0/16', entries: ['azure'], offered: true, approved: true }, { route: '10.60.7.4/32', entries: ['azure'], offered: true, approved: false }],
      hosts: [{ name: 'kv.vault.azure.net', addresses: ['10.60.7.4'] }], dns: { applied: true } },
  };
  const h = await harness('gateway', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/gateway' && options.method === 'PUT') { saved.push(JSON.parse(options.body)); return { body: gateway }; }
    if (path === '/api/gateway') return { body: gateway };
    if (path === '/api/users') return { body: { users: [{ id: '1', name: 'alice@example.com' }, { id: '2', name: 'bob@example.com', displayName: 'Bob' }] } };
    throw new Error('Unexpected request ' + path + ' ' + options.method);
  });
  const text = h.document.root.textContent;
  assert.ok(text.includes('Azure private networks'));
  assert.ok(text.includes('kv.vault.azure.net → 10.60.7.4'), 'a host name shows its addresses');
  assert.ok(text.includes('1 of 2 active'));
  assert.ok(text.includes('Everyone in the network'));
  assert.ok(text.includes('vault.azure.net'));

  await h.findButton('Add destination').dispatch('click'); await h.flush();
  h.document.querySelector('#field-label').value = 'MongoDB Atlas';
  h.document.querySelector('#field-destinations').value = 'cluster0-shard-00-00.abc.mongodb.net\n203.0.113.7';
  const everyone = h.document.querySelector('#field-everyone');
  everyone.checked = false; await everyone.dispatch('change');
  h.document.querySelector('#field-person-1').checked = true;
  await h.document.querySelector('#gateway-form').dispatch('submit'); await h.flush();
  assert.equal(saved.length, 1);
  assert.equal(saved[0].revision, 'rev-1');
  assert.deepEqual(saved[0].dns, gateway.settings.dns);
  assert.deepEqual(saved[0].entries[1], { id: '', label: 'MongoDB Atlas', destinations: ['cluster0-shard-00-00.abc.mongodb.net', '203.0.113.7'], users: ['bob@example.com'] });
  assert.deepEqual(saved[0].entries[0], gateway.settings.entries[0], 'other entries are sent unchanged');
});

test('a stale gateway save says to refresh', async () => {
  const gateway = { enabled: true, revision: 'old', settings: { entries: [], dns: [] }, status: { device: null, routes: [], hosts: [], dns: { applied: true } } };
  const h = await harness('gateway', async (path, options) => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/gateway' && options.method === 'PUT') return { status: 409, body: { code: 'revision_conflict', error: 'changed' } };
    if (path === '/api/gateway') return { body: gateway };
    throw new Error('Unexpected request ' + path);
  });
  assert.ok(h.document.root.textContent.includes('has not joined the network yet'));
  await h.findButton('Add domain').dispatch('click'); await h.flush();
  h.document.querySelector('#field-domain').value = 'vault.azure.net';
  await h.document.querySelector('#gateway-dns-form').dispatch('submit'); await h.flush();
  assert.ok(h.document.querySelector('#dialog').textContent.includes('changed since this page loaded'));
});

test('people read as their names and emails, not their account IDs', async () => {
  const users = [{ id: '1', name: 'u0a1b', displayName: 'Pat Example', email: 'pat@example.com' }, { id: '2', name: 'u2c3d', displayName: 'Covee user' }];
  const gateway = { enabled: true, revision: 'rev-1', settings: { entries: [{ id: 'kv', label: 'Key Vault', destinations: ['10.60.7.4'], users: ['u0a1b'] }], dns: [] },
    status: { device: { id: '12', name: 'gateway', online: true }, problem: '', routes: [{ route: '10.60.7.4/32', entries: ['kv'], offered: true, approved: true }], hosts: [], dns: { applied: true } } };
  const respond = async path => {
    if (path === '/api/session') return { body: { authenticated: true, csrfToken: 'csrf-fixture', permissions: { canRead: true, canWrite: true } } };
    if (path === '/api/gateway') return { body: gateway };
    if (path === '/api/users') return { body: { users } };
    throw new Error('Unexpected request ' + path);
  };
  const page = await harness('gateway', respond);
  const row = page.document.root.querySelectorAll('tr').find(node => node.textContent.includes('Key Vault'));
  assert.ok(row.textContent.includes('Pat Example') && !row.textContent.includes('u0a1b'), 'the gateway names who may use an entry');
  await page.findButton('Edit').dispatch('click'); await page.flush();
  const people = page.document.querySelector('#gateway-people').textContent;
  assert.ok(people.includes('Pat Example · pat@example.com') && people.includes('Covee user · u2c3d'), people);

  const list = await harness('users', respond);
  const pat = list.document.root.querySelectorAll('tr').find(node => node.textContent.includes('Pat Example'));
  assert.ok(pat.textContent.includes('pat@example.com') && !pat.textContent.includes('u0a1b'), 'a person with an email needs no ID');
});
