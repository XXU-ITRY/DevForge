/**
 * ============================================================
 *   DevForge — Single-file Cloudflare Worker
 *   Build Together. Code Better.
 * ============================================================
 *   Everything in one file: HTML, CSS, client JS, API,
 *   authentication, database schema, and Git integration.
 *
 *   Deploy:  wrangler deploy
 *   Local:   wrangler dev
 *
 *   The `[[d1_databases]]` binding in wrangler.toml is declared
 *   without `database_id`, so Cloudflare auto-provisions D1 on
 *   first deploy. Tables are created on first request via
 *   `initDB()` — no migrations CLI, no manual SQL.
 * ============================================================
 */

// ============================================================
//  Utilities
// ============================================================
const enc = new TextEncoder();
const dec = new TextDecoder();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });

const err = (msg, status = 400) => json({ error: msg }, status);
const uid = () => crypto.randomUUID();

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

const b64uDec = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};

// ============================================================
//  Crypto (JWT + PBKDF2, no external deps)
// ============================================================
const DEFAULT_SECRET = 'devforge-replace-this-with-a-long-random-string';
const secretOf = (env) => env.JWT_SECRET || DEFAULT_SECRET;

async function signJWT(payload, secret) {
  const h = b64u(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const b = b64u(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(h + '.' + b));
  return h + '.' + b + '.' + b64u(sig);
}

async function verifyJWT(token, secret) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const ok = await crypto.subtle.verify('HMAC', key, b64uDec(s), enc.encode(h + '.' + b));
    if (!ok) return null;
    return JSON.parse(dec.decode(b64uDec(b)));
  } catch {
    return null;
  }
}

async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  return b64u(salt) + '.' + b64u(bits);
}

async function verifyPassword(pw, stored) {
  try {
    const [sb, hb] = stored.split('.');
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: b64uDec(sb), iterations: 100000, hash: 'SHA-256' }, key, 256
    );
    return b64u(bits) === hb;
  } catch {
    return false;
  }
}

// ============================================================
//  Database schema init (idempotent, cached per isolate)
// ============================================================
let _dbInit = null;

async function initDB(db) {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      lang TEXT DEFAULT 'en',
      theme TEXT DEFAULT 'dark',
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      joined_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (team_id, user_id)
    )`,
    `CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      repo_url TEXT,
      provider TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      channel_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL,
      file_key TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      message TEXT,
      read INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch())
    )`,
    `CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at)`,
  ];
  for (const s of stmts) {
    try { await db.prepare(s).run(); }
    catch (e) { console.error('[initDB]', e.message); }
  }
}

function ensureDB(db) {
  if (!_dbInit) {
    _dbInit = initDB(db).catch((e) => { _dbInit = null; throw e; });
  }
  return _dbInit;
}

// ============================================================
//  Frontend: Internationalization
// ============================================================
const I18N = {
  en: {
    tagline: 'Build Together. Code Better.',
    login: 'Sign in',
    register: 'Create account',
    email: 'Email address',
    username: 'Username',
    password: 'Password',
    haveAccount: 'Already have an account?',
    noAccount: "Don't have an account?",
    dashboard: 'Dashboard',
    teams: 'Teams',
    settings: 'Settings',
    logout: 'Sign out',
    newTeam: 'New Team',
    teamsEmpty: 'No teams yet. Create your first team to get started.',
    channels: 'Channels',
    projects: 'Projects',
    members: 'Members',
    newChannel: 'New Channel',
    newProject: 'New Project',
    chatPlaceholder: 'Type a message...',
    chatEmpty: 'No messages yet. Say hello!',
    attach: 'Attach file',
    language: 'Language',
    theme: 'Theme',
    dark: 'Dark',
    light: 'Light',
    profile: 'Profile',
    cancel: 'Cancel',
    create: 'Create',
    save: 'Save',
    loading: 'Loading...',
    error: 'Something went wrong',
    gitTitle: 'Repository',
    commits: 'Recent Commits',
    repoUrl: 'Repository (owner/repo)',
    notifications: 'Notifications',
    noNotifications: 'No notifications',
    teamName: 'Team name',
    channelName: 'Channel name',
    projectName: 'Project name',
    welcome: 'Welcome',
    openTeam: 'Open team',
    noRepo: 'No repository linked to this project',
    filesNotReady: 'File storage not configured. Add R2 binding in wrangler.toml',
    pwdTooShort: 'Password must be at least 6 characters',
    userExists: 'That user already exists',
    invalidCreds: 'Invalid email or password',
    signInRequired: 'Please sign in to continue'
  },
  fa: {
    tagline: 'با هم بسازید. بهتر کد بزنید.',
    login: 'ورود',
    register: 'ایجاد حساب',
    email: 'ایمیل',
    username: 'نام کاربری',
    password: 'رمز عبور',
    haveAccount: 'حساب دارید؟',
    noAccount: 'حساب ندارید؟',
    dashboard: 'داشبورد',
    teams: 'تیم‌ها',
    settings: 'تنظیمات',
    logout: 'خروج',
    newTeam: 'تیم جدید',
    teamsEmpty: 'هنوز تیمی ندارید. اولین تیم خود را بسازید.',
    channels: 'کانال‌ها',
    projects: 'پروژه‌ها',
    members: 'اعضا',
    newChannel: 'کانال جدید',
    newProject: 'پروژه جدید',
    chatPlaceholder: 'پیامی بنویسید...',
    chatEmpty: 'هنوز پیامی نیست. سلام کنید!',
    attach: 'پیوست فایل',
    language: 'زبان',
    theme: 'تم',
    dark: 'تیره',
    light: 'روشن',
    profile: 'پروفایل',
    cancel: 'لغو',
    create: 'ایجاد',
    save: 'ذخیره',
    loading: 'در حال بارگذاری...',
    error: 'خطایی رخ داد',
    gitTitle: 'مخزن',
    commits: 'کامیت‌های اخیر',
    repoUrl: 'مسیر مخزن (owner/repo)',
    notifications: 'اعلان‌ها',
    noNotifications: 'اعلانی نیست',
    teamName: 'نام تیم',
    channelName: 'نام کانال',
    projectName: 'نام پروژه',
    welcome: 'خوش آمدید',
    openTeam: 'باز کردن تیم',
    noRepo: 'هیچ مخزنی به این پروژه متصل نیست',
    filesNotReady: 'ذخیره‌سازی فایل پیکربندی نشده. binding R2 را در wrangler.toml اضافه کنید',
    pwdTooShort: 'رمز عبور باید حداقل ۶ کاراکتر باشد',
    userExists: 'این کاربر قبلاً ثبت شده',
    invalidCreds: 'ایمیل یا رمز عبور نامعتبر است',
    signInRequired: 'برای ادامه وارد شوید'
  }
};

// ============================================================
//  Frontend: SVG icons
// ============================================================
const ICONS = {
  home: '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  hash: '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  bell: '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
  git: '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M6 9v6"/><circle cx="18" cy="6" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>',
  sun: '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  paperclip: '<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
  file: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>',
  code: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>'
};

// ============================================================
//  Frontend: CSS
// ============================================================
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bgh:#30363d;
  --bd:#30363d;--tx:#e6edf3;--tx2:#8b949e;--tx3:#6e7681;
  --ac:#58a6ff;--ac2:#1f6feb;--ok:#3fb950;--er:#f85149;
  --r:10px;--rs:6px;--sh:0 8px 24px rgba(0,0,0,.4);
  --grad:linear-gradient(135deg,#58a6ff,#a371f7)
}
[data-theme="light"]{
  --bg:#fff;--bg2:#f6f8fa;--bg3:#eaeef2;--bgh:#d0d7de;
  --bd:#d0d7de;--tx:#1f2328;--tx2:#656d76;--tx3:#8c959f;
  --ac:#0969da;--ac2:#0550ae;--ok:#1a7f37;--er:#cf222e;
  --sh:0 8px 24px rgba(0,0,0,.15)
}
html,body{height:100%}
body{
  font-family:'Vazirmatn',-apple-system,BlinkMacSystemFont,'Segoe UI',Tahoma,sans-serif;
  background:var(--bg);color:var(--tx);font-size:14px;line-height:1.6;
  -webkit-font-smoothing:antialiased;transition:background .2s,color .2s
}
button,input,textarea,select{font-family:inherit;font-size:inherit;color:inherit}
button{border:none;background:none;cursor:pointer}
a{color:var(--ac);text-decoration:none}
a:hover{text-decoration:underline}

/* Layout */
#root{display:flex;height:100vh;overflow:hidden}
.sidebar{
  width:260px;background:var(--bg2);border-right:1px solid var(--bd);
  display:flex;flex-direction:column;flex-shrink:0
}
[dir="rtl"] .sidebar{border-right:none;border-left:1px solid var(--bd)}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}

/* Sidebar */
.sidebar-header{
  padding:16px 18px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:10px;color:var(--ac)
}
.brand{
  font-weight:700;font-size:17px;
  background:var(--grad);-webkit-background-clip:text;
  -webkit-text-fill-color:transparent;background-clip:text
}
.sidebar-content{flex:1;overflow-y:auto;padding:10px}
.sidebar-label{
  font-size:11px;font-weight:600;text-transform:uppercase;
  color:var(--tx3);padding:0 10px;margin:14px 0 6px;letter-spacing:.5px
}
.nav-item{
  display:flex;align-items:center;gap:10px;padding:8px 10px;
  border-radius:var(--rs);color:var(--tx2);cursor:pointer;
  transition:background .15s,color .15s;user-select:none;margin-bottom:2px;
  font-size:13.5px
}
.nav-item:hover{background:var(--bg3);color:var(--tx)}
.nav-item.active{background:var(--bg3);color:var(--tx);font-weight:500}
.nav-item svg{flex-shrink:0;opacity:.85}
.sidebar-footer{
  padding:12px;border-top:1px solid var(--bd);
  display:flex;align-items:center;gap:10px
}
.avatar{
  width:32px;height:32px;border-radius:50%;background:var(--grad);
  display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:600;font-size:13px;flex-shrink:0
}

/* Main */
.main-header{
  padding:16px 24px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;justify-content:space-between;
  background:var(--bg);gap:12px;flex-wrap:wrap
}
.main-title{font-size:17px;font-weight:600;display:flex;align-items:center;gap:10px}
.main-title svg{color:var(--tx2)}
.main-content{flex:1;overflow-y:auto;padding:24px}

/* Buttons */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:8px 14px;border-radius:var(--rs);font-weight:500;
  transition:background .15s,opacity .15s,transform .1s;
  white-space:nowrap;font-size:13.5px
}
.btn:active{transform:scale(.98)}
.btn-primary{background:var(--ac);color:#fff}
.btn-primary:hover{background:var(--ac2)}
.btn-secondary{background:var(--bg3);color:var(--tx);border:1px solid var(--bd)}
.btn-secondary:hover{background:var(--bgh)}
.btn-ghost{color:var(--tx2)}
.btn-ghost:hover{background:var(--bg3);color:var(--tx)}
.btn-icon{padding:6px;border-radius:var(--rs);color:var(--tx2);display:inline-flex}
.btn-icon:hover{background:var(--bg3);color:var(--tx)}
.btn-block{width:100%;padding:10px;font-size:14px}

/* Auth */
.auth-container{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:20px;
  background:radial-gradient(circle at 50% 0%,rgba(88,166,255,.15),transparent 60%),var(--bg)
}
.auth-card{
  width:100%;max-width:400px;background:var(--bg2);
  border:1px solid var(--bd);border-radius:var(--r);padding:32px;
  box-shadow:var(--sh);animation:su .3s ease-out
}
@keyframes su{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.auth-logo{text-align:center;margin-bottom:24px}
.auth-logo .brand{font-size:26px;display:block;margin-bottom:6px}
.auth-logo p{color:var(--tx2);font-size:13px}
.auth-tabs{
  display:flex;gap:4px;margin-bottom:22px;background:var(--bg3);
  padding:4px;border-radius:var(--rs)
}
.auth-tab{
  flex:1;padding:8px;text-align:center;border-radius:4px;
  color:var(--tx2);font-weight:500;transition:all .15s;font-size:13px
}
.auth-tab.active{background:var(--bg2);color:var(--tx)}
.auth-switch{text-align:center;margin-top:16px;color:var(--tx2);font-size:13px}
.auth-switch a{cursor:pointer}

/* Forms */
.form-group{margin-bottom:14px}
.form-group label{
  display:block;margin-bottom:6px;font-size:12.5px;
  color:var(--tx2);font-weight:500
}
.form-control{
  width:100%;padding:9px 12px;background:var(--bg);
  border:1px solid var(--bd);border-radius:var(--rs);color:var(--tx);
  transition:border-color .15s,box-shadow .15s
}
.form-control:focus{
  outline:none;border-color:var(--ac);
  box-shadow:0 0 0 3px rgba(88,166,255,.15)
}

/* Cards & Grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px}
.card{
  background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);
  padding:18px;transition:border-color .15s,transform .1s;cursor:pointer
}
.card:hover{border-color:var(--bgh)}
.card:active{transform:scale(.99)}
.card-title{
  font-size:15px;font-weight:600;margin-bottom:6px;
  display:flex;align-items:center;gap:8px
}
.card-title svg{color:var(--ac)}
.card-desc{
  color:var(--tx2);font-size:12.5px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap
}

/* Empty state */
.empty{text-align:center;padding:60px 20px;color:var(--tx2)}
.empty-icon{opacity:.3;margin-bottom:16px;display:flex;justify-content:center}
.empty h3{color:var(--tx);font-size:16px;margin-bottom:6px}
.empty p{font-size:13.5px;margin-bottom:16px}

/* Chat */
.chat-container{display:flex;flex-direction:column;height:100%}
.chat-messages{
  flex:1;overflow-y:auto;padding:20px 24px;
  display:flex;flex-direction:column;gap:14px
}
.message{display:flex;gap:10px;animation:fi .2s ease-out}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.message-content{flex:1;min-width:0}
.message-header{display:flex;align-items:baseline;gap:8px;margin-bottom:2px}
.message-author{font-weight:600;font-size:13.5px}
.message-time{font-size:11px;color:var(--tx3)}
.message-text{word-wrap:break-word;overflow-wrap:break-word;font-size:14px}
.message-file{
  display:inline-flex;align-items:center;gap:6px;padding:6px 10px;
  background:var(--bg3);border-radius:var(--rs);color:var(--ac);
  font-size:13px;margin-top:6px
}
.chat-input{
  padding:16px 24px;border-top:1px solid var(--bd);
  display:flex;gap:8px;align-items:flex-end
}
.chat-input textarea{
  flex:1;padding:10px 14px;background:var(--bg2);
  border:1px solid var(--bd);border-radius:var(--r);
  color:var(--tx);resize:none;max-height:120px;
  font-family:inherit;transition:border-color .15s;line-height:1.5
}
.chat-input textarea:focus{outline:none;border-color:var(--ac)}

/* Modal */
.modal-backdrop{
  position:fixed;inset:0;background:rgba(0,0,0,.6);
  display:flex;align-items:center;justify-content:center;
  z-index:1000;padding:20px;animation:fi .15s ease-out
}
.modal{
  background:var(--bg2);border:1px solid var(--bd);border-radius:var(--r);
  padding:24px;width:100%;max-width:440px;box-shadow:var(--sh);
  animation:su .2s ease-out
}
.modal-title{font-size:16px;font-weight:600;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}

/* Toast */
.toast-container{
  position:fixed;bottom:24px;inset-inline-end:24px;
  display:flex;flex-direction:column;gap:8px;z-index:2000;
  max-width:360px
}
.toast{
  padding:11px 16px;background:var(--bg2);border:1px solid var(--bd);
  border-radius:var(--rs);box-shadow:var(--sh);
  animation:su .2s ease-out;font-size:13px
}
.toast.error{border-color:var(--er);color:var(--er)}
.toast.success{border-color:var(--ok);color:var(--ok)}

/* Settings */
.settings-section{margin-bottom:28px}
.settings-section h3{
  font-size:12px;font-weight:600;margin-bottom:12px;
  color:var(--tx2);text-transform:uppercase;letter-spacing:.5px
}
.setting-row{
  display:flex;justify-content:space-between;align-items:center;
  padding:14px 16px;background:var(--bg2);border:1px solid var(--bd);
  border-radius:var(--rs);margin-bottom:8px;gap:16px;flex-wrap:wrap
}
.setting-info h4{font-weight:500;margin-bottom:2px;font-size:14px}
.setting-info p{font-size:12.5px;color:var(--tx2)}
.segmented{
  display:inline-flex;background:var(--bg3);border-radius:var(--rs);
  padding:3px;flex-shrink:0;gap:2px
}
.segmented button{
  padding:6px 12px;border-radius:4px;color:var(--tx2);
  transition:all .15s;font-size:12.5px;display:inline-flex;
  align-items:center;gap:5px
}
.segmented button.active{background:var(--bg2);color:var(--tx)}

/* List */
.list{display:flex;flex-direction:column;gap:4px}
.list-item{
  display:flex;align-items:center;gap:12px;padding:10px 12px;
  border-radius:var(--rs);cursor:pointer;transition:background .15s
}
.list-item:hover{background:var(--bg2)}
.list-item-icon{
  width:34px;height:34px;border-radius:var(--rs);background:var(--bg3);
  display:flex;align-items:center;justify-content:center;
  color:var(--tx2);flex-shrink:0
}

/* Spinner */
.spinner{
  display:inline-block;width:16px;height:16px;
  border:2px solid var(--tx3);border-top-color:var(--ac);
  border-radius:50%;animation:sp .6s linear infinite
}
@keyframes sp{to{transform:rotate(360deg)}}

/* Commits */
.commit{
  padding:10px 12px;border-radius:var(--rs);background:var(--bg2);
  border:1px solid var(--bd);margin-bottom:6px;font-size:13px
}
.commit-sha{
  font-family:ui-monospace,'SF Mono',Menlo,monospace;
  color:var(--ac);font-size:12px;margin-inline-end:8px
}
.commit-msg{color:var(--tx);word-break:break-word}
.commit-meta{color:var(--tx3);font-size:11px;margin-top:2px}

/* Responsive */
@media (max-width:768px){
  .sidebar{width:220px}
  .main-content{padding:16px}
  .main-header{padding:12px 16px}
  .chat-messages{padding:14px}
  .chat-input{padding:12px}
}
`;

// ============================================================
//  Frontend: Client JS (all views, router, state)
//  NOTE: No backticks or ${} in this string.
// ============================================================
const CLIENT_JS = String.raw`
(function () {
  'use strict';

  var I18N = window.__I18N__;
  var ICONS = window.__ICONS__;

  var state = {
    user: null,
    teams: [],
    currentTeam: null,
    currentChannel: null,
    lang: 'en',
    theme: 'dark',
    pollTimer: null
  };

  function t(key) {
    var dict = I18N[state.lang] || I18N.en;
    return dict[key] || I18N.en[key] || key;
  }

  function icon(name, size) {
    var s = size || 18;
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + s +
      '" height="' + s + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      (ICONS[name] || '') + '</svg>';
  }

  function esc(str) {
    var d = document.createElement('div');
    d.textContent = str == null ? '' : String(str);
    return d.innerHTML;
  }

  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return d.toLocaleTimeString(state.lang === 'fa' ? 'fa-IR' : 'en-US', {
      hour: '2-digit', minute: '2-digit'
    });
  }

  function getToken() { return localStorage.getItem('df_token'); }
  function setToken(v) {
    if (v) localStorage.setItem('df_token', v);
    else localStorage.removeItem('df_token');
  }

  function api(path, opts) {
    var o = opts || {};
    var headers = { 'Content-Type': 'application/json' };
    var tok = getToken();
    if (tok) headers.Authorization = 'Bearer ' + tok;
    var opts2 = {
      method: o.method || 'GET',
      headers: headers
    };
    if (o.body) opts2.body = o.body;
    return fetch('/api' + path, opts2).then(function (res) {
      if (res.status === 401 && path.indexOf('/auth/') !== 0) {
        setToken(null);
        location.href = '/login';
        return Promise.reject(new Error('Unauthorized'));
      }
      return res.json().then(function (data) {
        if (!res.ok) throw new Error(data.error || 'Request failed');
        return data;
      });
    });
  }

  // ---------- Theme & Direction ----------
  function applyTheme() {
    document.documentElement.setAttribute('data-theme', state.theme);
  }
  function applyDir() {
    document.documentElement.setAttribute('dir', state.lang === 'fa' ? 'rtl' : 'ltr');
    document.documentElement.setAttribute('lang', state.lang);
  }

  // ---------- Toast ----------
  function toast(msg, type) {
    var box = document.querySelector('.toast-container');
    if (!box) {
      box = document.createElement('div');
      box.className = 'toast-container';
      document.body.appendChild(box);
    }
    var el = document.createElement('div');
    el.className = 'toast' + (type ? ' ' + type : '');
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 3500);
  }

  // ---------- Navigation ----------
  function navigate(path) {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    history.pushState({}, '', path);
    render();
  }

  // ---------- Modal ----------
  function showModal(opts) {
    var back = document.createElement('div');
    back.className = 'modal-backdrop';
    var fieldsHtml = '';
    for (var i = 0; i < opts.fields.length; i++) {
      var f = opts.fields[i];
      fieldsHtml += '<div class="form-group">' +
        '<label>' + esc(f.label) + '</label>' +
        '<input class="form-control" name="' + esc(f.name) + '"' +
        (f.required ? ' required' : '') +
        (f.type ? ' type="' + esc(f.type) + '"' : '') +
        (f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '') +
        '>' +
        '</div>';
    }
    back.innerHTML =
      '<div class="modal">' +
        '<div class="modal-title">' + esc(opts.title) + '</div>' +
        '<form id="dfModalForm">' +
          fieldsHtml +
          '<div class="modal-actions">' +
            '<button type="button" class="btn btn-secondary" data-cancel>' + esc(t('cancel')) + '</button>' +
            '<button type="submit" class="btn btn-primary">' + esc(opts.submit || t('create')) + '</button>' +
          '</div>' +
        '</form>' +
      '</div>';
    document.body.appendChild(back);

    function close() { if (back.parentNode) back.parentNode.removeChild(back); }
    back.querySelector('[data-cancel]').onclick = close;
    back.onclick = function (e) { if (e.target === back) close(); };
    document.addEventListener('keydown', function escKey(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escKey); }
    });
    back.querySelector('#dfModalForm').onsubmit = function (e) {
      e.preventDefault();
      var data = {};
      var inputs = e.target.querySelectorAll('input');
      for (var i = 0; i < inputs.length; i++) data[inputs[i].name] = inputs[i].value;
      Promise.resolve(opts.onSubmit(data)).then(close).catch(function (ex) {
        toast(ex.message, 'error');
      });
    };
    var firstInput = back.querySelector('input');
    if (firstInput) firstInput.focus();
  }

  // ============================================================
  //  Views
  // ============================================================

  // ---------- Auth ----------
  function renderAuth() {
    var root = document.getElementById('root');
    var mode = location.pathname === '/register' ? 'register' : 'login';
    var initial = function (u) { return (u || 'U')[0].toUpperCase(); };

    root.innerHTML =
      '<div class="auth-container">' +
        '<div class="auth-card">' +
          '<div class="auth-logo">' +
            '<span class="brand">DevForge</span>' +
            '<p>' + esc(t('tagline')) + '</p>' +
          '</div>' +
          '<div class="auth-tabs">' +
            '<div class="auth-tab' + (mode === 'login' ? ' active' : '') + '" data-mode="login">' + esc(t('login')) + '</div>' +
            '<div class="auth-tab' + (mode === 'register' ? ' active' : '') + '" data-mode="register">' + esc(t('register')) + '</div>' +
          '</div>' +
          '<form id="dfAuthForm">' +
            (mode === 'register'
              ? '<div class="form-group"><label>' + esc(t('username')) + '</label>' +
                '<input class="form-control" name="username" required minlength="3" autocomplete="username"></div>'
              : '') +
            '<div class="form-group"><label>' + esc(t('email')) + '</label>' +
              '<input class="form-control" type="email" name="email" required autocomplete="email"></div>' +
            '<div class="form-group"><label>' + esc(t('password')) + '</label>' +
              '<input class="form-control" type="password" name="password" required minlength="6" autocomplete="current-password"></div>' +
            '<button type="submit" class="btn btn-primary btn-block">' + esc(t(mode)) + '</button>' +
          '</form>' +
          '<div class="auth-switch">' +
            (mode === 'login'
              ? '<span>' + esc(t('noAccount')) + '</span> <a data-mode="register">' + esc(t('register')) + '</a>'
              : '<span>' + esc(t('haveAccount')) + '</span> <a data-mode="login">' + esc(t('login')) + '</a>') +
          '</div>' +
        '</div>' +
      '</div>';

    var modeBtns = root.querySelectorAll('[data-mode]');
    for (var i = 0; i < modeBtns.length; i++) {
      (function (el) {
        el.onclick = function () {
          navigate(el.getAttribute('data-mode') === 'register' ? '/register' : '/login');
        };
      })(modeBtns[i]);
    }

    document.getElementById('dfAuthForm').onsubmit = function (e) {
      e.preventDefault();
      var fd = new FormData(e.target);
      var body = {};
      fd.forEach(function (v, k) { body[k] = v; });
      api('/auth/' + mode, { method: 'POST', body: JSON.stringify(body) })
        .then(function (data) {
          setToken(data.token);
          state.user = data.user;
          if (data.user.lang) state.lang = data.user.lang;
          if (data.user.theme) state.theme = data.user.theme;
          localStorage.setItem('df_lang', state.lang);
          localStorage.setItem('df_theme', state.theme);
          applyTheme(); applyDir();
          return api('/teams').then(function (teams) {
            state.teams = teams;
            navigate('/');
          });
        })
        .catch(function (ex) { toast(ex.message, 'error'); });
    };
  }

  // ---------- Shell ----------
  function renderShell() {
    var root = document.getElementById('root');
    var initial = (state.user.username || 'U')[0].toUpperCase();
    var path = location.pathname;

    root.innerHTML =
      '<div class="sidebar">' +
        '<div class="sidebar-header">' +
          icon('code', 22) +
          '<span class="brand">DevForge</span>' +
        '</div>' +
        '<div class="sidebar-content">' +
          '<div class="nav-item' + (path === '/' ? ' active' : '') + '" data-nav="/">' +
            icon('home') + '<span>' + esc(t('dashboard')) + '</span>' +
          '</div>' +
          '<div class="sidebar-label">' + esc(t('teams')) + '</div>' +
          '<div id="dfTeamList"></div>' +
          '<div class="nav-item" id="dfNewTeamBtn" style="color:var(--tx2);font-size:12.5px">' +
            icon('plus', 16) + '<span>' + esc(t('newTeam')) + '</span>' +
          '</div>' +
          '<div class="sidebar-label">' + esc(t('notifications')) + '</div>' +
          '<div id="dfNotifs" style="padding:0 10px;font-size:12px;color:var(--tx3)">' +
            esc(t('noNotifications')) +
          '</div>' +
        '</div>' +
        '<div class="sidebar-footer">' +
          '<div class="avatar">' + esc(initial) + '</div>' +
          '<div style="flex:1;min-width:0">' +
            '<div style="font-weight:500;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(state.user.username) + '</div>' +
          '</div>' +
          '<button class="btn-icon" id="dfSettingsBtn" title="' + esc(t('settings')) + '">' + icon('settings', 16) + '</button>' +
          '<button class="btn-icon" id="dfLogoutBtn" title="' + esc(t('logout')) + '">' + icon('logout', 16) + '</button>' +
        '</div>' +
      '</div>' +
      '<div class="main" id="dfMain"></div>';

    var navItems = root.querySelectorAll('[data-nav]');
    for (var i = 0; i < navItems.length; i++) {
      (function (el) {
        el.onclick = function () { navigate(el.getAttribute('data-nav')); };
      })(navItems[i]);
    }

    document.getElementById('dfSettingsBtn').onclick = function () { navigate('/settings'); };
    document.getElementById('dfLogoutBtn').onclick = function () {
      setToken(null);
      state.user = null;
      state.teams = [];
      state.currentTeam = null;
      if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
      navigate('/login');
    };
    document.getElementById('dfNewTeamBtn').onclick = function () {
      showModal({
        title: t('newTeam'),
        fields: [{ name: 'name', label: t('teamName'), required: true }],
        onSubmit: function (d) {
          return api('/teams', { method: 'POST', body: JSON.stringify(d) })
            .then(function () { return api('/teams'); })
            .then(function (teams) {
              state.teams = teams;
              renderTeamList();
              if (teams[0]) navigate('/team/' + teams[0].id);
            });
        }
      });
    };

    renderTeamList();
    loadNotifications();
  }

  function renderTeamList() {
    var el = document.getElementById('dfTeamList');
    if (!el) return;
    if (!state.teams.length) {
      el.innerHTML = '<div style="padding:4px 10px;font-size:12px;color:var(--tx3)">' + esc(t('teamsEmpty')) + '</div>';
      return;
    }
    var path = location.pathname;
    var html = '';
    for (var i = 0; i < state.teams.length; i++) {
      var tm = state.teams[i];
      var active = path === '/team/' + tm.id;
      html += '<div class="nav-item' + (active ? ' active' : '') + '" data-team="' + esc(tm.id) + '">' +
        icon('users', 16) +
        '<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(tm.name) + '</span>' +
        '</div>';
    }
    el.innerHTML = html;
    var items = el.querySelectorAll('[data-team]');
    for (var j = 0; j < items.length; j++) {
      (function (x) {
        x.onclick = function () { navigate('/team/' + x.getAttribute('data-team')); };
      })(items[j]);
    }
  }

  function loadNotifications() {
    api('/notifications').then(function (list) {
      var el = document.getElementById('dfNotifs');
      if (!el) return;
      if (!list.length) {
        el.innerHTML = '<div style="font-size:12px;color:var(--tx3)">' + esc(t('noNotifications')) + '</div>';
        return;
      }
      el.innerHTML = list.slice(0, 4).map(function (n) {
        return '<div style="font-size:12px;color:var(--tx2);padding:2px 0">' + esc(n.message) + '</div>';
      }).join('');
    }).catch(function () {});
  }

  // ---------- Dashboard ----------
  function renderDashboard() {
    var main = document.getElementById('dfMain');
    var teamsHtml;
    if (state.teams.length) {
      teamsHtml = '<div class="grid">' + state.teams.map(function (tm) {
        return '<div class="card" data-team="' + esc(tm.id) + '">' +
          '<div class="card-title">' + icon('users', 16) + esc(tm.name) + '</div>' +
          '<div class="card-desc">' + esc(tm.role === 'owner' ? 'Owner' : 'Member') + '</div>' +
          '</div>';
      }).join('') + '</div>';
    } else {
      teamsHtml = '<div class="empty">' +
        '<div class="empty-icon">' + icon('users', 48) + '</div>' +
        '<h3>' + esc(t('teams')) + '</h3>' +
        '<p>' + esc(t('teamsEmpty')) + '</p>' +
        '<button class="btn btn-primary" id="dfEmptyNewTeam">' + icon('plus', 16) + esc(t('newTeam')) + '</button>' +
        '</div>';
    }
    main.innerHTML =
      '<div class="main-header">' +
        '<div class="main-title">' + icon('home', 20) + esc(t('dashboard')) + '</div>' +
        '<button class="btn btn-primary" id="dfDashNewTeam">' + icon('plus', 16) + esc(t('newTeam')) + '</button>' +
      '</div>' +
      '<div class="main-content">' + teamsHtml + '</div>';

    function openModal() {
      showModal({
        title: t('newTeam'),
        fields: [{ name: 'name', label: t('teamName'), required: true }],
        onSubmit: function (d) {
          return api('/teams', { method: 'POST', body: JSON.stringify(d) })
            .then(function () { return api('/teams'); })
            .then(function (teams) {
              state.teams = teams;
              renderTeamList();
              if (teams[0]) navigate('/team/' + teams[0].id);
            });
        }
      });
    }
    document.getElementById('dfDashNewTeam').onclick = openModal;
    var emptyBtn = document.getElementById('dfEmptyNewTeam');
    if (emptyBtn) emptyBtn.onclick = openModal;
    var cards = main.querySelectorAll('[data-team]');
    for (var i = 0; i < cards.length; i++) {
      (function (c) {
        c.onclick = function () { navigate('/team/' + c.getAttribute('data-team')); };
      })(cards[i]);
    }
  }

  // ---------- Team ----------
  function renderTeam(teamId) {
    var main = document.getElementById('dfMain');
    main.innerHTML =
      '<div class="main-header"><div class="main-title">' + esc(t('loading')) + '</div></div>' +
      '<div class="main-content"><div class="spinner"></div></div>';

    api('/teams/' + teamId).then(function (data) {
      state.currentTeam = data.team;
      var channelsHtml = data.channels.length
        ? '<div class="list">' + data.channels.map(function (c) {
            return '<div class="list-item" data-ch="' + esc(c.id) + '" data-name="' + esc(c.name) + '">' +
              '<div class="list-item-icon">' + icon('hash', 16) + '</div>' +
              '<div style="flex:1;min-width:0"><div style="font-weight:500">' + esc(c.name) + '</div></div>' +
              '</div>';
          }).join('') + '</div>'
        : '<div style="padding:8px;color:var(--tx3);font-size:13px">—</div>';

      var projectsHtml = data.projects.length
        ? '<div class="grid">' + data.projects.map(function (p) {
            return '<div class="card" data-proj="' + esc(p.id) + '">' +
              '<div class="card-title">' + icon('folder', 16) + esc(p.name) + '</div>' +
              '<div class="card-desc">' + esc(p.repo_url || '—') + '</div>' +
              '</div>';
          }).join('') + '</div>'
        : '<div style="padding:8px;color:var(--tx3);font-size:13px">—</div>';

      var membersHtml = data.members.length
        ? '<div class="list">' + data.members.map(function (m) {
            return '<div class="list-item" style="cursor:default">' +
              '<div class="avatar">' + esc((m.username || 'U')[0].toUpperCase()) + '</div>' +
              '<div style="flex:1;min-width:0">' +
                '<div style="font-weight:500">' + esc(m.username) + '</div>' +
                '<div style="font-size:12px;color:var(--tx3)">' + esc(m.role) + '</div>' +
              '</div>' +
              '</div>';
          }).join('') + '</div>'
        : '';

      main.innerHTML =
        '<div class="main-header">' +
          '<div class="main-title">' + icon('users', 20) + esc(data.team.name) + '</div>' +
          '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
            '<button class="btn btn-secondary" id="dfNewProjBtn">' + icon('folder', 16) + esc(t('newProject')) + '</button>' +
            '<button class="btn btn-primary" id="dfNewChanBtn">' + icon('hash', 16) + esc(t('newChannel')) + '</button>' +
          '</div>' +
        '</div>' +
        '<div class="main-content">' +
          '<div class="settings-section">' +
            '<h3>' + esc(t('channels')) + '</h3>' + channelsHtml +
          '</div>' +
          '<div class="settings-section">' +
            '<h3>' + esc(t('projects')) + '</h3>' + projectsHtml +
          '</div>' +
          (membersHtml
            ? '<div class="settings-section"><h3>' + esc(t('members')) + '</h3>' + membersHtml + '</div>'
            : '') +
        '</div>';

      var chItems = main.querySelectorAll('[data-ch]');
      for (var i = 0; i < chItems.length; i++) {
        (function (el) {
          el.onclick = function () {
            var cid = el.getAttribute('data-ch');
            var cname = el.getAttribute('data-name');
            navigate('/channel/' + cid + '?n=' + encodeURIComponent(cname));
          };
        })(chItems[i]);
      }

      var projCards = main.querySelectorAll('[data-proj]');
      for (var k = 0; k < projCards.length; k++) {
        (function (el) {
          el.onclick = function () {
            navigate('/project/' + el.getAttribute('data-proj'));
          };
        })(projCards[k]);
      }

      document.getElementById('dfNewChanBtn').onclick = function () {
        showModal({
          title: t('newChannel'),
          fields: [{ name: 'name', label: t('channelName'), required: true }],
          onSubmit: function (d) {
            return api('/teams/' + teamId + '/channels', { method: 'POST', body: JSON.stringify(d) })
              .then(function () { renderTeam(teamId); });
          }
        });
      };
      document.getElementById('dfNewProjBtn').onclick = function () {
        showModal({
          title: t('newProject'),
          fields: [
            { name: 'name', label: t('projectName'), required: true },
            { name: 'repo_url', label: t('repoUrl'), placeholder: 'owner/repo' }
          ],
          onSubmit: function (d) {
            var body = {
              name: d.name,
              repo_url: d.repo_url || null,
              provider: d.repo_url ? 'github' : null
            };
            return api('/teams/' + teamId + '/projects', { method: 'POST', body: JSON.stringify(body) })
              .then(function () { renderTeam(teamId); });
          }
        });
      };
    }).catch(function (ex) {
      main.innerHTML = '<div class="main-header"><div class="main-title">' + esc(t('error')) + '</div></div>' +
        '<div class="main-content" style="color:var(--er)">' + esc(ex.message) + '</div>';
    });
  }

  // ---------- Channel (chat) ----------
  function renderChannel(channelId) {
    var main = document.getElementById('dfMain');
    var params = new URLSearchParams(location.search);
    var channelName = params.get('n') || channelId.slice(0, 6);

    main.innerHTML =
      '<div class="main-header"><div class="main-title">' + icon('hash', 20) + esc(channelName) + '</div></div>' +
      '<div class="main-content" style="padding:0;display:flex;flex-direction:column">' +
        '<div class="chat-container">' +
          '<div class="chat-messages" id="dfChatMsgs"></div>' +
          '<form class="chat-input" id="dfChatForm">' +
            '<button type="button" class="btn-icon" id="dfAttachBtn" title="' + esc(t('attach')) + '">' + icon('paperclip', 18) + '</button>' +
            '<textarea rows="1" id="dfChatInput" placeholder="' + esc(t('chatPlaceholder')) + '"></textarea>' +
            '<button type="submit" class="btn btn-primary">' + icon('send', 16) + '</button>' +
          '</form>' +
          '<input type="file" id="dfFileInput" style="display:none">' +
        '</div>' +
      '</div>';

    refreshMessages(channelId);

    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(function () { refreshMessages(channelId); }, 3000);

    var form = document.getElementById('dfChatForm');
    var ta = document.getElementById('dfChatInput');
    ta.focus();
    ta.oninput = function () {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
    };
    ta.onkeydown = function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        form.requestSubmit();
      }
    };
    form.onsubmit = function (e) {
      e.preventDefault();
      var v = ta.value.trim();
      if (!v) return;
      ta.value = '';
      ta.style.height = 'auto';
      api('/channels/' + channelId + '/messages', {
        method: 'POST',
        body: JSON.stringify({ content: v })
      }).then(function () { refreshMessages(channelId); })
        .catch(function (ex) { toast(ex.message, 'error'); });
    };

    var fileInput = document.getElementById('dfFileInput');
    document.getElementById('dfAttachBtn').onclick = function () { fileInput.click(); };
    fileInput.onchange = function () {
      var f = fileInput.files[0];
      if (!f) return;
      var fd = new FormData();
      fd.append('file', f);
      fetch('/api/channels/' + channelId + '/upload', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + getToken() },
        body: fd
      }).then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.error); });
        return r.json();
      }).then(function (up) {
        return api('/channels/' + channelId + '/messages', {
          method: 'POST',
          body: JSON.stringify({ content: '📎 ' + f.name, file_key: up.key })
        });
      }).then(function () {
        fileInput.value = '';
        refreshMessages(channelId);
      }).catch(function (ex) { toast(ex.message, 'error'); });
    };
  }

  function refreshMessages(channelId) {
    if (location.pathname !== '/channel/' + channelId) return;
    api('/channels/' + channelId + '/messages').then(function (list) {
      var box = document.getElementById('dfChatMsgs');
      if (!box) return;
      if (!list.length) {
        box.innerHTML = '<div class="empty">' + icon('hash', 40) +
          '<h3>' + esc(t('chatEmpty')) + '</h3></div>';
        return;
      }
      var html = '';
      for (var i = 0; i < list.length; i++) {
        var m = list[i];
        var initial = (m.username || 'U')[0].toUpperCase();
        var fileHtml = '';
        if (m.file_key) {
          fileHtml = '<a class="message-file" href="/api/files/' + encodeURIComponent(m.file_key) +
            '" target="_blank" rel="noopener">' + icon('file', 14) + esc(m.content) + '</a>';
        }
        html += '<div class="message">' +
          '<div class="avatar">' + esc(initial) + '</div>' +
          '<div class="message-content">' +
            '<div class="message-header">' +
              '<span class="message-author">' + esc(m.username) + '</span>' +
              '<span class="message-time">' + fmtTime(m.created_at) + '</span>' +
            '</div>' +
            '<div class="message-text">' + esc(m.content) + '</div>' +
            fileHtml +
          '</div>' +
          '</div>';
      }
      box.innerHTML = html;
      box.scrollTop = box.scrollHeight;
    }).catch(function () {});
  }

  // ---------- Project (git) ----------
  function renderProject(projectId) {
    var main = document.getElementById('dfMain');
    main.innerHTML =
      '<div class="main-header">' +
        '<div class="main-title">' + esc(t('loading')) + '</div>' +
        '<button class="btn btn-secondary" id="dfBackBtn">' + esc(t('cancel')) + '</button>' +
      '</div>' +
      '<div class="main-content"><div class="spinner"></div></div>';

    var backBtn = document.getElementById('dfBackBtn');
    backBtn.onclick = function () {
      if (state.currentTeam) navigate('/team/' + state.currentTeam.id);
      else navigate('/');
    };

    api('/projects/' + projectId).then(function (proj) {
      if (!proj.repo_url) {
        main.innerHTML =
          '<div class="main-header">' +
            '<div class="main-title">' + icon('git', 20) + esc(proj.name) + '</div>' +
            '<button class="btn btn-secondary" id="dfBackBtn2">' + esc(t('cancel')) + '</button>' +
          '</div>' +
          '<div class="main-content">' +
            '<div class="empty"><div class="empty-icon">' + icon('git', 40) + '</div>' +
            '<p>' + esc(t('noRepo')) + '</p></div>' +
          '</div>';
        document.getElementById('dfBackBtn2').onclick = function () {
          if (state.currentTeam) navigate('/team/' + state.currentTeam.id);
          else navigate('/');
        };
        return;
      }
      var repoPath = proj.repo_url.indexOf('github.com/') >= 0
        ? proj.repo_url.split('github.com/').pop().replace(/\.git$/, '').replace(/\/$/, '')
        : proj.repo_url.replace(/^https?:\/\/(www\.)?/, '').split('/').slice(-2).join('/');
      main.innerHTML =
        '<div class="main-header">' +
          '<div class="main-title">' + icon('folder', 20) + esc(proj.name) + '</div>' +
          '<div style="display:flex;gap:8px">' +
            '<a class="btn btn-secondary" href="https://github.com/' + esc(repoPath) + '" target="_blank" rel="noopener">' + icon('git', 16) + 'GitHub</a>' +
            '<button class="btn btn-secondary" id="dfBackBtn3">' + esc(t('cancel')) + '</button>' +
          '</div>' +
        '</div>' +
        '<div class="main-content">' +
          '<div class="settings-section">' +
            '<h3>' + esc(t('commits')) + '</h3>' +
            '<div id="dfCommits"><div class="spinner"></div></div>' +
          '</div>' +
        '</div>';
      document.getElementById('dfBackBtn3').onclick = function () {
        if (state.currentTeam) navigate('/team/' + state.currentTeam.id);
        else navigate('/');
      };
      api('/git/commits?repo=' + encodeURIComponent(repoPath)).then(function (list) {
        var box = document.getElementById('dfCommits');
        if (!list.length) {
          box.innerHTML = '<div style="color:var(--tx3)">—</div>';
          return;
        }
        box.innerHTML = list.map(function (c) {
          return '<div class="commit">' +
            '<div>' +
              '<span class="commit-sha">' + esc(c.sha.slice(0, 7)) + '</span>' +
              '<span class="commit-msg">' + esc(c.commit.message.split('\n')[0]) + '</span>' +
            '</div>' +
            '<div class="commit-meta">' + esc(c.commit.author.name) + ' · ' +
              esc(new Date(c.commit.author.date).toLocaleString()) + '</div>' +
            '</div>';
        }).join('');
      }).catch(function (ex) {
        document.getElementById('dfCommits').innerHTML =
          '<div style="color:var(--er);font-size:13px">' + esc(ex.message) + '</div>';
      });
    }).catch(function (ex) {
      main.innerHTML = '<div class="main-header"><div class="main-title">' + esc(t('error')) + '</div></div>' +
        '<div class="main-content" style="color:var(--er)">' + esc(ex.message) + '</div>';
    });
  }

  // ---------- Settings ----------
  function renderSettings() {
    var main = document.getElementById('dfMain');
    main.innerHTML =
      '<div class="main-header"><div class="main-title">' + icon('settings', 20) + esc(t('settings')) + '</div></div>' +
      '<div class="main-content">' +
        '<div class="settings-section">' +
          '<h3>' + esc(t('language')) + '</h3>' +
          '<div class="setting-row">' +
            '<div class="setting-info"><h4>' + esc(t('language')) + '</h4><p>English / فارسی</p></div>' +
            '<div class="segmented" id="dfLangSeg">' +
              '<button data-lang="en" class="' + (state.lang === 'en' ? 'active' : '') + '">English</button>' +
              '<button data-lang="fa" class="' + (state.lang === 'fa' ? 'active' : '') + '">فارسی</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="settings-section">' +
          '<h3>' + esc(t('theme')) + '</h3>' +
          '<div class="setting-row">' +
            '<div class="setting-info"><h4>' + esc(t('theme')) + '</h4><p>' + esc(t('dark')) + ' / ' + esc(t('light')) + '</p></div>' +
            '<div class="segmented" id="dfThemeSeg">' +
              '<button data-theme="dark" class="' + (state.theme === 'dark' ? 'active' : '') + '">' + icon('moon', 12) + esc(t('dark')) + '</button>' +
              '<button data-theme="light" class="' + (state.theme === 'light' ? 'active' : '') + '">' + icon('sun', 12) + esc(t('light')) + '</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="settings-section">' +
          '<h3>' + esc(t('profile')) + '</h3>' +
          '<div class="setting-row">' +
            '<div class="setting-info"><h4>' + esc(state.user.username) + '</h4><p>' + esc(state.user.email) + '</p></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    var langBtns = main.querySelectorAll('#dfLangSeg [data-lang]');
    for (var i = 0; i < langBtns.length; i++) {
      (function (el) {
        el.onclick = function () {
          state.lang = el.getAttribute('data-lang');
          localStorage.setItem('df_lang', state.lang);
          applyDir();
          api('/me', { method: 'PUT', body: JSON.stringify({ lang: state.lang }) }).catch(function () {});
          render();
        };
      })(langBtns[i]);
    }
    var themeBtns = main.querySelectorAll('#dfThemeSeg [data-theme]');
    for (var j = 0; j < themeBtns.length; j++) {
      (function (el) {
        el.onclick = function () {
          state.theme = el.getAttribute('data-theme');
          localStorage.setItem('df_theme', state.theme);
          applyTheme();
          api('/me', { method: 'PUT', body: JSON.stringify({ theme: state.theme }) }).catch(function () {});
          render();
        };
      })(themeBtns[j]);
    }
  }

  // ============================================================
  //  Router
  // ============================================================
  function render() {
    var path = location.pathname;

    if (!state.user) {
      if (path !== '/login' && path !== '/register') {
        history.replaceState({}, '', '/login');
      }
      renderAuth();
      return;
    }
    if (path === '/login' || path === '/register') {
      history.replaceState({}, '', '/');
      path = '/';
    }

    renderShell();

    if (path.indexOf('/team/') === 0) return renderTeam(path.slice(6));
    if (path.indexOf('/channel/') === 0) return renderChannel(path.slice(9));
    if (path.indexOf('/project/') === 0) return renderProject(path.slice(9));
    if (path === '/settings') return renderSettings();
    return renderDashboard();
  }

  window.addEventListener('popstate', function () {
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
    render();
  });

  // ============================================================
  //  Boot
  // ============================================================
  state.lang = localStorage.getItem('df_lang') || 'en';
  state.theme = localStorage.getItem('df_theme') || 'dark';
  applyTheme(); applyDir();

  var token = getToken();
  if (token) {
    api('/me').then(function (u) {
      state.user = u;
      if (u.lang) state.lang = u.lang;
      if (u.theme) state.theme = u.theme;
      localStorage.setItem('df_lang', state.lang);
      localStorage.setItem('df_theme', state.theme);
      applyTheme(); applyDir();
      return api('/teams').then(function (teams) {
        state.teams = teams;
        render();
      });
    }).catch(function () {
      setToken(null);
      state.user = null;
      render();
    });
  } else {
    render();
  }
})();
`;

// ============================================================
//  Frontend: HTML shell
// ============================================================
const HTML = '<!DOCTYPE html>' +
  '<html lang="en" dir="ltr" data-theme="dark">' +
  '<head>' +
    '<meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>DevForge</title>' +
    '<link rel="preconnect" href="https://cdn.jsdelivr.net">' +
    '<link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet">' +
    '<style>' + CSS + '</style>' +
  '</head>' +
  '<body>' +
    '<div id="root"></div>' +
    '<script>' +
      'window.__I18N__=' + JSON.stringify(I18N) + ';' +
      'window.__ICONS__=' + JSON.stringify(ICONS) + ';' +
    '</script>' +
    '<script>' + CLIENT_JS + '</script>' +
  '</body>' +
  '</html>';

// ============================================================
//  API route handler
// ============================================================
async function handleAPI(req, env, user, path, method, url) {
  const db = env.DB;

  // ---------- Auth: register ----------
  if (path === '/auth/register' && method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const email = (body.email || '').trim().toLowerCase();
    const username = (body.username || '').trim();
    const password = body.password || '';
    if (!email || !username || !password) return err('Missing required fields');
    if (password.length < 6) return err('Password must be at least 6 characters');
    const id = uid();
    try {
      await db.prepare(
        'INSERT INTO users (id,email,username,password_hash) VALUES (?,?,?,?)'
      ).bind(id, email, username, await hashPassword(password)).run();
    } catch (e) {
      return err('User already exists', 409);
    }
    await db.prepare(
      'INSERT INTO notifications (id,user_id,message) VALUES (?,?,?)'
    ).bind(uid(), id, 'Welcome to DevForge!').run().catch(() => {});
    const token = await signJWT({ sub: id }, secretOf(env));
    return json({
      token,
      user: { id, email, username, lang: 'en', theme: 'dark' },
    });
  }

  // ---------- Auth: login ----------
  if (path === '/auth/login' && method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';
    if (!email || !password) return err('Missing required fields');
    const u = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    if (!u || !(await verifyPassword(password, u.password_hash))) {
      return err('Invalid credentials', 401);
    }
    const token = await signJWT({ sub: u.id }, secretOf(env));
    return json({
      token,
      user: { id: u.id, email: u.email, username: u.username, lang: u.lang || 'en', theme: u.theme || 'dark' },
    });
  }

  // ---------- All routes below require auth ----------
  if (!user) return err('Unauthorized', 401);

  if (path === '/me' && method === 'GET') {
    const u = await db.prepare(
      'SELECT id,email,username,lang,theme FROM users WHERE id=?'
    ).bind(user.sub).first();
    if (!u) return err('Not found', 404);
    return json(u);
  }

  if (path === '/me' && method === 'PUT') {
    const body = await req.json().catch(() => ({}));
    const updates = [];
    const binds = [];
    if (body.lang === 'en' || body.lang === 'fa') { updates.push('lang=?'); binds.push(body.lang); }
    if (body.theme === 'dark' || body.theme === 'light') { updates.push('theme=?'); binds.push(body.theme); }
    if (updates.length) {
      binds.push(user.sub);
      await db.prepare('UPDATE users SET ' + updates.join(',') + ' WHERE id=?')
        .bind(...binds).run();
    }
    return json({ ok: true });
  }

  // ---------- Teams ----------
  if (path === '/teams' && method === 'GET') {
    const list = await db.prepare(
      'SELECT t.*, m.role FROM teams t ' +
      'JOIN team_members m ON m.team_id=t.id ' +
      'WHERE m.user_id=? ORDER BY t.created_at DESC'
    ).bind(user.sub).all();
    return json(list.results || []);
  }

  if (path === '/teams' && method === 'POST') {
    const body = await req.json().catch(() => ({}));
    const name = (body.name || '').trim();
    if (!name) return err('Missing name');
    const id = uid();
    const channelId = uid();
    await db.prepare('INSERT INTO teams (id,name,owner_id) VALUES (?,?,?)')
      .bind(id, name, user.sub).run();
    await db.prepare("INSERT INTO team_members (team_id,user_id,role) VALUES (?,?,'owner')")
      .bind(id, user.sub).run();
    await db.prepare('INSERT INTO channels (id,team_id,name) VALUES (?,?,?)')
      .bind(channelId, id, 'general').run();
    return json({ id, name });
  }

  const teamMatch = path.match(/^\/teams\/([^/]+)$/);
  if (teamMatch && method === 'GET') {
    const tid = teamMatch[1];
    const team = await db.prepare('SELECT * FROM teams WHERE id=?').bind(tid).first();
    if (!team) return err('Not found', 404);
    const membership = await db.prepare(
      'SELECT role FROM team_members WHERE team_id=? AND user_id=?'
    ).bind(tid, user.sub).first();
    if (!membership) return err('Forbidden', 403);
    const channels = await db.prepare(
      'SELECT * FROM channels WHERE team_id=? ORDER BY created_at ASC'
    ).bind(tid).all();
    const projects = await db.prepare(
      'SELECT * FROM projects WHERE team_id=? ORDER BY created_at DESC'
    ).bind(tid).all();
    const members = await db.prepare(
      'SELECT u.id,u.username,m.role FROM team_members m ' +
      'JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY m.joined_at ASC'
    ).bind(tid).all();
    return json({
      team,
      channels: channels.results || [],
      projects: projects.results || [],
      members: members.results || [],
    });
  }

  const teamSub = path.match(/^\/teams\/([^/]+)\/(channels|projects)$/);
  if (teamSub && method === 'POST') {
    const tid = teamSub[1];
    const kind = teamSub[2];
    const membership = await db.prepare(
      'SELECT role FROM team_members WHERE team_id=? AND user_id=?'
    ).bind(tid, user.sub).first();
    if (!membership) return err('Forbidden', 403);
    const body = await req.json().catch(() => ({}));
    if (kind === 'channels') {
      const name = (body.name || '').trim();
      if (!name) return err('Missing name');
      const id = uid();
      await db.prepare('INSERT INTO channels (id,team_id,name) VALUES (?,?,?)')
        .bind(id, tid, name).run();
      return json({ id, name });
    }
    if (kind === 'projects') {
      const name = (body.name || '').trim();
      if (!name) return err('Missing name');
      const id = uid();
      await db.prepare(
        'INSERT INTO projects (id,team_id,name,repo_url,provider) VALUES (?,?,?,?,?)'
      ).bind(id, tid, name, body.repo_url || null, body.provider || null).run();
      return json({ id });
    }
  }

  // ---------- Projects ----------
  const projMatch = path.match(/^\/projects\/([^/]+)$/);
  if (projMatch && method === 'GET') {
    const p = await db.prepare('SELECT * FROM projects WHERE id=?').bind(projMatch[1]).first();
    if (!p) return err('Not found', 404);
    const mem = await db.prepare(
      'SELECT role FROM team_members WHERE team_id=? AND user_id=?'
    ).bind(p.team_id, user.sub).first();
    if (!mem) return err('Forbidden', 403);
    return json(p);
  }

  // ---------- Channels: messages ----------
  const msgMatch = path.match(/^\/channels\/([^/]+)\/messages$/);
  if (msgMatch && method === 'GET') {
    const cid = msgMatch[1];
    const ch = await db.prepare('SELECT team_id FROM channels WHERE id=?').bind(cid).first();
    if (!ch) return err('Not found', 404);
    const mem = await db.prepare(
      'SELECT role FROM team_members WHERE team_id=? AND user_id=?'
    ).bind(ch.team_id, user.sub).first();
    if (!mem) return err('Forbidden', 403);
    const list = await db.prepare(
      'SELECT m.id,m.content,m.file_key,m.created_at,u.username FROM messages m ' +
      'JOIN users u ON u.id=m.user_id WHERE m.channel_id=? ORDER BY m.created_at ASC LIMIT 200'
    ).bind(cid).all();
    return json(list.results || []);
  }
  if (msgMatch && method === 'POST') {
    const cid = msgMatch[1];
    const ch = await db.prepare('SELECT team_id FROM channels WHERE id=?').bind(cid).first();
    if (!ch) return err('Not found', 404);
    const mem = await db.prepare(
      'SELECT role FROM team_members WHERE team_id=? AND user_id=?'
    ).bind(ch.team_id, user.sub).first();
    if (!mem) return err('Forbidden', 403);
    const body = await req.json().catch(() => ({}));
    const content = (body.content || '').trim();
    if (!content) return err('Empty message');
    const id = uid();
    await db.prepare(
      'INSERT INTO messages (id,channel_id,user_id,content,file_key) VALUES (?,?,?,?,?)'
    ).bind(id, cid, user.sub, content, body.file_key || null).run();
    return json({ id });
  }

  // ---------- File upload / download ----------
  const uploadMatch = path.match(/^\/channels\/([^/]+)\/upload$/);
  if (uploadMatch && method === 'POST') {
    if (!env.BUCKET) return err('File storage not configured (add R2 binding BUCKET)', 501);
    const form = await req.formData();
    const file = form.get('file');
    if (!file || typeof file === 'string') return err('No file provided');
    const key = user.sub + '/' + uid() + '-' + file.name;
    await env.BUCKET.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || 'application/octet-stream' },
    });
    return json({ key, name: file.name });
  }
  if (path.startsWith('/files/') && method === 'GET') {
    if (!env.BUCKET) return err('File storage not configured', 501);
    const key = decodeURIComponent(path.slice(7));
    const obj = await env.BUCKET.get(key);
    if (!obj) return err('Not found', 404);
    return new Response(obj.body, {
      headers: {
        'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  }

  // ---------- Notifications ----------
  if (path === '/notifications' && method === 'GET') {
    const list = await db.prepare(
      'SELECT id,message,read,created_at FROM notifications ' +
      'WHERE user_id=? ORDER BY created_at DESC LIMIT 20'
    ).bind(user.sub).all();
    return json(list.results || []);
  }

  // ---------- Git: recent commits from GitHub ----------
  if (path === '/git/commits' && method === 'GET') {
    const repo = url.searchParams.get('repo') || '';
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return err('Invalid repo path');
    const headers = {
      'User-Agent': 'DevForge',
      Accept: 'application/vnd.github+json',
    };
    if (env.GITHUB_TOKEN) headers.Authorization = 'Bearer ' + env.GITHUB_TOKEN;
    const r = await fetch(
      'https://api.github.com/repos/' + repo + '/commits?per_page=20',
      { headers }
    );
    if (!r.ok) return err('GitHub API error: ' + r.status, r.status);
    const data = await r.json();
    return json(data.map((c) => ({
      sha: c.sha,
      commit: {
        message: c.commit.message,
        author: c.commit.author,
      },
    })));
  }

  return err('Not found', 404);
}

// ============================================================
//  Main fetch handler
// ============================================================
export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });

    const url = new URL(req.url);
    const path = url.pathname;

    // Serve SPA for all non-API routes
    if (!path.startsWith('/api/')) {
      return new Response(HTML, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache',
        },
      });
    }

    // Ensure schema exists
    try {
      if (!env.DB) {
        return err('Database not configured. Add a D1 binding named DB.', 500);
      }
      await ensureDB(env.DB);
    } catch (e) {
      return err('Database initialization failed: ' + e.message, 500);
    }

    // Auth check
    let user = null;
    const authHeader = req.headers.get('Authorization') || '';
    if (authHeader.startsWith('Bearer ')) {
      user = await verifyJWT(authHeader.slice(7), secretOf(env));
    }

    const apiPath = path.slice(4);
    try {
      const res = await handleAPI(req, env, user, apiPath, req.method, url);
      Object.entries(cors).forEach(([k, v]) => res.headers.set(k, v));
      return res;
    } catch (e) {
      console.error('[api]', e);
      const res = err(e.message || 'Server error', 500);
      Object.entries(cors).forEach(([k, v]) => res.headers.set(k, v));
      return res;
    }
  },
};
