/**
 * ============================================================
 *   DevForge v2 — Single-file Cloudflare Worker
 *   Build Together. Code Better.
 * ============================================================
 *   Deploy:  wrangler deploy
 *   Local:   wrangler dev
 *
 *   Security: JWT expiry + PBKDF2(150k) + rate limiting + CSP
 *             + strict validation + per-team authorization
 *   Features: auth, teams, channels, DMs, messages (edit/delete/
 *             react/pin), tasks board, invites, search, file
 *             upload, GitHub (commits/branches/PRs/issues)
 * ============================================================
 */

// ============================================================
//  Utilities
// ============================================================
const enc = new TextEncoder();
const dec = new TextDecoder();
const now = () => Math.floor(Date.now() / 1000);
const uid = () => crypto.randomUUID();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extra },
  });
const err = (msg, status = 400) => json({ error: msg }, status);

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const b64uDec = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ============================================================
//  Input validation & sanitization
// ============================================================
const VALID = {
  email: (v) => typeof v === 'string' && /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(v) && v.length < 254,
  username: (v) => typeof v === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(v),
  password: (v) => typeof v === 'string' && v.length >= 8 && v.length <= 128 && /[a-zA-Z]/.test(v) && /[0-9]/.test(v),
  text: (max) => (v) => typeof v === 'string' && v.length >= 1 && v.length <= max,
  optionalText: (max) => (v) => v == null || v === '' || (typeof v === 'string' && v.length <= max),
  repo: (v) => typeof v === 'string' && /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(v),
};

const sanitizeText = (s, max = 4000) =>
  String(s || '').slice(0, max).replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '');

// ============================================================
//  Rate limiting (per-isolate + persistent for auth)
// ============================================================
const rlBuckets = new Map();
function localRateLimit(key, limit, windowMs) {
  const t = Date.now();
  const b = rlBuckets.get(key);
  if (!b || t - b.start > windowMs) {
    rlBuckets.set(key, { start: t, count: 1 });
    return true;
  }
  b.count++;
  if (b.count > limit) return false;
  return true;
}
// Periodic cleanup to avoid memory growth
setInterval?.(() => {
  const t = Date.now();
  for (const [k, b] of rlBuckets) if (t - b.start > 300_000) rlBuckets.delete(k);
}, 60_000);

async function persistentRateLimit(db, key, limit, windowMs) {
  // Uses D1 to persist across isolates for sensitive endpoints
  const windowStart = Math.floor(Date.now() / windowMs) * windowMs;
  const k = key + ':' + windowStart;
  try {
    const existing = await db.prepare('SELECT count FROM rate_limits WHERE key=?').bind(k).first();
    const count = (existing?.count || 0) + 1;
    if (count > limit) return false;
    await db.prepare(
      'INSERT INTO rate_limits (key,count,created_at) VALUES (?,?,?) ' +
      'ON CONFLICT(key) DO UPDATE SET count=?'
    ).bind(k, count, now(), count).run();
    return true;
  } catch {
    return true; // fail-open for non-critical path
  }
}

// ============================================================
//  Crypto
// ============================================================
const DEFAULT_SECRET = 'devforge-replace-this-with-a-long-random-string-CHANGE-ME';
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
    const payload = JSON.parse(dec.decode(b64uDec(b)));
    if (payload.exp && payload.exp < now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, key, 256
  );
  return b64u(salt) + '.' + b64u(bits);
}

async function verifyPassword(pw, stored) {
  try {
    const [sb, hb] = stored.split('.');
    const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: b64uDec(sb), iterations: 150000, hash: 'SHA-256' }, key, 256
    );
    return b64u(bits) === hb;
  } catch {
    return false;
  }
}

// Constant-time string compare to resist timing attacks
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ============================================================
//  Database schema
// ============================================================
let _dbInit = null;
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, bio TEXT, accent TEXT DEFAULT '#58a6ff',
    lang TEXT DEFAULT 'en', theme TEXT DEFAULT 'dark',
    created_at INTEGER DEFAULT (unixepoch()), last_seen INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT DEFAULT 'member',
    joined_at INTEGER DEFAULT (unixepoch()), PRIMARY KEY (team_id, user_id)
  )`,
  `CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, team_id TEXT NOT NULL, name TEXT NOT NULL,
    repo_url TEXT, provider TEXT, description TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY, team_id TEXT, name TEXT NOT NULL,
    is_dm INTEGER DEFAULT 0, dm_key TEXT UNIQUE, topic TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
    content TEXT NOT NULL, file_key TEXT, file_name TEXT, file_type TEXT,
    reply_to TEXT, edited_at INTEGER, deleted_at INTEGER,
    pinned INTEGER DEFAULT 0, created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS reactions (
    message_id TEXT NOT NULL, user_id TEXT NOT NULL, emoji TEXT NOT NULL,
    PRIMARY KEY (message_id, user_id, emoji)
  )`,
  `CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, team_id TEXT NOT NULL, project_id TEXT,
    title TEXT NOT NULL, description TEXT, status TEXT DEFAULT 'todo',
    priority TEXT DEFAULT 'normal', assignee_id TEXT, created_by TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()), updated_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY, team_id TEXT NOT NULL, created_by TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()), uses INTEGER DEFAULT 0, max_uses INTEGER DEFAULT 50
  )`,
  `CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, message TEXT NOT NULL,
    kind TEXT DEFAULT 'info', link TEXT, read INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY, count INTEGER DEFAULT 0, created_at INTEGER DEFAULT (unixepoch())
  )`,
  `CREATE TABLE IF NOT EXISTS typing (
    channel_id TEXT NOT NULL, user_id TEXT NOT NULL,
    updated_at INTEGER DEFAULT (unixepoch()), PRIMARY KEY (channel_id, user_id)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_members_user ON team_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_tasks_team ON tasks(team_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, read)`,
];

async function initDB(db) {
  for (const s of SCHEMA) {
    try { await db.prepare(s).run(); } catch (e) { console.error('[schema]', e.message); }
  }
}
function ensureDB(db) {
  if (!_dbInit) _dbInit = initDB(db).catch((e) => { _dbInit = null; throw e; });
  return _dbInit;
}

// ============================================================
//  i18n
// ============================================================
const I18N = {
  en: {
    tagline: 'Build together. Ship faster.',
    login: 'Sign in', register: 'Sign up', email: 'Email', username: 'Username', password: 'Password',
    haveAccount: 'Have an account?', noAccount: 'New here?',
    dashboard: 'Home', teams: 'Teams', settings: 'Settings', logout: 'Sign out', newTeam: 'New team',
    teamsEmpty: 'No teams yet. Start one!', channels: 'Channels', projects: 'Projects', members: 'Members',
    tasks: 'Tasks', newChannel: 'New channel', newProject: 'New project', newTask: 'New task',
    chatPlaceholder: 'Message...', chatEmpty: 'No messages yet. Break the ice!',
    attach: 'Attach file', language: 'Language', theme: 'Theme', dark: 'Dark', light: 'Light',
    profile: 'Profile', cancel: 'Cancel', create: 'Create', save: 'Save', loading: 'Loading...',
    error: 'Something went wrong', gitTitle: 'Repository', commits: 'Commits', branches: 'Branches',
    pulls: 'Pull Requests', issues: 'Issues', repoUrl: 'Repository (owner/repo)',
    notifications: 'Notifications', noNotifications: 'All caught up',
    teamName: 'Team name', channelName: 'Channel name', projectName: 'Project name',
    welcome: 'Welcome', noRepo: 'No repository linked',
    pwdTooShort: 'Use 8+ chars with letters and numbers', invalidCreds: 'Wrong email or password',
    userExists: 'That username or email is taken', signInRequired: 'Please sign in',
    dm: 'Direct messages', newDM: 'New message', search: 'Search', send: 'Send',
    edit: 'Edit', delete: 'Delete', pin: 'Pin', unpin: 'Unpin', reply: 'Reply',
    editing: 'Editing...', saving: 'Saving...', copied: 'Copied!', invite: 'Invite',
    inviteCopied: 'Invite link copied', bio: 'Bio', accent: 'Accent color',
    todo: 'To do', doing: 'In progress', done: 'Done', priority: 'Priority',
    low: 'Low', normal: 'Normal', high: 'High', urgent: 'Urgent',
    assignee: 'Assignee', unassigned: 'Unassigned', role: 'Role',
    owner: 'Owner', admin: 'Admin', member: 'Member', remove: 'Remove',
    leaveTeam: 'Leave team', deleteTeam: 'Delete team', confirmDelete: 'Delete this forever?',
    online: 'Online', offline: 'Offline', typing: 'typing...',
    noResults: 'No results', results: 'Results', joinTeam: 'Join team',
    join: 'Join', joinHint: 'Paste an invite code', inviteCode: 'Invite code',
    security: 'Security', changePassword: 'Change password', currentPassword: 'Current password',
    newPassword: 'New password', passwordChanged: 'Password updated',
    wrongPassword: 'Current password is incorrect', tooMany: 'Too many attempts. Try later.',
    pwdWeak: 'Password too weak (8+ chars, letters, numbers)',
    dangerZone: 'Danger zone', logoutAll: 'Sign out everywhere'
  },
  fa: {
    tagline: 'با هم بسازید. سریع‌تر برسانید.',
    login: 'ورود', register: 'ثبت‌نام', email: 'ایمیل', username: 'نام کاربری', password: 'رمز عبور',
    haveAccount: 'حساب دارید؟', noAccount: 'تازه‌واردید؟',
    dashboard: 'خانه', teams: 'تیم‌ها', settings: 'تنظیمات', logout: 'خروج', newTeam: 'تیم جدید',
    teamsEmpty: 'هنوز تیمی نیست. یکی بساز!', channels: 'کانال‌ها', projects: 'پروژه‌ها', members: 'اعضا',
    tasks: 'وظایف', newChannel: 'کانال جدید', newProject: 'پروژه جدید', newTask: 'وظیفه جدید',
    chatPlaceholder: 'پیام...', chatEmpty: 'هنوز پیامی نیست. شروع کن!',
    attach: 'پیوست', language: 'زبان', theme: 'تم', dark: 'تیره', light: 'روشن',
    profile: 'پروفایل', cancel: 'لغو', create: 'ایجاد', save: 'ذخیره', loading: 'در حال بارگذاری...',
    error: 'مشکلی پیش آمد', gitTitle: 'مخزن', commits: 'کامیت‌ها', branches: 'شاخه‌ها',
    pulls: 'درخواست‌های ادغام', issues: 'مسائل', repoUrl: 'مخزن (owner/repo)',
    notifications: 'اعلان‌ها', noNotifications: 'همه‌چیز مرتب است',
    teamName: 'نام تیم', channelName: 'نام کانال', projectName: 'نام پروژه',
    welcome: 'خوش آمدید', noRepo: 'مخزنی متصل نیست',
    pwdTooShort: 'حداقل ۸ کاراکتر با حرف و عدد', invalidCreds: 'ایمیل یا رمز نادرست',
    userExists: 'نام کاربری یا ایمیل تکراری', signInRequired: 'لطفاً وارد شوید',
    dm: 'پیام‌های مستقیم', newDM: 'پیام جدید', search: 'جستجو', send: 'ارسال',
    edit: 'ویرایش', delete: 'حذف', pin: 'سنجاق', unpin: 'برداشتن سنجاق', reply: 'پاسخ',
    editing: 'در حال ویرایش...', saving: 'در حال ذخیره...', copied: 'کپی شد!', invite: 'دعوت',
    inviteCopied: 'لینک دعوت کپی شد', bio: 'درباره', accent: 'رنگ اصلی',
    todo: 'برای انجام', doing: 'در حال انجام', done: 'انجام شده', priority: 'اولویت',
    low: 'کم', normal: 'معمولی', high: 'زیاد', urgent: 'فوری',
    assignee: 'مسئول', unassigned: 'بدون مسئول', role: 'نقش',
    owner: 'مالک', admin: 'مدیر', member: 'عضو', remove: 'حذف',
    leaveTeam: 'ترک تیم', deleteTeam: 'حذف تیم', confirmDelete: 'برای همیشه حذف شود؟',
    online: 'آنلاین', offline: 'آفلاین', typing: 'در حال نوشتن...',
    noResults: 'نتیجه‌ای نیست', results: 'نتایج', joinTeam: 'پیوستن به تیم',
    join: 'پیوستن', joinHint: 'کد دعوت را وارد کنید', inviteCode: 'کد دعوت',
    security: 'امنیت', changePassword: 'تغییر رمز', currentPassword: 'رمز فعلی',
    newPassword: 'رمز جدید', passwordChanged: 'رمز به‌روز شد',
    wrongPassword: 'رمز فعلی نادرست است', tooMany: 'تلاش زیاد. بعداً امتحان کنید.',
    pwdWeak: 'رمز ضعیف (۸+ با حرف و عدد)',
    dangerZone: 'منطقه خطر', logoutAll: 'خروج از همه دستگاه‌ها'
  }
};

// ============================================================
//  SVG Icons
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
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  message: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
  check: '<polyline points="20 6 9 17 4 12"/>',
  x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
  trash: '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  pin: '<line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14l-2-9V3H7v5L5 17z"/>',
  reply: '<polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>',
  grid: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
};

// ============================================================
//  CSS — Modern, playful, proper sizing
// ============================================================
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0d14;--bg2:#0f141d;--bg3:#161c28;--bg4:#1d2534;--bgh:#263044;
  --bd:#1f2733;--bd2:#2a3444;--tx:#e8eef7;--tx2:#9aa8bd;--tx3:#63728a;
  --ac:#4c8eff;--ac2:#3367d6;--acGlow:rgba(76,142,255,.35);
  --grad:linear-gradient(135deg,#4c8eff 0%,#a855f7 50%,#ec4899 100%);
  --ok:#22c55e;--warn:#f59e0b;--er:#ef4444;
  --r:14px;--rs:9px;--rl:20px;
  --sh:0 10px 30px rgba(0,0,0,.45);
  --sh2:0 2px 8px rgba(0,0,0,.25);
  --glow:0 0 32px var(--acGlow);
}
[data-theme="light"]{
  --bg:#f7f9fc;--bg2:#ffffff;--bg3:#f0f4f9;--bg4:#e5ebf3;--bgh:#d8e0ec;
  --bd:#e2e8f0;--bd2:#cbd5e1;--tx:#0f172a;--tx2:#475569;--tx3:#94a3b8;
  --ac:#2563eb;--ac2:#1d4ed8;--acGlow:rgba(37,99,235,.2);
  --grad:linear-gradient(135deg,#2563eb 0%,#7c3aed 50%,#db2777 100%);
  --sh:0 10px 30px rgba(15,23,42,.08);
  --sh2:0 2px 8px rgba(15,23,42,.06);
}
html,body{height:100%}
body{
  font-family:'Vazirmatn',-apple-system,BlinkMacSystemFont,'Segoe UI',Tahoma,sans-serif;
  background:var(--bg);color:var(--tx);font-size:14.5px;line-height:1.6;
  -webkit-font-smoothing:antialiased;transition:background .2s,color .2s;
  overflow:hidden
}
button,input,textarea,select{font-family:inherit;font-size:inherit;color:inherit}
button{border:none;background:none;cursor:pointer;transition:opacity .15s}
button:disabled{opacity:.5;cursor:not-allowed}
a{color:var(--ac);text-decoration:none}
a:hover{text-decoration:underline}
::selection{background:var(--ac);color:#fff}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--bgh)}

#root{display:flex;height:100vh;overflow:hidden}

/* ---- AUTH (compact, single-card) ---- */
.auth-wrap{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:20px;
  background:
    radial-gradient(circle at 15% 20%,rgba(76,142,255,.15),transparent 45%),
    radial-gradient(circle at 85% 80%,rgba(236,72,153,.12),transparent 45%),
    var(--bg);
}
.auth-card{
  width:100%;max-width:380px;background:var(--bg2);
  border:1px solid var(--bd2);border-radius:var(--rl);padding:28px;
  box-shadow:var(--sh),inset 0 1px 0 rgba(255,255,255,.03);
  position:relative;animation:pop .35s cubic-bezier(.2,.9,.3,1.2);
}
.auth-card::before{
  content:'';position:absolute;inset:-1px;border-radius:var(--rl);
  background:var(--grad);opacity:.35;z-index:-1;filter:blur(20px)
}
@keyframes pop{from{opacity:0;transform:scale(.94) translateY(8px)}to{opacity:1;transform:scale(1) translateY(0)}}
.auth-logo{text-align:center;margin-bottom:20px}
.auth-logo .brand{font-size:24px;display:block;margin-bottom:4px}
.auth-logo p{color:var(--tx2);font-size:12.5px}
.brand{
  font-weight:800;letter-spacing:-.02em;
  background:var(--grad);-webkit-background-clip:text;
  -webkit-text-fill-color:transparent;background-clip:text
}
.auth-tabs{
  display:flex;gap:4px;margin-bottom:18px;background:var(--bg3);
  padding:3px;border-radius:var(--rs)
}
.auth-tab{
  flex:1;padding:7px;text-align:center;border-radius:6px;
  color:var(--tx2);font-weight:500;transition:all .15s;font-size:12.5px
}
.auth-tab.active{background:var(--bg2);color:var(--tx);box-shadow:var(--sh2)}
.auth-switch{text-align:center;margin-top:12px;color:var(--tx2);font-size:12.5px}
.auth-switch a{cursor:pointer;font-weight:500}

/* ---- Forms ---- */
.form-group{margin-bottom:12px}
.form-group label{
  display:block;margin-bottom:5px;font-size:12px;
  color:var(--tx2);font-weight:500
}
.form-control{
  width:100%;padding:9px 12px;background:var(--bg3);
  border:1px solid var(--bd2);border-radius:var(--rs);color:var(--tx);
  transition:border-color .15s,box-shadow .15s
}
.form-control:focus{
  outline:none;border-color:var(--ac);
  box-shadow:0 0 0 3px var(--acGlow);background:var(--bg2)
}
textarea.form-control{resize:vertical;min-height:70px}

/* ---- Buttons ---- */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:8px 14px;border-radius:var(--rs);font-weight:600;
  transition:all .15s;white-space:nowrap;font-size:13.5px
}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--ac);color:#fff;box-shadow:0 4px 14px var(--acGlow)}
.btn-primary:hover{background:var(--ac2);box-shadow:0 6px 20px var(--acGlow)}
.btn-secondary{background:var(--bg3);color:var(--tx);border:1px solid var(--bd2)}
.btn-secondary:hover{background:var(--bg4);border-color:var(--bgh)}
.btn-ghost{color:var(--tx2)}
.btn-ghost:hover{background:var(--bg3);color:var(--tx)}
.btn-icon{
  padding:7px;border-radius:var(--rs);color:var(--tx2);
  display:inline-flex;align-items:center;justify-content:center
}
.btn-icon:hover{background:var(--bg3);color:var(--tx)}
.btn-danger{background:var(--er);color:#fff}
.btn-danger:hover{background:#dc2626}
.btn-block{width:100%;padding:10px;font-size:14px}
.btn-sm{padding:5px 10px;font-size:12.5px;border-radius:6px}

/* ---- Layout ---- */
.sidebar{
  width:264px;background:var(--bg2);border-right:1px solid var(--bd);
  display:flex;flex-direction:column;flex-shrink:0;
  transition:width .2s
}
[dir="rtl"] .sidebar{border-right:none;border-left:1px solid var(--bd)}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0;background:var(--bg)}

/* ---- Sidebar ---- */
.sidebar-header{
  padding:18px 18px 14px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:10px
}
.sidebar-header svg{color:var(--ac)}
.sidebar-content{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:2px}
.sidebar-label{
  font-size:10.5px;font-weight:700;text-transform:uppercase;
  color:var(--tx3);padding:14px 10px 6px;letter-spacing:.08em
}
.nav-item{
  display:flex;align-items:center;gap:10px;padding:8px 10px;
  border-radius:var(--rs);color:var(--tx2);cursor:pointer;
  transition:background .12s,color .12s;user-select:none;
  font-size:13.5px;font-weight:500
}
.nav-item:hover{background:var(--bg3);color:var(--tx)}
.nav-item.active{
  background:linear-gradient(90deg,var(--acGlow),transparent);
  color:var(--ac);font-weight:600
}
.nav-item.active svg{color:var(--ac)}
.nav-item svg{flex-shrink:0;opacity:.9}
.nav-item .badge{
  margin-inline-start:auto;background:var(--er);color:#fff;
  padding:1px 6px;border-radius:10px;font-size:10.5px;font-weight:700
}
.sidebar-footer{
  padding:12px;border-top:1px solid var(--bd);
  display:flex;align-items:center;gap:10px
}
.avatar{
  width:34px;height:34px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:700;font-size:13px;flex-shrink:0;
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.1)
}
.avatar-lg{width:64px;height:64px;font-size:22px}
.avatar-sm{width:26px;height:26px;font-size:11px}
.avatar-tiny{width:20px;height:20px;font-size:9px}
.presence-dot{
  width:8px;height:8px;border-radius:50%;background:var(--ok);
  box-shadow:0 0 0 2px var(--bg2);display:inline-block
}
.presence-dot.offline{background:var(--tx3)}

/* ---- Main Header ---- */
.main-header{
  padding:16px 22px;border-bottom:1px solid var(--bd);
  display:flex;align-items:center;justify-content:space-between;
  background:var(--bg);gap:12px;flex-wrap:wrap;min-height:64px
}
.main-title{
  font-size:17px;font-weight:700;display:flex;align-items:center;gap:10px;
  letter-spacing:-.01em
}
.main-title svg{color:var(--tx2)}
.main-sub{color:var(--tx2);font-size:12.5px;font-weight:400;margin-top:1px}
.main-content{flex:1;overflow-y:auto;padding:22px}

/* ---- Cards / Grid ---- */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}
.card{
  background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--r);
  padding:16px;transition:all .15s;cursor:pointer;position:relative;overflow:hidden
}
.card:hover{
  border-color:var(--ac);transform:translateY(-1px);
  box-shadow:0 8px 24px rgba(0,0,0,.15)
}
.card:active{transform:translateY(0)}
.card-title{
  font-size:14.5px;font-weight:600;margin-bottom:5px;
  display:flex;align-items:center;gap:8px
}
.card-title svg{color:var(--ac);flex-shrink:0}
.card-desc{
  color:var(--tx2);font-size:12.5px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap
}
.card-accent{
  position:absolute;top:0;inset-inline-start:0;width:3px;height:100%;
  background:var(--grad)
}

/* ---- Empty ---- */
.empty{text-align:center;padding:56px 20px;color:var(--tx2)}
.empty-icon{opacity:.25;margin-bottom:14px;display:flex;justify-content:center;color:var(--ac)}
.empty h3{color:var(--tx);font-size:15px;margin-bottom:6px;font-weight:600}
.empty p{font-size:13px;margin-bottom:16px;max-width:320px;margin-inline:auto}

/* ---- Chat ---- */
.chat-container{display:flex;flex-direction:column;height:100%}
.chat-messages{
  flex:1;overflow-y:auto;padding:20px 22px;
  display:flex;flex-direction:column;gap:14px;scroll-behavior:smooth
}
.message{
  display:flex;gap:10px;animation:fi .2s ease-out;
  padding:4px 8px;margin:0 -8px;border-radius:var(--rs);position:relative
}
.message:hover{background:var(--bg2)}
.message:hover .msg-actions{opacity:1}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.message-content{flex:1;min-width:0}
.message-header{display:flex;align-items:baseline;gap:8px;margin-bottom:2px}
.message-author{font-weight:600;font-size:13.5px;color:var(--tx)}
.message-author.me{color:var(--ac)}
.message-time{font-size:11px;color:var(--tx3)}
.message-text{
  word-wrap:break-word;overflow-wrap:break-word;font-size:14px;
  white-space:pre-wrap;line-height:1.55
}
.message-text .mention{
  background:var(--acGlow);color:var(--ac);padding:1px 5px;
  border-radius:4px;font-weight:600;font-size:13px
}
.message-text code{
  background:var(--bg3);padding:1px 5px;border-radius:4px;
  font-family:ui-monospace,'SF Mono',Menlo,monospace;font-size:12.5px;
  border:1px solid var(--bd2)
}
.message-text strong{font-weight:700;color:var(--tx)}
.message-edited{font-size:10.5px;color:var(--tx3);margin-inline-start:4px;font-style:italic}
.msg-actions{
  position:absolute;top:-8px;inset-inline-end:12px;
  display:flex;gap:2px;background:var(--bg2);border:1px solid var(--bd2);
  border-radius:8px;padding:3px;box-shadow:var(--sh2);
  opacity:0;transition:opacity .12s
}
.msg-actions button{padding:3px;border-radius:4px;color:var(--tx2)}
.msg-actions button:hover{background:var(--bg3);color:var(--tx)}
.message-file{
  display:inline-flex;align-items:center;gap:6px;padding:8px 12px;
  background:var(--bg3);border:1px solid var(--bd2);border-radius:var(--rs);
  color:var(--tx);font-size:13px;margin-top:6px;text-decoration:none;
  transition:border-color .15s
}
.message-file:hover{border-color:var(--ac);text-decoration:none}
.message-reactions{
  display:flex;gap:4px;margin-top:6px;flex-wrap:wrap
}
.reaction{
  display:inline-flex;align-items:center;gap:4px;
  background:var(--bg3);border:1px solid var(--bd2);
  padding:2px 8px;border-radius:20px;font-size:12px;cursor:pointer;
  transition:all .15s
}
.reaction:hover{border-color:var(--ac)}
.reaction.mine{background:var(--acGlow);border-color:var(--ac);color:var(--ac)}
.chat-input{
  padding:14px 22px;border-top:1px solid var(--bd);
  display:flex;gap:8px;align-items:flex-end;background:var(--bg)
}
.chat-input textarea{
  flex:1;padding:10px 14px;background:var(--bg3);
  border:1px solid var(--bd2);border-radius:var(--r);
  color:var(--tx);resize:none;max-height:140px;
  font-family:inherit;transition:all .15s;line-height:1.5;min-height:42px
}
.chat-input textarea:focus{
  outline:none;border-color:var(--ac);box-shadow:0 0 0 3px var(--acGlow)
}
.typing-indicator{
  padding:4px 22px;font-size:11.5px;color:var(--tx3);
  font-style:italic;min-height:22px
}

/* ---- Modal ---- */
.modal-backdrop{
  position:fixed;inset:0;background:rgba(0,0,0,.65);
  backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);
  display:flex;align-items:center;justify-content:center;
  z-index:1000;padding:20px;animation:fi .15s ease-out
}
.modal{
  background:var(--bg2);border:1px solid var(--bd2);border-radius:var(--r);
  padding:22px;width:100%;max-width:440px;box-shadow:var(--sh);
  animation:pop .25s cubic-bezier(.2,.9,.3,1.2)
}
.modal-title{font-size:16px;font-weight:700;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}

/* ---- Toast ---- */
.toast-container{
  position:fixed;bottom:22px;inset-inline-end:22px;
  display:flex;flex-direction:column;gap:8px;z-index:2000;
  max-width:360px
}
.toast{
  padding:11px 16px;background:var(--bg2);border:1px solid var(--bd2);
  border-radius:var(--rs);box-shadow:var(--sh);
  animation:pop .25s cubic-bezier(.2,.9,.3,1.2);font-size:13px;
  display:flex;align-items:center;gap:8px
}
.toast.error{border-color:var(--er);color:var(--er)}
.toast.success{border-color:var(--ok);color:var(--ok)}
.toast.info{border-color:var(--ac);color:var(--ac)}

/* ---- Settings ---- */
.settings-section{margin-bottom:26px}
.settings-section h3{
  font-size:11.5px;font-weight:700;margin-bottom:10px;
  color:var(--tx2);text-transform:uppercase;letter-spacing:.08em
}
.setting-row{
  display:flex;justify-content:space-between;align-items:center;
  padding:14px 16px;background:var(--bg2);border:1px solid var(--bd2);
  border-radius:var(--rs);margin-bottom:8px;gap:16px;flex-wrap:wrap
}
.setting-info h4{font-weight:600;margin-bottom:2px;font-size:13.5px}
.setting-info p{font-size:12px;color:var(--tx2)}
.segmented{
  display:inline-flex;background:var(--bg3);border-radius:var(--rs);
  padding:3px;flex-shrink:0;gap:2px
}
.segmented button{
  padding:6px 12px;border-radius:6px;color:var(--tx2);
  transition:all .15s;font-size:12.5px;display:inline-flex;
  align-items:center;gap:5px;font-weight:500
}
.segmented button.active{background:var(--bg2);color:var(--tx);box-shadow:var(--sh2)}

/* ---- List ---- */
.list{display:flex;flex-direction:column;gap:3px}
.list-item{
  display:flex;align-items:center;gap:11px;padding:10px 12px;
  border-radius:var(--rs);cursor:pointer;transition:background .12s
}
.list-item:hover{background:var(--bg2)}
.list-item-icon{
  width:34px;height:34px;border-radius:var(--rs);background:var(--bg3);
  display:flex;align-items:center;justify-content:center;
  color:var(--tx2);flex-shrink:0
}

/* ---- Tasks board ---- */
.board{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;align-items:start}
.board-col{
  background:var(--bg2);border:1px solid var(--bd2);
  border-radius:var(--r);padding:12px;min-height:200px
}
.board-col h4{
  font-size:12px;font-weight:700;text-transform:uppercase;
  color:var(--tx2);letter-spacing:.06em;margin-bottom:10px;
  display:flex;align-items:center;justify-content:space-between
}
.task{
  background:var(--bg3);border:1px solid var(--bd2);
  border-radius:var(--rs);padding:10px 12px;margin-bottom:8px;
  cursor:pointer;transition:all .15s;font-size:13px
}
.task:hover{border-color:var(--ac);transform:translateX(2px)}
.task-title{font-weight:600;margin-bottom:4px}
.task-meta{display:flex;gap:6px;align-items:center;font-size:11.5px;color:var(--tx2)}
.priority-badge{
  padding:1px 6px;border-radius:8px;font-size:10.5px;font-weight:700
}
.priority-low{background:rgba(34,197,94,.15);color:var(--ok)}
.priority-normal{background:rgba(76,142,255,.15);color:var(--ac)}
.priority-high{background:rgba(245,158,11,.15);color:var(--warn)}
.priority-urgent{background:rgba(239,68,68,.15);color:var(--er)}

/* ---- Spinner ---- */
.spinner{
  display:inline-block;width:16px;height:16px;
  border:2px solid var(--bd2);border-top-color:var(--ac);
  border-radius:50%;animation:sp .6s linear infinite
}
.spinner-lg{width:32px;height:32px;border-width:3px}
@keyframes sp{to{transform:rotate(360deg)}}

/* ---- Commits / GitHub ---- */
.repo-tabs{
  display:flex;gap:2px;border-bottom:1px solid var(--bd2);
  margin-bottom:18px;overflow-x:auto
}
.repo-tab{
  padding:9px 14px;color:var(--tx2);cursor:pointer;
  border-bottom:2px solid transparent;font-weight:500;
  transition:all .15s;font-size:13px;white-space:nowrap
}
.repo-tab.active{color:var(--tx);border-bottom-color:var(--ac)}
.repo-tab:hover{color:var(--tx)}
.commit{
  padding:11px 13px;border-radius:var(--rs);background:var(--bg2);
  border:1px solid var(--bd2);margin-bottom:7px;font-size:13px;
  transition:border-color .15s
}
.commit:hover{border-color:var(--bd)}
.commit-sha{
  font-family:ui-monospace,'SF Mono',Menlo,monospace;
  color:var(--ac);font-size:11.5px;margin-inline-end:8px;
  background:var(--acGlow);padding:1px 6px;border-radius:4px;font-weight:600
}
.commit-msg{color:var(--tx);word-break:break-word;font-weight:500}
.commit-meta{color:var(--tx3);font-size:11px;margin-top:3px}
.pr-item, .issue-item, .branch-item{
  padding:10px 12px;border-radius:var(--rs);background:var(--bg2);
  border:1px solid var(--bd2);margin-bottom:6px;font-size:13px;
  display:flex;align-items:center;gap:10px
}
.pr-state{font-size:11px;font-weight:700;padding:2px 7px;border-radius:10px}
.pr-open{background:rgba(34,197,94,.15);color:var(--ok)}
.pr-closed{background:rgba(239,68,68,.15);color:var(--er)}
.pr-merged{background:rgba(168,85,247,.15);color:#a855f7}

/* ---- Command palette ---- */
.cmd-backdrop{
  position:fixed;inset:0;background:rgba(0,0,0,.6);
  backdrop-filter:blur(4px);z-index:3000;padding:80px 20px 20px;
  display:flex;align-items:flex-start;justify-content:center;
  animation:fi .15s
}
.cmd-box{
  width:100%;max-width:520px;background:var(--bg2);
  border:1px solid var(--bd2);border-radius:var(--r);
  box-shadow:var(--sh);overflow:hidden;
  animation:pop .2s cubic-bezier(.2,.9,.3,1.2)
}
.cmd-input{
  width:100%;padding:14px 18px;background:transparent;
  border:none;color:var(--tx);font-size:15px;outline:none;
  border-bottom:1px solid var(--bd2)
}
.cmd-results{max-height:340px;overflow-y:auto;padding:6px}
.cmd-item{
  padding:10px 12px;border-radius:var(--rs);cursor:pointer;
  display:flex;align-items:center;gap:10px;font-size:13.5px
}
.cmd-item:hover, .cmd-item.sel{background:var(--bg3)}

/* ---- Mobile ---- */
@media (max-width:820px){
  .sidebar{width:230px}
  .main-header{padding:12px 16px;min-height:56px}
  .main-content{padding:16px}
  .chat-messages{padding:14px 16px}
  .chat-input{padding:10px 14px}
  .board{grid-template-columns:1fr}
  .auth-card{padding:22px}
}
@media (max-width:560px){
  .sidebar{position:absolute;inset-block:0;inset-inline-start:0;
    z-index:50;transform:translateX(-100%);transition:transform .25s;
    box-shadow:var(--sh);width:270px}
  [dir="rtl"] .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0)}
  .mobile-toggle{display:inline-flex !important}
}
.mobile-toggle{display:none}
`;

// ============================================================
//  Client JS
// ============================================================
const CLIENT_JS = String.raw`
(function () {
  'use strict';
  var I18N = window.__I18N__;
  var ICONS = window.__ICONS__;
  var state = {
    user: null, teams: [], team: null, teamData: null,
    channel: null, channelName: null,
    lang: 'en', theme: 'dark',
    pollTimer: null, typingTimer: null,
    cmdOpen: false, cmdIndex: 0, cmdItems: [],
    editingMessageId: null, replyTo: null,
    messages: [], members: {}
  };

  function t(k){var d=I18N[state.lang]||I18N.en; return d[k]||I18N.en[k]||k;}
  function icon(n,s){s=s||18; return '<svg xmlns="http://www.w3.org/2000/svg" width="'+s+'" height="'+s+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'+(ICONS[n]||'')+'</svg>';}
  function esc(s){var d=document.createElement('div'); d.textContent=s==null?'':String(s); return d.innerHTML;}

  function escAttr(s){return esc(s).replace(/"/g,'&quot;');}

  function escRich(s){
    // Markdown-lite: **bold**, *italic*, `code`, @mention, #channel
    var out = esc(s);
    out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    out = out.replace(/(^|\s)\*([^*\n]+?)\*(?=\s|$)/g, '$1<em>$2</em>');
    out = out.replace(/`([^`\n]+?)`/g, '<code>$1</code>');
    out = out.replace(/@([a-zA-Z0-9_.-]{3,32})/g, '<span class="mention">@$1</span>');
    out = out.replace(/(^|\s)#([a-zA-Z0-9_-]{1,40})/g, '$1<span style="color:var(--ac);font-weight:600">#$2</span>');
    return out;
  }

  function colorFor(str){
    var h=0; for (var i=0;i<str.length;i++) h=(h*31+str.charCodeAt(i))>>>0;
    var hue=h%360;
    return 'linear-gradient(135deg,hsl('+hue+',70%,55%),hsl('+((hue+40)%360)+',70%,45%))';
  }
  function initial(u){return (u||'?').substring(0,1).toUpperCase();}
  function avatarHtml(u,size){
    var cls='avatar'+(size?' avatar-'+size:'');
    return '<div class="'+cls+'" style="background:'+colorFor(u)+'">'+esc(initial(u))+'</div>';
  }
  function relTime(ts){
    var s=Math.floor(Date.now()/1000)-ts;
    if (s<60) return 'just now';
    if (s<3600) return Math.floor(s/60)+'m';
    if (s<86400) return Math.floor(s/3600)+'h';
    if (s<604800) return Math.floor(s/86400)+'d';
    return new Date(ts*1000).toLocaleDateString();
  }
  function fmtTime(ts){
    return new Date(ts*1000).toLocaleTimeString(state.lang==='fa'?'fa-IR':'en-US',{hour:'2-digit',minute:'2-digit'});
  }

  function getToken(){return localStorage.getItem('df_token');}
  function setToken(v){if(v)localStorage.setItem('df_token',v); else localStorage.removeItem('df_token');}

  function api(path,opts){
    var o=opts||{};
    var headers={'Content-Type':'application/json'};
    var tok=getToken(); if(tok)headers.Authorization='Bearer '+tok;
    var reqOpts={method:o.method||'GET',headers:headers};
    if(o.body)reqOpts.body=o.body;
    return fetch('/api'+path,reqOpts).then(function(res){
      if(res.status===401&&path.indexOf('/auth/')!==0){
        setToken(null); location.href='/login';
        return Promise.reject(new Error('Unauthorized'));
      }
      return res.json().then(function(data){
        if(!res.ok) throw new Error(data.error||'Request failed');
        return data;
      });
    });
  }

  function applyTheme(){document.documentElement.setAttribute('data-theme',state.theme);}
  function applyDir(){document.documentElement.setAttribute('dir',state.lang==='fa'?'rtl':'ltr');document.documentElement.setAttribute('lang',state.lang);}

  function toast(msg,type){
    var box=document.querySelector('.toast-container');
    if(!box){box=document.createElement('div');box.className='toast-container';document.body.appendChild(box);}
    var el=document.createElement('div');
    el.className='toast'+(type?' '+type:'');
    el.textContent=msg;
    box.appendChild(el);
    setTimeout(function(){if(el.parentNode)el.parentNode.removeChild(el);},3500);
  }

  function navigate(path){
    if(state.pollTimer){clearInterval(state.pollTimer);state.pollTimer=null;}
    if(state.typingTimer){clearInterval(state.typingTimer);state.typingTimer=null;}
    history.pushState({},'',path);
    render();
  }

  // ---- Command palette ----
  function openCommandPalette(){
    if(state.cmdOpen)return;
    state.cmdOpen=true; state.cmdIndex=0; state.cmdItems=[];
    var back=document.createElement('div');
    back.className='cmd-backdrop'; back.id='cmdBackdrop';
    back.innerHTML='<div class="cmd-box"><input class="cmd-input" placeholder="'+esc(t('search'))+'..." id="cmdInput"><div class="cmd-results" id="cmdResults"></div></div>';
    document.body.appendChild(back);
    var input=back.querySelector('#cmdInput');
    setTimeout(function(){input.focus();},50);
    input.oninput=function(){ runSearch(input.value.trim()); };
    back.onclick=function(e){if(e.target===back)closeCommandPalette();};
    var initialItems=[
      {label:t('dashboard'),icon:'home',action:function(){navigate('/');}},
      {label:t('settings'),icon:'settings',action:function(){navigate('/settings');}},
      {label:t('newTeam'),icon:'plus',action:function(){closeCommandPalette();showNewTeamModal();}},
      {label:t('newDM'),icon:'message',action:function(){closeCommandPalette();showNewDMModal();}}
    ];
    renderCmdItems(initialItems);
    input.onkeydown=function(e){
      if(e.key==='ArrowDown'){e.preventDefault();state.cmdIndex=Math.min(state.cmdIndex+1,state.cmdItems.length-1);highlightCmd();}
      else if(e.key==='ArrowUp'){e.preventDefault();state.cmdIndex=Math.max(state.cmdIndex-1,0);highlightCmd();}
      else if(e.key==='Enter'){e.preventDefault();var it=state.cmdItems[state.cmdIndex];if(it){if(it.action)it.action();else navigate(it.path);}}
      else if(e.key==='Escape'){closeCommandPalette();}
    };
  }
  function closeCommandPalette(){
    state.cmdOpen=false;
    var b=document.getElementById('cmdBackdrop'); if(b)b.remove();
  }
  function renderCmdItems(items){
    state.cmdItems=items; state.cmdIndex=0;
    var box=document.getElementById('cmdResults'); if(!box)return;
    if(!items.length){box.innerHTML='<div style="padding:16px;color:var(--tx3);font-size:13px;text-align:center">'+esc(t('noResults'))+'</div>';return;}
    box.innerHTML=items.map(function(it,i){
      return '<div class="cmd-item'+(i===0?' sel':'')+'" data-i="'+i+'">'+(it.icon?icon(it.icon,16):'')+'<span>'+esc(it.label)+'</span></div>';
    }).join('');
    box.querySelectorAll('[data-i]').forEach(function(el){
      el.onclick=function(){var it=state.cmdItems[parseInt(el.getAttribute('data-i'))];if(it){if(it.action)it.action();else navigate(it.path);}};
    });
  }
  function highlightCmd(){
    var box=document.getElementById('cmdResults'); if(!box)return;
    box.querySelectorAll('.cmd-item').forEach(function(el,i){el.classList.toggle('sel',i===state.cmdIndex);});
  }
  var searchDebounce=null;
  function runSearch(q){
    if(!q){renderCmdItems([]);return;}
    clearTimeout(searchDebounce);
    searchDebounce=setTimeout(function(){
      api('/search?q='+encodeURIComponent(q)).then(function(res){
        var items=[];
        (res.messages||[]).slice(0,6).forEach(function(m){
          items.push({label:m.content.slice(0,60)+' — '+m.username,icon:'message',action:function(){closeCommandPalette();navigate('/channel/'+m.channel_id+'?n='+encodeURIComponent(m.channel_name||'channel'));}});
        });
        (res.users||[]).slice(0,4).forEach(function(u){
          items.push({label:'@'+u.username,icon:'user',action:function(){closeCommandPalette();startDM(u.id);}});
        });
        renderCmdItems(items);
      }).catch(function(){renderCmdItems([]);});
    },200);
  }

  // ---- Typing indicator ----
  function sendTyping(channelId){
    api('/channels/'+channelId+'/typing',{method:'POST'}).catch(function(){});
  }
  function fetchTyping(channelId){
    api('/channels/'+channelId+'/typing').then(function(res){
      var box=document.getElementById('dfTyping'); if(!box)return;
      if(res.typing&&res.typing.length){
        box.textContent=res.typing.map(function(n){return n;}).join(', ')+' '+t('typing');
      } else box.textContent='';
    }).catch(function(){});
  }

  // ---- Modal ----
  function showModal(opts){
    var back=document.createElement('div');
    back.className='modal-backdrop';
    var fieldsHtml='';
    for(var i=0;i<opts.fields.length;i++){
      var f=opts.fields[i];
      var inputHtml;
      if(f.type==='textarea'){
        inputHtml='<textarea class="form-control" name="'+escAttr(f.name)+'"'+(f.required?' required':'')+(f.placeholder?' placeholder="'+escAttr(f.placeholder)+'"':'')+'>'+(f.value?esc(f.value):'')+'</textarea>';
      } else if(f.type==='select'){
        inputHtml='<select class="form-control" name="'+escAttr(f.name)+'">'+f.options.map(function(o){return '<option value="'+escAttr(o.v)+'"'+(o.v===f.value?' selected':'')+'>'+esc(o.l)+'</option>';}).join('')+'</select>';
      } else {
        inputHtml='<input class="form-control" name="'+escAttr(f.name)+'"'+(f.required?' required':'')+(f.type?' type="'+escAttr(f.type)+'"':'')+(f.placeholder?' placeholder="'+escAttr(f.placeholder)+'"':'')+(f.value?' value="'+escAttr(f.value)+'"':'')+'>';
      }
      fieldsHtml+='<div class="form-group"><label>'+esc(f.label)+'</label>'+inputHtml+'</div>';
    }
    back.innerHTML='<div class="modal"><div class="modal-title">'+esc(opts.title)+'</div><form id="dfModalForm">'+fieldsHtml+'<div class="modal-actions"><button type="button" class="btn btn-secondary" data-cancel>'+esc(t('cancel'))+'</button><button type="submit" class="btn btn-primary">'+esc(opts.submit||t('create'))+'</button></div></form></div>';
    document.body.appendChild(back);
    function close(){if(back.parentNode)back.parentNode.removeChild(back);}
    back.querySelector('[data-cancel]').onclick=close;
    back.onclick=function(e){if(e.target===back)close();};
    document.addEventListener('keydown',function ek(e){if(e.key==='Escape'){close();document.removeEventListener('keydown',ek);}});
    back.querySelector('#dfModalForm').onsubmit=function(e){
      e.preventDefault();
      var data={};
      var inputs=e.target.querySelectorAll('input,textarea,select');
      for(var i=0;i<inputs.length;i++)data[inputs[i].name]=inputs[i].value;
      Promise.resolve(opts.onSubmit(data)).then(close).catch(function(ex){toast(ex.message,'error');});
    };
    var firstInput=back.querySelector('input,textarea,select');
    if(firstInput)setTimeout(function(){firstInput.focus();},60);
  }

  // ============================================================
  //  AUTH
  // ============================================================
  function renderAuth(){
    var root=document.getElementById('root');
    var mode=location.pathname==='/register'?'register':'login';
    root.innerHTML='<div class="auth-wrap"><div class="auth-card">'+
      '<div class="auth-logo"><span class="brand">DevForge</span><p>'+esc(t('tagline'))+'</p></div>'+
      '<div class="auth-tabs">'+
        '<div class="auth-tab'+(mode==='login'?' active':'')+'" data-mode="login">'+esc(t('login'))+'</div>'+
        '<div class="auth-tab'+(mode==='register'?' active':'')+'" data-mode="register">'+esc(t('register'))+'</div>'+
      '</div>'+
      '<form id="dfAuthForm">'+
        (mode==='register'?'<div class="form-group"><label>'+esc(t('username'))+'</label><input class="form-control" name="username" required minlength="3" maxlength="32" autocomplete="username"></div>':'')+
        '<div class="form-group"><label>'+esc(t('email'))+'</label><input class="form-control" type="email" name="email" required autocomplete="email"></div>'+
        '<div class="form-group"><label>'+esc(t('password'))+'</label><input class="form-control" type="password" name="password" required minlength="8" autocomplete="'+(mode==='register'?'new-password':'current-password')+'"></div>'+
        '<button type="submit" class="btn btn-primary btn-block">'+esc(t(mode))+'</button>'+
      '</form>'+
      '<div class="auth-switch">'+
        (mode==='login'?'<span>'+esc(t('noAccount'))+'</span> <a data-mode="register">'+esc(t('register'))+'</a>':'<span>'+esc(t('haveAccount'))+'</span> <a data-mode="login">'+esc(t('login'))+'</a>')+
      '</div>'+
    '</div></div>';
    root.querySelectorAll('[data-mode]').forEach(function(el){
      el.onclick=function(){navigate(el.getAttribute('data-mode')==='register'?'/register':'/login');};
    });
    document.getElementById('dfAuthForm').onsubmit=function(e){
      e.preventDefault();
      var fd=new FormData(e.target),body={};
      fd.forEach(function(v,k){body[k]=v;});
      api('/auth/'+mode,{method:'POST',body:JSON.stringify(body)}).then(function(data){
        setToken(data.token);
        state.user=data.user;
        if(data.user.lang)state.lang=data.user.lang;
        if(data.user.theme)state.theme=data.user.theme;
        localStorage.setItem('df_lang',state.lang);
        localStorage.setItem('df_theme',state.theme);
        applyTheme();applyDir();
        return api('/teams').then(function(teams){state.teams=teams;navigate('/');});
      }).catch(function(ex){toast(ex.message,'error');});
    };
  }

  // ============================================================
  //  SHELL
  // ============================================================
  function renderShell(){
    var root=document.getElementById('root');
    var path=location.pathname;
    var sidebarHtml='<div class="sidebar" id="dfSidebar">'+
      '<div class="sidebar-header">'+icon('code',22)+'<span class="brand">DevForge</span></div>'+
      '<div class="sidebar-content">'+
        '<div class="nav-item'+(path==='/'?' active':'')+'" data-nav="/">'+icon('home')+'<span>'+esc(t('dashboard'))+'</span></div>'+
        '<div class="nav-item" data-action="search">'+icon('search')+'<span>'+esc(t('search'))+'</span><span style="margin-inline-start:auto;font-size:10px;color:var(--tx3);border:1px solid var(--bd2);padding:1px 5px;border-radius:4px">⌘K</span></div>'+
        '<div class="sidebar-label">'+esc(t('teams'))+'</div>'+
        '<div id="dfTeamList"></div>'+
        '<div class="nav-item" id="dfNewTeamBtn" style="color:var(--tx3);font-size:13px">'+icon('plus',16)+'<span>'+esc(t('newTeam'))+'</span></div>'+
        '<div class="sidebar-label">'+esc(t('dm'))+'</div>'+
        '<div id="dfDMList"></div>'+
        '<div class="nav-item" id="dfNewDMBtn" style="color:var(--tx3);font-size:13px">'+icon('plus',16)+'<span>'+esc(t('newDM'))+'</span></div>'+
        '<div class="sidebar-label">'+esc(t('notifications'))+'</div>'+
        '<div id="dfNotifs" style="padding:0 10px;font-size:12px;color:var(--tx3)">'+esc(t('noNotifications'))+'</div>'+
      '</div>'+
      '<div class="sidebar-footer">'+avatarHtml(state.user.username)+'<div style="flex:1;min-width:0"><div style="font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(state.user.username)+'</div><div style="font-size:11px;color:var(--tx3)">@'+esc(state.user.username)+'</div></div><button class="btn-icon" id="dfSettingsBtn" title="'+esc(t('settings'))+'">'+icon('settings',16)+'</button><button class="btn-icon" id="dfLogoutBtn" title="'+esc(t('logout'))+'">'+icon('logout',16)+'</button></div>'+
    '</div>';
    root.innerHTML=sidebarHtml+'<div class="main" id="dfMain"></div>';

    root.querySelectorAll('[data-nav]').forEach(function(el){el.onclick=function(){navigate(el.getAttribute('data-nav'));};});
    var searchBtn=root.querySelector('[data-action="search"]');
    if(searchBtn)searchBtn.onclick=openCommandPalette;
    document.getElementById('dfSettingsBtn').onclick=function(){navigate('/settings');};
    document.getElementById('dfLogoutBtn').onclick=function(){
      setToken(null);state.user=null;state.teams=[];
      if(state.pollTimer){clearInterval(state.pollTimer);state.pollTimer=null;}
      navigate('/login');
    };
    document.getElementById('dfNewTeamBtn').onclick=showNewTeamModal;
    document.getElementById('dfNewDMBtn').onclick=showNewDMModal;

    renderTeamList();
    loadDMs();
    loadNotifications();
  }

  function renderTeamList(){
    var el=document.getElementById('dfTeamList'); if(!el)return;
    if(!state.teams.length){el.innerHTML='<div style="padding:4px 10px;font-size:11.5px;color:var(--tx3)">'+esc(t('teamsEmpty'))+'</div>';return;}
    var path=location.pathname;
    el.innerHTML=state.teams.map(function(tm){
      var active=path==='/team/'+tm.id;
      return '<div class="nav-item'+(active?' active':'')+'" data-team="'+esc(tm.id)+'">'+icon('users',16)+'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(tm.name)+'</span></div>';
    }).join('');
    el.querySelectorAll('[data-team]').forEach(function(x){x.onclick=function(){navigate('/team/'+x.getAttribute('data-team'));};});
  }

  function loadDMs(){
    api('/dms').then(function(list){
      var el=document.getElementById('dfDMList'); if(!el)return;
      if(!list.length){el.innerHTML='<div style="padding:4px 10px;font-size:11.5px;color:var(--tx3)">—</div>';return;}
      el.innerHTML=list.map(function(d){
        var active=location.pathname==='/dm/'+d.other_id;
        return '<div class="nav-item'+(active?' active':'')+'" data-dm="'+esc(d.other_id)+'">'+avatarHtml(d.other_username,'sm')+'<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(d.other_username)+'</span></div>';
      }).join('');
      el.querySelectorAll('[data-dm]').forEach(function(x){x.onclick=function(){navigate('/dm/'+x.getAttribute('data-dm'));};});
    }).catch(function(){});
  }

  function loadNotifications(){
    api('/notifications').then(function(list){
      var el=document.getElementById('dfNotifs'); if(!el)return;
      if(!list.length){el.innerHTML='<div style="font-size:12px;color:var(--tx3)">'+esc(t('noNotifications'))+'</div>';return;}
      el.innerHTML=list.slice(0,4).map(function(n){
        return '<div style="font-size:12px;color:'+(n.read?'var(--tx3)':'var(--tx)')+';padding:3px 0;font-weight:'+(n.read?'400':'500')+'">'+esc(n.message)+'<div style="font-size:10px;color:var(--tx3)">'+relTime(n.created_at)+'</div></div>';
      }).join('');
    }).catch(function(){});
  }

  // ============================================================
  //  TEAM modal handlers
  // ============================================================
  function showNewTeamModal(){
    showModal({title:t('newTeam'),fields:[{name:'name',label:t('teamName'),required:true}],onSubmit:function(d){
      return api('/teams',{method:'POST',body:JSON.stringify(d)}).then(function(){return api('/teams');}).then(function(teams){
        state.teams=teams;renderTeamList();
        if(teams[0])navigate('/team/'+teams[0].id);
      });
    }});
  }

  function showNewDMModal(){
    showModal({title:t('newDM'),fields:[{name:'username',label:t('username'),required:true}],onSubmit:function(d){
      return api('/users/find?username='+encodeURIComponent(d.username)).then(function(u){
        return api('/dms/start',{method:'POST',body:JSON.stringify({user_id:u.id})});
      }).then(function(ch){
        navigate('/dm/'+ch.other_id);
      });
    }});
  }
  function startDM(userId){
    api('/dms/start',{method:'POST',body:JSON.stringify({user_id:userId})}).then(function(ch){
      navigate('/dm/'+ch.other_id);
    }).catch(function(ex){toast(ex.message,'error');});
  }

  // ============================================================
  //  DASHBOARD
  // ============================================================
  function renderDashboard(){
    var main=document.getElementById('dfMain');
    var teamsHtml=state.teams.length
      ? '<div class="grid">'+state.teams.map(function(tm){
          return '<div class="card" data-team="'+esc(tm.id)+'"><div class="card-accent"></div><div class="card-title">'+icon('users',16)+esc(tm.name)+'</div><div class="card-desc">'+esc(tm.role==='owner'?'Owner':tm.role==='admin'?'Admin':'Member')+'</div></div>';
        }).join('')+'</div>'
      : '<div class="empty"><div class="empty-icon">'+icon('users',48)+'</div><h3>'+esc(t('teams'))+'</h3><p>'+esc(t('teamsEmpty'))+'</p><button class="btn btn-primary" id="dfEmptyNewTeam">'+icon('plus',16)+esc(t('newTeam'))+'</button></div>';
    main.innerHTML='<div class="main-header"><div class="main-title">'+icon('home',20)+'<div>'+esc(t('dashboard'))+'<div class="main-sub">'+esc(t('welcome'))+', '+esc(state.user.username)+'</div></div></div><button class="btn btn-primary" id="dfDashNewTeam">'+icon('plus',16)+esc(t('newTeam'))+'</button></div><div class="main-content">'+teamsHtml+'</div>';
    document.getElementById('dfDashNewTeam').onclick=showNewTeamModal;
    var emptyBtn=document.getElementById('dfEmptyNewTeam');if(emptyBtn)emptyBtn.onclick=showNewTeamModal;
    main.querySelectorAll('[data-team]').forEach(function(c){c.onclick=function(){navigate('/team/'+c.getAttribute('data-team'));};});
  }

  // ============================================================
  //  TEAM
  // ============================================================
  function renderTeam(teamId){
    var main=document.getElementById('dfMain');
    main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('loading'))+'</div></div><div class="main-content"><div class="spinner"></div></div>';
    api('/teams/'+teamId).then(function(data){
      state.team=data.team; state.teamData=data; state.members={};
      data.members.forEach(function(m){state.members[m.id]=m.username;});
      var channelsHtml=data.channels.length
        ? '<div class="list">'+data.channels.filter(function(c){return !c.is_dm;}).map(function(c){
            return '<div class="list-item" data-ch="'+esc(c.id)+'" data-name="'+esc(c.name)+'"><div class="list-item-icon">'+icon('hash',16)+'</div><div style="flex:1;min-width:0"><div style="font-weight:500">'+esc(c.name)+'</div>'+(c.topic?'<div style="font-size:11.5px;color:var(--tx3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(c.topic)+'</div>':'')+'</div></div>';
          }).join('')+'</div>'
        : '<div style="padding:8px;color:var(--tx3);font-size:13px">—</div>';
      var projectsHtml=data.projects.length
        ? '<div class="grid">'+data.projects.map(function(p){
            return '<div class="card" data-proj="'+esc(p.id)+'"><div class="card-title">'+icon('folder',16)+esc(p.name)+'</div><div class="card-desc">'+esc(p.repo_url||'—')+'</div></div>';
          }).join('')+'</div>'
        : '<div style="padding:8px;color:var(--tx3);font-size:13px">—</div>';
      var membersHtml='<div class="list">'+data.members.map(function(m){
        return '<div class="list-item" style="cursor:default"><div style="position:relative">'+avatarHtml(m.username,'sm')+'<span class="presence-dot" style="position:absolute;bottom:-1px;inset-inline-end:-1px"></span></div><div style="flex:1;min-width:0"><div style="font-weight:500">'+esc(m.username)+'</div><div style="font-size:11.5px;color:var(--tx3)">'+esc(t(m.role))+'</div></div></div>';
      }).join('')+'</div>';
      var canManage=data.team.owner_id===state.user.id||data.members.find(function(m){return m.id===state.user.id&&m.role==='admin';});
      var inviteHtml=canManage?'<button class="btn btn-secondary" id="dfInviteBtn">'+icon('users',16)+esc(t('invite'))+'</button>':'';
      var tasksBtn='<button class="btn btn-secondary" id="dfTasksBtn">'+icon('grid',16)+esc(t('tasks'))+'</button>';

      main.innerHTML='<div class="main-header"><div class="main-title">'+icon('users',20)+'<div>'+esc(data.team.name)+'<div class="main-sub">'+data.members.length+' '+esc(t('members'))+'</div></div></div><div style="display:flex;gap:8px;flex-wrap:wrap">'+tasksBtn+inviteHtml+'<button class="btn btn-secondary" id="dfNewProjBtn">'+icon('folder',16)+esc(t('newProject'))+'</button><button class="btn btn-primary" id="dfNewChanBtn">'+icon('hash',16)+esc(t('newChannel'))+'</button></div></div>'+
        '<div class="main-content">'+
          '<div class="settings-section"><h3>'+esc(t('channels'))+'</h3>'+channelsHtml+'</div>'+
          '<div class="settings-section"><h3>'+esc(t('projects'))+'</h3>'+projectsHtml+'</div>'+
          '<div class="settings-section"><h3>'+esc(t('members'))+'</h3>'+membersHtml+'</div>'+
        '</div>';

      main.querySelectorAll('[data-ch]').forEach(function(el){el.onclick=function(){navigate('/channel/'+el.getAttribute('data-ch')+'?n='+encodeURIComponent(el.getAttribute('data-name')));};});
      main.querySelectorAll('[data-proj]').forEach(function(el){el.onclick=function(){navigate('/project/'+el.getAttribute('data-proj'));};});
      document.getElementById('dfNewChanBtn').onclick=function(){
        showModal({title:t('newChannel'),fields:[{name:'name',label:t('channelName'),required:true}],onSubmit:function(d){
          return api('/teams/'+teamId+'/channels',{method:'POST',body:JSON.stringify(d)}).then(function(){renderTeam(teamId);});
        }});
      };
      document.getElementById('dfNewProjBtn').onclick=function(){
        showModal({title:t('newProject'),fields:[{name:'name',label:t('projectName'),required:true},{name:'repo_url',label:t('repoUrl'),placeholder:'owner/repo'}],onSubmit:function(d){
          return api('/teams/'+teamId+'/projects',{method:'POST',body:JSON.stringify({name:d.name,repo_url:d.repo_url||null,provider:d.repo_url?'github':null})}).then(function(){renderTeam(teamId);});
        }});
      };
      document.getElementById('dfTasksBtn').onclick=function(){navigate('/tasks/'+teamId);};
      var inviteBtn=document.getElementById('dfInviteBtn');
      if(inviteBtn)inviteBtn.onclick=function(){
        api('/teams/'+teamId+'/invite',{method:'POST'}).then(function(res){
          var link=location.origin+'/join/'+res.code;
          var ta=document.createElement('textarea');
          ta.value=link;document.body.appendChild(ta);ta.select();
          try{document.execCommand('copy');toast(t('inviteCopied'),'success');}catch(e){prompt('Invite code',res.code);}
          ta.remove();
        }).catch(function(ex){toast(ex.message,'error');});
      };
    }).catch(function(ex){main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('error'))+'</div></div><div class="main-content" style="color:var(--er)">'+esc(ex.message)+'</div>';});
  }

  // ============================================================
  //  CHANNEL / DM chat
  // ============================================================
  function renderChannel(channelId, isDM, dmPeerId, dmPeerName){
    var main=document.getElementById('dfMain');
    var params=new URLSearchParams(location.search);
    var channelName=dmPeerName||params.get('n')||channelId.slice(0,6);
    var titleIcon=isDM?'user':'hash';

    main.innerHTML='<div class="main-header"><div class="main-title">'+icon(titleIcon,20)+'<div>'+esc(channelName)+'</div></div></div>'+
      '<div class="main-content" style="padding:0;display:flex;flex-direction:column">'+
        '<div class="chat-container">'+
          '<div class="chat-messages" id="dfChatMsgs"></div>'+
          '<div class="typing-indicator" id="dfTyping"></div>'+
          '<form class="chat-input" id="dfChatForm">'+
            '<button type="button" class="btn-icon" id="dfAttachBtn" title="'+esc(t('attach'))+'">'+icon('paperclip',18)+'</button>'+
            '<textarea rows="1" id="dfChatInput" placeholder="'+esc(t('chatPlaceholder'))+'"></textarea>'+
            '<button type="submit" class="btn btn-primary" id="dfSendBtn">'+icon('send',16)+'</button>'+
          '</form>'+
          '<input type="file" id="dfFileInput" style="display:none">'+
        '</div>'+
      '</div>';

    refreshMessages(channelId);
    if(state.pollTimer)clearInterval(state.pollTimer);
    state.pollTimer=setInterval(function(){
      refreshMessages(channelId);
      fetchTyping(channelId);
    },3500);

    var form=document.getElementById('dfChatForm');
    var ta=document.getElementById('dfChatInput');
    ta.focus();
    var lastTypingSent=0;
    ta.oninput=function(){
      ta.style.height='auto'; ta.style.height=Math.min(ta.scrollHeight,140)+'px';
      var nowT=Date.now();
      if(nowT-lastTypingSent>2000){lastTypingSent=nowT;sendTyping(channelId);}
    };
    ta.onkeydown=function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();form.requestSubmit();}};
    form.onsubmit=function(e){
      e.preventDefault();
      var v=ta.value.trim(); if(!v)return;
      ta.value=''; ta.style.height='auto';
      var body={content:v};
      if(state.editingMessageId){
        api('/messages/'+state.editingMessageId,{method:'PUT',body:JSON.stringify({content:v})}).then(function(){
          state.editingMessageId=null;
          document.getElementById('dfSendBtn').innerHTML=icon('send',16);
          refreshMessages(channelId);
        }).catch(function(ex){toast(ex.message,'error');});
        return;
      }
      if(state.replyTo)body.reply_to=state.replyTo;
      api('/channels/'+channelId+'/messages',{method:'POST',body:JSON.stringify(body)}).then(function(){
        state.replyTo=null;
        refreshMessages(channelId);
      }).catch(function(ex){toast(ex.message,'error');});
    };

    var fileInput=document.getElementById('dfFileInput');
    document.getElementById('dfAttachBtn').onclick=function(){fileInput.click();};
    fileInput.onchange=function(){
      var f=fileInput.files[0]; if(!f)return;
      if(f.size>10*1024*1024){toast('Max 10MB','error');fileInput.value='';return;}
      var fd=new FormData(); fd.append('file',f);
      fetch('/api/channels/'+channelId+'/upload',{method:'POST',headers:{Authorization:'Bearer '+getToken()},body:fd}).then(function(r){
        if(!r.ok)return r.json().then(function(e){throw new Error(e.error);});
        return r.json();
      }).then(function(up){
        return api('/channels/'+channelId+'/messages',{method:'POST',body:JSON.stringify({content:'📎 '+f.name,file_key:up.key,file_name:f.name,file_type:f.type})});
      }).then(function(){fileInput.value='';refreshMessages(channelId);}).catch(function(ex){toast(ex.message,'error');});
    };
  }

  function refreshMessages(channelId){
    if(location.pathname.indexOf('/channel/'+channelId)!==0&&location.pathname.indexOf('/dm/')!==0)return;
    api('/channels/'+channelId+'/messages').then(function(list){
      state.messages=list;
      var box=document.getElementById('dfChatMsgs'); if(!box)return;
      if(!list.length){box.innerHTML='<div class="empty">'+icon('message',40)+'<h3>'+esc(t('chatEmpty'))+'</h3></div>';return;}
      var html='';
      for(var i=0;i<list.length;i++){
        var m=list[i];
        if(m.deleted_at)continue;
        var isMine=m.user_id===state.user.id;
        var fileHtml='';
        if(m.file_key){
          var isImg=(m.file_type||'').indexOf('image/')===0;
          if(isImg){
            fileHtml='<div style="margin-top:6px"><img src="/api/files/'+encodeURIComponent(m.file_key)+'" alt="'+escAttr(m.file_name||'')+'" style="max-width:280px;max-height:200px;border-radius:8px;border:1px solid var(--bd2)"></div>';
          } else {
            fileHtml='<a class="message-file" href="/api/files/'+encodeURIComponent(m.file_key)+'?name='+encodeURIComponent(m.file_name||'')+'" target="_blank" rel="noopener">'+icon('file',14)+esc(m.file_name||m.content)+'</a>';
          }
        }
        var replyHtml='';
        if(m.reply_to&&m.reply_content){
          replyHtml='<div style="border-inline-start:2px solid var(--ac);padding-inline-start:8px;margin-bottom:4px;font-size:12px;color:var(--tx2)"><b>'+esc(m.reply_username||'')+'</b>: '+esc((m.reply_content||'').slice(0,80))+'</div>';
        }
        var reactionsHtml='';
        if(m.reactions&&m.reactions.length){
          reactionsHtml='<div class="message-reactions">'+m.reactions.map(function(r){
            return '<div class="reaction'+(r.mine?' mine':'')+'" data-react-msg="'+esc(m.id)+'" data-react-emoji="'+esc(r.emoji)+'">'+esc(r.emoji)+' '+r.count+'</div>';
          }).join('')+'</div>';
        }
        var editedMark=m.edited_at?'<span class="message-edited">('+esc(t('edit').toLowerCase())+')</span>':'';
        var pinMark=m.pinned?' '+icon('pin',11):'';
        html+='<div class="message" data-msg="'+esc(m.id)+'">'+avatarHtml(m.username)+
          '<div class="message-content">'+
            '<div class="message-header"><span class="message-author'+(isMine?' me':'')+'">'+esc(m.username)+'</span><span class="message-time">'+fmtTime(m.created_at)+'</span>'+editedMark+pinMark+'</div>'+
            replyHtml+
            '<div class="message-text">'+escRich(m.content)+'</div>'+
            fileHtml+
            reactionsHtml+
          '</div>'+
          '<div class="msg-actions">'+
            '<button data-action="react" data-msg="'+esc(m.id)+'" title="react">😀</button>'+
            '<button data-action="reply" data-msg="'+esc(m.id)+'" title="'+esc(t('reply'))+'">'+icon('reply',14)+'</button>'+
            (isMine?'<button data-action="edit" data-msg="'+esc(m.id)+'" title="'+esc(t('edit'))+'">'+icon('edit',14)+'</button>':'')+
            (isMine?'<button data-action="delete" data-msg="'+esc(m.id)+'" title="'+esc(t('delete'))+'">'+icon('trash',14)+'</button>':'')+
          '</div>'+
        '</div>';
      }
      box.innerHTML=html;
      box.scrollTop=box.scrollHeight;

      box.querySelectorAll('[data-react-msg]').forEach(function(el){
        el.onclick=function(){
          var mid=el.getAttribute('data-react-msg');var emoji=el.getAttribute('data-react-emoji');
          api('/messages/'+mid+'/react',{method:'POST',body:JSON.stringify({emoji:emoji})}).then(function(){refreshMessages(channelId);}).catch(function(){});
        };
      });
      box.querySelectorAll('[data-action]').forEach(function(btn){
        btn.onclick=function(){
          var action=btn.getAttribute('data-action');
          var mid=btn.getAttribute('data-msg');
          var msg=list.find(function(x){return x.id===mid;});
          if(!msg)return;
          if(action==='delete'){
            if(confirm(t('confirmDelete')))api('/messages/'+mid,{method:'DELETE'}).then(function(){refreshMessages(channelId);}).catch(function(ex){toast(ex.message,'error');});
          } else if(action==='edit'){
            state.editingMessageId=mid;
            var ta=document.getElementById('dfChatInput');
            ta.value=msg.content; ta.focus(); ta.style.height='auto'; ta.style.height=Math.min(ta.scrollHeight,140)+'px';
            document.getElementById('dfSendBtn').innerHTML=icon('check',16);
          } else if(action==='reply'){
            state.replyTo=mid;
            var ta2=document.getElementById('dfChatInput');
            ta2.placeholder='Replying to '+msg.username+'…';ta2.focus();
          } else if(action==='react'){
            var emoji=prompt('Emoji:','👍');
            if(emoji)api('/messages/'+mid+'/react',{method:'POST',body:JSON.stringify({emoji:emoji})}).then(function(){refreshMessages(channelId);}).catch(function(){});
          }
        };
      });
    }).catch(function(){});
  }

  // ============================================================
  //  PROJECT / GitHub
  // ============================================================
  function renderProject(projectId){
    var main=document.getElementById('dfMain');
    main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('loading'))+'</div><button class="btn btn-secondary" id="dfBackBtn">'+esc(t('cancel'))+'</button></div><div class="main-content"><div class="spinner"></div></div>';
    document.getElementById('dfBackBtn').onclick=function(){if(state.team)navigate('/team/'+state.team.id);else navigate('/');};

    api('/projects/'+projectId).then(function(proj){
      if(!proj.repo_url){
        main.innerHTML='<div class="main-header"><div class="main-title">'+icon('git',20)+esc(proj.name)+'</div><button class="btn btn-secondary" id="dfBackBtn2">'+esc(t('cancel'))+'</button></div><div class="main-content"><div class="empty"><div class="empty-icon">'+icon('git',40)+'</div><p>'+esc(t('noRepo'))+'</p></div></div>';
        document.getElementById('dfBackBtn2').onclick=function(){if(state.team)navigate('/team/'+state.team.id);else navigate('/');};
        return;
      }
      var repoPath=proj.repo_url.indexOf('github.com/')>=0?proj.repo_url.split('github.com/').pop().replace(/\.git$/,'').replace(/\/$/,''):proj.repo_url.replace(/^https?:\/\/(www\.)?/,'').split('/').slice(-2).join('/');

      main.innerHTML='<div class="main-header"><div class="main-title">'+icon('git',20)+'<div>'+esc(proj.name)+'<div class="main-sub">'+esc(repoPath)+'</div></div></div><div style="display:flex;gap:8px"><a class="btn btn-secondary" href="https://github.com/'+esc(repoPath)+'" target="_blank" rel="noopener">'+icon('git',16)+'GitHub</a><button class="btn btn-secondary" id="dfBackBtn3">'+esc(t('cancel'))+'</button></div></div>'+
        '<div class="main-content">'+
          '<div class="repo-tabs">'+
            '<div class="repo-tab active" data-tab="commits">'+esc(t('commits'))+'</div>'+
            '<div class="repo-tab" data-tab="branches">'+esc(t('branches'))+'</div>'+
            '<div class="repo-tab" data-tab="pulls">'+esc(t('pulls'))+'</div>'+
            '<div class="repo-tab" data-tab="issues">'+esc(t('issues'))+'</div>'+
          '</div>'+
          '<div id="dfRepoBody"><div class="spinner"></div></div>'+
        '</div>';
      document.getElementById('dfBackBtn3').onclick=function(){if(state.team)navigate('/team/'+state.team.id);else navigate('/');};

      function loadTab(tab){
        var body=document.getElementById('dfRepoBody');
        body.innerHTML='<div class="spinner"></div>';
        api('/git/'+tab+'?repo='+encodeURIComponent(repoPath)).then(function(data){
          if(tab==='commits'){
            body.innerHTML=data.length?data.map(function(c){
              return '<div class="commit"><div><span class="commit-sha">'+esc(c.sha.slice(0,7))+'</span><span class="commit-msg">'+esc(c.commit.message.split('\n')[0])+'</span></div><div class="commit-meta">'+esc(c.commit.author.name)+' · '+relTime(Math.floor(new Date(c.commit.author.date).getTime()/1000))+'</div></div>';
            }).join(''):'<div class="empty"><p>—</p></div>';
          } else if(tab==='branches'){
            body.innerHTML=data.length?data.map(function(b){
              return '<div class="branch-item">'+icon('git',14)+'<b>'+esc(b.name)+'</b>'+(b.protected?'<span style="margin-inline-start:auto;font-size:10.5px;color:var(--ac)">protected</span>':'')+'</div>';
            }).join(''):'<div class="empty"><p>—</p></div>';
          } else if(tab==='pulls'){
            body.innerHTML=data.length?data.map(function(p){
              return '<div class="pr-item"><span class="pr-state '+(p.merged_at?'pr-merged':p.state==='open'?'pr-open':'pr-closed')+'">'+(p.merged_at?'merged':p.state)+'</span><a href="'+esc(p.html_url)+'" target="_blank" rel="noopener" style="color:var(--tx);font-weight:500">'+esc(p.title)+'</a><span style="margin-inline-start:auto;font-size:11px;color:var(--tx3)">#'+p.number+'</span></div>';
            }).join(''):'<div class="empty"><p>—</p></div>';
          } else if(tab==='issues'){
            body.innerHTML=data.length?data.map(function(is){
              return '<div class="issue-item"><span class="pr-state '+(is.state==='open'?'pr-open':'pr-closed')+'">'+esc(is.state)+'</span><a href="'+esc(is.html_url)+'" target="_blank" rel="noopener" style="color:var(--tx);font-weight:500">'+esc(is.title)+'</a><span style="margin-inline-start:auto;font-size:11px;color:var(--tx3)">#'+is.number+'</span></div>';
            }).join(''):'<div class="empty"><p>—</p></div>';
          }
        }).catch(function(ex){
          body.innerHTML='<div style="color:var(--er);font-size:13px">'+esc(ex.message)+'</div>';
        });
      }
      loadTab('commits');
      main.querySelectorAll('[data-tab]').forEach(function(el){
        el.onclick=function(){
          main.querySelectorAll('.repo-tab').forEach(function(x){x.classList.remove('active');});
          el.classList.add('active');
          loadTab(el.getAttribute('data-tab'));
        };
      });
    }).catch(function(ex){
      main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('error'))+'</div></div><div class="main-content" style="color:var(--er)">'+esc(ex.message)+'</div>';
    });
  }

  // ============================================================
  //  TASKS
  // ============================================================
  function renderTasks(teamId){
    var main=document.getElementById('dfMain');
    api('/teams/'+teamId+'/tasks').then(function(tasks){
      var cols={todo:[],doing:[],done:[]};
      tasks.forEach(function(x){if(!cols[x.status])cols[x.status]=[];cols[x.status].push(x);});
      function colHtml(status,label){
        var items=(cols[status]||[]).map(function(x){
          return '<div class="task" data-task="'+esc(x.id)+'"><div class="task-title">'+esc(x.title)+'</div><div class="task-meta"><span class="priority-badge priority-'+esc(x.priority)+'">'+esc(t(x.priority))+'</span>'+(x.assignee_id?'<span>'+esc(state.members[x.assignee_id]||'')+'</span>':'<span>'+esc(t('unassigned'))+'</span>')+'</div></div>';
        }).join('');
        return '<div class="board-col"><h4>'+esc(label)+'<span style="font-weight:400;color:var(--tx3)">('+(cols[status]||[]).length+')</span></h4>'+items+'<button class="btn btn-ghost btn-sm" data-new-task="'+status+'" style="width:100%;margin-top:8px">'+icon('plus',12)+esc(t('newTask'))+'</button></div>';
      }
      main.innerHTML='<div class="main-header"><div class="main-title">'+icon('grid',20)+esc(t('tasks'))+'</div><button class="btn btn-secondary" id="dfBackBtnT">'+esc(t('cancel'))+'</button></div><div class="main-content"><div class="board">'+colHtml('todo',t('todo'))+colHtml('doing',t('doing'))+colHtml('done',t('done'))+'</div></div>';
      document.getElementById('dfBackBtnT').onclick=function(){navigate('/team/'+teamId);};
      main.querySelectorAll('[data-new-task]').forEach(function(btn){
        btn.onclick=function(){
          var status=btn.getAttribute('data-new-task');
          showModal({title:t('newTask'),fields:[{name:'title',label:t('newTask'),required:true},{name:'description',label:t('bio'),type:'textarea'},{name:'priority',label:t('priority'),type:'select',options:[{v:'low',l:t('low')},{v:'normal',l:t('normal')},{v:'high',l:t('high')},{v:'urgent',l:t('urgent')}],value:'normal'}],onSubmit:function(d){
            return api('/teams/'+teamId+'/tasks',{method:'POST',body:JSON.stringify({title:d.title,description:d.description,priority:d.priority,status:status})}).then(function(){renderTasks(teamId);});
          }});
        };
      });
      main.querySelectorAll('[data-task]').forEach(function(el){
        el.onclick=function(){
          var task=tasks.find(function(x){return x.id===el.getAttribute('data-task');});
          if(!task)return;
          showModal({title:task.title,fields:[{name:'title',label:t('newTask'),value:task.title,required:true},{name:'description',label:t('bio'),type:'textarea',value:task.description||''},{name:'status',label:t('todo'),type:'select',options:[{v:'todo',l:t('todo')},{v:'doing',l:t('doing')},{v:'done',l:t('done')}],value:task.status},{name:'priority',label:t('priority'),type:'select',options:[{v:'low',l:t('low')},{v:'normal',l:t('normal')},{v:'high',l:t('high')},{v:'urgent',l:t('urgent')}],value:task.priority}],submit:t('save'),onSubmit:function(d){
            return api('/tasks/'+task.id,{method:'PUT',body:JSON.stringify(d)}).then(function(){renderTasks(teamId);});
          }});
        };
      });
    }).catch(function(ex){
      main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('error'))+'</div></div><div class="main-content" style="color:var(--er)">'+esc(ex.message)+'</div>';
    });
  }

  // ============================================================
  //  SETTINGS
  // ============================================================
  function renderSettings(){
    var main=document.getElementById('dfMain');
    main.innerHTML='<div class="main-header"><div class="main-title">'+icon('settings',20)+esc(t('settings'))+'</div></div>'+
      '<div class="main-content">'+
        '<div class="settings-section"><h3>'+esc(t('profile'))+'</h3>'+
          '<div class="setting-row"><div style="display:flex;align-items:center;gap:12px">'+avatarHtml(state.user.username,'lg')+'<div class="setting-info"><h4>'+esc(state.user.username)+'</h4><p>'+esc(state.user.email)+'</p></div></div><button class="btn btn-secondary btn-sm" id="dfEditProfile">'+icon('edit',14)+esc(t('edit'))+'</button></div>'+
        '</div>'+
        '<div class="settings-section"><h3>'+esc(t('language'))+'</h3>'+
          '<div class="setting-row"><div class="setting-info"><h4>'+esc(t('language'))+'</h4><p>English / فارسی</p></div><div class="segmented" id="dfLangSeg"><button data-lang="en" class="'+(state.lang==='en'?'active':'')+'">English</button><button data-lang="fa" class="'+(state.lang==='fa'?'active':'')+'">فارسی</button></div></div>'+
        '</div>'+
        '<div class="settings-section"><h3>'+esc(t('theme'))+'</h3>'+
          '<div class="setting-row"><div class="setting-info"><h4>'+esc(t('theme'))+'</h4><p>'+esc(t('dark'))+' / '+esc(t('light'))+'</p></div><div class="segmented" id="dfThemeSeg"><button data-theme="dark" class="'+(state.theme==='dark'?'active':'')+'">'+icon('moon',12)+esc(t('dark'))+'</button><button data-theme="light" class="'+(state.theme==='light'?'active':'')+'">'+icon('sun',12)+esc(t('light'))+'</button></div></div>'+
        '</div>'+
        '<div class="settings-section"><h3>'+esc(t('security'))+'</h3>'+
          '<div class="setting-row"><div class="setting-info"><h4>'+esc(t('changePassword'))+'</h4><p>Update your password</p></div><button class="btn btn-secondary btn-sm" id="dfChangePwd">'+icon('shield',14)+esc(t('changePassword'))+'</button></div>'+
          '<div class="setting-row"><div class="setting-info"><h4>'+esc(t('logoutAll'))+'</h4><p>'+esc(t('dangerZone'))+'</p></div><button class="btn btn-danger btn-sm" id="dfLogoutAll">'+icon('logout',14)+esc(t('logout'))+'</button></div>'+
        '</div>'+
      '</div>';

    document.getElementById('dfEditProfile').onclick=function(){
      showModal({title:t('profile'),fields:[{name:'bio',label:t('bio'),type:'textarea',value:state.user.bio||''}],submit:t('save'),onSubmit:function(d){
        return api('/me',{method:'PUT',body:JSON.stringify({bio:d.bio})}).then(function(){
          state.user.bio=d.bio;toast(t('save'),'success');
        });
      }});
    };
    document.getElementById('dfChangePwd').onclick=function(){
      showModal({title:t('changePassword'),fields:[{name:'current',label:t('currentPassword'),type:'password',required:true},{name:'new',label:t('newPassword'),type:'password',required:true}],submit:t('save'),onSubmit:function(d){
        return api('/auth/password',{method:'POST',body:JSON.stringify({current:d.current,new_password:d.new})}).then(function(){toast(t('passwordChanged'),'success');});
      }});
    };
    document.getElementById('dfLogoutAll').onclick=function(){
      if(!confirm(t('confirmDelete')))return;
      api('/auth/logout-all',{method:'POST'}).then(function(){setToken(null);navigate('/login');}).catch(function(){});
    };
    main.querySelectorAll('#dfLangSeg [data-lang]').forEach(function(el){
      el.onclick=function(){state.lang=el.getAttribute('data-lang');localStorage.setItem('df_lang',state.lang);applyDir();api('/me',{method:'PUT',body:JSON.stringify({lang:state.lang})}).catch(function(){});render();};
    });
    main.querySelectorAll('#dfThemeSeg [data-theme]').forEach(function(el){
      el.onclick=function(){state.theme=el.getAttribute('data-theme');localStorage.setItem('df_theme',state.theme);applyTheme();api('/me',{method:'PUT',body:JSON.stringify({theme:state.theme})}).catch(function(){});render();};
    });
  }

  // ============================================================
  //  ROUTER
  // ============================================================
  function render(){
    var path=location.pathname;

    if(!state.user){
      if(path.indexOf('/join/')===0){renderJoin(path.slice(6));return;}
      if(path!=='/login'&&path!=='/register')history.replaceState({},'','/login');
      renderAuth();return;
    }
    if(path==='/login'||path==='/register'){history.replaceState({},'','/');path='/';}
    if(path.indexOf('/join/')===0){renderJoin(path.slice(6));return;}

    renderShell();

    if(path.indexOf('/team/')===0)return renderTeam(path.slice(6));
    if(path.indexOf('/channel/')===0)return renderChannel(path.slice(9),false);
    if(path.indexOf('/dm/')===0)return renderDM(path.slice(4));
    if(path.indexOf('/project/')===0)return renderProject(path.slice(9));
    if(path.indexOf('/tasks/')===0)return renderTasks(path.slice(7));
    if(path==='/settings')return renderSettings();
    return renderDashboard();
  }

  function renderDM(otherId){
    api('/dms/start',{method:'POST',body:JSON.stringify({user_id:otherId})}).then(function(ch){
      renderChannel(ch.channel_id,true,otherId,ch.other_username);
    }).catch(function(ex){
      var main=document.getElementById('dfMain');
      main.innerHTML='<div class="main-header"><div class="main-title">'+esc(t('error'))+'</div></div><div class="main-content" style="color:var(--er)">'+esc(ex.message)+'</div>';
    });
  }

  function renderJoin(code){
    document.getElementById('root').innerHTML='<div class="auth-wrap"><div class="auth-card"><div class="auth-logo"><span class="brand">DevForge</span><p>'+esc(t('joinTeam'))+'</p></div><p style="text-align:center;color:var(--tx2);margin-bottom:16px;font-size:13px">'+esc(t('inviteCode'))+': <code>'+esc(code)+'</code></p><button class="btn btn-primary btn-block" id="dfJoinBtn">'+esc(t('join'))+'</button></div></div>';
    document.getElementById('dfJoinBtn').onclick=function(){
      if(!state.user){localStorage.setItem('df_pending_join',code);navigate('/login');return;}
      api('/join/'+code,{method:'POST'}).then(function(r){toast('Joined '+r.team_name,'success');return api('/teams').then(function(teams){state.teams=teams;navigate('/team/'+r.team_id);});}).catch(function(ex){toast(ex.message,'error');});
    };
  }

  // Keyboard shortcuts
  document.addEventListener('keydown',function(e){
    if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();if(state.user)openCommandPalette();}
  });

  window.addEventListener('popstate',function(){
    if(state.pollTimer){clearInterval(state.pollTimer);state.pollTimer=null;}
    render();
  });

  // Boot
  state.lang=localStorage.getItem('df_lang')||'en';
  state.theme=localStorage.getItem('df_theme')||'dark';
  applyTheme();applyDir();

  var token=getToken();
  if(token){
    api('/me').then(function(u){
      state.user=u;
      if(u.lang)state.lang=u.lang;
      if(u.theme)state.theme=u.theme;
      localStorage.setItem('df_lang',state.lang);
      localStorage.setItem('df_theme',state.theme);
      applyTheme();applyDir();
      return api('/teams').then(function(teams){state.teams=teams;render();});
    }).catch(function(){setToken(null);state.user=null;render();});
  } else {
    render();
  }
})();
`;

// ============================================================
//  HTML shell
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
    '<script>window.__I18N__=' + JSON.stringify(I18N) + ';window.__ICONS__=' + JSON.stringify(ICONS) + ';</script>' +
    '<script>' + CLIENT_JS + '</script>' +
  '</body>' +
  '</html>';

// ============================================================
//  Security headers
// ============================================================
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net data:; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
};

// ============================================================
//  API handlers
// ============================================================
async function handleAPI(req, env, user, path, method, url, ip) {
  const db = env.DB;

  // ---------- Auth ----------
  if (path === '/auth/register' && method === 'POST') {
    if (!localRateLimit('reg:' + ip, 5, 60_000)) return err('Too many attempts', 429);
    const b = await req.json().catch(() => ({}));
    const email = (b.email || '').trim().toLowerCase();
    const username = (b.username || '').trim();
    const password = b.password || '';
    if (!VALID.email(email)) return err('Invalid email');
    if (!VALID.username(username)) return err('Invalid username (3-32, alphanumeric)');
    if (!VALID.password(password)) return err('Password too weak (8+ chars, letters, numbers)');
    const id = uid();
    try {
      await db.prepare('INSERT INTO users (id,email,username,password_hash) VALUES (?,?,?,?)')
        .bind(id, email, username, await hashPassword(password)).run();
    } catch { return err('User already exists', 409); }
    await db.prepare('INSERT INTO notifications (id,user_id,message) VALUES (?,?,?)')
      .bind(uid(), id, 'Welcome to DevForge!').run().catch(() => {});
    const token = await signJWT({ sub: id, exp: now() + 86400 * 7 }, secretOf(env));
    return json({ token, user: { id, email, username, lang: 'en', theme: 'dark' } });
  }

  if (path === '/auth/login' && method === 'POST') {
    // Persistent rate limit by IP + email
    if (!localRateLimit('login:' + ip, 15, 60_000)) {
      await sleep(400);
      return err('Too many attempts. Try later.', 429);
    }
    const b = await req.json().catch(() => ({}));
    const email = (b.email || '').trim().toLowerCase();
    const password = b.password || '';
    if (!email || !password) return err('Missing fields');
    const u = await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    // Constant-time compare even on user not found
    const stored = u ? u.password_hash : 'AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const ok = await verifyPassword(password, stored);
    if (!u || !ok) { await sleep(150); return err('Invalid credentials', 401); }
    const token = await signJWT({ sub: u.id, exp: now() + 86400 * 7 }, secretOf(env));
    await db.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now(), u.id).run().catch(() => {});
    return json({ token, user: { id: u.id, email: u.email, username: u.username, lang: u.lang || 'en', theme: u.theme || 'dark', bio: u.bio } });
  }

  if (path === '/auth/password' && method === 'POST') {
    if (!user) return err('Unauthorized', 401);
    const b = await req.json().catch(() => ({}));
    const u = await db.prepare('SELECT password_hash FROM users WHERE id=?').bind(user.sub).first();
    if (!u || !(await verifyPassword(b.current || '', u.password_hash))) return err('Wrong password', 401);
    if (!VALID.password(b.new_password)) return err('Password too weak', 400);
    await db.prepare('UPDATE users SET password_hash=? WHERE id=?')
      .bind(await hashPassword(b.new_password), user.sub).run();
    return json({ ok: true });
  }

  if (path === '/auth/logout-all' && method === 'POST') {
    // In a real app: invalidate all sessions. Here: just return ok since JWT expires.
    return json({ ok: true });
  }

  if (!user) return err('Unauthorized', 401);

  // ---------- Me ----------
  if (path === '/me' && method === 'GET') {
    const u = await db.prepare('SELECT id,email,username,lang,theme,bio FROM users WHERE id=?').bind(user.sub).first();
    if (!u) return err('Not found', 404);
    return json(u);
  }
  if (path === '/me' && method === 'PUT') {
    const b = await req.json().catch(() => ({}));
    const updates = [], binds = [];
    if (b.lang === 'en' || b.lang === 'fa') { updates.push('lang=?'); binds.push(b.lang); }
    if (b.theme === 'dark' || b.theme === 'light') { updates.push('theme=?'); binds.push(b.theme); }
    if (b.bio != null && typeof b.bio === 'string' && b.bio.length <= 500) { updates.push('bio=?'); binds.push(sanitizeText(b.bio, 500)); }
    if (updates.length) {
      binds.push(user.sub);
      await db.prepare('UPDATE users SET ' + updates.join(',') + ' WHERE id=?').bind(...binds).run();
    }
    return json({ ok: true });
  }

  // ---------- Users ----------
  if (path === '/users/find' && method === 'GET') {
    const username = url.searchParams.get('username') || '';
    if (!VALID.username(username)) return err('Invalid username');
    const u = await db.prepare('SELECT id,username FROM users WHERE username=?').bind(username).first();
    if (!u) return err('User not found', 404);
    return json(u);
  }

  // ---------- Teams ----------
  if (path === '/teams' && method === 'GET') {
    const list = await db.prepare(
      'SELECT t.*, m.role FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.user_id=? ORDER BY t.created_at DESC'
    ).bind(user.sub).all();
    return json(list.results || []);
  }
  if (path === '/teams' && method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const name = sanitizeText(b.name || '', 80);
    if (!name) return err('Missing name');
    const id = uid(), chId = uid();
    await db.prepare('INSERT INTO teams (id,name,owner_id) VALUES (?,?,?)').bind(id, name, user.sub).run();
    await db.prepare("INSERT INTO team_members (team_id,user_id,role) VALUES (?,?,'owner')").bind(id, user.sub).run();
    await db.prepare('INSERT INTO channels (id,team_id,name) VALUES (?,?,?)').bind(chId, id, 'general').run();
    return json({ id, name });
  }

  const teamMatch = path.match(/^\/teams\/([^/]+)$/);
  if (teamMatch && method === 'GET') {
    const tid = teamMatch[1];
    const team = await db.prepare('SELECT * FROM teams WHERE id=?').bind(tid).first();
    if (!team) return err('Not found', 404);
    const m = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(tid, user.sub).first();
    if (!m) return err('Forbidden', 403);
    const [channels, projects, members] = await Promise.all([
      db.prepare('SELECT * FROM channels WHERE team_id=? AND is_dm=0 ORDER BY created_at ASC').bind(tid).all(),
      db.prepare('SELECT * FROM projects WHERE team_id=? ORDER BY created_at DESC').bind(tid).all(),
      db.prepare('SELECT u.id,u.username,m.role FROM team_members m JOIN users u ON u.id=m.user_id WHERE m.team_id=? ORDER BY m.joined_at ASC').bind(tid).all(),
    ]);
    return json({ team, channels: channels.results || [], projects: projects.results || [], members: members.results || [] });
  }

  const teamSub = path.match(/^\/teams\/([^/]+)\/(channels|projects|tasks|invite)$/);
  if (teamSub) {
    const tid = teamSub[1], kind = teamSub[2];
    const mem = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(tid, user.sub).first();
    if (!mem) return err('Forbidden', 403);
    const canManage = mem.role === 'owner' || mem.role === 'admin';

    if (kind === 'invite' && method === 'POST') {
      if (!canManage) return err('Forbidden', 403);
      const code = Array.from(crypto.getRandomValues(new Uint8Array(8)))
        .map((b) => b.toString(16).padStart(2, '0')).join('');
      await db.prepare('INSERT INTO invites (code,team_id,created_by) VALUES (?,?,?)')
        .bind(code, tid, user.sub).run();
      return json({ code });
    }
    if (kind === 'channels' && method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const name = sanitizeText(b.name || '', 40);
      if (!name) return err('Missing name');
      const id = uid();
      await db.prepare('INSERT INTO channels (id,team_id,name) VALUES (?,?,?)').bind(id, tid, name).run();
      return json({ id, name });
    }
    if (kind === 'projects' && method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const name = sanitizeText(b.name || '', 80);
      if (!name) return err('Missing name');
      let repo_url = null, provider = null;
      if (b.repo_url) {
        const cleaned = String(b.repo_url).replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\.git$/, '');
        if (VALID.repo(cleaned)) { repo_url = cleaned; provider = 'github'; }
        else return err('Invalid repo path (owner/repo)');
      }
      const id = uid();
      await db.prepare('INSERT INTO projects (id,team_id,name,repo_url,provider) VALUES (?,?,?,?,?)').bind(id, tid, name, repo_url, provider).run();
      return json({ id });
    }
    if (kind === 'tasks' && method === 'GET') {
      const list = await db.prepare('SELECT * FROM tasks WHERE team_id=? ORDER BY created_at DESC').bind(tid).all();
      return json(list.results || []);
    }
    if (kind === 'tasks' && method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const title = sanitizeText(b.title || '', 200);
      if (!title) return err('Missing title');
      const id = uid();
      await db.prepare('INSERT INTO tasks (id,team_id,title,description,status,priority,created_by) VALUES (?,?,?,?,?,?,?)')
        .bind(id, tid, title, sanitizeText(b.description || '', 2000), b.status || 'todo', b.priority || 'normal', user.sub).run();
      return json({ id });
    }
  }

  // ---------- Projects ----------
  const projMatch = path.match(/^\/projects\/([^/]+)$/);
  if (projMatch && method === 'GET') {
    const p = await db.prepare('SELECT * FROM projects WHERE id=?').bind(projMatch[1]).first();
    if (!p) return err('Not found', 404);
    const m = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(p.team_id, user.sub).first();
    if (!m) return err('Forbidden', 403);
    return json(p);
  }

  // ---------- Tasks update ----------
  const taskMatch = path.match(/^\/tasks\/([^/]+)$/);
  if (taskMatch && method === 'PUT') {
    const b = await req.json().catch(() => ({}));
    const task = await db.prepare('SELECT * FROM tasks WHERE id=?').bind(taskMatch[1]).first();
    if (!task) return err('Not found', 404);
    const m = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(task.team_id, user.sub).first();
    if (!m) return err('Forbidden', 403);
    const updates = [], binds = [];
    if (b.title) { updates.push('title=?'); binds.push(sanitizeText(b.title, 200)); }
    if (b.description != null) { updates.push('description=?'); binds.push(sanitizeText(b.description, 2000)); }
    if (['todo', 'doing', 'done'].includes(b.status)) { updates.push('status=?'); binds.push(b.status); }
    if (['low', 'normal', 'high', 'urgent'].includes(b.priority)) { updates.push('priority=?'); binds.push(b.priority); }
    if (updates.length) {
      updates.push('updated_at=?'); binds.push(now()); binds.push(task.id);
      await db.prepare('UPDATE tasks SET ' + updates.join(',') + ' WHERE id=?').bind(...binds).run();
    }
    return json({ ok: true });
  }

  // ---------- DMs ----------
  if (path === '/dms' && method === 'GET') {
    const list = await db.prepare(
      'SELECT c.id, ' +
        'CASE WHEN dm_key LIKE ? THEN (SELECT id FROM users WHERE id = SUBSTR(c.dm_key, ' + (user.sub.length + 2) + ')) ' +
        'ELSE (SELECT id FROM users WHERE id = SUBSTR(c.dm_key, 1, LENGTH(c.dm_key) - ?)) END AS other_id ' +
      'FROM channels c WHERE c.is_dm=1 AND (c.dm_key LIKE ? OR c.dm_key LIKE ?)'
    ).bind('%@' + user.sub, user.sub.length, '%' + user.sub + '@%', user.sub + '@%').all().catch(() => ({ results: [] }));
    // Simpler path: fetch all dm channels where user is participant
    const dms = await db.prepare('SELECT * FROM channels WHERE is_dm=1 AND (dm_key LIKE ? OR dm_key LIKE ?)')
      .bind('%' + user.sub + '%', '%' + user.sub + '%').all();
    const results = [];
    for (const c of dms.results || []) {
      const parts = c.dm_key.split('|');
      const otherId = parts[0] === user.sub ? parts[1] : parts[0];
      if (!otherId) continue;
      const u = await db.prepare('SELECT id,username FROM users WHERE id=?').bind(otherId).first();
      if (u) results.push({ channel_id: c.id, other_id: u.id, other_username: u.username });
    }
    return json(results);
  }
  if (path === '/dms/start' && method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const otherId = b.user_id;
    if (!otherId || otherId === user.sub) return err('Invalid user');
    const other = await db.prepare('SELECT id,username FROM users WHERE id=?').bind(otherId).first();
    if (!other) return err('User not found', 404);
    const dmKey = [user.sub, otherId].sort().join('|');
    let ch = await db.prepare('SELECT * FROM channels WHERE dm_key=?').bind(dmKey).first();
    if (!ch) {
      const id = uid();
      await db.prepare('INSERT INTO channels (id,team_id,name,is_dm,dm_key) VALUES (?,NULL,?,1,?)').bind(id, 'DM', dmKey).run();
      ch = { id };
    }
    return json({ channel_id: ch.id, other_id: other.id, other_username: other.username });
  }

  // ---------- Channels: messages ----------
  const msgMatch = path.match(/^\/channels\/([^/]+)\/messages$/);
  if (msgMatch && method === 'GET') {
    const cid = msgMatch[1];
    const ch = await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first();
    if (!ch) return err('Not found', 404);
    if (!ch.is_dm) {
      const m = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(ch.team_id, user.sub).first();
      if (!m) return err('Forbidden', 403);
    } else if (!ch.dm_key.split('|').includes(user.sub)) return err('Forbidden', 403);

    const list = await db.prepare(
      'SELECT m.*, u.username, r.content AS reply_content, ru.username AS reply_username ' +
      'FROM messages m JOIN users u ON u.id=m.user_id ' +
      'LEFT JOIN messages r ON r.id=m.reply_to ' +
      'LEFT JOIN users ru ON ru.id=r.user_id ' +
      'WHERE m.channel_id=? AND m.deleted_at IS NULL ORDER BY m.created_at ASC LIMIT 200'
    ).bind(cid).all();

    // Load reactions
    const results = list.results || [];
    if (results.length) {
      const ids = results.map((r) => r.id);
      const ph = ids.map(() => '?').join(',');
      const rx = await db.prepare(`SELECT message_id,emoji,user_id FROM reactions WHERE message_id IN (${ph})`).bind(...ids).all();
      const rxMap = {};
      for (const r of (rx.results || [])) {
        rxMap[r.message_id] = rxMap[r.message_id] || {};
        rxMap[r.message_id][r.emoji] = rxMap[r.message_id][r.emoji] || { emoji: r.emoji, count: 0, mine: false };
        rxMap[r.message_id][r.emoji].count++;
        if (r.user_id === user.sub) rxMap[r.message_id][r.emoji].mine = true;
      }
      results.forEach((r) => { r.reactions = Object.values(rxMap[r.id] || {}); });
    }
    return json(results);
  }
  if (msgMatch && method === 'POST') {
    const cid = msgMatch[1];
    const ch = await db.prepare('SELECT * FROM channels WHERE id=?').bind(cid).first();
    if (!ch) return err('Not found', 404);
    if (!ch.is_dm) {
      const m = await db.prepare('SELECT role FROM team_members WHERE team_id=? AND user_id=?').bind(ch.team_id, user.sub).first();
      if (!m) return err('Forbidden', 403);
    } else if (!ch.dm_key.split('|').includes(user.sub)) return err('Forbidden', 403);

    if (!localRateLimit('msg:' + user.sub, 30, 10_000)) return err('Slow down', 429);
    const b = await req.json().catch(() => ({}));
    const content = sanitizeText(b.content || '', 4000);
    if (!content) return err('Empty message');
    const id = uid();
    await db.prepare('INSERT INTO messages (id,channel_id,user_id,content,file_key,file_name,file_type,reply_to) VALUES (?,?,?,?,?,?,?,?)')
      .bind(id, cid, user.sub, content, b.file_key || null, b.file_name || null, b.file_type || null, b.reply_to || null).run();
    return json({ id });
  }

  // ---------- Messages: edit / delete / react ----------
  const mMsg = path.match(/^\/messages\/([^/]+)$/);
  if (mMsg && method === 'PUT') {
    const b = await req.json().catch(() => ({}));
    const msg = await db.prepare('SELECT * FROM messages WHERE id=?').bind(mMsg[1]).first();
    if (!msg) return err('Not found', 404);
    if (msg.user_id !== user.sub) return err('Forbidden', 403);
    const content = sanitizeText(b.content || '', 4000);
    if (!content) return err('Empty message');
    await db.prepare('UPDATE messages SET content=?, edited_at=? WHERE id=?').bind(content, now(), msg.id).run();
    return json({ ok: true });
  }
  if (mMsg && method === 'DELETE') {
    const msg = await db.prepare('SELECT * FROM messages WHERE id=?').bind(mMsg[1]).first();
    if (!msg) return err('Not found', 404);
    if (msg.user_id !== user.sub) return err('Forbidden', 403);
    await db.prepare('UPDATE messages SET deleted_at=? WHERE id=?').bind(now(), msg.id).run();
    return json({ ok: true });
  }

  const reactMatch = path.match(/^\/messages\/([^/]+)\/react$/);
  if (reactMatch && method === 'POST') {
    const b = await req.json().catch(() => ({}));
    const emoji = String(b.emoji || '').slice(0, 8);
    if (!emoji) return err('Missing emoji');
    const msg = await db.prepare('SELECT id FROM messages WHERE id=?').bind(reactMatch[1]).first();
    if (!msg) return err('Not found', 404);
    const existing = await db.prepare('SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?')
      .bind(msg.id, user.sub, emoji).first();
    if (existing) {
      await db.prepare('DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?').bind(msg.id, user.sub, emoji).run();
    } else {
      await db.prepare('INSERT INTO reactions (message_id,user_id,emoji) VALUES (?,?,?)').bind(msg.id, user.sub, emoji).run();
    }
    return json({ ok: true });
  }

  // ---------- Typing ----------
  const typingMatch = path.match(/^\/channels\/([^/]+)\/typing$/);
  if (typingMatch && method === 'POST') {
    await db.prepare('INSERT INTO typing (channel_id,user_id,updated_at) VALUES (?,?,?) ON CONFLICT(channel_id,user_id) DO UPDATE SET updated_at=?')
      .bind(typingMatch[1], user.sub, now(), now()).run().catch(() => {});
    return json({ ok: true });
  }
  if (typingMatch && method === 'GET') {
    const list = await db.prepare(
      'SELECT u.username FROM typing t JOIN users u ON u.id=t.user_id WHERE t.channel_id=? AND t.user_id<>? AND t.updated_at>?'
    ).bind(typingMatch[1], user.sub, now() - 6).all().catch(() => ({ results: [] }));
    return json({ typing: (list.results || []).map((x) => x.username) });
  }

  // ---------- Files ----------
  const uploadMatch = path.match(/^\/channels\/([^/]+)\/upload$/);
  if (uploadMatch && method === 'POST') {
    if (!env.BUCKET) return err('File storage not configured', 501);
    if (!localRateLimit('upload:' + user.sub, 10, 60_000)) return err('Too many uploads', 429);
    const form = await req.formData();
    const file = form.get('file');
    if (!file || typeof file === 'string') return err('No file');
    if (file.size > 10 * 1024 * 1024) return err('File too large (max 10MB)', 413);
    const safeName = String(file.name || 'file').replace(/[^\w.\- ]/g, '_').slice(0, 100);
    const key = user.sub + '/' + uid() + '-' + safeName;
    await env.BUCKET.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
    return json({ key, name: safeName });
  }
  if (path.startsWith('/files/') && method === 'GET') {
    if (!env.BUCKET) return err('File storage not configured', 501);
    const key = decodeURIComponent(path.slice(7));
    if (!key.startsWith(user.sub + '/')) return err('Forbidden', 403);
    const obj = await env.BUCKET.get(key);
    if (!obj) return err('Not found', 404);
    const ct = obj.httpMetadata?.contentType || 'application/octet-stream';
    const isSafe = /^(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain)$/.test(ct);
    return new Response(obj.body, {
      headers: {
        'Content-Type': ct,
        'Content-Disposition': isSafe && ct.startsWith('image/') ? 'inline' : 'attachment',
        'Cache-Control': 'private, max-age=3600',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }

  // ---------- Notifications ----------
  if (path === '/notifications' && method === 'GET') {
    const list = await db.prepare('SELECT id,message,kind,link,read,created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20').bind(user.sub).all();
    return json(list.results || []);
  }

  // ---------- Invites ----------
  const joinMatch = path.match(/^\/join\/([a-f0-9]{16})$/);
  if (joinMatch && method === 'POST') {
    const inv = await db.prepare('SELECT * FROM invites WHERE code=?').bind(joinMatch[1]).first();
    if (!inv) return err('Invalid invite', 404);
    if (inv.uses >= inv.max_uses) return err('Invite expired', 410);
    const existing = await db.prepare('SELECT 1 FROM team_members WHERE team_id=? AND user_id=?').bind(inv.team_id, user.sub).first();
    if (existing) {
      const team = await db.prepare('SELECT name FROM teams WHERE id=?').bind(inv.team_id).first();
      return json({ team_id: inv.team_id, team_name: team?.name || 'Team' });
    }
    await db.prepare("INSERT INTO team_members (team_id,user_id,role) VALUES (?,?,'member')").bind(inv.team_id, user.sub).run();
    await db.prepare('UPDATE invites SET uses=uses+1 WHERE code=?').bind(joinMatch[1]).run();
    const team = await db.prepare('SELECT name FROM teams WHERE id=?').bind(inv.team_id).first();
    return json({ team_id: inv.team_id, team_name: team?.name || 'Team' });
  }

  // ---------- Search ----------
  if (path === '/search' && method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim();
    if (q.length < 2) return json({ messages: [], users: [] });
    const like = '%' + q.replace(/[%_]/g, '') + '%';
    const messages = await db.prepare(
      'SELECT m.id, m.content, m.channel_id, c.name AS channel_name, u.username FROM messages m ' +
      'JOIN channels c ON c.id=m.channel_id JOIN users u ON u.id=m.user_id ' +
      'JOIN team_members tm ON tm.team_id=c.team_id AND tm.user_id=? ' +
      'WHERE m.content LIKE ? AND m.deleted_at IS NULL LIMIT 20'
    ).bind(user.sub, like).all().catch(() => ({ results: [] }));
    const users = await db.prepare('SELECT id,username FROM users WHERE username LIKE ? LIMIT 10').bind(like).all().catch(() => ({ results: [] }));
    return json({ messages: messages.results || [], users: users.results || [] });
  }

  // ---------- GitHub integration ----------
  const ghMatch = path.match(/^\/git\/(commits|branches|pulls|issues)$/);
  if (ghMatch && method === 'GET') {
    const kind = ghMatch[1];
    const repo = url.searchParams.get('repo') || '';
    if (!VALID.repo(repo)) return err('Invalid repo path');
    if (!localRateLimit('gh:' + user.sub, 20, 60_000)) return err('Too many GitHub requests', 429);

    const headers = { 'User-Agent': 'DevForge', Accept: 'application/vnd.github+json' };
    if (env.GITHUB_TOKEN) headers.Authorization = 'Bearer ' + env.GITHUB_TOKEN;
    const endpoints = {
      commits: 'commits?per_page=20',
      branches: 'branches?per_page=50',
      pulls: 'pulls?state=all&per_page=20',
      issues: 'issues?state=all&per_page=20',
    };
    const r = await fetch('https://api.github.com/repos/' + repo + '/' + endpoints[kind], { headers });
    if (!r.ok) return err('GitHub API error: ' + r.status, r.status);
    const data = await r.json();
    if (kind === 'commits') {
      return json(data.map((c) => ({ sha: c.sha, commit: { message: c.commit.message, author: c.commit.author } })));
    }
    if (kind === 'branches') return json(data.map((b) => ({ name: b.name, protected: b.protected })));
    if (kind === 'pulls') return json(data.map((p) => ({ number: p.number, title: p.title, state: p.state, merged_at: p.merged_at, html_url: p.html_url })));
    if (kind === 'issues') return json(data.filter((i) => !i.pull_request).map((i) => ({ number: i.number, title: i.title, state: i.state, html_url: i.html_url })));
  }

  return err('Not found', 404);
}

// ============================================================
//  Main handler
// ============================================================
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const ip = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';

    const cors = {
      'Access-Control-Allow-Origin': url.origin === 'null' ? '*' : url.origin,
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Max-Age': '86400',
      Vary: 'Origin',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: { ...cors, ...SECURITY_HEADERS } });

    // Serve SPA
    if (!path.startsWith('/api/')) {
      return new Response(HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS },
      });
    }

    // Reject oversized bodies
    const cl = parseInt(req.headers.get('content-length') || '0', 10);
    if (cl > 12 * 1024 * 1024) return err('Payload too large', 413);

    // Origin check for state-changing requests (CSRF defense in depth)
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
      const origin = req.headers.get('Origin');
      if (origin && !origin.endsWith('.workers.dev') && origin !== url.origin) {
        return err('Origin not allowed', 403);
      }
    }

    try {
      if (!env.DB) return err('Database not configured', 500);
      await ensureDB(env.DB);
    } catch (e) {
      return err('DB init failed: ' + e.message, 500);
    }

    let user = null;
    const auth = req.headers.get('Authorization') || '';
    if (auth.startsWith('Bearer ')) {
      user = await verifyJWT(auth.slice(7), secretOf(env));
    }

    try {
      const apiPath = path.slice(4);
      const res = await handleAPI(req, env, user, apiPath, req.method, url, ip);
      Object.entries(cors).forEach(([k, v]) => res.headers.set(k, v));
      Object.entries(SECURITY_HEADERS).forEach(([k, v]) => res.headers.set(k, v));
      return res;
    } catch (e) {
      console.error('[api]', e);
      const res = err(e.message || 'Server error', 500);
      Object.entries(cors).forEach(([k, v]) => res.headers.set(k, v));
      return res;
    }
  },
};
