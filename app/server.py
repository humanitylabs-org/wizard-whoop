"""WHOOP: the WHOOP connector for a Wizard box (contract wizard.health-data/1).

Setup happens on this app's own screen. The owner creates a free WHOOP developer app, pastes its Client ID and
Client Secret here (stored server-side, never sent back), then signs in to WHOOP with OAuth 2.0. WHOOP sends the
one-time code to the Redirect URL the owner registered: either this app's own https address (the app finishes on
its own) or a loopback address such as http://localhost:3000/callback, in which case the owner pastes the address
the browser landed on back into the app. The code is useless without the client secret that never leaves the box.

The app keeps a local SQLite copy of cycles (strain), recovery, sleep and workouts: a full-history backfill after
sign-in, then an incremental sync every 20 minutes (every 5 minutes inside the morning window, WHOOP_MORNING_WINDOW /
WHOOP_MORNING_SYNC_MINUTES / WHOOP_TZ) with a few days of overlap so re-scored records are updated.
WHOOP has no webhooks on a private box, so polling is the update path. Other apps on the box (the Health app) read
the copy through the box-only health-data contract: GET /api/status and GET /api/days (docs/health-data-contract.md).
Every stored change bumps a sequence number, so readers can ask for only the days changed since their cursor.

Stdlib only. Secrets live in DATA_DIR (0600 files, 0700 folder) and are never returned by any API or tool.
"""
import base64
import datetime as dt
import json
import os
import re
import secrets
import sqlite3
import struct
import threading
import time
import urllib.error
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

ROOT = Path(__file__).resolve().parent.parent if '__file__' in globals() else Path(os.environ.get('APP_ROOT', '.')).resolve()
DATA = Path(os.environ.get('DATA_DIR', ROOT / '.data'))
APP_ID = 'wizard-whoop'
VERSION = '0.2.8'
PREFIX = '/' + APP_ID
PORT = os.environ.get('PORT', '8824')
OAUTH_BASE = os.environ.get('WHOOP_OAUTH_BASE', 'https://api.prod.whoop.com/oauth/oauth2').rstrip('/')
API_BASE = os.environ.get('WHOOP_API_BASE', 'https://api.prod.whoop.com/developer').rstrip('/')
AUTH_URL = OAUTH_BASE + '/auth'
TOKEN_URL = OAUTH_BASE + '/token'
DASHBOARD_URL = 'https://developer-dashboard.whoop.com'
SIGNUP_URL = os.environ.get('WHOOP_SIGNUP_URL', 'https://www.whoop.com/membership/')
DEFAULT_REDIRECT = 'http://localhost:3000/callback'
SUGGESTED_APP_NAME = 'Wizard Health'   # the WHOOP developer app's name; any name works
READ_SCOPES = ['read:recovery', 'read:cycles', 'read:sleep', 'read:workout', 'read:profile', 'read:body_measurement']
SCOPE = ' '.join(['offline'] + READ_SCOPES)
SYNC_MINUTES = float(os.environ.get('WHOOP_SYNC_MINUTES', '20'))
# Mornings sync faster so a night that just ended reaches Health (and a morning report) within minutes of waking.
# Window in the owner's local time: WHOOP_TZ (IANA name) if set, else the zone of his latest WHOOP record, else the box.
MORNING_WINDOW = os.environ.get('WHOOP_MORNING_WINDOW', '05:00-11:00')   # empty = off
MORNING_SYNC_MINUTES = float(os.environ.get('WHOOP_MORNING_SYNC_MINUTES', '5'))
META_MINUTES = float(os.environ.get('WHOOP_META_MINUTES', '360'))   # profile + body change rarely: refresh every 6 h
STATE_TTL = float(os.environ.get('WHOOP_STATE_TTL', str(2 * 3600)))   # a sign-in started here stays valid for two hours
OVERLAP_DAYS = int(os.environ.get('WHOOP_OVERLAP_DAYS', '4'))
PAGE = 25
REQUEST_GAP = float(os.environ.get('WHOOP_REQUEST_GAP', '0.7'))   # ~85 requests a minute, under WHOOP's 100
RETRIES = int(os.environ.get('WHOOP_RETRIES', '5'))
BACKOFF = float(os.environ.get('WHOOP_BACKOFF', '5'))
UA = f'{APP_ID}/{VERSION} (+Wizard OS)'
STATIC = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml'}
FORWARDED = ('tailscale-user-login', 'x-forwarded-for', 'forwarded', 'x-real-ip', 'cf-connecting-ip')
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
COLLECTIONS = [('cycle', '/v2/cycle'), ('recovery', '/v2/recovery'), ('sleep', '/v2/activity/sleep'), ('workout', '/v2/activity/workout')]
LOCK = threading.RLock()          # local files + database
TOKEN_LOCK = threading.Lock()     # one refresh at a time: WHOOP refresh tokens rotate
SYNC_LOCK = threading.Lock()
WAKE = threading.Event()


class Problem(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


class WhoopError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# ---------------- private storage ----------------

def _private():
    DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    return DATA


def _write_secret(name, text):
    p = _private() / name
    tmp = p.with_name('.' + name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def _read(name):
    try:
        return json.loads((DATA / name).read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _shred(name):
    p = DATA / name
    try:
        size = p.stat().st_size
        with open(p, 'r+b') as f:
            f.write(b'\0' * size)
            f.flush()
            os.fsync(f.fileno())
        p.unlink()
    except FileNotFoundError:
        pass


def _keys():
    return _read('client.json')


def _tokens():
    return _read('tokens.json')


def _save_tokens(t):
    with LOCK:
        if t:
            _write_secret('tokens.json', json.dumps(t))
        else:
            _shred('tokens.json')


def _state():
    return _read('state.json')


def _update_state(**kv):
    with LOCK:
        s = _state()
        for k, v in kv.items():
            if v is None:
                s.pop(k, None)
            else:
                s[k] = v
        _write_secret('state.json', json.dumps(s))
        return s


def secure_files():
    """Runtipi loosens app-data permissions; tighten them again on every start."""
    db().close()
    for p in DATA.iterdir():
        if p.is_file():
            os.chmod(p, 0o600)


def db():
    path = _private() / 'whoop.sqlite3'
    fresh = not path.exists()
    c = sqlite3.connect(path, timeout=15)
    if fresh:
        os.chmod(path, 0o600)
    c.row_factory = sqlite3.Row
    c.executescript('''
      CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, start TEXT, end_at TEXT, updated_at TEXT,
        cycle_id TEXT, sleep_id TEXT, nap INTEGER DEFAULT 0, score_state TEXT, day TEXT, data TEXT NOT NULL,
        PRIMARY KEY (kind, id));
      CREATE INDEX IF NOT EXISTS records_day ON records(kind, day);
      CREATE INDEX IF NOT EXISTS records_cycle ON records(kind, cycle_id);
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, data TEXT NOT NULL);
    ''')
    cols = {r[1] for r in c.execute('PRAGMA table_info(records)')}
    if 'changed_seq' not in cols:   # 0.2.0: change sequence for the health-data contract's changed_since cursor
        with c:
            c.execute('ALTER TABLE records ADD COLUMN changed_seq INTEGER NOT NULL DEFAULT 0')
            c.execute('UPDATE records SET changed_seq=1')
            c.execute("INSERT OR REPLACE INTO meta (key,data) VALUES ('seq','1')")
            c.execute("INSERT OR REPLACE INTO meta (key,data) VALUES ('reemit_need_parts','1')")   # everything just moved
    c.execute('CREATE INDEX IF NOT EXISTS records_changed ON records(changed_seq)')
    if not c.execute("SELECT 1 FROM meta WHERE key='reemit_need_parts'").fetchone():
        # 0.2.7 added sleep.need_parts: move every record once so front ends re-read their days with the new field
        with c:
            if c.execute('SELECT 1 FROM records LIMIT 1').fetchone():
                c.execute('UPDATE records SET changed_seq=?', (_next_seq(c),))
            c.execute("INSERT OR REPLACE INTO meta (key,data) VALUES ('reemit_need_parts','1')")
    return c


def _next_seq(c):
    n = int(json.loads((c.execute("SELECT data FROM meta WHERE key='seq'").fetchone() or ['0'])[0])) + 1
    c.execute("INSERT OR REPLACE INTO meta (key,data) VALUES ('seq',?)", (str(n),))
    return n


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _iso(t):
    return t.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def _parse(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace('Z', '+00:00'))
    except ValueError:
        return None


def _offset(s):
    m = re.match(r'^([+-])(\d{2}):?(\d{2})$', s or '')
    if not m:
        return dt.timezone.utc
    mins = int(m.group(2)) * 60 + int(m.group(3))
    return dt.timezone(dt.timedelta(minutes=-mins if m.group(1) == '-' else mins))


def _window(spec=None):
    """'HH:MM-HH:MM' -> (start, end) minutes after midnight, or None when off/invalid."""
    m = re.match(r'^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$', MORNING_WINDOW if spec is None else spec or '')
    if not m:
        return None
    a, b = int(m[1]) * 60 + int(m[2]), int(m[3]) * 60 + int(m[4])
    return (a, b) if a != b and max(a, b) <= 24 * 60 else None


def _local_tz():
    name = os.environ.get('WHOOP_TZ', '').strip()
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            pass
    try:
        with LOCK:
            c = db()
            row = c.execute("SELECT data FROM records WHERE kind='sleep' ORDER BY start DESC LIMIT 1").fetchone()
            c.close()
        off = (json.loads(row['data']) or {}).get('timezone_offset') if row else None
        if off:
            return _offset(off)
    except Exception:
        pass
    return dt.datetime.now().astimezone().tzinfo


def sync_minutes(now=None, tz=None):
    """Minutes between syncs right now: MORNING_SYNC_MINUTES inside the morning window, SYNC_MINUTES otherwise.
    Each incremental sync is ~4-6 WHOOP calls, so 5-minute mornings stay far below WHOOP's 100/min and 10,000/day."""
    w = _window()
    if not w or MORNING_SYNC_MINUTES <= 0:
        return SYNC_MINUTES
    local = (now or _now()).astimezone(tz or _local_tz())
    t = local.hour * 60 + local.minute
    inside = w[0] <= t < w[1] if w[0] < w[1] else (t >= w[0] or t < w[1])   # a window may wrap past midnight
    return min(SYNC_MINUTES, MORNING_SYNC_MINUTES) if inside else SYNC_MINUTES


def _ago(iso):
    t = _parse(iso)
    return (_now() - t).total_seconds() if t else 1e12


# ---------------- WHOOP HTTP ----------------

def _http(method, url, form=None, headers=None, timeout=45):
    data = urlencode(form).encode() if form is not None else None
    h = {'User-Agent': UA, 'Accept': 'application/json'}
    if form is not None:
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})
    except (urllib.error.URLError, TimeoutError, OSError):
        raise WhoopError(0, 'unreachable', 'WHOOP did not answer. Check the box is online; the app will retry.') from None


def _json(b):
    try:
        return json.loads(b or b'{}')
    except ValueError:
        return {}


def _token_call(form):
    k = _keys()
    if not k.get('client_id') or not k.get('client_secret'):
        raise Problem(409, 'Save your WHOOP Client ID and Client Secret first (step 4).')
    form = dict(form, client_id=k['client_id'], client_secret=k['client_secret'])
    status, body, _ = _http('POST', TOKEN_URL, form=form)
    return status, _json(body)


def test_keys():
    """Exchange a made-up code: WHOOP answers invalid_grant when the client is real, invalid_client when not."""
    k = _keys()
    if not k.get('client_id') or not k.get('client_secret'):
        raise Problem(409, 'Save your WHOOP Client ID and Client Secret first.')
    status, d = _token_call({'grant_type': 'authorization_code', 'code': 'wizard-key-check-' + secrets.token_hex(8),
                             'redirect_uri': k.get('redirect_uri') or DEFAULT_REDIRECT})
    err = str(d.get('error') or '')
    if err == 'invalid_grant':
        result, msg = 'valid', 'WHOOP recognised your Client ID and Client Secret. You can connect now.'
    elif err in ('invalid_client', 'unauthorized_client'):
        result, msg = 'invalid', 'WHOOP did not accept this Client ID and Client Secret. Copy both again from your WHOOP app and save.'
    elif status == 429:
        result, msg = 'unknown', 'WHOOP is busy right now. Try the test again in a minute.'
    else:
        result, msg = 'unknown', 'WHOOP gave an unexpected answer, so the keys could not be confirmed. Try again shortly.'
    with LOCK:
        k = _keys()
        if k:
            k.update(verified=result, checked_at=_iso(_now()))
            _write_secret('client.json', json.dumps(k))
    return {'result': result, 'message': msg}


def save_keys(body):
    cid = str(body.get('client_id') or '').strip()
    secret = str(body.get('client_secret') or '').strip()
    redirect = str(body.get('redirect_uri') or '').strip() or DEFAULT_REDIRECT
    if not re.fullmatch(r'[A-Za-z0-9._~-]{8,200}', cid):
        raise Problem(400, 'That Client ID does not look right. Copy it again from your WHOOP app.')
    if not re.fullmatch(r'[\x21-\x7e]{8,300}', secret):
        raise Problem(400, 'That Client Secret does not look right. Copy it again from your WHOOP app.')
    u = urlsplit(redirect)
    if u.scheme not in ('http', 'https') or not u.netloc or len(redirect) > 300:
        raise Problem(400, 'The Redirect URL must be the exact http(s) address you entered in your WHOOP app.')
    if u.scheme == 'http' and u.hostname not in ('localhost', '127.0.0.1'):
        raise Problem(400, 'WHOOP accepts plain http only for localhost. Use https or http://localhost:3000/callback.')
    with LOCK:
        old = _keys()
        changed = old.get('client_id') != cid or old.get('client_secret') != secret
        _write_secret('client.json', json.dumps({'client_id': cid, 'client_secret': secret, 'redirect_uri': redirect,
                                                 'saved_at': _iso(_now()), 'verified': None}))
        if changed and _tokens():
            _save_tokens(None)   # tokens belong to the old WHOOP app; sign in again with the new one
            _update_state(auth='needs_login', pending=None)
    return setup_info()


def forget_keys():
    with LOCK:
        _shred('client.json')
        _save_tokens(None)
        _update_state(pending=None, auth=None)
    return setup_info()


def _mask(v):
    v = str(v or '')
    return ('•' * 6 + v[-4:]) if len(v) > 8 else '•' * 6


def setup_info():
    k = _keys()
    return {'dashboard_url': DASHBOARD_URL, 'signup_url': SIGNUP_URL, 'suggested_name': SUGGESTED_APP_NAME,
            'default_redirect': DEFAULT_REDIRECT, 'scopes': READ_SCOPES, 'keys_saved': bool(k.get('client_id') and k.get('client_secret')),
            'client_id_hint': _mask(k.get('client_id')) if k.get('client_id') else None, 'secret_saved': bool(k.get('client_secret')),
            'redirect_uri': k.get('redirect_uri'), 'verified': k.get('verified'), 'checked_at': k.get('checked_at'),
            'connected': bool(_tokens().get('refresh_token') or _tokens().get('access_token'))}


# ---------------- OAuth sign-in ----------------

def login_start():
    k = _keys()
    if not k.get('client_id') or not k.get('client_secret'):
        raise Problem(409, 'Save your WHOOP Client ID and Client Secret first (step 4).')
    state = secrets.token_hex(16)
    with LOCK:
        pend = [p for p in (_state().get('pending') or []) if _ago(p.get('at')) < STATE_TTL][-4:]
        pend.append({'state': state, 'at': _iso(_now())})
        _update_state(pending=pend)
    q = {'response_type': 'code', 'client_id': k['client_id'], 'redirect_uri': k.get('redirect_uri') or DEFAULT_REDIRECT,
         'scope': SCOPE, 'state': state}
    return {'authorize_url': AUTH_URL + '?' + urlencode(q), 'redirect_uri': q['redirect_uri'],
            'paste_back': urlsplit(q['redirect_uri']).hostname in ('localhost', '127.0.0.1')}


def login_finish(pasted):
    raw = str(pasted or '').strip()
    if not raw or len(raw) > 4096:
        raise Problem(400, 'Paste the whole address from the browser bar after you tapped Grant.')
    u = urlsplit(raw if '://' in raw else 'http://x/?' + raw.lstrip('?'))
    q = {a: b[0] for a, b in parse_qs(u.query).items()}
    if q.get('error'):
        _update_state(pending=None)
        msg = 'You chose not to allow access.' if q['error'] == 'access_denied' else 'WHOOP did not finish the sign-in.'
        raise Problem(400, msg + ' Tap Connect with WHOOP to try again.')
    code, state = q.get('code'), q.get('state')
    if not code or not state:
        raise Problem(400, 'That address has no sign-in code. Paste the whole address, starting with http.')
    with LOCK:
        pend = [p for p in (_state().get('pending') or []) if _ago(p.get('at')) < STATE_TTL]
        if not any(secrets.compare_digest(p['state'], state) for p in pend):
            raise Problem(400, 'This sign-in link expired or was already used. Tap Connect with WHOOP to start again.')
        _update_state(pending=[p for p in pend if p['state'] != state])
    k = _keys()
    status, d = _token_call({'grant_type': 'authorization_code', 'code': code, 'redirect_uri': k.get('redirect_uri') or DEFAULT_REDIRECT})
    if status != 200 or not d.get('access_token'):
        err = d.get('error')
        if err == 'invalid_client':
            raise Problem(400, 'WHOOP did not accept the saved Client ID and Client Secret. Replace the keys and try again.')
        if err == 'invalid_grant':
            raise Problem(400, 'WHOOP refused this code. It may have been used already or the Redirect URL does not match. Tap Connect with WHOOP again.')
        raise Problem(502, 'WHOOP did not finish the sign-in. Try again in a minute.')
    _store_tokens(d)
    _update_state(auth='connected', last_error=None, connected_at=_iso(_now()))
    start_sync_thread(full=not _state().get('backfilled'))
    return status_info()


def _store_tokens(d, old=None):
    t = {'access_token': d['access_token'], 'refresh_token': d.get('refresh_token') or (old or {}).get('refresh_token'),
         'expires_at': time.time() + int(d.get('expires_in') or 3600), 'scope': d.get('scope') or (old or {}).get('scope') or SCOPE}
    _save_tokens(t)
    return t


def _access_token(force=False):
    with TOKEN_LOCK:
        t = _tokens()
        if not t.get('access_token') and not t.get('refresh_token'):
            raise Problem(409, 'Not connected to WHOOP. Open the WHOOP app and tap Connect with WHOOP.')
        if not force and t.get('access_token') and t.get('expires_at', 0) - 120 > time.time():
            return t['access_token']
        if not t.get('refresh_token'):
            _needs_login('WHOOP sign-in expired. Connect again in the WHOOP app.')
        status, d = _token_call({'grant_type': 'refresh_token', 'refresh_token': t['refresh_token'], 'scope': 'offline'})
        if status == 200 and d.get('access_token'):
            return _store_tokens(d, t)['access_token']   # persist the rotated refresh token before using it
        if status in (400, 401) and d.get('error') in ('invalid_grant', 'invalid_request', 'invalid_token', 'unauthorized_client', 'invalid_client'):
            _needs_login('WHOOP ended this sign-in. Connect again in the WHOOP app.')
        raise WhoopError(status, 'refresh_failed', 'WHOOP could not renew the sign-in right now. The app will retry.')


def _needs_login(msg):
    _save_tokens(None)
    _update_state(auth='needs_login', last_error=msg)
    raise Problem(401, msg)


def api_get(path, params=None):
    url = API_BASE + path + ('?' + urlencode(params) if params else '')
    refreshed, status = False, 0
    for attempt in range(RETRIES + 1):
        status, body, headers = _http('GET', url, headers={'Authorization': 'Bearer ' + _access_token()})
        if status == 200:
            return _json(body)
        if status == 401 and not refreshed:
            refreshed = True
            _access_token(force=True)
            continue
        if status == 404:
            return None
        if status == 429 or status >= 500:
            if attempt >= RETRIES:
                break
            try:
                wait = float({k.lower(): v for k, v in headers.items()}.get('retry-after') or 0)
            except ValueError:
                wait = 0
            time.sleep(min(120.0, max(wait, BACKOFF * (2 ** attempt))))
            continue
        raise WhoopError(status, 'api_error', f'WHOOP answered {status} for {path}.')
    if status == 429:
        until = time.time() + 900
        _update_state(rate_limited_until=until)
        raise WhoopError(429, 'rate_limited', 'WHOOP asked the app to slow down. Syncing resumes in about 15 minutes.')
    raise WhoopError(status, 'api_error', f'WHOOP answered {status} for {path}. The app will retry.')


# ---------------- sync ----------------

def _rec_fields(kind, r):
    score = r.get('score') or {}
    if kind == 'recovery':
        rid = str(r.get('cycle_id'))
        return rid, None, None, r.get('updated_at'), rid, r.get('sleep_id'), 0
    rid = str(r.get('id'))
    cyc = r.get('cycle_id')
    start = r.get('start')
    return rid, start, r.get('end'), r.get('updated_at'), (str(cyc) if cyc is not None else None), None, 1 if r.get('nap') else 0


def _day_of(kind, r):
    start = _parse(r.get('start'))
    if not start:
        return None
    local = start.astimezone(_offset(r.get('timezone_offset')))
    if kind == 'cycle':      # a cycle starts at sleep onset; label it by the day it mostly covers
        local = local + dt.timedelta(hours=12)
    elif kind == 'sleep':
        end = _parse(r.get('end'))
        local = (end or start).astimezone(_offset(r.get('timezone_offset')))
    return local.date().isoformat()


def _save(kind, rows):
    """Upsert WHOOP records. A row's changed_seq moves only when its data really changed, so an overlapping
    re-sync does not make every reader re-read the last few days."""
    with LOCK:
        c = db()
        with c:
            seq = _next_seq(c)
            for r in rows:
                if not isinstance(r, dict):
                    continue
                rid, start, end, upd, cyc, slp, nap = _rec_fields(kind, r)
                if not rid or rid == 'None':
                    continue
                c.execute('''INSERT INTO records (kind,id,start,end_at,updated_at,cycle_id,sleep_id,nap,score_state,day,data,changed_seq)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                             ON CONFLICT(kind,id) DO UPDATE SET start=excluded.start, end_at=excluded.end_at,
                               updated_at=excluded.updated_at, sleep_id=excluded.sleep_id, nap=excluded.nap,
                               score_state=excluded.score_state,
                               day=CASE WHEN records.cycle_id IS excluded.cycle_id AND records.kind IN ('recovery','sleep')
                                        THEN COALESCE(records.day, excluded.day) ELSE excluded.day END,
                               cycle_id=excluded.cycle_id,
                               changed_seq=CASE WHEN records.data IS excluded.data THEN records.changed_seq ELSE excluded.changed_seq END,
                               data=excluded.data''',
                          (kind, rid, start, end, upd, cyc, slp, nap, r.get('score_state'), _day_of(kind, r), json.dumps(r), seq))
        c.close()


def _fix_days():
    with LOCK:
        c = db()
        with c:
            seq = _next_seq(c)
            c.execute("""UPDATE records SET day=(SELECT x.day FROM records x WHERE x.kind='cycle' AND x.id=records.cycle_id), changed_seq=?
                         WHERE kind IN ('recovery','sleep') AND cycle_id IS NOT NULL
                         AND EXISTS (SELECT 1 FROM records x WHERE x.kind='cycle' AND x.id=records.cycle_id)
                         AND day IS NOT (SELECT x.day FROM records x WHERE x.kind='cycle' AND x.id=records.cycle_id)""", (seq,))
        c.close()


def _pull(kind, path, start=None):
    params, n, token = {'limit': PAGE}, 0, None
    if start:
        params['start'] = _iso(start)
    for _ in range(10000):
        p = dict(params, **({'nextToken': token} if token else {}))
        d = api_get(path, p) or {}
        rows = d.get('records') or []
        _save(kind, rows)
        n += len(rows)
        token = d.get('next_token') or d.get('nextToken')
        _update_state(progress={'kind': kind, 'records': n})
        if not token:
            break
        time.sleep(REQUEST_GAP)
    return n


def sync(full=False):
    if not SYNC_LOCK.acquire(blocking=False):
        return dict(status_info(), note='A sync is already running.')
    try:
        st = _state()
        if (st.get('rate_limited_until') or 0) > time.time():
            raise WhoopError(429, 'rate_limited', 'WHOOP asked the app to slow down. Syncing resumes shortly.')
        full = full or not st.get('backfilled')
        _update_state(syncing=_iso(_now()), sync_kind='backfill' if full else 'incremental')
        since = None
        if not full:
            last = _parse(st.get('last_sync')) or _now()
            since = last - dt.timedelta(days=OVERLAP_DAYS)
        counts = {}
        for kind, path in COLLECTIONS:
            counts[kind] = _pull(kind, path, since)
            time.sleep(REQUEST_GAP)
        meta_due = full or _ago(st.get('meta_at')) >= META_MINUTES * 60
        for key, path in (('profile', '/v2/user/profile/basic'), ('body', '/v2/user/measurement/body')) if meta_due else ():
            d = api_get(path)
            if isinstance(d, dict):
                with LOCK:
                    c = db()
                    with c:
                        c.execute('INSERT OR REPLACE INTO meta (key,data) VALUES (?,?)', (key, json.dumps(d)))
                    c.close()
        _fix_days()
        if meta_due:
            _update_state(meta_at=_iso(_now()))
        _update_state(last_sync=_iso(_now()), last_error=None, backfilled=True, auth='connected', syncing=None, progress=None,
                      sync_kind=None, last_counts=counts, rate_limited_until=None)
        return dict(status_info(), pulled=counts)
    except (Problem, WhoopError) as e:
        _update_state(last_error=e.message, syncing=None, progress=None, sync_kind=None)
        raise
    finally:
        SYNC_LOCK.release()


def _safe_sync(full=False):
    try:
        sync(full)
    except (Problem, WhoopError):
        pass
    except Exception:   # never let a bad record stop the scheduler
        _update_state(last_error='Sync failed unexpectedly; it will retry.', syncing=None, progress=None)


def start_sync_thread(full=False):
    threading.Thread(target=_safe_sync, args=(full,), daemon=True).start()


def _scheduler():
    time.sleep(5)
    while True:
        st = _state()
        if _tokens().get('refresh_token') or _tokens().get('access_token'):
            due = not st.get('backfilled') or _ago(st.get('last_sync')) >= sync_minutes() * 60
            if due and (st.get('rate_limited_until') or 0) <= time.time():
                _safe_sync(full=not st.get('backfilled'))
        WAKE.wait(60)
        WAKE.clear()


# ---------------- the health-data contract (wizard.health-data/1, see docs/health-data-contract.md) ----------------

CONTRACT = 'wizard.health-data/1'
SOURCE = {'id': APP_ID, 'provider': 'whoop', 'name': 'WHOOP', 'app_path': PREFIX + '/'}
SCALES = {'readiness': {'label': 'Recovery', 'min': 0, 'max': 100},
          'sleep_score': {'label': 'Sleep performance', 'min': 0, 'max': 100},
          'load': {'label': 'Strain', 'min': 0, 'max': 21, 'scale_max': 21}}
LOAD = {'max': 21, 'scale_max': 21, 'label': 'Strain'}   # scale_max: Health sets activity targets on it
STATES = {'SCORED': 'scored', 'PENDING_SCORE': 'pending', 'UNSCORABLE': 'unscorable'}


def _r(v, n=1):
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return None
    return round(v) if n == 0 else round(v, n)


def _hours(ms):
    return round(ms / 3600000, 2) if isinstance(ms, (int, float)) else None


def _minutes(ms):
    return round(ms / 60000, 1) if isinstance(ms, (int, float)) else None


def _kcal(kj):
    return round(kj / 4.184) if isinstance(kj, (int, float)) else None


def _band(score):
    if not isinstance(score, (int, float)):
        return None
    return 'high' if score >= 67 else 'medium' if score >= 34 else 'low'


def _dataset():
    st = _state()
    if not st.get('dataset'):
        st = _update_state(dataset=secrets.token_hex(12))
    return st['dataset']


def _n_sleep(r, main=True):
    s = r.get('score') or {}
    st = s.get('stage_summary') or {}
    need = s.get('sleep_needed') or {}
    light, deep, rem = st.get('total_light_sleep_time_milli'), st.get('total_slow_wave_sleep_time_milli'), st.get('total_rem_sleep_time_milli')
    stages = [x for x in (light, deep, rem) if isinstance(x, (int, float))]
    out = {'start': r.get('start'), 'end': r.get('end'), 'asleep_h': _hours(sum(stages)) if stages else None,
           'in_bed_h': _hours(st.get('total_in_bed_time_milli')), 'awake_h': _hours(st.get('total_awake_time_milli')),
           'light_h': _hours(light), 'deep_h': _hours(deep), 'rem_h': _hours(rem),
           'score': _r(s.get('sleep_performance_percentage'), 0), 'efficiency_pct': _r(s.get('sleep_efficiency_percentage'), 0),
           'respiratory_rate': _r(s.get('respiratory_rate')), 'state': STATES.get(r.get('score_state'), 'pending')}
    if main:
        need_ms = [v for v in need.values() if isinstance(v, (int, float))]
        out['need_h'] = _hours(sum(need_ms)) if need_ms else None
        # 0.2.7: what the need is made of (hours): the usual night, catch-up for recent short nights, extra after hard
        # days, minus recent naps (negative). Lets a front end say why the need is high.
        parts = {'usual_h': need.get('baseline_milli'), 'debt_h': need.get('need_from_sleep_debt_milli'),
                 'strain_h': need.get('need_from_recent_strain_milli'), 'naps_h': need.get('need_from_recent_nap_milli')}
        out['need_parts'] = {k: _hours(v) for k, v in parts.items()} if isinstance(parts['usual_h'], (int, float)) else None
    return out


def _n_workout(r):
    s = r.get('score') or {}
    a, b = _parse(r.get('start')), _parse(r.get('end'))
    z = s.get('zone_durations') or {}
    zones = [_minutes(z.get(f'zone_{n}_milli')) for n in ('zero', 'one', 'two', 'three', 'four', 'five')]
    return {'id': str(r.get('id')), 'sport': r.get('sport_name') or 'Activity', 'start': r.get('start'), 'end': r.get('end'),
            'minutes': round((b - a).total_seconds() / 60) if a and b else None,
            'load': dict(LOAD, value=_r(s.get('strain'))) if s.get('strain') is not None else None,
            'avg_hr_bpm': s.get('average_heart_rate'), 'max_hr_bpm': s.get('max_heart_rate'),
            'calories_kcal': _kcal(s.get('kilojoule')), 'energy_kj': _r(s.get('kilojoule'), 0),
            'distance_m': _r(s.get('distance_meter'), 0), 'zones_min': zones if any(x is not None for x in zones) else None,
            'extras': {'whoop': {'sport_id': r.get('sport_id'), 'percent_recorded': _r(s.get('percent_recorded'), 0),
                                 'altitude_gain_m': _r(s.get('altitude_gain_meter'), 0), 'state': r.get('score_state')}}}


def _n_day(day, cyc, rec, sleeps, works):
    """One normalized day record built from a WHOOP cycle and what belongs to it."""
    cs = cyc.get('score') or {}
    rs = (rec or {}).get('score') or {}
    main = None
    if rec and rec.get('sleep_id'):
        main = next((s for s in sleeps if s.get('id') == rec.get('sleep_id')), None)
    if main is None:
        main = next((s for s in sleeps if not s.get('nap')), None)
    sleep = None
    if main or sleeps:
        sleep = _n_sleep(main) if main else {k: None for k in ('start', 'end', 'asleep_h', 'in_bed_h', 'awake_h', 'light_h', 'deep_h',
                                                                 'rem_h', 'score', 'efficiency_pct', 'respiratory_rate', 'need_h', 'need_parts')}
        sleep['naps'] = [_n_sleep(s, main=False) for s in sleeps if s is not main]
    readiness = None
    if rec:
        sc = rs.get('recovery_score')
        readiness = {'score': _r(sc, 0), 'band': _band(sc), 'state': STATES.get(rec.get('score_state'), 'pending'),
                     'calibrating': bool(rs.get('user_calibrating'))}
    ms = (main or {}).get('score') or {}
    stage = ms.get('stage_summary') or {}
    stamps = [x.get('updated_at') for x in [cyc, rec or {}] + sleeps + works if x.get('updated_at')]
    return {
        'date': day, 'updated_at': max(stamps) if stamps else None, 'readiness': readiness,
        'hrv_ms': _r(rs.get('hrv_rmssd_milli')), 'resting_hr_bpm': _r(rs.get('resting_heart_rate'), 0),
        'spo2_pct': _r(rs.get('spo2_percentage')), 'skin_temp_c': _r(rs.get('skin_temp_celsius'), 2), 'skin_temp_delta_c': None,
        'respiratory_rate': _r(ms.get('respiratory_rate')), 'sleep': sleep,
        'load': dict(LOAD, value=_r(cs.get('strain'))) if cs.get('strain') is not None else None,
        'calories_kcal': _kcal(cs.get('kilojoule')), 'energy_kj': _r(cs.get('kilojoule'), 0),
        'avg_hr_bpm': cs.get('average_heart_rate'), 'max_hr_bpm': cs.get('max_heart_rate'), 'steps': cyc.get('step_count'),
        'workouts': [_n_workout(w) for w in works],
        'extras': {'whoop': {'cycle_id': str(cyc.get('id')), 'cycle_start': cyc.get('start'), 'cycle_end': cyc.get('end'),
                             'cycle_state': cyc.get('score_state'), 'sleep_id': (main or {}).get('id'),
                             'sleep_consistency_pct': _r(ms.get('sleep_consistency_percentage'), 0),
                             'disturbances': stage.get('disturbance_count'), 'sleep_cycles': stage.get('sleep_cycle_count'),
                             'no_data_h': _hours(stage.get('total_no_data_time_milli'))}},
    }


def _build_days(dates):
    """Complete day records for the given dates (WHOOP cycles labelled with those dates), oldest first."""
    if not dates:
        return []
    with LOCK:
        c = db()
        try:
            marks = ','.join('?' * len(dates))
            cyc = [(json.loads(x['data']), x['day']) for x in
                   c.execute(f"SELECT data, day FROM records WHERE kind='cycle' AND day IN ({marks}) ORDER BY day, start", list(dates))]
            ids = [str(x[0].get('id')) for x in cyc]
            rec, slp = {}, {}
            if ids:
                im = ','.join('?' * len(ids))
                for x in c.execute(f"SELECT data FROM records WHERE kind='recovery' AND cycle_id IN ({im})", ids):
                    d = json.loads(x['data'])
                    rec[str(d.get('cycle_id'))] = d
                for x in c.execute(f"SELECT data FROM records WHERE kind='sleep' AND cycle_id IN ({im}) ORDER BY start", ids):
                    d = json.loads(x['data'])
                    slp.setdefault(str(d.get('cycle_id')), []).append(d)
            lo = min((x[0].get('start') or '') for x in cyc) if cyc else ''
            works = [json.loads(x['data']) for x in c.execute("SELECT data FROM records WHERE kind='workout' AND start>=? ORDER BY start", (lo,))]
        finally:
            c.close()
    out, seen = [], set()
    for d, day in cyc:
        if day in seen:      # two cycles on one date (travel): keep the first, it holds the night's sleep
            continue
        seen.add(day)
        cs, ce = d.get('start') or '', d.get('end') or '9999'
        cid = str(d.get('id'))
        out.append(_n_day(day, d, rec.get(cid), slp.get(cid, []), [w for w in works if cs <= (w.get('start') or '') < ce]))
    return out


def _token(d):
    return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).decode().rstrip('=')


def _untoken(s):
    try:
        d = json.loads(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)))
        if isinstance(d, dict):
            return d
    except (ValueError, TypeError):
        pass
    raise Problem(400, 'page is not a page token from this source.')


def _cursor_seq(s):
    if s in (None, ''):
        return 0
    m = re.fullmatch(r'w1\.(\d{1,15})', str(s))
    if not m:
        raise Problem(400, 'changed_since is not a cursor from this source.')
    return int(m.group(1))


def _seq_now(c):
    row = c.execute("SELECT data FROM meta WHERE key='seq'").fetchone()
    return int(json.loads(row['data'])) if row else 0


def _check_day(v, name):
    if v is None or v == '':
        return None
    if not DATE_RE.match(str(v)):
        raise Problem(400, f'{name} must be YYYY-MM-DD.')
    return str(v)


def contract_days(args):
    """GET /api/days: normalized day records, oldest first, paged; optionally only days changed since a cursor."""
    frm, to = _check_day(args.get('from'), 'from'), _check_day(args.get('to'), 'to')
    if frm and to and frm > to:
        raise Problem(400, 'from must be on or before to.')
    try:
        limit = max(1, min(500, int(args.get('limit') or 100)))
    except (TypeError, ValueError):
        raise Problem(400, 'limit must be a number.') from None
    page = _untoken(str(args['page'])) if args.get('page') else {}
    changed = 'changed_since' in args
    since = _cursor_seq(args.get('changed_since')) if changed else 0
    after = page.get('after') or ''
    with LOCK:
        c = db()
        try:
            hw = int(page.get('hw') or _seq_now(c))
            q, p = ["SELECT DISTINCT day FROM records WHERE kind='cycle' AND day IS NOT NULL AND day>?"], [after]
            if frm:
                q.append('AND day>=?'); p.append(frm)
            if to:
                q.append('AND day<=?'); p.append(to)
            if changed:
                # a day changed when its cycle, recovery or sleep changed, or a workout inside its cycle did
                q.append("""AND day IN (
                    SELECT day FROM records WHERE kind IN ('cycle','recovery','sleep') AND changed_seq>? AND changed_seq<=? AND day IS NOT NULL
                    UNION SELECT cy.day FROM records w JOIN records cy ON cy.kind='cycle' AND cy.start<=w.start
                          AND (cy.end_at IS NULL OR cy.end_at>w.start)
                     WHERE w.kind='workout' AND w.changed_seq>? AND w.changed_seq<=?)""")
                p += [since, hw, since, hw]
            q.append('ORDER BY day LIMIT ?'); p.append(limit + 1)
            dates = [r['day'] for r in c.execute(' '.join(q), p)]
        finally:
            c.close()
    more = len(dates) > limit
    dates = dates[:limit]
    return {'contract': CONTRACT, 'source': APP_ID, 'dataset': _dataset(), 'days': _build_days(dates),
            'next_page': _token({'after': dates[-1], 'hw': hw}) if more else None, 'cursor': f'w1.{hw}'}


def _counts():
    with LOCK:
        c = db()
        out = {r['kind']: r['n'] for r in c.execute('SELECT kind, COUNT(*) n FROM records GROUP BY kind')}
        span = c.execute("SELECT MIN(day) a, MAX(day) b FROM records WHERE kind='cycle'").fetchone()
        c.close()
    return out, span['a'], span['b']


def _meta(key):
    with LOCK:
        c = db()
        row = c.execute('SELECT data FROM meta WHERE key=?', (key,)).fetchone()
        c.close()
    return json.loads(row['data']) if row else None


def status_info():
    k, t, st = _keys(), _tokens(), _state()
    keys = bool(k.get('client_id') and k.get('client_secret'))
    if not (t.get('refresh_token') or t.get('access_token')):
        state = 'needs_login' if keys and st.get('auth') == 'needs_login' else 'not_configured'
    elif st.get('syncing') and _ago(st.get('syncing')) < 7200:
        state = 'syncing'
    elif (st.get('rate_limited_until') or 0) > time.time():
        state = 'rate_limited'
    else:
        state = 'connected'
    counts, first, last = _counts()
    prof = _meta('profile') or {}
    nxt, every = None, sync_minutes()
    if state in ('connected', 'rate_limited') and st.get('last_sync'):
        nxt = _iso(_parse(st['last_sync']) + dt.timedelta(minutes=every))
    live = state in ('connected', 'syncing', 'rate_limited')
    return {
        'contract': CONTRACT, 'source': SOURCE, 'status': state, 'version': VERSION,
        'account': {'name': prof.get('first_name')} if live or counts else None, 'dataset': _dataset(),
        'last_sync': st.get('last_sync'), 'next_sync': nxt, 'sync_every_minutes': every,
        'sync_plan': {'every_minutes': SYNC_MINUTES, 'morning_window': MORNING_WINDOW if _window() else None,
                      'morning_every_minutes': MORNING_SYNC_MINUTES if _window() else None},
        'history_from': first, 'latest_date': last,
        'counts': {'days': counts.get('cycle', 0), 'sleeps': counts.get('sleep', 0), 'workouts': counts.get('workout', 0)},
        'error': st.get('last_error'), 'scales': SCALES,
        # WHOOP setup state, for this app's own screen
        'setup': {'keys_saved': keys, 'keys_verified': k.get('verified'), 'redirect_uri': k.get('redirect_uri') if keys else None,
                  'backfilled': bool(st.get('backfilled')), 'sync_kind': st.get('sync_kind') if state == 'syncing' else None,
                  'progress': st.get('progress') if state == 'syncing' else None},
    }


def disconnect(forget=False):
    t = _tokens()
    if t.get('access_token'):
        try:   # best effort: tell WHOOP to revoke this app's access
            _http('DELETE', API_BASE + '/v2/user/access', headers={'Authorization': 'Bearer ' + t['access_token']}, timeout=15)
        except WhoopError:
            pass
    with LOCK:
        _save_tokens(None)
        for p in list(DATA.glob('whoop.sqlite3*')):
            p.unlink(missing_ok=True)
        _shred('state.json')     # also drops the dataset id, so readers know the copy is gone
        if forget:
            _shred('client.json')
    return status_info()


# ---------------- logo (square PNG the WHOOP form may ask for) ----------------

def logo_png(size=512):
    """A plain ring on a dark square, drawn with stdlib so the app ships no binary file."""
    cx = cy = (size - 1) / 2
    r_out, r_in = size * 0.36, size * 0.26
    rows = []
    for y in range(size):
        row = bytearray(b'\x00')
        for x in range(size):
            d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
            edge = min(max(r_out - d + .5, 0), 1) * min(max(d - r_in + .5, 0), 1)
            bg = (18, 20, 26)
            fg = (92, 214, 140)
            row += bytes(round(bg[i] + (fg[i] - bg[i]) * edge) for i in range(3))
        rows.append(bytes(row))

    def chunk(t, b):
        return struct.pack('>I', len(b)) + t + b + struct.pack('>I', zlib.crc32(t + b) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(b''.join(rows), 9)) + chunk(b'IEND', b''))


_LOGO = []


_LOGO = []


# ---------------- MCP ----------------

_NONE = {'type': 'object', 'properties': {}, 'additionalProperties': False}
TOOLS = [
    {'name': 'health_data_status', 'description': "WHOOP connector status (contract wizard.health-data/1): not_configured, needs_login, syncing, connected or rate_limited; the connected account's first name, last/next sync, history span and record counts. Never returns keys or tokens. If not connected, send the owner the WHOOP app link [WHOOP](/wizard-whoop/); its own screen walks him through setup. Never ask for WHOOP keys, passwords or codes in chat. For health questions use the Health app's tools instead.",
     'inputSchema': _NONE, 'annotations': {'readOnlyHint': True}},
    {'name': 'health_data_sync', 'description': 'Ask the WHOOP connector to pull new data from WHOOP now (it also syncs every 20 minutes, every 5 in the morning). Returns at once; check health_data_status for progress. Reads WHOOP only.',
     'inputSchema': _NONE, 'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True}},
    {'name': 'health_data_days', 'description': 'Raw contract read: normalized WHOOP day records (readiness/recovery, HRV, resting HR, SpO2, skin temp, sleep, strain, calories, workouts, extras.whoop), oldest first, paged with next_page; pass changed_since=<cursor> to get only changed days. For owner questions prefer the Health app tools.',
     'inputSchema': {'type': 'object', 'properties': {
         'from': {'type': 'string', 'description': 'YYYY-MM-DD inclusive'}, 'to': {'type': 'string', 'description': 'YYYY-MM-DD inclusive'},
         'limit': {'type': 'integer', 'description': 'days per page, default 100, max 500'},
         'page': {'type': 'string', 'description': 'next_page from the previous reply'},
         'changed_since': {'type': 'string', 'description': 'cursor from an earlier reply; empty string = everything'}},
         'additionalProperties': False}, 'annotations': {'readOnlyHint': True}},
]


def request_sync(full=False):
    s = status_info()
    if s['status'] in ('not_configured', 'needs_login'):
        raise Problem(409, 'WHOOP is not connected. The owner finishes setup in the WHOOP app (/wizard-whoop/).')
    start_sync_thread(full=full)
    return dict(status_info(), note='Sync started.')


def call(name, a):
    if name == 'health_data_status':
        return status_info()
    if name == 'health_data_sync':
        return request_sync()
    if name == 'health_data_days':
        return contract_days(a)
    raise KeyError(name)


def rpc(msg):
    if not isinstance(msg, dict):
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Expected a JSON-RPC object.'}}
    m, i, p = msg.get('method'), msg.get('id'), msg.get('params') or {}
    if 'id' not in msg:
        return None
    try:
        if m == 'initialize':
            r = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, 'serverInfo': {'name': APP_ID, 'version': VERSION}}
        elif m == 'tools/list':
            r = {'tools': TOOLS}
        elif m == 'tools/call':
            try:
                v = call(p.get('name'), p.get('arguments') or {})
            except KeyError:
                return {'jsonrpc': '2.0', 'id': i, 'error': {'code': -32602, 'message': 'Unknown tool.'}}
            r = {'content': [{'type': 'text', 'text': json.dumps(v, ensure_ascii=False)}], 'structuredContent': v, 'isError': False}
        elif m == 'ping':
            r = {}
        else:
            return {'jsonrpc': '2.0', 'id': i, 'error': {'code': -32601, 'message': 'Unknown method.'}}
    except (Problem, WhoopError) as e:
        r = {'content': [{'type': 'text', 'text': e.message}], 'isError': True}
    except (ValueError, TypeError, AttributeError):
        r = {'content': [{'type': 'text', 'text': 'Invalid arguments.'}], 'isError': True}
    return {'jsonrpc': '2.0', 'id': i, 'result': r}


# ---------------- HTTP ----------------

def _csv(name):
    return {x.strip().lower() for x in os.environ.get(name, '').split(',') if x.strip()}


_LOOPBACK = {f'127.0.0.1:{PORT}', f'localhost:{PORT}', f'{APP_ID}:{PORT}'}
TRUSTED_HOSTS = _csv('WIZARD_TRUSTED_HOSTS') | _LOOPBACK
TRUSTED_ORIGINS = _csv('WIZARD_TRUSTED_ORIGINS') | {'http://' + h for h in _LOOPBACK}
# A bare host name (no port) in WIZARD_TRUSTED_HOSTS is trusted on every shell port of that host.
TRUSTED_NAMES = {h.split(':')[0] for h in TRUSTED_HOSTS}
CSP = ("default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'")


def _host_ok(host):
    host = (host or '').lower()
    return host in TRUSTED_HOSTS or host.split(':')[0] in TRUSTED_NAMES


class Handler(BaseHTTPRequestHandler):
    def refused(self, write=False):
        host = (self.headers.get('Host') or '').lower()
        if not _host_ok(host):
            self.send(403, {'error': 'Unknown host.'}); return True
        origin = (self.headers.get('Origin') or '').lower()
        if origin and origin not in TRUSTED_ORIGINS and urlsplit(origin).netloc != host:
            self.send(403, {'error': 'Cross-origin request refused.'}); return True
        if write and not origin and (self.headers.get('Sec-Fetch-Site') or '') == 'cross-site':
            self.send(403, {'error': 'Cross-origin request refused.'}); return True
        return False

    def forwarded(self):
        return any(self.headers.get(h) for h in FORWARDED)

    def send(self, code, body=None, kind='application/json', extra=None):
        b = body if isinstance(body, bytes) else b'' if body is None else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(b)

    def route(self):
        p = urlsplit(self.path).path
        return '/' if p == PREFIX else p[len(PREFIX):] if p.startswith(PREFIX + '/') else p

    def body(self):
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            raise Problem(415, 'Use application/json.')
        size = int(self.headers.get('Content-Length', '0') or 0)
        if not 0 <= size <= 65536:
            raise Problem(413, 'Request too large.')
        try:
            d = json.loads(self.rfile.read(size) or b'{}')
        except ValueError:
            raise Problem(400, 'Invalid JSON.') from None
        if not isinstance(d, dict):
            raise Problem(400, 'Expected a JSON object.')
        return d

    def callback_page(self, ok, message):
        home = PREFIX + '/' if self.path.startswith(PREFIX) else '/'
        title = 'WHOOP connected' if ok else 'WHOOP sign-in did not finish'
        esc = lambda s: s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        html = (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{title}</title><body style="font:16px/1.5 system-ui;margin:2rem;max-width:36rem">'
                f'<h1 style="font-size:1.4rem">{title}</h1><p>{esc(message)}</p><p><a href="{home}">Open WHOOP</a></p>')
        self.send(200 if ok else 400, html.encode(), 'text/html; charset=utf-8')

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.refused():
            return
        path = self.route()
        query = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query, keep_blank_values=True).items()}
        try:
            if path in ('/healthz', '/api/health'):
                s = status_info()
                return self.send(200, {'ok': True, 'app': APP_ID, 'version': VERSION, 'status': s['status'],
                                       'connected': s['status'] in ('connected', 'syncing', 'rate_limited'), 'last_sync': s['last_sync']})
            if path == '/api/status':
                return self.send(200, status_info())
            if path == '/api/setup':
                return self.send(200, setup_info())
            if path == '/api/days':
                if self.forwarded():
                    return self.send(403, {'error': 'Health data reads are box-only.'})
                return self.send(200, contract_days(query))
            if path == '/logo.png':
                if not _LOGO:
                    _LOGO.append(logo_png())
                return self.send(200, _LOGO[0], 'image/png', {'Content-Disposition': 'attachment; filename="wizard-whoop-logo.png"'})
            if path in ('/callback', '/oauth/callback'):   # when the Redirect URL points at this app itself
                try:
                    login_finish('http://x' + self.path)
                    return self.callback_page(True, 'Your WHOOP data is downloading now. You can close this tab and go back to the WHOOP app.')
                except (Problem, WhoopError) as e:
                    return self.callback_page(False, e.message)
            if path == '/openapi.json':
                return self.send(200, (ROOT / 'openapi.json').read_bytes())
            name = 'index.html' if path == '/' else path[1:]
            kind = STATIC.get(Path(name).suffix)
            if kind and '/' not in name and not name.startswith('.') and (ROOT / 'web' / name).is_file():
                return self.send(200, (ROOT / 'web' / name).read_bytes(), kind)
            self.send(405 if path == '/mcp' else 404, {'error': 'Use POST /mcp.' if path == '/mcp' else 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})
        except (ValueError, TypeError):
            self.send(400, {'error': 'Invalid query.'})

    def do_POST(self):
        if self.refused(write=True):
            return
        path = self.route()
        try:
            if path == '/mcp':
                if self.forwarded():
                    return self.send(403, {'error': 'MCP is box-only.'})
                out = rpc(self.body())
                return self.send(202 if out is None else 200, out)
            b = self.body()
            if path == '/api/keys':
                return self.send(200, save_keys(b))
            if path == '/api/keys/test':
                return self.send(200, test_keys())
            if path == '/api/keys/forget':
                return self.send(200, forget_keys())
            if path == '/api/oauth/start':
                return self.send(200, login_start())
            if path == '/api/oauth/finish':
                return self.send(200, login_finish(b.get('url')))
            if path == '/api/sync':
                return self.send(202, request_sync(full=bool(b.get('full'))))
            if path == '/api/disconnect':
                return self.send(200, disconnect(forget=bool(b.get('forget_keys'))))
            self.send(404, {'error': 'Not found.'})
        except Problem as e:
            self.send(e.code, {'error': e.message})
        except WhoopError as e:
            self.send(429 if e.code == 'rate_limited' else 502, {'error': e.message})
        except (ValueError, TypeError):
            self.send(400, {'error': 'Invalid request.'})

    def log_message(self, *a):
        pass


def main():
    secure_files()
    st = _state()
    if st.get('syncing'):
        _update_state(syncing=None, progress=None, sync_kind=None)   # a restart interrupted it; the scheduler resumes
    threading.Thread(target=_scheduler, daemon=True).start()
    ThreadingHTTPServer((os.environ.get('BIND', '0.0.0.0'), int(PORT)), Handler).serve_forever()


if __name__ == '__main__':
    main()
