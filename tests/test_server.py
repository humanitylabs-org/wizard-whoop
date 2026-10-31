"""Tests for the WHOOP connector against a fake WHOOP: setup keys, key test, OAuth state, token refresh
rotation, paginated backfill with 401/429 handling, incremental overlap, the wizard.health-data/1 contract
(normalized days, paging, changed_since cursor, dataset id, box-only reads), HTTP/MCP guards, disconnect.
Run: python3 -m unittest discover -s tests"""
import datetime as dt
import importlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
CID, SECRET = 'test-client-id-0001', 'test-secret-value-XYZ-123'
DAYS = 60
BASE = dt.datetime(2026, 8, 1, 16, 0, tzinfo=dt.timezone.utc)   # 23:00 at +07:00


def iso(t):
    return t.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def make_data():
    cycles, recs, sleeps, works = [], [], [], []
    for i in range(DAYS):
        s = BASE + dt.timedelta(days=i)
        e = s + dt.timedelta(days=1)
        cid = 1000 + i
        cycles.append({'id': cid, 'user_id': 1, 'created_at': iso(s), 'updated_at': iso(s), 'start': iso(s), 'end': iso(e) if i < DAYS - 1 else None,
                       'timezone_offset': '+07:00', 'score_state': 'SCORED', 'score': {'strain': 8 + (i % 10), 'kilojoule': 9000 + i, 'average_heart_rate': 60, 'max_heart_rate': 150}})
        sid = f'sleep-{i:04d}'
        sleeps.append({'id': sid, 'cycle_id': cid, 'v1_id': i, 'user_id': 1, 'created_at': iso(s), 'updated_at': iso(s), 'start': iso(s + dt.timedelta(minutes=30)),
                       'end': iso(s + dt.timedelta(hours=8)), 'timezone_offset': '+07:00', 'nap': False, 'score_state': 'SCORED',
                       'score': {'stage_summary': {'total_in_bed_time_milli': 27000000, 'total_awake_time_milli': 1800000, 'total_no_data_time_milli': 0,
                                                   'total_light_sleep_time_milli': 12600000, 'total_slow_wave_sleep_time_milli': 5400000,
                                                   'total_rem_sleep_time_milli': 7200000, 'sleep_cycle_count': 4, 'disturbance_count': 9},
                                 'sleep_needed': {'baseline_milli': 27000000, 'need_from_sleep_debt_milli': 900000, 'need_from_recent_strain_milli': 300000, 'need_from_recent_nap_milli': 0},
                                 'respiratory_rate': 15.2, 'sleep_performance_percentage': 88, 'sleep_consistency_percentage': 75, 'sleep_efficiency_percentage': 93}})
        recs.append({'cycle_id': cid, 'sleep_id': sid, 'user_id': 1, 'created_at': iso(s + dt.timedelta(hours=8)), 'updated_at': iso(s + dt.timedelta(hours=8)),
                     'score_state': 'SCORED', 'score': {'user_calibrating': False, 'recovery_score': [20, 50, 80][i % 3], 'resting_heart_rate': 50 + i % 5,
                                                        'hrv_rmssd_milli': 60.5 + i % 7, 'spo2_percentage': 96.4, 'skin_temp_celsius': 33.71}})
        if i % 3 == 0:
            ws = s + dt.timedelta(hours=12)
            works.append({'id': f'work-{i:04d}', 'v1_id': i, 'user_id': 1, 'created_at': iso(ws), 'updated_at': iso(ws), 'start': iso(ws), 'end': iso(ws + dt.timedelta(minutes=45)),
                          'timezone_offset': '+07:00', 'sport_name': 'running', 'sport_id': 0, 'score_state': 'SCORED',
                          'score': {'strain': 11.2, 'average_heart_rate': 140, 'max_heart_rate': 175, 'kilojoule': 2000, 'percent_recorded': 100, 'distance_meter': 7000}})
    return {'/developer/v2/cycle': cycles, '/developer/v2/recovery': recs, '/developer/v2/activity/sleep': sleeps, '/developer/v2/activity/workout': works}


class Fake:
    def __init__(self):
        self.data = make_data()
        self.access, self.refresh = None, None
        self.used_refresh = set()
        self.calls = []
        self.force_401 = 0
        self.force_429 = 0
        self.revoked = False


FAKE = Fake()


class FakeWhoop(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, headers=None):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def issue(self):
        FAKE.access = 'acc-' + os.urandom(6).hex()
        FAKE.refresh = 'ref-' + os.urandom(6).hex()
        return {'access_token': FAKE.access, 'refresh_token': FAKE.refresh, 'expires_in': 3600, 'scope': 'offline read:recovery', 'token_type': 'bearer'}

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        f = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        FAKE.calls.append(('POST', self.path, f.get('grant_type')))
        if self.path != '/oauth/oauth2/token':
            return self.reply(404, {})
        if f.get('client_id') != CID or f.get('client_secret') != SECRET:
            return self.reply(401, {'error': 'invalid_client', 'error_description': 'Client authentication failed'})
        if f.get('grant_type') == 'authorization_code':
            if f.get('code') == 'good-code' and f.get('redirect_uri'):
                return self.reply(200, self.issue())
            return self.reply(400, {'error': 'invalid_grant'})
        if f.get('grant_type') == 'refresh_token':
            if f.get('refresh_token') == FAKE.refresh and f.get('refresh_token') not in FAKE.used_refresh:
                FAKE.used_refresh.add(f['refresh_token'])
                return self.reply(200, self.issue())
            return self.reply(400, {'error': 'invalid_grant'})
        return self.reply(400, {'error': 'unsupported_grant_type'})

    def do_DELETE(self):
        FAKE.calls.append(('DELETE', self.path, None))
        FAKE.revoked = True
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        FAKE.calls.append(('GET', u.path, q))
        if self.headers.get('Authorization') != 'Bearer ' + str(FAKE.access):
            return self.reply(401, {'error': 'unauthorized'})
        if FAKE.force_401:
            FAKE.force_401 -= 1
            return self.reply(401, {'error': 'unauthorized'})
        if FAKE.force_429:
            FAKE.force_429 -= 1
            return self.reply(429, {'error': 'rate'}, {'Retry-After': '0'})
        if u.path == '/developer/v2/user/profile/basic':
            return self.reply(200, {'user_id': 1, 'email': 'person@example.com', 'first_name': 'Sam', 'last_name': 'Example'})
        if u.path == '/developer/v2/user/measurement/body':
            return self.reply(200, {'height_meter': 1.8, 'weight_kilogram': 75.0, 'max_heart_rate': 190})
        rows = FAKE.data.get(u.path)
        if rows is None:
            return self.reply(404, {})
        limit = min(int(q.get('limit', 10)), 25)
        if 'start' in q:
            start = q['start']
            cyc = {c['id']: c['start'] for c in FAKE.data['/developer/v2/cycle']}
            rows = [r for r in rows if (r.get('start') or cyc.get(r.get('cycle_id'))) >= start]
        rows = sorted(rows, key=lambda r: r.get('start') or r['created_at'], reverse=True)
        off = int(q.get('nextToken') or 0)
        page = rows[off:off + limit]
        nxt = str(off + limit) if off + limit < len(rows) else None
        return self.reply(200, {'records': page, 'next_token': nxt})


def http(port, method, path, body=None, headers=None):
    h = {'Host': f'127.0.0.1:{port}'}
    if body is not None:
        h['Content-Type'] = 'application/json'
    h.update(headers or {})
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class HealthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = ThreadingHTTPServer(('127.0.0.1', 0), FakeWhoop)
        threading.Thread(target=cls.fake.serve_forever, daemon=True).start()
        fp = cls.fake.server_address[1]
        cls.tmp = tempfile.mkdtemp()
        os.environ.update({'DATA_DIR': cls.tmp + '/private', 'WHOOP_OAUTH_BASE': f'http://127.0.0.1:{fp}/oauth/oauth2',
                           'WHOOP_API_BASE': f'http://127.0.0.1:{fp}/developer', 'WHOOP_REQUEST_GAP': '0', 'WHOOP_BACKOFF': '0.01',
                           'PORT': '18999', 'WIZARD_TRUSTED_HOSTS': 'box.example.ts.net'})
        sys.path.insert(0, str(ROOT / 'app'))
        import server
        cls.S = importlib.reload(server)
        cls.app = ThreadingHTTPServer(('127.0.0.1', 0), cls.S.Handler)
        threading.Thread(target=cls.app.serve_forever, daemon=True).start()
        cls.port = cls.app.server_address[1]
        cls.S._LOOPBACK.add(f'127.0.0.1:{cls.port}')
        cls.S.TRUSTED_HOSTS.add(f'127.0.0.1:{cls.port}')

    @classmethod
    def tearDownClass(cls):
        cls.fake.shutdown()
        cls.app.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def files_text(self):
        out = ''
        for p in Path(self.tmp).rglob('*'):
            if p.is_file():
                out += p.read_bytes().decode('latin-1')
        return out

    def wait_sync(self, timeout=30):
        t = time.time()
        while time.time() - t < timeout:
            if not self.S.SYNC_LOCK.locked() and self.S._state().get('last_sync'):
                return
            time.sleep(0.05)
        self.fail('sync did not finish')

    def test_flow(self):
        S = self.S
        # ---- from scratch: nothing configured
        self.assertEqual(S.status_info()['status'], 'not_configured')
        info = S.setup_info()
        self.assertEqual(info['scopes'], ['read:recovery', 'read:cycles', 'read:sleep', 'read:workout', 'read:profile', 'read:body_measurement'])
        self.assertEqual(info['default_redirect'], 'http://localhost:3000/callback')
        self.assertFalse(info['keys_saved'])
        with self.assertRaises(S.Problem):
            S.login_start()

        # ---- step 4: save keys through the HTTP API the form uses; secret never echoed
        code, body = http(self.port, 'POST', '/api/keys', {'client_id': 'x', 'client_secret': SECRET, 'redirect_uri': 'http://localhost:3000/callback'})
        self.assertEqual(code, 400)
        code, body = http(self.port, 'POST', '/api/keys', {'client_id': CID, 'client_secret': 'wrong-secret-value', 'redirect_uri': 'http://localhost:3000/callback'})
        self.assertEqual(code, 200)
        code, body = http(self.port, 'POST', '/api/keys/test', {})
        self.assertEqual(json.loads(body)['result'], 'invalid')
        code, body = http(self.port, 'POST', '/api/keys', {'client_id': CID, 'client_secret': SECRET, 'redirect_uri': 'http://localhost:3000/callback'})
        self.assertEqual(code, 200)
        self.assertNotIn(SECRET.encode(), body)
        self.assertNotIn(CID.encode(), body)
        self.assertTrue(json.loads(body)['keys_saved'])
        code, body = http(self.port, 'POST', '/api/keys/test', {})
        r = json.loads(body)
        self.assertEqual(r['result'], 'valid', r)
        self.assertIn('recognised', r['message'])
        self.assertEqual(S.status_info()['status'], 'not_configured')
        self.assertTrue(S.status_info()['setup']['keys_saved'])
        self.assertEqual(oct(os.stat(S.DATA).st_mode & 0o777), '0o700')
        self.assertEqual(oct(os.stat(S.DATA / 'client.json').st_mode & 0o777), '0o600')
        # plain http redirect only for localhost
        code, _ = http(self.port, 'POST', '/api/keys', {'client_id': CID, 'client_secret': SECRET, 'redirect_uri': 'http://box.example/callback'})
        self.assertEqual(code, 400)

        # ---- step 5: OAuth state handling
        start = S.login_start()
        q = {k: v[0] for k, v in parse_qs(urlsplit(start['authorize_url']).query).items()}
        self.assertGreaterEqual(len(q['state']), 8)
        self.assertEqual(q['scope'].split(), ['offline'] + info['scopes'])
        self.assertEqual(q['redirect_uri'], 'http://localhost:3000/callback')
        self.assertTrue(start['paste_back'])
        with self.assertRaises(S.Problem):
            S.login_finish('http://localhost:3000/callback?code=good-code&state=not-the-state')
        with self.assertRaises(S.Problem) as e:
            S.login_finish(f"http://localhost:3000/callback?error=access_denied&state={q['state']}")
        self.assertIn('not to allow', e.exception.message)
        start = S.login_start()
        state = parse_qs(urlsplit(start['authorize_url']).query)['state'][0]
        FAKE.force_429, FAKE.force_401 = 1, 1        # first data calls: one rate limit, one expired token
        code, body = http(self.port, 'POST', '/api/oauth/finish', {'url': f'http://localhost:3000/callback?code=good-code&state={state}'})
        self.assertEqual(code, 200, body)
        self.wait_sync()
        with self.assertRaises(S.Problem):          # state is single-use
            S.login_finish(f'http://localhost:3000/callback?code=good-code&state={state}')
        st = S.status_info()
        self.assertEqual(st['status'], 'connected', st)
        self.assertEqual(st['counts'], {'days': DAYS, 'sleeps': DAYS, 'workouts': DAYS // 3}, st)
        self.assertTrue(st['setup']['backfilled'])
        self.assertEqual(st['account'], {'name': 'Sam'})
        self.assertEqual(st['contract'], 'wizard.health-data/1')
        self.assertEqual(st['source'], {'id': 'wizard-whoop', 'provider': 'whoop', 'name': 'WHOOP', 'app_path': '/wizard-whoop/'})
        self.assertEqual(st['scales']['load'], {'label': 'Strain', 'min': 0, 'max': 21})
        cycle_pages = [c for c in FAKE.calls if c[0] == 'GET' and c[1] == '/developer/v2/cycle']
        self.assertGreaterEqual(len(cycle_pages), 3)                    # 60 records / 25 per page, plus the retried calls
        self.assertTrue(all('start' not in c[2] for c in cycle_pages))   # backfill = full history
        self.assertTrue(any(c[2].get('nextToken') for c in cycle_pages))
        self.assertTrue(all(int(c[2]['limit']) == 25 for c in cycle_pages))
        self.assertEqual(oct(os.stat(S.DATA / 'tokens.json').st_mode & 0o777), '0o600')

        # ---- the contract: normalized days, oldest first, complete records
        last_cycle = FAKE.data['/developer/v2/cycle'][-1]
        exp_day = (dt.datetime.fromisoformat(last_cycle['start'].replace('Z', '+00:00')) + dt.timedelta(hours=7 + 12)).date().isoformat()
        self.assertEqual(st['latest_date'], exp_day)
        r = S.contract_days({'from': exp_day, 'to': exp_day})
        self.assertEqual(r['contract'], 'wizard.health-data/1')
        self.assertEqual(r['dataset'], st['dataset'])
        self.assertEqual(len(r['days']), 1)
        d = r['days'][0]
        check_day(self, d)
        self.assertEqual(d['date'], exp_day)
        self.assertEqual(d['readiness']['band'], {20: 'low', 50: 'medium', 80: 'high'}[d['readiness']['score']])
        self.assertEqual(d['readiness']['state'], 'scored')
        self.assertEqual(d['sleep']['asleep_h'], 7.0)
        self.assertEqual(d['sleep']['deep_h'], 1.5)
        self.assertEqual(d['sleep']['need_h'], 7.83)
        self.assertEqual(d['sleep']['score'], 88)
        self.assertEqual(d['load'], {'value': 8 + (DAYS - 1) % 10, 'max': 21, 'label': 'Strain'})
        self.assertEqual(d['calories_kcal'], round((9000 + DAYS - 1) / 4.184))
        self.assertEqual(d['extras']['whoop']['sleep_id'], f'sleep-{DAYS - 1:04d}')
        self.assertEqual(d['spo2_pct'], 96.4)
        withw = [x for x in S.contract_days({'limit': 500})['days'] if x['workouts']]
        self.assertEqual(len(withw), DAYS // 3)
        w = withw[0]['workouts'][0]
        self.assertEqual((w['sport'], w['minutes'], w['avg_hr_bpm'], w['distance_m']), ('running', 45, 140, 7000))
        self.assertEqual(w['load']['value'], 11.2)
        with self.assertRaises(S.Problem):
            S.contract_days({'from': 'yesterday'})
        with self.assertRaises(S.Problem):
            S.contract_days({'changed_since': 'not-a-cursor'})
        # paging: 60 days in pages of 25, oldest first, no gaps or repeats, same cursor on every page
        seen, page, cursors = [], None, set()
        while True:
            r = S.contract_days(dict({'limit': 25}, **({'page': page} if page else {})))
            seen += [x['date'] for x in r['days']]
            cursors.add(r['cursor'])
            page = r['next_page']
            if not page:
                break
        self.assertEqual(len(seen), DAYS)
        self.assertEqual(seen, sorted(set(seen)))
        self.assertEqual(len(cursors), 1)
        cursor = cursors.pop()
        # changed_since: nothing new -> nothing; a re-scored sleep and a new workout -> exactly those days
        self.assertEqual(S.contract_days({'changed_since': cursor})['days'], [])
        S.sync(full=True)
        self.assertEqual(S.contract_days({'changed_since': cursor})['days'], [], 'an unchanged overlap re-sync must not re-emit days')
        sl = FAKE.data['/developer/v2/activity/sleep'][-2]
        sl['score']['sleep_performance_percentage'] = 61
        sl['updated_at'] = iso(dt.datetime.now(dt.timezone.utc))
        ws = dt.datetime.fromisoformat(FAKE.data['/developer/v2/cycle'][-1]['start'].replace('Z', '+00:00')) + dt.timedelta(hours=3)
        FAKE.data['/developer/v2/activity/workout'].append({'id': 'work-new', 'user_id': 1, 'created_at': iso(ws), 'updated_at': iso(ws), 'start': iso(ws),
            'end': iso(ws + dt.timedelta(minutes=30)), 'timezone_offset': '+07:00', 'sport_name': 'cycling', 'sport_id': 1, 'score_state': 'SCORED',
            'score': {'strain': 7.5, 'average_heart_rate': 120, 'max_heart_rate': 150, 'kilojoule': 900, 'percent_recorded': 100,
                      'zone_durations': {'zone_zero_milli': 0, 'zone_one_milli': 600000, 'zone_two_milli': 1200000, 'zone_three_milli': 0, 'zone_four_milli': 0, 'zone_five_milli': 0}}})
        S.sync(full=True)
        ch = S.contract_days({'changed_since': cursor})
        self.assertEqual(len(ch['days']), 2, [x['date'] for x in ch['days']])
        self.assertEqual(ch['days'][0]['sleep']['score'], 61)
        self.assertEqual(ch['days'][1]['date'], exp_day)
        self.assertEqual([x['sport'] for x in ch['days'][1]['workouts']], ['cycling'])
        self.assertEqual(ch['days'][1]['workouts'][0]['zones_min'], [0.0, 10.0, 20.0, 0.0, 0.0, 0.0])
        self.assertNotEqual(ch['cursor'], cursor)
        self.assertEqual(S.contract_days({'changed_since': ch['cursor']})['days'], [])
        self.assertEqual(len(S.contract_days({'changed_since': ''})['days']), DAYS)

        # ---- token refresh rotates and the new refresh token is persisted
        t = S._tokens()
        old_refresh = t['refresh_token']
        t['expires_at'] = time.time() - 10
        S._save_tokens(t)
        S.api_get('/v2/user/measurement/body')
        t2 = S._tokens()
        self.assertNotEqual(t2['refresh_token'], old_refresh)
        self.assertEqual(t2['refresh_token'], FAKE.refresh)
        self.assertEqual(t2['access_token'], FAKE.access)

        # ---- incremental sync asks from last sync minus the overlap
        FAKE.calls.clear()
        S.sync()
        cyc = [c for c in FAKE.calls if c[1] == '/developer/v2/cycle']
        self.assertTrue(cyc and all('start' in c[2] for c in cyc))
        since = dt.datetime.fromisoformat(cyc[0][2]['start'].replace('Z', '+00:00'))
        self.assertAlmostEqual((dt.datetime.now(dt.timezone.utc) - since).total_seconds() / 86400, S.OVERLAP_DAYS, delta=0.1)
        self.assertEqual(S.status_info()['counts']['days'], DAYS)    # upserts, no duplicates

        # ---- HTTP + MCP
        code, body = http(self.port, 'POST', '/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        names = [t['name'] for t in json.loads(body)['result']['tools']]
        self.assertEqual(names, ['health_data_status', 'health_data_sync', 'health_data_days'])
        for name, args in [('health_data_status', {}), ('health_data_days', {'from': exp_day}), ('health_data_days', {'changed_since': ''})]:
            code, body = http(self.port, 'POST', '/mcp', {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}})
            res = json.loads(body)['result']
            self.assertFalse(res['isError'], (name, res))
            for secret in (SECRET, FAKE.access, FAKE.refresh, CID):
                self.assertNotIn(secret, body.decode())
        code, _ = http(self.port, 'POST', '/mcp', {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'}, {'Tailscale-User-Login': 'someone@example.com'})
        self.assertEqual(code, 403)
        code, _ = http(self.port, 'GET', '/api/status', headers={'Host': 'evil.example:18999'})
        self.assertEqual(code, 403)
        code, _ = http(self.port, 'GET', '/api/status', headers={'Host': 'box.example.ts.net:8444'})   # bare trusted name, any port
        self.assertEqual(code, 200)
        code, _ = http(self.port, 'POST', '/api/sync', {}, {'Host': 'box.example.ts.net:8444', 'Origin': 'https://evil.example'})
        self.assertEqual(code, 403)
        for path in ('/api/status', '/api/setup', '/api/days', '/api/days?changed_since=', '/wizard-whoop/api/status', '/healthz'):
            code, body = http(self.port, 'GET', path)
            self.assertEqual(code, 200, path)
            for secret in (SECRET, FAKE.access, FAKE.refresh):
                self.assertNotIn(secret, body.decode(), path)
        for path in ('/api/summary', '/api/trends?days=30', '/api/workouts'):       # the dashboard moved to the Health app
            self.assertEqual(http(self.port, 'GET', path)[0], 404, path)
        for hdr in ('X-Forwarded-For', 'Tailscale-User-Login', 'Forwarded', 'X-Real-IP', 'CF-Connecting-IP'):   # contract reads are box-only
            code, body = http(self.port, 'GET', '/api/days', headers={hdr: 'x'})
            self.assertEqual(code, 403, hdr)
        code, body = http(self.port, 'GET', '/api/status', headers={'Host': 'box.example.ts.net:8444', 'X-Forwarded-For': '100.1.2.3'})
        self.assertEqual(code, 200)                                   # the screen's status still works through the shell
        code, body = http(self.port, 'GET', '/logo.png')
        self.assertEqual(code, 200)
        self.assertTrue(body.startswith(b'\x89PNG'))
        self.assertEqual(int.from_bytes(body[16:20], 'big'), int.from_bytes(body[20:24], 'big'))   # square

        # ---- the app's own callback route (https Redirect URL case)
        start = S.login_start()
        state = parse_qs(urlsplit(start['authorize_url']).query)['state'][0]
        code, body = http(self.port, 'GET', f'/wizard-whoop/callback?code=good-code&state={state}')
        self.assertEqual(code, 200)
        self.assertIn(b'WHOOP connected', body)
        self.wait_sync()

        # ---- refresh refused -> needs sign-in, tokens removed, data kept
        while S.SYNC_LOCK.locked():
            time.sleep(0.05)
        FAKE.refresh = 'rotated-elsewhere'
        t = S._tokens(); t['expires_at'] = 0; S._save_tokens(t)
        with self.assertRaises(S.Problem):
            S.api_get('/v2/cycle', {'limit': 1})
        st = S.status_info()
        self.assertEqual(st['status'], 'needs_login')
        self.assertFalse((S.DATA / 'tokens.json').exists())
        self.assertEqual(st['counts']['days'], DAYS)
        ds = st['dataset']

        # ---- replace keys clears the old sign-in; disconnect wipes data, forget wipes keys
        start = S.login_start()
        state = parse_qs(urlsplit(start['authorize_url']).query)['state'][0]
        S.login_finish(f'http://localhost:3000/callback?code=good-code&state={state}')
        self.wait_sync()
        while S.SYNC_LOCK.locked():
            time.sleep(0.05)
        access, refresh = FAKE.access, FAKE.refresh
        code, body = http(self.port, 'POST', '/api/disconnect', {'forget_keys': True})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['status'], 'not_configured')
        self.assertTrue(FAKE.revoked)
        blob = self.files_text()
        for secret in (SECRET, CID, access, refresh):
            self.assertNotIn(secret, blob)
        st = S.status_info()
        self.assertEqual(st['counts'], {'days': 0, 'sleeps': 0, 'workouts': 0})
        self.assertNotEqual(st['dataset'], ds, 'readers must see the copy was wiped')

    def test_migrates_013_database(self):
        """A 0.1.3 database (no change sequence) keeps every record and becomes readable through the contract."""
        import sqlite3
        tmp = Path(tempfile.mkdtemp())
        try:
            old = sqlite3.connect(tmp / 'whoop.sqlite3')
            old.executescript('''CREATE TABLE records (kind TEXT NOT NULL, id TEXT NOT NULL, start TEXT, end_at TEXT, updated_at TEXT,
                cycle_id TEXT, sleep_id TEXT, nap INTEGER DEFAULT 0, score_state TEXT, day TEXT, data TEXT NOT NULL, PRIMARY KEY (kind, id));
                CREATE TABLE meta (key TEXT PRIMARY KEY, data TEXT NOT NULL);''')
            c = make_data()['/developer/v2/cycle'][0]
            old.execute("INSERT INTO records (kind,id,start,end_at,updated_at,day,data) VALUES ('cycle',?,?,?,?,?,?)",
                        (str(c['id']), c['start'], c['end'], c['updated_at'], '2026-08-02', json.dumps(c)))
            old.commit(); old.close()
            data = self.S.DATA
            self.S.DATA = tmp
            try:
                r = self.S.contract_days({'changed_since': ''})
                self.assertEqual([d['date'] for d in r['days']], ['2026-08-02'])
                self.assertEqual(r['cursor'], 'w1.1')
                self.assertEqual(self.S.contract_days({'changed_since': r['cursor']})['days'], [])
            finally:
                self.S.DATA = data
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


DAY_KEYS = {'date', 'updated_at', 'readiness', 'hrv_ms', 'resting_hr_bpm', 'spo2_pct', 'skin_temp_c', 'skin_temp_delta_c', 'respiratory_rate',
            'sleep', 'load', 'calories_kcal', 'energy_kj', 'avg_hr_bpm', 'max_hr_bpm', 'steps', 'workouts', 'extras'}
SLEEP_KEYS = {'start', 'end', 'asleep_h', 'in_bed_h', 'awake_h', 'light_h', 'deep_h', 'rem_h', 'score', 'efficiency_pct', 'respiratory_rate', 'need_h', 'naps'}
WORKOUT_KEYS = {'id', 'sport', 'start', 'end', 'minutes', 'load', 'avg_hr_bpm', 'max_hr_bpm', 'calories_kcal', 'energy_kj', 'distance_m', 'zones_min', 'extras'}


def check_day(t, d):
    """The day record shape promised by docs/health-data-contract.md."""
    t.assertTrue(DAY_KEYS <= set(d), DAY_KEYS - set(d))
    t.assertRegex(d['date'], r'^\d{4}-\d{2}-\d{2}$')
    if d['readiness']:
        t.assertIn(d['readiness']['band'], ('high', 'medium', 'low', None))
        t.assertIn(d['readiness']['state'], ('scored', 'pending', 'unscorable'))
    if d['sleep']:
        t.assertTrue(SLEEP_KEYS <= set(d['sleep']), SLEEP_KEYS - set(d['sleep']))
    if d['load']:
        t.assertEqual(set(d['load']), {'value', 'max', 'label'})
    for w in d['workouts']:
        t.assertTrue(WORKOUT_KEYS <= set(w), WORKOUT_KEYS - set(w))
    t.assertEqual(set(d['extras']), {'whoop'})



class IconTest(unittest.TestCase):
    """Own icon: full-colour store square (icon.png from wizard.md) and a silhouette at web/icon.svg the shell tints.
    A generic strap with a sensor pod; never WHOOP's own logo or wordmark."""
    root = Path(__file__).resolve().parent.parent

    def test_icons(self):
        self.assertIn('\nicon: icon.png\n', (self.root / 'wizard.md').read_text())
        png = (self.root / 'icon.png').read_bytes()
        self.assertEqual(png[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual((int.from_bytes(png[16:20], 'big'), int.from_bytes(png[20:24], 'big')), (1024, 1024))
        mask = (self.root / 'web' / 'icon.svg').read_text()
        self.assertIn('viewBox="0 0 512 512"', mask)
        self.assertNotRegex(mask, r'<text|<image|href=')
        self.assertNotIn('WHOOP', mask + (self.root / 'icon.svg').read_text())

if __name__ == '__main__':
    unittest.main()
