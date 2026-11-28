"""Offline tests: exercise reconciliation and the actual urllib request shape."""
import contextlib
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('runway_auth_redirects', ROOT / 'scripts/supabase_auth_redirects.py')
assert SPEC is not None and SPEC.loader is not None
auth = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = auth
SPEC.loader.exec_module(auth)
HOST = 'soflists.zenara.be'
REF = 'abcdefghijklmnopqrst'
CALLBACKS = (
    'https://soflists.zenara.be/auth/callback?next=/lists',
    'https://soflists.zenara.be/auth/callback?type=recovery&next=/auth/reset-password',
)
BINDING = {'hostname': HOST, 'repository_id': '2000000001', 'source_sha': 'a' * 40,
           'supabase_url': f'https://{REF}.supabase.co'}
POLICY = {'schema_version': 1, 'enabled': True, 'project_ref': REF, 'callbacks': list(CALLBACKS)}


class PolicyTests(unittest.TestCase):
    def test_off_by_default_and_literal_callbacks(self):
        raw = (ROOT / auth.CONFIG).read_text()
        # A generated app can enable its policy without changing inherited tests.
        payload = json.loads(raw)
        self.assertEqual(set(payload), set(POLICY))
        disabled = dict(POLICY, enabled=False, project_ref=None, callbacks=[])
        if payload['enabled'] is False:
            self.assertEqual(payload, disabled)
        self.assertIsNone(auth.parse_intent(json.dumps(disabled), **BINDING))
        intent = auth.parse_intent(json.dumps(POLICY), **BINDING)
        self.assertEqual(intent.callbacks, CALLBACKS)
        self.assertEqual(json.loads(json.dumps(intent.artifact()))['callbacks'], list(CALLBACKS))

    def test_second_app_needs_only_new_config_and_binding(self):
        callbacks = ['https://journal.example.org/login/return']
        intent = auth.parse_intent(json.dumps(dict(POLICY, callbacks=callbacks)),
                                   **dict(BINDING, hostname='journal.example.org', repository_id='22'))
        self.assertEqual(intent.callbacks, tuple(callbacks))

    def test_rejects_destinations_outside_policy(self):
        for suffix_or_url in (
            'http://' + HOST + '/auth/callback', 'https://preview.' + HOST + '/auth/callback',
            'https://' + HOST + '.example.net/auth/callback', 'https://' + HOST + ':443/auth/callback',
            'https://' + HOST + '@example.net/auth/callback', 'https://' + HOST + '/**',
            'https://' + HOST + '/auth/[callback]', 'https://' + HOST + '/auth/callback#fragment',
            'https://' + HOST + '/auth/callback?next=//example.net',
            'https://' + HOST + '/auth/callback?next=/%2e%2e',
            'https://' + HOST + '/auth/callback?next=/lists&next=/other',
            'https://' + HOST + '/auth/callback?next=/lists,https://example.net',
            'https://' + HOST + '/auth/callback?next=/lists\n',
            'https://' + HOST + '/auth/callback?next=/list?',
        ):
            with self.subTest(url=suffix_or_url), self.assertRaisesRegex(
                    auth.AuthRedirectError, '^auth_redirect_callback_invalid$'):
                auth.parse_intent(json.dumps(dict(POLICY, callbacks=[suffix_or_url])), **BINDING)

    def test_rejects_invalid_manifest_and_binding_without_echoing_values(self):
        for payload in (None, [], dict(POLICY, enabled=1), dict(POLICY, schema_version=True),
                        dict(POLICY, unknown='never-echo'), dict(POLICY, enabled=False),
                        dict(POLICY, callbacks=[]), dict(POLICY, callbacks=[CALLBACKS[0]] * 2),
                        dict(POLICY, project_ref='../../bad')):
            with self.subTest(payload=payload), self.assertRaises(auth.AuthRedirectError) as error:
                auth.parse_intent(json.dumps(payload), **BINDING)
            self.assertNotIn('never-echo', str(error.exception))
        with self.assertRaisesRegex(auth.AuthRedirectError, 'config_json_invalid'):
            auth.parse_intent('{"enabled":true,"enabled":false}', **BINDING)
        with self.assertRaisesRegex(auth.AuthRedirectError, 'project_mismatch'):
            auth.parse_intent(json.dumps(POLICY), **dict(BINDING, supabase_url='https://other.supabase.co'))


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.before = 'https://existing.example.com/**, http://localhost:3000/cb,https://existing.example.com/**'
        self.site = 'https://existing.example.com'
        self.snapshot = {'site_url': self.site, 'uri_allow_list': self.before,
                         'smtp_pass': 'fixture-never-in-report'}
        self.intent = auth.parse_intent(json.dumps(POLICY), **BINDING)
        self.sequence = []
        self.fixture_auth = 'fixture-transport-only'
        self.read_override = None
        self.read_exception = None
        self.patch_exception = None
        self.readback = None
        self.approvals = iter([True, True])
        self.cut = auth.ManagementAuth(self.fixture_auth)

    @contextlib.contextmanager
    def lock(self, ref):
        self.assertEqual(ref, REF)
        self.sequence.append('lock')
        try:
            yield
        finally:
            self.sequence.append('unlock')

    def authorize(self, intent):
        self.assertIs(intent, self.intent)
        self.sequence.append('authorize')
        return next(self.approvals)

    def open(self, req, *, timeout):
        self.assertEqual(timeout, 20)
        self.assertEqual(urlsplit(req.full_url).netloc, 'api.supabase.com')
        self.assertEqual(req.full_url, f'https://api.supabase.com/v1/projects/{REF}/config/auth')
        self.assertEqual(req.get_header('Authorization'), 'Bearer ' + self.fixture_auth)
        method = req.get_method()
        self.sequence.append(method)
        if method == 'PATCH':
            if self.patch_exception:
                raise self.patch_exception
            payload = json.loads(req.data)
            self.assertEqual(set(payload), {'uri_allow_list'})
            missing = [c for c in CALLBACKS if c not in self.before.split(',')]
            self.assertEqual(payload['uri_allow_list'], self.before + ',' + ','.join(missing))
            self.snapshot.update(payload)
            return io.BytesIO(b'')
        self.assertEqual(method, 'GET')
        self.assertIsNone(req.data)
        if self.read_exception:
            raise self.read_exception
        if self.readback is not None and 'PATCH' in self.sequence:
            return io.BytesIO(self.readback)
        return io.BytesIO(self.read_override if self.read_override is not None else
                          json.dumps(self.snapshot).encode())

    def reconcile(self, **kw):
        args = dict(expected_project_ref=REF, authorize=self.authorize, project_lock=self.lock,
                    transport=self.cut)
        with patch.object(self.cut._opener, 'open', side_effect=self.open):
            return auth.reconcile(self.intent, **dict(args, **kw))

    def test_add_both_then_replay_is_noop(self):
        self.assertEqual(self.reconcile(), {'status': 'auth_redirects_verified', 'added_count': 2})
        self.assertEqual(self.sequence, ['lock', 'authorize', 'GET', 'authorize', 'PATCH', 'GET', 'unlock'])
        self.assertEqual(self.snapshot['site_url'], self.site)
        self.sequence.clear()
        self.approvals = iter([True])
        self.assertEqual(self.reconcile(), {'status': 'auth_redirects_already_present', 'added_count': 0})
        self.assertEqual(self.sequence, ['lock', 'authorize', 'GET', 'unlock'])

    def test_append_only_missing_exact_query_variant(self):
        self.before += ',' + CALLBACKS[0]
        self.snapshot['uri_allow_list'] = self.before
        self.assertEqual(self.reconcile()['added_count'], 1)
        self.assertEqual(self.snapshot['uri_allow_list'], self.before + ',' + CALLBACKS[1])

    def test_no_url_normalization_when_checking_existing_entries(self):
        self.before += ', ' + CALLBACKS[0] + ',' + CALLBACKS[1].replace('&', '%26')
        self.snapshot['uri_allow_list'] = self.before
        self.assertEqual(self.reconcile()['added_count'], 2)
        self.assertEqual(self.snapshot['uri_allow_list'], ','.join((self.before, *CALLBACKS)))

    def test_target_and_authorization_guards(self):
        with self.assertRaisesRegex(auth.AuthRedirectError, 'project_mismatch'):
            self.reconcile(expected_project_ref='z' * 20)
        self.assertEqual(self.sequence, [])
        for approvals, expected in (([False], ['lock', 'authorize', 'unlock']),
                                    ([True, False], ['lock', 'authorize', 'GET', 'authorize', 'unlock'])):
            self.sequence.clear()
            self.approvals = iter(approvals)
            with self.assertRaisesRegex(auth.AuthRedirectError, 'not_authorized'):
                self.reconcile()
            self.assertEqual(self.sequence, expected)

    def test_read_denial_and_bad_snapshots_do_not_write(self):
        for override, failure, code in (
            (None, HTTPError('https://api.supabase.com', 403, self.fixture_auth, Message(),
                             io.BytesIO(b'private')), 'access_denied'),
            (None, URLError(self.fixture_auth), 'provider_response_failed'),
            (b'{"site_url":"https://example.com","uri_allow_list":null}', None, 'snapshot_invalid'),
            (b'{"site_url":"x","uri_allow_list":"","uri_allow_list":"x"}', None, 'provider_response_failed'),
        ):
            self.sequence.clear()
            self.approvals = iter([True])
            self.read_override, self.read_exception = override, failure
            with self.assertRaisesRegex(auth.AuthRedirectError, '^auth_redirect_' + code + '$'):
                self.reconcile()
            self.assertEqual(self.sequence, ['lock', 'authorize', 'GET', 'unlock'])

    def test_no_retry_on_patch_failure(self):
        self.patch_exception = URLError(self.fixture_auth)
        with self.assertRaisesRegex(auth.AuthRedirectError, 'write_unverified'):
            self.reconcile()
        self.assertEqual(self.sequence, ['lock', 'authorize', 'GET', 'authorize', 'PATCH', 'unlock'])

    def test_readback_drift_or_failure_is_not_success(self):
        for body, error in (
            (dict(self.snapshot, uri_allow_list=','.join(CALLBACKS)), 'readback_mismatch'),
            (dict(self.snapshot, site_url='https://drift.example.net',
                  uri_allow_list=','.join((self.before, *CALLBACKS))), 'readback_mismatch'),
            (dict(self.snapshot, uri_allow_list=self.before), 'readback_mismatch'),
            (None, 'readback_failed'),
        ):
            self.sequence.clear()
            self.snapshot.update(site_url=self.site, uri_allow_list=self.before)
            self.approvals = iter([True, True])
            self.readback = json.dumps(body).encode() if body else b'not JSON'
            with self.assertRaisesRegex(auth.AuthRedirectError, error):
                self.reconcile()
            self.assertEqual(self.sequence.count('PATCH'), 1)
            self.assertEqual(self.sequence[-1], 'unlock')

    def test_no_redirect_or_environment_proxy(self):
        self.assertFalse(any(isinstance(h, auth.urllib.request.ProxyHandler) and h.proxies
                             for h in self.cut._opener.handlers))
        handler = next(h for h in self.cut._opener.handlers if isinstance(h, auth._NoRedirect))
        self.assertIsNone(handler.redirect_request(None, None, 302, '', {}, 'https://other.invalid'))


if __name__ == '__main__':
    unittest.main()
