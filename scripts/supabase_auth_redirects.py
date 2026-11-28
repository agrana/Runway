"""Supabase Auth redirect intent and project-owned append-only reconciliation.

No CLI or environment credential lookup. An app workflow may publish an intent,
not apply it. A trusted project owner must supply authorization, project-wide
serialization and a dedicated Management API transport.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
import http.client
import json
import re
import urllib.error
import urllib.request

CONFIG = 'supabase-auth-redirects.config.json'
PROJECT_REF = r'[a-z0-9]{20}'
HOST_LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
HOST = rf'(?:{HOST_LABEL}\.)+[a-z]{{2,63}}'
PATH = r'/(?:[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*)?'
CALLBACK_SUFFIX = rf'{PATH}(?:\?(?:type=recovery&)?next={PATH})?'
MAX_CALLBACKS = 16
MAX_CONFIG_BYTES = 16_384
MAX_RESPONSE_BYTES = 1_048_576


class AuthRedirectError(Exception):
    """Stable error code; never attach provider content or credentials."""


def unique_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def validate_host(host):
    if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(HOST, host):
        raise AuthRedirectError('auth_redirect_hostname_invalid')


def validate_callbacks(callbacks, host):
    if not isinstance(callbacks, (list, tuple)) or not 1 <= len(callbacks) <= MAX_CALLBACKS:
        raise AuthRedirectError('auth_redirect_callbacks_invalid')
    if any(not isinstance(url, str) or len(url) > 512 or not re.fullmatch(
            re.escape(f'https://{host}') + CALLBACK_SUFFIX, url) for url in callbacks):
        raise AuthRedirectError('auth_redirect_callback_invalid')
    if len(set(callbacks)) != len(callbacks):
        raise AuthRedirectError('auth_redirect_callback_duplicate')


@dataclass(frozen=True)
class RedirectIntent:
    repository_id: str
    source_sha: str
    hostname: str
    project_ref: str
    callbacks: tuple[str, ...]

    def __post_init__(self):
        for value, pattern in ((self.repository_id, r'[1-9][0-9]*'),
                               (self.source_sha, r'[0-9a-f]{40}'),
                               (self.project_ref, PROJECT_REF)):
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise AuthRedirectError('auth_redirect_binding_invalid')
        validate_host(self.hostname)
        if not isinstance(self.callbacks, tuple):
            raise AuthRedirectError('auth_redirect_callbacks_invalid')
        validate_callbacks(self.callbacks, self.hostname)

    def artifact(self):
        return {'schema_version': 1, **asdict(self)}


def parse_intent(raw, *, hostname, repository_id, source_sha, supabase_url):
    """Derive intent from a reviewed manifest and independently bound shell values."""
    try:
        data = json.loads(raw, object_pairs_hook=unique_mapping)
    except (ValueError, RecursionError):
        raise AuthRedirectError('auth_redirect_config_json_invalid') from None
    if (not isinstance(data, dict) or set(data) != {
            'schema_version', 'enabled', 'project_ref', 'callbacks'}
            or type(data['schema_version']) is not int or data['schema_version'] != 1
            or type(data['enabled']) is not bool or not isinstance(data['callbacks'], list)):
        raise AuthRedirectError('auth_redirect_config_invalid')
    if not data['enabled']:
        if data['project_ref'] is not None or data['callbacks']:
            raise AuthRedirectError('auth_redirect_disabled_config_not_empty')
        return None
    intent = RedirectIntent(repository_id, source_sha, hostname, data['project_ref'],
                            tuple(data['callbacks']))
    if supabase_url != f'https://{intent.project_ref}.supabase.co':
        raise AuthRedirectError('auth_redirect_project_mismatch')
    return intent


def load_intent(source, *, git, **binding):
    """Read only a regular policy blob in the already verified application commit.

    The merge orchestrator supplies its sanitized Git runner. Older templates
    with no policy are disabled. An ignored/untracked lookalike is not accepted.
    """
    path = Path(source) / CONFIG
    sha = binding['source_sha']
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise AuthRedirectError('auth_redirect_binding_invalid')
    entry = git(['git', 'ls-tree', '--full-tree', sha, '--', CONFIG], source)
    if not entry:
        if path.exists() or path.is_symlink():
            raise AuthRedirectError('auth_redirect_config_untracked')
        return None
    if not re.fullmatch(r'100(?:644|755) blob [0-9a-f]{40}\t' + re.escape(CONFIG), entry):
        raise AuthRedirectError('auth_redirect_config_not_regular')
    spec = sha + ':' + CONFIG
    size = git(['git', 'cat-file', '-s', spec], source)
    if not size.isdecimal() or int(size) > MAX_CONFIG_BYTES:
        raise AuthRedirectError('auth_redirect_config_too_large')
    return parse_intent(git(['git', 'show', spec], source), **binding)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ManagementAuth:
    """Fixed-host transport; callers inject a dedicated Auth credential explicitly."""

    def __init__(self, token):
        if (not isinstance(token, str) or not re.fullmatch(r'[!-~]{1,1024}', token)
                or token == 'SETUP_REQUIRED_REPLACE_WITH_REAL_VALUE'):
            raise AuthRedirectError('auth_redirect_credential_invalid')
        self._token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _request(self, project_ref, method, payload=None):
        if not isinstance(project_ref, str) or not re.fullmatch(PROJECT_REF, project_ref):
            raise AuthRedirectError('auth_redirect_binding_invalid')
        req = urllib.request.Request(
            f'https://api.supabase.com/v1/projects/{project_ref}/config/auth',
            method=method, data=json.dumps(payload).encode() if payload is not None else None,
            headers={'Authorization': f'Bearer {self._token}', 'Accept': 'application/json',
                     'Content-Type': 'application/json'},
        )
        try:
            with self._opener.open(req, timeout=20) as response:
                if method == 'PATCH':
                    return None  # Only the subsequent GET can prove the write.
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise AuthRedirectError('auth_redirect_response_too_large')
            return json.loads(body, object_pairs_hook=unique_mapping)
        except urllib.error.HTTPError as exc:
            exc.close()
            code = ('auth_redirect_access_denied' if exc.code in (401, 403)
                    else 'auth_redirect_provider_http_failed')
            raise AuthRedirectError(code) from None
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            raise AuthRedirectError('auth_redirect_provider_response_failed') from None

    def read(self, project_ref):
        return self._request(project_ref, 'GET')

    def patch_allow_list(self, project_ref, allow_list):
        self._request(project_ref, 'PATCH', {'uri_allow_list': allow_list})


def _snapshot(data):
    if (not isinstance(data, dict) or not isinstance(data.get('site_url'), str)
            or not data['site_url'] or not isinstance(data.get('uri_allow_list'), str)):
        raise AuthRedirectError('auth_redirect_snapshot_invalid')
    return data['site_url'], data['uri_allow_list']


def _entries(allow_list):
    return Counter(item for item in allow_list.split(',') if item)


def reconcile(intent, *, expected_project_ref, project_lock, authorize, transport):
    """Project-owner integration boundary, not an app-repository apply command.

    project_lock(ref) must serialize *all* Auth config writers for that project.
    authorize(intent) must independently confirm exact intent/current head/owned
    hostname under that lock (never just trust an app artifact). A denial makes
    zero provider calls. There is no retry or rollback on an uncertain write.
    """
    if not isinstance(intent, RedirectIntent) or expected_project_ref != intent.project_ref:
        raise AuthRedirectError('auth_redirect_project_mismatch')
    ref = intent.project_ref
    with project_lock(ref):
        if authorize(intent) is not True:
            raise AuthRedirectError('auth_redirect_not_authorized')
        site_url, before = _snapshot(transport.read(ref))
        entries = _entries(before)
        missing = [url for url in intent.callbacks if url not in entries]
        if not missing:
            return {'status': 'auth_redirects_already_present', 'added_count': 0}
        after = (before + ',' if before else '') + ','.join(missing)
        if authorize(intent) is not True:
            raise AuthRedirectError('auth_redirect_not_authorized')
        try:
            transport.patch_allow_list(ref, after)
        except AuthRedirectError as exc:
            if str(exc) == 'auth_redirect_access_denied':
                raise
            raise AuthRedirectError('auth_redirect_write_unverified') from None
        try:
            observed_site, observed_list = _snapshot(transport.read(ref))
        except AuthRedirectError:
            raise AuthRedirectError('auth_redirect_readback_failed') from None
        if observed_site != site_url or _entries(observed_list) != entries + Counter(missing):
            raise AuthRedirectError('auth_redirect_readback_mismatch')
        return {'status': 'auth_redirects_verified', 'added_count': len(missing)}
