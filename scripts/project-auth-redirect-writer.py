#!/usr/bin/env python3
"""Runway-only Auth writer; invoked inside the shared workflow concurrency group."""
from __future__ import annotations

import base64
from contextlib import nullcontext
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

from supabase_auth_redirects import (AuthRedirectError, CONFIG, MAX_CONFIG_BYTES,
                                   ManagementAuth, PROJECT_REF, RedirectIntent,
                                   _NoRedirect, parse_intent, reconcile, unique_mapping)

OWNER = 'agrana/Runway'
OWNER_ID = 1051601680
BRANCH = 'main'
WORKFLOW = '.github/workflows/project-auth-redirect-writer.yml'
ONBOARDING = '.github/workflows/merge-onboarding.yml'
REGISTRY = Path(__file__).resolve().parents[1] / 'project-auth-redirect-writer.config.json'
SHA = r'[0-9a-f]{40}'
DIGEST = r'sha256:[0-9a-f]{64}'
REPO = r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+'
ID = r'[1-9][0-9]{0,19}'
MAX_JSON = 2_000_000
MAX_ZIP = 16_000_000
HANDOFF = 'infrastructure_dns_verified_auth_pending_database_incomplete'
VERIFY_CHECKS = frozenset({
    'provider_domain_attached', 'provider_production_routing', 'provider_domain_verified',
    'configuration_mutations_outstanding', 'authoritative_cname', 'resolver_1_1_1_1',
    'resolver_8_8_8_8', 'tls', 'http_home', 'http_health', 'production_sha_stable',
})


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


onboarding = load('merge-onboarding')
onboarding_config = load('onboarding-config')


class Refusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def positive(value):
    return type(value) is int and 0 < value < 10**20


def mapping(value):
    return value if isinstance(value, dict) else {}


def decode(raw, error):
    try:
        data = json.loads(raw, object_pairs_hook=unique_mapping)
    except (ValueError, RecursionError):
        raise Refusal(error) from None
    require(isinstance(data, dict), error)
    return data


def parse_handoff(data):
    require(set(data) == {'schema_version', 'repository_id', 'source_sha', 'hostname',
                          'project_ref', 'callbacks'} and type(data['schema_version']) is int
            and data['schema_version'] == 1 and isinstance(data['callbacks'], list),
            'intent_schema_invalid')
    return RedirectIntent(data['repository_id'], data['source_sha'], data['hostname'],
                          data['project_ref'], tuple(data['callbacks']))


@dataclass(frozen=True)
class Review:
    repository: str
    default_branch: str
    vercel_project_id: str
    onboarding_run_id: int
    artifact_id: int
    artifact_digest: str
    intent: RedirectIntent


def select_review(raw, project_ref, repository_id):
    require(matches(PROJECT_REF, project_ref) and matches(ID, repository_id), 'selection_invalid')
    doc = decode(raw, 'registry_invalid')
    require(set(doc) == {'schema_version', 'enabled', 'requests'}
            and type(doc['schema_version']) is int and doc['schema_version'] == 1
            and type(doc['enabled']) is bool and isinstance(doc['requests'], list)
            and len(doc['requests']) <= 100, 'registry_invalid')
    require(doc['enabled'], 'writer_disabled')
    reviews = {}
    names = set()
    for item in doc['requests']:
        require(isinstance(item, dict) and set(item) == {
            'repository', 'default_branch', 'vercel_project_id', 'onboarding_run_id',
            'artifact_id', 'artifact_digest', 'intent'}, 'review_invalid')
        intent = parse_handoff(mapping(item['intent']))
        repo, branch = item['repository'], item['default_branch']
        require(matches(REPO, repo) and all(part not in ('.', '..') for part in repo.split('/'))
                and repo.lower() != OWNER.lower() and intent.repository_id != str(OWNER_ID)
                and matches(r'[A-Za-z0-9_-][A-Za-z0-9_./-]{0,127}', branch)
                and matches(r'prj_[A-Za-z0-9]+', item['vercel_project_id'])
                and positive(item['onboarding_run_id']) and positive(item['artifact_id'])
                and matches(DIGEST, item['artifact_digest']), 'review_invalid')
        key = (intent.project_ref, intent.repository_id)
        require(key not in reviews and repo.lower() not in names, 'duplicate_review')
        names.add(repo.lower())
        reviews[key] = Review(**dict(item, intent=intent))
    review = reviews.get((project_ref, repository_id))
    require(review is not None, 'request_not_reviewed')
    return review


class GitHubEvidence:
    def __init__(self, token):
        require(matches(r'[!-~]{1,1024}', token) and token != onboarding.PLACEHOLDER,
                'github_evidence_not_configured')
        self._token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _api_request(self, path):
        return urllib.request.Request('https://api.github.com' + path, headers={
            'Authorization': 'Bearer ' + self._token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        })

    def _read(self, request, limit):
        try:
            with self._opener.open(request, timeout=20) as response:
                raw = response.read(limit + 1)
        except (OSError, ValueError, HTTPException) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise Refusal('github_request_failed') from None
        require(len(raw) <= limit, 'github_response_too_large')
        return raw

    def get(self, path):
        return decode(self._read(self._api_request(path), MAX_JSON), 'github_response_invalid')

    def archive(self, repo_path, artifact_id):
        request = self._api_request(f'{repo_path}/actions/artifacts/{artifact_id}/zip')
        try:
            with self._opener.open(request, timeout=20):
                raise Refusal('github_archive_redirect_invalid')
        except urllib.error.HTTPError as exc:
            try:
                require(exc.code == 302, 'github_archive_redirect_invalid')
                url = exc.headers.get('Location', '')
                target = urllib.parse.urlsplit(url)
                require(target.scheme == 'https' and not target.fragment and matches(
                    r'[a-z0-9-]+\.(?:blob\.core\.windows\.net|actions\.githubusercontent\.com)',
                    target.netloc), 'github_archive_redirect_invalid')
            except ValueError:
                raise Refusal('github_archive_redirect_invalid') from None
            finally:
                exc.close()
        except (OSError, ValueError, HTTPException):
            raise Refusal('github_request_failed') from None
        # A signed URL is sensitive; no logging, no GitHub header, no redirect following.
        return self._read(urllib.request.Request(url), MAX_ZIP)


def unpack(raw, digest):
    require('sha256:' + sha256(raw).hexdigest() == digest, 'archive_digest_mismatch')
    selected = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            require(len(infos) <= 128, 'archive_invalid')
            for name in ('auth-redirect-intent.json', 'merge-onboarding-result.json'):
                found = [info for info in infos if info.filename == name]
                require(len(found) == 1 and found[0].file_size <= 256_000, 'archive_invalid')
                selected[name] = decode(archive.read(found[0]), 'archive_json_invalid')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, ValueError,
            EOFError, zlib.error):
        raise Refusal('archive_invalid') from None
    return selected['auth-redirect-intent.json'], selected['merge-onboarding-result.json']


def check_head(api, repo, repository_id, branch, sha, *, owner=False):
    meta = api.get(f'/repositories/{repository_id}')
    name = meta.get('full_name')
    require(type(meta.get('id')) is int and str(meta['id']) == repository_id
            and (name.lower() == repo.lower() if owner and isinstance(name, str) else name == repo)
            and meta.get('default_branch') == branch and meta.get('fork') is False
            and (owner or meta.get('is_template') is False), 'repository_binding_mismatch')
    current = api.get(f'/repos/{repo}/commits/' + urllib.parse.quote(branch, safe=''))
    require(current.get('sha') == sha, 'source_not_current')
    return current


def check_runs(api, review):
    intent = review.intent
    repo = f'/repos/{review.repository}'
    run = api.get(f'{repo}/actions/runs/{review.onboarding_run_id}')
    for field in ('repository', 'head_repository'):
        binding = mapping(run.get(field))
        require(positive(binding.get('id')) and str(binding['id']) == intent.repository_id
                and binding.get('full_name') == review.repository, 'onboarding_run_invalid')
    require(positive(run.get('id')) and run['id'] == review.onboarding_run_id
            and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
            and run.get('path') == ONBOARDING and run.get('event') == 'push'
            and run.get('head_branch') == review.default_branch and run.get('head_sha') == intent.source_sha
            and run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'onboarding_run_invalid')
    quality = api.get(f'{repo}/actions/workflows/app-quality.yml/runs?'
                      + urllib.parse.urlencode({'per_page': 100, 'head_sha': intent.source_sha}))
    rows = quality.get('workflow_runs')
    require(isinstance(rows, list) and type(quality.get('total_count')) is int
            and quality['total_count'] == len(rows) <= 100, 'quality_inventory_incomplete')
    kind, meta = onboarding.select_authoritative_quality_run(
        rows, intent.source_sha, review.default_branch, intent.repository_id, review.repository)
    require(kind == 'success', 'quality_not_current_success')
    return meta


def verify_policies(api, review, head):
    intent = review.intent
    tree_sha = mapping(mapping(head.get('commit')).get('tree')).get('sha')
    require(matches(SHA, tree_sha), 'policy_tree_invalid')
    repo = f'/repos/{review.repository}'
    tree = api.get(f'{repo}/git/trees/{tree_sha}')
    entries = tree.get('tree')
    require(tree.get('sha') == tree_sha and tree.get('truncated') is False
            and isinstance(entries, list), 'policy_tree_invalid')

    def blob(path):
        found = [entry for entry in entries if mapping(entry).get('path') == path]
        require(len(found) == 1, 'policy_blob_invalid')
        entry = found[0]
        size, oid = entry.get('size'), entry.get('sha')
        require(entry.get('mode') in ('100644', '100755') and entry.get('type') == 'blob'
                and positive(size) and size <= MAX_CONFIG_BYTES and matches(SHA, oid),
                'policy_blob_invalid')
        obj = api.get(f'{repo}/git/blobs/{oid}')
        require(obj.get('sha') == oid and type(obj.get('size')) is int and obj['size'] == size
                and obj.get('encoding') == 'base64' and isinstance(obj.get('content'), str),
                'policy_blob_invalid')
        try:
            raw = base64.b64decode(obj['content'].replace('\n', ''), validate=True)
            require(len(raw) == size, 'policy_blob_invalid')
            return raw.decode('utf-8')
        except ValueError:
            raise Refusal('policy_blob_invalid') from None

    raw = blob('onboarding.config.json')
    try:
        config = onboarding_config.validate_mapping(decode(raw, 'onboarding_policy_invalid'))
    except onboarding_config.ConfigError:
        raise Refusal('onboarding_policy_invalid') from None
    require(config['auto_apply'] is True and config['hostname'] == intent.hostname
            and (config['expected_project_id'] is None or (
                config['expected_project_id'] == review.vercel_project_id
                and config['confirm_repository_id'] == intent.repository_id)),
            'onboarding_policy_mismatch')
    rebuilt = parse_intent(blob(CONFIG), hostname=intent.hostname, repository_id=intent.repository_id,
                           source_sha=intent.source_sha,
                           supabase_url=f'https://{intent.project_ref}.supabase.co')
    require(rebuilt == intent, 'committed_intent_mismatch')


def verify_artifact(api, review, quality):
    intent = review.intent
    path = f'/repos/{review.repository}'
    items = api.get(f'{path}/actions/runs/{review.onboarding_run_id}/artifacts?per_page=100')
    rows = items.get('artifacts')
    require(isinstance(rows, list) and type(items.get('total_count')) is int
            and items['total_count'] == len(rows) <= 100, 'artifact_inventory_incomplete')
    name = 'merge-onboarding-' + intent.source_sha
    found = [row for row in rows if mapping(row).get('name') == name]
    require(len(found) == 1, 'artifact_binding_mismatch')
    entry = found[0]
    size = entry.get('size_in_bytes')
    require(positive(entry.get('id')) and entry['id'] == review.artifact_id
            and entry.get('expired') is False and entry.get('digest') == review.artifact_digest
            and positive(size) and size <= MAX_ZIP, 'artifact_binding_mismatch')
    archive = api.archive(path, review.artifact_id)
    require(len(archive) == size, 'artifact_binding_mismatch')
    handoff, result = unpack(archive, review.artifact_digest)
    require(parse_handoff(handoff) == intent, 'artifact_intent_mismatch')
    stages = mapping(result.get('stages'))
    require(result.get('status') == HANDOFF and result.get('infrastructure_dns_ready') is True
            and result.get('full_app_ready') is False and result.get('source_sha') == intent.source_sha
            and result.get('repository_id') == intent.repository_id
            and result.get('default_branch') == review.default_branch
            and mapping(result.get('config')).get('hostname') == intent.hostname
            and stages.get('auth_redirects') == {'status': 'awaiting_project_owner_apply', 'verified': False},
            'onboarding_result_invalid')
    gate = mapping(stages.get('quality_gate'))
    require(gate.get('status') == 'quality_gate_passed'
            and all(type(gate.get(key)) is type(value) and gate[key] == value
                    for key, value in quality.items() if key not in ('status', 'conclusion')),
            'quality_evidence_mismatch')
    shell = mapping(stages.get('shell_binding'))
    verify = mapping(stages.get('hostname_dns_verify'))
    checks = mapping(verify.get('checks'))
    require(shell.get('status') in onboarding.ALLOWED_SHELL_STATUSES
            and shell.get('source_sha') == intent.source_sha
            and shell.get('project_id') == review.vercel_project_id
            and matches(r'dpl_[A-Za-z0-9]+', shell.get('deployment_id'))
            and verify.get('status') == 'verification_passed' and verify.get('readiness') == 'ready'
            and verify.get('hostname') == intent.hostname
            and verify.get('project_id') == review.vercel_project_id
            and verify.get('app_deployment_sha') == intent.source_sha
            and verify.get('automation_source_sha') == intent.source_sha
            and verify.get('pending_checks') == [] and verify.get('failed_checks') == []
            and VERIFY_CHECKS.issubset(checks) and all(value == 'passed' for value in checks.values()),
            'deployment_evidence_invalid')


def apply_review(review, *, owner_sha, api, transport):
    """Caller holds the workflow job's project lock from start through readback."""
    intent = review.intent
    quality = None

    def authorize(candidate):
        nonlocal quality
        if candidate != intent:
            return False
        current_quality = check_runs(api, review)
        if quality is None:
            head = check_head(api, review.repository, intent.repository_id,
                              review.default_branch, intent.source_sha)
            verify_policies(api, review, head)
            verify_artifact(api, review, current_quality)
            quality = current_quality
        else:
            require(current_quality == quality, 'quality_evidence_changed')
        check_head(api, OWNER, str(OWNER_ID), BRANCH, owner_sha, owner=True)
        check_head(api, review.repository, intent.repository_id, review.default_branch, intent.source_sha)
        return True

    return reconcile(intent, expected_project_ref=intent.project_ref, authorize=authorize,
                     project_lock=lambda _ref: nullcontext(), transport=transport)


def load_request(env, registry):
    sha = env.get('GITHUB_SHA')
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY_ID') == str(OWNER_ID)
            and env.get('GITHUB_REPOSITORY', '').lower() == OWNER.lower()
            and env.get('GITHUB_REF') == f'refs/heads/{BRANCH}'
            and env.get('GITHUB_WORKFLOW_REF', '').lower()
            == f'{OWNER}/{WORKFLOW}@refs/heads/{BRANCH}'.lower()
            and matches(SHA, sha) and env.get('GITHUB_WORKFLOW_SHA') == sha,
            'writer_context_invalid')
    with registry.open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON, 'registry_invalid')
    return sha, select_review(raw, env.get('REQUEST_PROJECT_REF'), env.get('REQUEST_REPOSITORY_ID'))


def run(env, registry=REGISTRY, *, check_registry=False):
    sha, review = load_request(env, registry)
    if check_registry:
        return {'status': 'reviewed_request_selected'}
    output = apply_review(review, owner_sha=sha, api=GitHubEvidence(env.get('AUTH_REDIRECT_EVIDENCE_TOKEN')),
                          transport=ManagementAuth(env.get('SUPABASE_AUTH_MANAGEMENT_TOKEN')))
    return {**output, 'project_ref': review.intent.project_ref, 'repository_id': review.intent.repository_id,
            'source_sha': review.intent.source_sha}


def main():
    try:
        require(sys.argv[1:] in ([], ['--check-registry']), 'writer_arguments_invalid')
        result = run(os.environ, check_registry=sys.argv[1:] == ['--check-registry'])
    except (Refusal, AuthRedirectError) as exc:
        print(json.dumps({'status': str(exc)}))  # Only closed codes from the trusted implementation.
        return 1
    except Exception:
        print(json.dumps({'status': 'writer_internal_failure'}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
