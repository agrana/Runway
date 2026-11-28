"""Offline contract checks for the Runway-only Auth writer workflow and evidence gate."""
import base64
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.parse import urlencode
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/project-auth-redirect-writer.py'
SPEC = importlib.util.spec_from_file_location('runway_project_auth_writer', SCRIPT)
assert SPEC is not None and SPEC.loader is not None
writer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = writer
with patch.object(sys, 'path', [str(SCRIPT.parent), *sys.path]):
    SPEC.loader.exec_module(writer)

REF = 'abcdefghijklmnopqrst'
REPO = 'example/app'
RID = '123456789'
APP_SHA = 'a' * 40
OWNER_SHA = 'b' * 40
HOST = 'app.example.org'
CALLBACK = 'https://app.example.org/auth/callback?next=/lists'
LEGACY = 'https://legacy.example.org/**'
API_ROOT = f'/repos/{REPO}'
ARTIFACTS = API_ROOT + '/actions/runs/12/artifacts?per_page=100'
ENV = {
    'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_REPOSITORY_ID': str(writer.OWNER_ID), 'GITHUB_REPOSITORY': writer.OWNER,
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': OWNER_SHA, 'GITHUB_WORKFLOW_SHA': OWNER_SHA,
    'GITHUB_WORKFLOW_REF': f'{writer.OWNER}/{writer.WORKFLOW}@refs/heads/main',
    'REQUEST_PROJECT_REF': REF, 'REQUEST_REPOSITORY_ID': RID,
}


def evidence():
    binding = {'id': int(RID), 'full_name': REPO}
    common = dict(head_sha=APP_SHA, head_branch='main', head_repository=binding,
                  event='push', status='completed', conclusion='success', run_attempt=1)
    quality = dict(common, id=22, workflow_id=33, path='.github/workflows/app-quality.yml')
    _, meta = writer.onboarding.classify_quality_run(quality, APP_SHA, 'main', RID, REPO)
    intent = dict(schema_version=1, repository_id=RID, source_sha=APP_SHA, hostname=HOST,
                  project_ref=REF, callbacks=[CALLBACK])
    verify = dict(status='verification_passed', readiness='ready', hostname=HOST,
                  project_id='prj_fixture', app_deployment_sha=APP_SHA,
                  automation_source_sha=APP_SHA, pending_checks=[], failed_checks=[],
                  checks=dict.fromkeys(writer.VERIFY_CHECKS, 'passed'))
    result = dict(status=writer.HANDOFF, infrastructure_dns_ready=True, full_app_ready=False,
                  source_sha=APP_SHA, repository_id=RID, default_branch='main',
                  config={'hostname': HOST}, stages={
                      'auth_redirects': {'status': 'awaiting_project_owner_apply', 'verified': False},
                      'quality_gate': dict(meta, status='quality_gate_passed'),
                      'shell_binding': {'status': 'page_and_health_verified', 'source_sha': APP_SHA,
                                        'project_id': 'prj_fixture', 'deployment_id': 'dpl_fixture'},
                      'hostname_dns_verify': verify,
                  })
    data = io.BytesIO()
    with ZipFile(data, 'w') as archive:
        archive.writestr('auth-redirect-intent.json', json.dumps(intent))
        archive.writestr('merge-onboarding-result.json', json.dumps(result))
    raw = data.getvalue()
    digest = 'sha256:' + sha256(raw).hexdigest()
    artifacts = {'total_count': 1, 'artifacts': [dict(id=13, expired=False, digest=digest,
                 size_in_bytes=len(raw), name='merge-onboarding-' + APP_SHA)]}
    tree = 'c' * 40
    paths = {
        f'/repositories/{RID}': dict(binding, default_branch='main', fork=False, is_template=False),
        f'/repositories/{writer.OWNER_ID}': dict(id=writer.OWNER_ID, full_name=writer.OWNER,
                                                default_branch='main', fork=False),
        API_ROOT + '/commits/main': dict(sha=APP_SHA, commit={'tree': {'sha': tree}}),
        f'/repos/{writer.OWNER}/commits/main': {'sha': OWNER_SHA},
        API_ROOT + '/actions/runs/12': dict(common, id=12, repository=binding, path=writer.ONBOARDING),
        API_ROOT + '/actions/workflows/app-quality.yml/runs?' + urlencode(
            {'per_page': 100, 'head_sha': APP_SHA}): dict(total_count=1, workflow_runs=[quality]),
        ARTIFACTS: artifacts,
    }
    entries = []
    for i, (path, policy) in enumerate({
        'onboarding.config.json': dict(schema_version=1, hostname=HOST, cloudflare_zone_name='example.org',
                                       auto_apply=True, expected_project_id=None, confirm_repository_id=None),
        writer.CONFIG: dict(schema_version=1, enabled=True, project_ref=REF, callbacks=[CALLBACK]),
    }.items()):
        blob = str(i + 1) * 40
        value = json.dumps(policy).encode()
        entries.append(dict(path=path, sha=blob, mode='100644', type='blob', size=len(value)))
        paths[API_ROOT + '/git/blobs/' + blob] = dict(sha=blob, size=len(value), encoding='base64',
                                                   content=base64.b64encode(value).decode())
    paths[API_ROOT + '/git/trees/' + tree] = dict(sha=tree, truncated=False, tree=entries)
    registry = dict(schema_version=1, enabled=True, requests=[dict(
        repository=REPO, default_branch='main', vercel_project_id='prj_fixture', onboarding_run_id=12,
        artifact_id=13, artifact_digest=digest, intent=intent)])
    return registry, paths, raw


class WorkflowTests(unittest.TestCase):
    def test_workflow_contract_and_actual_disabled_cli(self):
        text = (ROOT / writer.WORKFLOW).read_text()
        self.assertEqual(re.findall(r'^  (\w+):', text.split('permissions:')[0], re.M), ['workflow_dispatch'])
        self.assertIn("github.repository_id == '1051601680'", text)
        self.assertIn("github.event.repository.default_branch == 'main'", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("github.workflow_ref == '" + ENV['GITHUB_WORKFLOW_REF'] + "'", text)
        self.assertIn('github.workflow_sha == github.sha', text)
        self.assertIn('permissions:\n  contents: read\n\njobs:', text)
        self.assertIn('group: supabase-project-auth-config-writer\n      cancel-in-progress: false', text)
        self.assertIn('environment: project-auth-redirect-writer', text)
        self.assertIn('ref: ${{ github.sha }}\n          persist-credentials: false', text)
        self.assertIn('REQUEST_PROJECT_REF: ${{ inputs.project_ref }}', text)
        self.assertIn('REQUEST_REPOSITORY_ID: ${{ inputs.repository_id }}', text)
        steps = text.split('    steps:', 1)[1].split('      - name: ')
        self.assertEqual(len(steps), 3)
        self.assertNotIn('secrets.', ''.join(steps[:2]))
        self.assertEqual(re.findall(r'\$\{\{ secrets\.(\w+) \}\}', steps[-1]),
                         ['AUTH_REDIRECT_EVIDENCE_TOKEN', 'SUPABASE_AUTH_MANAGEMENT_TOKEN'])
        # Run the literal workflow commands in a minimal checkout fixture, without secret values.
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            scripts = checkout / 'scripts'
            scripts.mkdir()
            for name in (SCRIPT.name, 'supabase_auth_redirects.py', 'merge-onboarding.py', 'onboarding-config.py'):
                (scripts / name).write_bytes((SCRIPT.parent / name).read_bytes())
            registry = checkout / writer.REGISTRY.name
            registry.write_text('{"schema_version":1,"enabled":false,"requests":[]}')
            commands = []
            for step in steps[1:]:
                match = re.search(r'^        run: (.+)$', step, re.M)
                assert match is not None
                command = match[1]
                self.assertNotIn('${{', command)
                commands.append(shlex.split(command))

            def check(command, status, code):
                result = subprocess.run(command, cwd=checkout, env={'PATH': os.defpath, **ENV},
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stderr, '')
                self.assertEqual(json.loads(result.stdout), {'status': status})

            for command in commands:
                check(command, 'writer_disabled', 1)
            reviewed, _, _ = evidence()
            registry.write_text(json.dumps(reviewed))
            check(commands[0], 'reviewed_request_selected', 0)
            check(commands[1], 'github_evidence_not_configured', 1)


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.paths, raw = evidence()
        self.api = Mock(spec=writer.GitHubEvidence)
        self.api.get.side_effect = self.paths.__getitem__
        self.api.archive.return_value = raw
        self.transport = Mock(spec=writer.ManagementAuth)
        self.before = {'site_url': 'https://legacy.example.org', 'uri_allow_list': LEGACY}
        self.after = dict(self.before, uri_allow_list=LEGACY + ',' + CALLBACK)
        self.transport.read.side_effect = [self.before, self.after]
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / writer.REGISTRY.name
        self.path.write_text(json.dumps(self.registry))
        for name, adapter in (('GitHubEvidence', self.api), ('ManagementAuth', self.transport)):
            self.enterContext(patch.object(writer, name, return_value=adapter))

    def test_verified_reconciliation_and_noop(self):
        result = writer.run(ENV, self.path)
        self.assertEqual(result, dict(status='auth_redirects_verified', added_count=1,
                                      project_ref=REF, repository_id=RID, source_sha=APP_SHA))
        self.assertEqual(self.transport.mock_calls,
                         [call.read(REF), call.patch_allow_list(REF, LEGACY + ',' + CALLBACK), call.read(REF)])
        self.transport.reset_mock()
        self.transport.read.side_effect = [self.after]
        self.assertEqual(writer.run(ENV, self.path)['status'], 'auth_redirects_already_present')
        self.assertEqual(self.transport.mock_calls, [call.read(REF)])

    def test_preflight_and_invalid_context_never_construct_authorized_adapters(self):
        self.assertEqual(writer.run(ENV, self.path, check_registry=True), {'status': 'reviewed_request_selected'})
        for key, value in [('GITHUB_REF', 'refs/heads/other'), ('GITHUB_REPOSITORY_ID', RID),
                           ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_WORKFLOW_SHA', APP_SHA),
                           ('GITHUB_WORKFLOW_REF', ENV['GITHUB_WORKFLOW_REF'] + '2')]:
            with self.subTest(key=key), self.assertRaisesRegex(writer.Refusal, '^writer_context_invalid$'):
                writer.run(dict(ENV, **{key: value}), self.path)
        with self.assertRaisesRegex(writer.Refusal, '^request_not_reviewed$'):
            writer.run(dict(ENV, REQUEST_REPOSITORY_ID='999'), self.path)
        with self.assertRaisesRegex(writer.Refusal, '^selection_invalid$'):
            writer.run(dict(ENV, REQUEST_PROJECT_REF=REF + '\ninvalid'), self.path)
        writer.GitHubEvidence.assert_not_called()
        writer.ManagementAuth.assert_not_called()

    def test_evidence_failures_precede_provider_calls(self):
        for path, replacement, error in (
            (API_ROOT + '/actions/runs/12', {'run_attempt': 2}, 'onboarding_run_invalid'),
            (ARTIFACTS, {'total_count': 2}, 'artifact_inventory_incomplete'),
            (API_ROOT + '/git/trees/' + 'c' * 40, {'truncated': True}, 'policy_tree_invalid'),
            (f'/repos/{writer.OWNER}/commits/main', {'sha': APP_SHA}, 'source_not_current'),
        ):
            original = self.paths[path]
            try:
                self.paths[path] = dict(original, **replacement)
                with self.subTest(error=error), self.assertRaisesRegex(writer.Refusal, '^' + error + '$'):
                    writer.run(ENV, self.path)
            finally:
                self.paths[path] = original
        self.api.archive.return_value = b'x' * len(self.api.archive.return_value)
        with self.assertRaisesRegex(writer.Refusal, '^archive_digest_mismatch$'):
            writer.run(ENV, self.path)
        self.assertEqual(self.transport.mock_calls, [])

    def test_head_change_after_get_blocks_patch(self):
        def read(ref):
            self.paths[API_ROOT + '/commits/main']['sha'] = 'd' * 40
            return self.before
        self.transport.read.side_effect = read
        with self.assertRaisesRegex(writer.Refusal, '^source_not_current$'):
            writer.run(ENV, self.path)
        self.assertEqual(self.transport.mock_calls, [call.read(REF)])

    def test_failed_readback_does_not_retry(self):
        self.transport.read.side_effect = [self.before, self.before]
        with self.assertRaisesRegex(writer.AuthRedirectError, '^auth_redirect_readback_mismatch$'):
            writer.run(ENV, self.path)
        self.assertEqual(self.transport.mock_calls,
                         [call.read(REF), call.patch_allow_list(REF, LEGACY + ',' + CALLBACK), call.read(REF)])
