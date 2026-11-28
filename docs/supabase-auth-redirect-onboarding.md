# Supabase Auth redirect onboarding

Auth-enabled apps declare their redirects during onboarding. The template ships with `supabase-auth-redirects.config.json` disabled; absence is also treated as disabled for older generated repositories. This feature does not change Supabase Auth providers, SMTP, Site URL, database policy or credentials.

## Application policy

Review and merge the generated app's normal `onboarding.config.json` (including `hostname`, zone and `auto_apply: true`) and this separate manifest. Set `enabled: true`, set `project_ref` to the approved hosted Supabase project ref, and list only callback URLs the app actually emits. The project ref must match the project in the existing `SUPABASE_URL` repository secret. Example shape (the ref below is synthetic):

```json
{
  "schema_version": 1,
  "enabled": true,
  "project_ref": "abcdefghijklmnopqrst",
  "callbacks": [
    "https://soflists.zenara.be/auth/callback?next=/lists",
    "https://soflists.zenara.be/auth/callback?type=recovery&next=/auth/reset-password"
  ]
}
```

Each entry must use the exact approved HTTPS hostname. The validator accepts simple slash-delimited paths and the literal `?next=/…` or `?type=recovery&next=/…` forms with a local slash-delimited destination; it rejects fragments, wildcard paths, external destinations, percent escapes, ports and preview aliases. The query string is not stripped, reordered, encoded or replaced with a wildcard. Audit the callback handler itself for safe redirect behavior; an allowlist entry is not a runtime redirect guard.

**Merge onboarding** checks the committed policy after the exact-head quality gate and before shell/provider writes. Once hostname, TLS, page, and deployment revision verification succeed and the source is still the current default-branch head, the existing workflow artifact contains `auth-redirect-intent.json`. It holds the immutable repository ID, source SHA, hostname, project ref and callbacks. `merge-onboarding-result.json` reports `awaiting_project_owner_apply`; neither artifact is Auth success or authorization. Protected or stale runs do not issue a handoff. The application workflow has no Auth Management credential and performs no Auth configuration API requests.

## Project-owned writer (maintainer only)

**Project Auth redirect writer** (`.github/workflows/project-auth-redirect-writer.yml`) runs only by manual dispatch on `agrana/Runway` (repository ID `1051601680`), on `main`. Generated repositories can produce handoffs but cannot use their copy of this writer. The owner registry, `project-auth-redirect-writer.config.json`, ships disabled with no entries.

1. Adopt the handoff producer in the generated app, merge its reviewed policies, and wait for a successful, first-attempt **Merge onboarding** push run with the Auth handoff at the app's current default-branch SHA. Do this before preparing a Runway registry change. If the app head changes, the run is rerun, or the artifact expires, obtain fresh qualifying evidence and review a new binding rather than bypassing the checks.
2. Separately review a Runway registry change: set `enabled: true` and add one entry per app, with `repository` (canonical `OWNER/REPO`), `default_branch`, `vercel_project_id`, numeric `onboarding_run_id` and `artifact_id`, the artifact's `artifact_digest` (`sha256:…` of the original ZIP), and `intent` (the exact six-field handoff JSON). Independently confirm ownership of the repository, hostname, deployment and target Supabase project; an app artifact alone does not authorize writes.
3. Before approval or dispatch, configure Runway's `project-auth-redirect-writer` GitHub environment with required reviewers, no self-approval, and deployment restricted to `main`. Store only these dedicated environment secrets there: `AUTH_REDIRECT_EVIDENCE_TOKEN` with read access to the registered app repositories' metadata, contents and Actions (including artifacts), and Runway metadata/contents; `SUPABASE_AUTH_MANAGEMENT_TOKEN` for the intended project (`GET` and `PATCH /v1/projects/{ref}/config/auth`). A scoped Supabase PAT needs **Auth Config: Read-write** and **Project Settings: Read-write** (`auth_config_read`, `auth_config_write`, and `project_admin_write` for these calls). Confirm the actual grants and approved credential delivery separately. A read probe in another repository does not establish Runway access or write permission. Do not reuse database Management credentials or add these secrets to app repositories. The YAML names the environment; it does not create its protection rules.
4. After the registry change is reviewed and merged and activation separately approved, dispatch on Runway `main` with the reviewed `project_ref` and `repository_id` strings. Only the apply step receives credentials. The writer checks authenticated current heads, exact-head App Quality, the onboarding run and artifact digest, committed app policies, and hostname/deployment evidence. It never checks out or executes app code. A dispatch selects an existing registry entry; it cannot supply callbacks or authorize a new target.

The workflow uses one Runway-wide concurrency group across projects, covering evidence validation through readback; it will not cancel an in-progress writer. GitHub may replace a pending run, so dispatch one request at a time and check its result before queuing another. PATCH replaces the entire allowlist and is not conditional. This lock cannot coordinate dashboard edits, another repository, or any other out-of-band writer. Do not activate unless all Auth config writers, including maintenance, are coordinated; fresh head checks are point-in-time checks, not transactions across GitHub and Supabase.

While holding the lock, the library GETs current Auth config, appends only missing exact entries and PATCHes **only** `uri_allow_list`. The existing list (including unrelated legacy entries) is carried forward. A second GET must confirm the expected entries and unchanged Site URL. An already present list does not cause a PATCH. Provider payloads, tokens and existing configuration are not returned as diagnostics. On transport uncertainty or failed readback, stop and inspect via a freshly authorized reconciliation; there is no automatic write retry or rollback. Disablement or removal from an app manifest never deletes a shared redirect.

`auth_redirects_verified` means the PATCH and readback passed; `auth_redirects_already_present` means the entries were present and no PATCH was needed. The workflow and registry are tested offline; protected-environment approval, credential delivery and grants, hosted execution, live readback, and registration/confirmation/recovery round-trips still need separate verification. Database migration, JWT/RLS and application data-path checks remain independent.
