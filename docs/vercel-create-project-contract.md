# Vercel project creation contract

The launcher uses `vercel api /v11/projects -X POST --input -` with exactly
`name` and `framework: "nextjs"`. The saved request schema in
`tests/fixtures/vercel-create-project.schema.json` comes from the official
[OpenAPI specification](https://openapi.vercel.sh), operation `createProject`.
The creation schema rejects unknown fields and has no `nodeVersion` field.
The former creation payload included that unsupported field.

The existing `package.json` `engines.node: "24.x"` selects the deployed major
runtime through Vercel's documented [package version override](https://vercel.com/docs/functions/runtimes/node-js/node-js-versions).
No extra project-update mutation or permission is introduced.

Regression tests validate the actual launcher command and stdin payload against
the saved provider schema, reject the old payload, and retain strict subprocess
stubs for creation, collision, exact-ID recovery and unchanged retry behavior.
Offline schema/tests establish request compatibility; a separately approved live
onboarding run establishes provider acceptance and production readiness.
Existing hostname, quality, ownership, DNS and disabled database gates are unchanged.
