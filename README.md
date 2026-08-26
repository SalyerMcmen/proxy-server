# Company npm Gateway

An authenticated, read-only npm registry gateway designed for an approved
company deployment on Vercel. Developers configure one `.npmrc` registry URL.
The gateway logs package requests, serves registered company-modified tarballs,
and fetches packages that are not registered locally from the configured npm
upstream.

The project has no third-party runtime dependencies.

## What is included

- Bearer authentication with a separate identity per developer or CI job
- Only SHA-256 token hashes stored in Vercel environment variables
- npm packument and tarball proxying, including scoped packages
- Streaming tarball responses with the upstream npm integrity value preserved
- Company-modified package registration with SHA-1 and SHA-512 generation
- `log-only` and exact-version `allowlist` policy modes
- Explicit package/version deny rules
- Structured audit events in Vercel Runtime Logs
- Optional signed audit webhook for durable SIEM or database storage
- npm security-audit endpoint forwarding
- Optional lockfile reporter for visibility even when npm uses its local cache
- SSRF defenses: fixed upstream, allowed tarball hosts, validated redirects,
  HTTPS-only production URLs, and no forwarding of developer credentials

## Request flow

1. npm requests a package document from `/<package>`.
2. The gateway authenticates the developer identity and records the request.
3. Registered custom versions are merged into, or replace, upstream metadata.
4. Every tarball URL is rewritten to this gateway.
5. The gateway streams a custom tarball or fetches the exact upstream version.
6. npm verifies the `dist.integrity` value before accepting the package.

## Deploy on Vercel

1. Put this directory in a private Git repository and import it into Vercel.
2. Select **Other** as the framework. The included `vercel.json` requires no
   package installation or build step.
3. Generate one credential per developer or CI identity:

   ```bash
   node scripts/hash-token.mjs developer-a
   node scripts/hash-token.mjs ci-production
   ```

4. Combine the printed hashes into one Vercel environment variable. Never put
   plaintext developer tokens in this value:

   ```text
   GATEWAY_TOKEN_HASHES_JSON={"developer-a":"<sha256>","ci-production":"<sha256>"}
   ```

5. Add these required Vercel variables:

   ```text
   PUBLIC_BASE_URL=https://your-company-npm.vercel.app
   GATEWAY_TOKEN_HASHES_JSON={...}
   PACKAGE_POLICY_MODE=log-only
   UPSTREAM_REGISTRY_URL=https://registry.npmjs.org/
   UPSTREAM_TARBALL_HOSTS=registry.npmjs.org
   ```

6. Deploy, then confirm the endpoint:

   ```bash
   curl -H "Authorization: Bearer $NPM_GATEWAY_TOKEN" \
     https://your-company-npm.vercel.app/-/ping
   ```

For durable audit retention, set `AUDIT_WEBHOOK_URL` and
`AUDIT_WEBHOOK_SECRET`, or configure a Vercel log drain. Webhook events contain
an `x-company-signature: sha256=...` HMAC header. Set `AUDIT_IP_SALT` if you want
stable, non-reversible client IP identifiers in audit events.

For an internet-reachable production hostname, also apply your company's
Vercel Firewall/WAF rate limits to `/*` (especially `/-/*`). Application authentication still
remains required for every registry request.

## Developer `.npmrc`

Copy `.npmrc.example` to the consuming project's `.npmrc` and change the host:

```ini
registry=https://register.com/
//register.com/:_authToken=${NPM_GATEWAY_TOKEN}
replace-registry-host=always
audit=true
package-lock=true
```

Set the developer's token outside the repository.

PowerShell:

```powershell
$env:NPM_GATEWAY_TOKEN = "the-developer-token"
npm ping
npm install
```

Bash:

```bash
export NPM_GATEWAY_TOKEN='the-developer-token'
npm ping
npm install
```

Do not commit a plaintext token. Each person should have a separate principal
so the `principal` field in audit events is meaningful.

## Register a modified package

Modify the package source and give it a distinct version. A company suffix
prevents collisions with immutable public npm versions:

```json
{
  "name": "problem-package",
  "version": "1.2.3-company.1"
}
```

Create and register the tarball:

```bash
cd ../problem-package
npm pack
cd ../company-npm-gateway
node scripts/register-custom-package.mjs \
  ../problem-package/problem-package-1.2.3-company.1.tgz \
  --tag company
```

The command copies the tarball to `packages/` and updates
`config/custom-packages.json`. Commit both changes and redeploy. Use
`--replace-upstream` when the gateway must expose only your custom versions, and
`--set-latest` only when you intentionally want the custom version behind the
`latest` tag.

For a patched transitive dependency, pin the company version in the consuming
project:

```json
{
  "overrides": {
    "problem-package": "1.2.3-company.1"
  }
}
```

Regenerate and commit `package-lock.json` after changing an override. Avoid
reusing an upstream name and version with different bytes; npm lockfiles and
local caches assume that a published version is immutable.

## Package policy

`config/package-policy.json` contains exact package and version rules.

`log-only` mode provides the requested automatic upstream fallback:

```json
{
  "mode": "log-only",
  "allow": {},
  "deny": {
    "known-bad-package": ["*"]
  }
}
```

`allowlist` mode permits only registered custom packages and listed upstream
versions:

```json
{
  "mode": "allowlist",
  "allow": {
    "react": ["19.1.1"],
    "@types/node": ["24.3.0"]
  },
  "deny": {}
}
```

The `PACKAGE_POLICY_MODE` environment variable overrides the file's `mode`.
An exact deny rule always wins. All transitive dependency versions must be
listed when allowlist mode is enabled.

## Accurate usage reporting

Registry logs show metadata lookups and tarball downloads. npm can reuse its
local content cache, so a registry alone cannot prove every package present in
every install. For an authoritative project-level record, report the completed
lockfile:

```bash
export NPM_GATEWAY_URL='https://register.com/'
export NPM_GATEWAY_TOKEN='the-developer-token'
node scripts/report-lockfile.mjs
```

Or require the included wrapper, which runs npm and reports the lockfile only
after npm succeeds:

```bash
node scripts/company-npm.mjs ci
```

Reporting is fail-closed by default. Set `COMPANY_NPM_REPORT_REQUIRED=false`
only if company policy permits installs to succeed while the audit sink is
temporarily unavailable.

## Audit event fields

The gateway emits JSON records with fields such as:

```json
{
  "type": "npm_gateway_audit",
  "timestamp": "2026-08-26T12:00:00.000Z",
  "principal": "developer-a",
  "action": "tarball_download",
  "package": "react",
  "version": "19.1.1",
  "source": "upstream",
  "integrityVerified": true,
  "result": "success"
}
```

Supported actions include `authentication`, `package_metadata`,
`tarball_download`, `npm_security_audit`, `dependency_report`, and
`request_error`. Tokens, upstream credentials, and raw IP addresses are never
logged.

## Local verification

Copy `.env.example` to `.env`, fill in the values, then run:

```bash
node --env-file=.env server.mjs
node --test
```

The tests use a local fake npm upstream; they do not require npmjs.org.

## Operational limits

- This is a read-only gateway. `npm publish`, user management, and dist-tag
  mutation endpoints are intentionally not implemented.
- Vercel Functions have request-body and execution-duration limits. Tarball
  downloads are streamed instead of buffered, but very slow or unusually large
  packages can still exceed the function duration allowed by your Vercel plan.
- Vercel's filesystem is immutable at runtime. Upstream packages are proxied,
  not persisted. Custom tarballs are committed with the deployment.
- If an upstream registry redirects tarballs to another trusted host, add that
  exact host to `UPSTREAM_TARBALL_HOSTS`; redirects to unlisted hosts fail.
- Git, GitHub, and arbitrary URL dependencies do not use the npm registry
  protocol and therefore cannot pass through this gateway. Register them as a
  custom tarball or replace them with a normal registry dependency.
- For a high-volume, persistent binary cache or package publishing, use a
  dedicated repository such as Verdaccio, JFrog Artifactory, or Sonatype Nexus
  behind the same company controls. This Vercel project is best for a controlled
  team gateway and audit layer.

## License

MIT
