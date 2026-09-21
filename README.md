# cleopatr

<img src="public/brand/cleopatr-logo.png" alt="cleopatr — gold feather and wordmark" width="220" />

Cleopatr is designed to be an agent execution enclave - a flexible system for creating harnesses for agentic AI applications. The project consists of a Cedar policy control plane, running as a standard Next.js web application, and a CLI - `cleo` - that sandboxes agents within the boundaries defined by the control plane, enforcing policy decisions via various Linux system administration tools. Cleopatr enables you to build Cedar policies with a visual rule builder or native policy code, assign them to a nested Environment hierarchy, manage resources, simulate decisions, and publish signed policy bundles for local authorization.

**Implementation status:** `cleo` defaults to a managed Linux VM on macOS ARM64 (Docker Desktop required), or the installed supervisor on native Linux, with cgroups, Landlock/seccomp restrictions, protected state, and HTTP/MCP HTTP mediation. The full production harness remains unfinished: arbitrary per-operation OS policies/audit, TLS inspection, database protocols and independent security validation are still WIP. See [Linux harness guide](docs/LINUX_HARNESS.md).

## Run the web application

Requires Node.js 22.13+ and npm.

```sh
npm ci
npm run dev
```

Open http://127.0.0.1:3000. The app runs on Node.js and stores data in `.local/cleopatr.sqlite` using Node's built-in SQLite driver. It creates the database and applies migrations automatically on first access. Local mode binds only to loopback and opens your workspace directly.

Navigation stores the selected screen in the URL (for example, `/?page=deploy`). Refreshing or bookmarking the page retains that screen, and browser Back/Forward follows screen changes. Unsaved forms and table filters are not persisted.

For a production build:

```sh
npm run build
npm start
```

To host on another machine, set `CLEO_ADMIN_TOKEN` to a long random secret and `CLEO_HOST=0.0.0.0` in `.env` or the process environment. The browser then requires the administrator token; sessions expire after 12 hours. Put HTTPS in front of remote deployments and preserve the original Host header. Client bearer tokens continue to work without a browser session and cannot administer the workspace. `PORT` changes the web port. Persist `CLEO_SERVER_DATA` on a local disk/volume, outside any public/static directory; it defaults to `.local`. Run one application instance per data volume. Starter policies and resources are **examples**; no catalog database is contacted automatically.

The application uses the existing native database in `CLEO_SERVER_DATA` without changing workspace IDs, client credentials or signing identity. Plain SQL migrations live in `migrations/`; their original filenames are retained to preserve the migration ledger. Initialization is part of normal startup; there is no separate database setup command. The retired development runtime and its one-time import utilities are no longer required.

## Share configuration as JSON

Use **Export JSON** and **Import JSON** in the sidebar. Exports include current drafts, published policy content, Environment hierarchy and modes, policy assignments, resources, and rule-builder settings. They exclude clients, enrollment tokens, signing keys, activity, and policy history. IDs are preserved so assignments and Cedar resource references remain valid. User-authored Cedar, descriptions, principal names and resource locators are configuration and are included; do not put passwords or tokens in those fields.

Import first validates the file and previews additions and updates. Confirming merges by ID: matching objects are updated, new objects are added, and objects absent from the file are retained. Published content, resource changes and Environment assignments/modes take effect immediately. Draft content remains editable; importing a draft without a published version does not unpublish an existing policy. Changes to published content create a new local version with rollback history. Existing client access, signing identity and activity remain intact, and the signed policy sequence advances. A concurrent edit invalidates the preview and requires another review. Invalid files leave the workspace unchanged. The versioned transfer format accepts files below 32 MiB.

These files are portable configuration, not full backups. Back up SQLite using a consistent SQLite backup/snapshot, or stop the app before copying its data directory (including any WAL files). Automatic pre-migration backups are stored in the data directory's `backups/` folder.

## Use the CLI with the local web application

```sh
npm run build:cli
npm install -g ./public/downloads/cleopatr-cli-0.6.1.tgz
```

1. In the app, configure policies, environments, and resources.
2. Use the Simulator to inspect allow/deny behavior. Cedar defaults to deny when no permit matches.
3. Publish policies directly from their Draft rows, or choose **Publish now** in the editor. Set their modes on Environments.
4. On Deploy, select an environment or group, create a client, and download its enrollment file.
5. Enroll and synchronize:

```sh
cleo enroll --config ./cleopatr-enrollment.json
cleo sync
eval "$(cleo init zsh)"
cleo | your-agent
cleo --env=PCI | npm run dev
cleo --audit --env=PCI | npm run dev
```

The local web application provides the same API the CLI uses. Client credentials bypass browser sign-in only at the application API layer and cannot administer policies. They are scoped to their assigned environments and do not expire by default.

Pipe-style launch requires the opt-in interactive zsh hook above. It rewrites a simple command before execution. An ordinary shell pipe without the hook starts the right-hand process independently. For scripts and other shells, use `cleo -- your-agent` or `cleo --env=PCI -- npm run dev`. `--env` accepts an assigned environment ID or a unique case-insensitive name; missing or ambiguous names stop the launch. See [CLI setup and syntax limits](cli/README.md#pipe-style-launch-in-interactive-zsh).

### Private hosted portal

The standalone application accepts enrolled client bearer tokens directly. For offline operation, select an active client in Deploy's **Offline bundle** dropdown, download its signed bundle, and use:

```sh
cleo import --file ./cleopatr-bundle.json
```

The bundle includes the selected client's signed ID/name and published policies for its assigned Environments and descendants, including inherited policies. Import requires an enrollment for that same client. Revoked or expired clients cannot receive a new download. The CLI still attempts its scheduled background refresh; an unreachable server leaves the verified local policies active. Configuration JSON exports are different from signed CLI bundles and cannot be used with `cleo import`.

### Authorize an action

```sh
cleo authorize --request examples/database-delete.json
cleo authorize --mode enforce --request examples/database-delete.json
cleo doctor
```

Use an enrolled environment matching the request (or override with `--env NAME_OR_ID`). Audit mode reports would-deny while returning success. Enforce mode blocks supported denied actions. `--audit` explicitly allows policy denials for this invocation, including inherited Enforce policies, while retaining enclave isolation and adapter limits.

The Cleo launcher authorizes only the initial executable. It preserves argv, inherited streams and TTY descriptors, forwards signals, and returns the child exit status. It does not constrain arbitrary descendants or create an OS enclave. `cleo mcp --` mediates supported stdio MCP requests. Legacy `cleo run --` remains compatible. See [CLI usage](cli/README.md).

Existing installations should upgrade to CLI **0.6.1** and run `cleo sync`, or import a new client-specific offline bundle. Import and authorization now require a signed client identity matching the enrollment ID; editing `clientName` in `.cleo/config` cannot change the principal. Unbound older bundles are rejected even under `--audit`. Existing bundles that already contain a signed identity remain usable offline. The server advances the policy sequence once for this contract upgrade, and new snapshots require CLI 0.6.1; existing client credentials and published/draft content are preserved.

Environment policy modes, the explicit `--audit` override, audit upload retries and managed VM startup deadlines are retained. Entirely Audit sessions can forward opaque HTTPS CONNECT tunnels; their encrypted methods, paths and bodies are not inspected. Sessions containing Enforce policies still require the unfinished HTTPS inspection adapter. See the CLI and Linux harness guides for the full coverage limits.

## Policy lifecycle and environments

Environments are available immediately. Each environment can contain children and inherits all parent policies. **Manage Policies** edits direct assignments; inherited policies are checked and locked and must be removed at their source environment. The assignment modal searches names and filters by resource type. Its tree is collapsible, and each environment exposes a copyable CLI ID. Legacy inherited exclusions are cleared on the one-time workspace upgrade.

Save a draft while keeping the previous published version active, or publish immediately from the editor. The Policies table publishes saved Draft rows directly. The Simulator’s **Policy | Environment** toggle chooses an isolated policy version or an environment’s published effective policy set. Its searchable **Control** dropdown lists Draft and Published entries separately, including both when draft edits exist. Enter the Cleo client name in **Principal** before choosing an action. Policy tests show their environment context (from the catalog resource or an assignment). **Version history** retains the 50 most recent previous published versions and the time each was replaced. **Rollback** republishes the previous content as a new version, preserving current assignments and saved draft edits.

Environment modes apply at authorization time:

Policy-row toggles remain editable in Audit, Enforce, and Custom. Changing a row preserves all other rows and updates the top-level indicator to Audit (all Audit), Enforce (all Enforce), or Custom (mixed). Selecting top-level Audit or Enforce still applies that mode to all editable policies. Inherited Enforce locks remain in place; the indicator includes those locked policies. Custom is an automatic mixed-state indicator, not a prerequisite for row editing. An empty environment retains its selected bulk mode.

- **Audit**: record locally controlled policies without blocking; policies enforced by any ancestor remain Enforce.
- **Enforce**: evaluate all effective policies; a matching permit is required, and forbids win.
- **Custom**: choose Audit or Enforce per policy. An inherited Audit policy can be strengthened to Enforce, but inherited Enforce cannot be downgraded. Only the Enforce subset determines blocking. An Audit permit cannot grant access to the Enforce subset; include an enforced permit for allowed actions. A matching Audit forbid is recorded but does not block an otherwise enforced allow.

Flagless execution follows effective Environment policy modes. `--audit` overrides policy blocking for one invocation while retaining enclave isolation; `--enforce` remains an optional way to strengthen all effective policies. Client bundles include published policies for the enrollment's allowed environments and their ancestors. Enforcement carries through every descendant; a second assignment cannot reset it. No separate publication stage exists beyond publishing each policy. The selected environment comes from `--env`, inherited `CLEO_ENVIRONMENT`, or the `environment` field in `.cleo/config` (with request/enrollment fallback for older configurations).

The **Recent environment activity** table shows the latest 50 uploaded policy decision events for that environment, with invocation time, policy/version, decision, mode, and authenticated client name. It refreshes every 15 seconds. Offline events appear after upload. Unmatched permits yield a default-deny event rather than a fictitious policy invocation.

## Principal identity

Cedar uses the enrolled Cleo client name as the entity ID: `Cleopatr::AgentSession::"My agent"`. Name matching is case-sensitive. Session IDs remain separate tracing metadata. The CLI takes the name exclusively from its verified, client-bound bundle; neither enrollment-file edits nor action JSON can override it. Simulator principal input uses the same Cedar identity, allowing named-client policies to be tested before publishing. Client credentials and audit attribution still use the distinct enrollment ID.

Deploy retains every created client in the tenant's database and shows a searchable list with creation, check-in, expiration, and revocation status. New client names must be unique within their workspace, including names of revoked or expired clients. Names are trimmed and case-sensitive, matching Cedar identity rules. Deploy flags duplicates immediately; the API returns HTTP 409, and SQLite insert/update guards prevent collisions even during simultaneous requests or direct SQL writes. The migration preserves legacy duplicate records and their credentials/history, but prevents further reuse of those names; those legacy clients continue sharing their original principal.

New credentials do not expire unless an optional expiration is chosen; existing expiration dates are preserved. Credential plaintext is returned only at creation, while the server stores its hash. The policy editor's **Principal** selector lists the saved client names and an **Any client (wildcard)** option.

New and existing workspaces receive one published **Default - &lt;action&gt;** permit for each of the 19 schema actions. These policies have unrestricted principal and resource scopes and no conditions. They start unassigned and can be selected in an Environment's **Manage Policies** dialog. The upgrade runs once, preserves existing rules and assignments, and does not recreate defaults that users later delete. Policies can also be saved or published while unassigned. Assigning all defaults permits every schema action at the Cedar layer, subject to applicable forbids; it does not remove kernel isolation, executable registration, or unsupported-adapter limits.

## Activity filters

Activity separates **Platform** changes from **Policy decisions**. Environment and Policy selectors support search and multiple selections; Resource selects resource types, and Principal selects distinct recorded Cleo client names. Selections match any item within a filter and combine across filters. The calendar button sets an inclusive date/time range in your local time zone, with optional open ends.

Filters run on the server across recorded history, with 50 events per page and **Load more** for older results. Decision rows share the environment activity table's columns. New platform changes retain their relevant environment, policy, and resource scope, including removed assignments. Historical decisions infer resource type from their recorded action. Older platform events that did not record scope cannot match scope filters; they remain available in the unfiltered Platform view.

## Five-minute non-blocking refresh

Each authorization reads and verifies the local signed bundle. When more than five minutes have elapsed since a successful refresh or 304 response, it starts a detached refresh worker and immediately evaluates against the current bundle. No network request is awaited on the authorization path. A lock coalesces concurrent refreshes; download timeouts and invalid responses retain last-known-good policies. Activation uses a separate lock and atomic rename. Signature, digest, tenant, assignments, schema, client version, and monotonic policy snapshot sequence must all match.

Explicit `cleo sync` is blocking, appropriate for initial enrollment. A cold client with no verified bundle returns an error instead of allowing ungoverned actions. Offline use has no automatic expiry in this implementation, matching the requested last-known-policy fallback. Offline clients cannot learn of revocations until they reconnect.

## Development and verification

```sh
npm run typecheck
npm run lint
npm test
npm run build:cli
npm run build
npm run test:web
```

The tests exercise Cedar semantics, inheritance, schema validation, signatures, tenant isolation, assignment scope, rollback and activation races, offline/304 caching, detached refresh, enforced-mode protection, process argv/exit propagation, and MCP denial before forwarding. `scripts/smoke-dev.mjs` verifies the running HTTP API. `scripts/integration.mjs` additionally creates an isolated Audit environment, published policy, and temporary client, exercises the packaged CLI and background refresh, uploads telemetry, then revokes the client and removes its temporary policy and environment; it records local audit events intentionally.

The retained Shadcn-derived UI primitives are excluded from lint because their upstream source does not satisfy all application lint rules. Unused scaffold components have been removed. Application source, shared policy code, CLI, tests, and service code are checked.

## Architecture

![Cleopatr target architecture: central Cedar policies distributed to local cleo adapters](docs/assets/cleopatr-architecture.png)

The infographic illustrates the target architecture; see the [coverage matrix](docs/IMPLEMENTATION_STATUS.md) for the current implementation. Brand assets and usage are documented in the [brand guide](docs/BRANDING.md).

- `app/`: responsive GUI and authenticated API routes.
- `core/`: canonical actions/schema, inheritance, builder, official Cedar evaluator integration, Ed25519 signing/verification.
- `control-plane/`: tenant-scoped service, persistence adapter, standalone loopback API.
- `migrations/`: plain SQL schema migrations, applied by the native SQLite adapter.
- `cli/`: launcher, MCP mediation, cache/refresh, bounded audit spool.
- `runtime/`: experimental privileged Linux supervisor, Cedar-to-Landlock capability compiler, HTTP/MCP HTTP adapters and real-kernel VM tests. See [Linux harness coverage](docs/LINUX_HARNESS.md).
- `tests/`: executable authorization and integration regressions.
- `public/downloads/`: installable CLI archive.

The web service and CLI use the official Cedar 4.12 WASM module and shared schema/evaluation code in Node. The GUI API and optional standalone API share native SQLite persistence, with WAL, transactional updates, automatic schema migrations, and restrictive file permissions. No ORM, migration generator, or external database service is required. The web app runs on standard Next.js 16.3.5 with Tailwind PostCSS; Cedar remains an external Node package so its WASM can load normally.

## Configuration

- `CLEO_SIGNING_JWK`: optional private Ed25519 JWK, supplied as a server secret. Never commit this value. If absent, a per-workspace key is generated and stored in SQLite. Preserve the same configured key when migrating an installation that used an external signing key. Production key rotation and KMS/HSM integration are not implemented.
- `CLEO_AUTHORING_ENDPOINT` and optional `CLEO_AUTHORING_TOKEN`: optional authoring provider endpoint. It accepts `{requirement, schema, resources, policies, contract}` and returns `{cedar, assumptions, testCases, model}`. Generated Cedar is server-validated, saved as a candidate only, and requires human review before publishing. No LLM runs during authorization. No provider credentials are bundled; drafting is unavailable until configured.
- `CLEO_HOME`: CLI config/cache/spool directory, default project-local `.cleo/`. Enrollment writes JSON to `.cleo/config`; set its `environment` field to an ID or unique name. Legacy `config.json` and `~/.config/cleopatr` enrollment remain readable.
- `CLEO_SERVER_DATA`: persistent data directory shared by the web app and `npm run api:local`, default `.local`.
- `CLEO_ADMIN_TOKEN`: enables browser sign-in and authenticates administrative scripts via `x-cleo-admin-token`; required for a non-loopback web server. Browser mutation requests also require a matching Origin header.
- `CLEO_HOST` and `PORT`: web bind address and port, default `127.0.0.1:3000`.
- `CLEO_WORKSPACE_ID`: selects an existing workspace after migrating a database containing multiple workspaces. A fresh database uses `local-workspace`; a single migrated workspace keeps its original ID.
- `CLEO_PORT`: port for the optional loopback-only `npm run api:local`, default `4318`. That endpoint requires `CLEO_ADMIN_TOKEN` for administration.

The standalone GUI administers one selected workspace. Existing migrated tenants remain isolated in storage and in client authentication; the administrator workspace is selected explicitly if multiple tenants exist. Shared organizations, SSO group mapping, separate author/approver roles, two-person review, signed client enrollment flows, and key rotation require the remaining enterprise work.

Upstream references: [Cedar source and WASM binding](https://github.com/cedar-policy/cedar/tree/main/cedar-wasm), [Cedar schema](https://docs.cedarpolicy.com/schema/json-schema.html), [authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html).

CLI 0.6 adds enclave mediation for signals, privilege attempts, file metadata, listeners, DNS, and PostgreSQL/MySQL text queries and transactions. See [enclave action setup and limits](docs/ENCLAVE_ACTIONS.md). Existing Environment policy modes apply; `--audit` retains enclave isolation.
