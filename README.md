# cleopatr

<img src="public/brand/cleopatr-logo.png" alt="cleopatr — gold feather and wordmark" width="220" />

A working Cedar policy control plane and installable CLI. Build policies with a visual rule builder or Cedar, assign them to nested environment groups, manage resources, simulate decisions, and publish signed policy bundles for local authorization.

**Implementation status:** the CLI now defaults to a managed Linux VM on macOS ARM64 (Docker Desktop required), or the installed supervisor on native Linux, with cgroups, Landlock/seccomp restrictions, protected state, and HTTP/MCP HTTP mediation. The full production harness remains unfinished: arbitrary per-operation OS policies/audit, TLS inspection, database protocols and independent security validation are still required. See [the coverage matrix](docs/IMPLEMENTATION_STATUS.md) and [Linux harness guide](docs/LINUX_HARNESS.md).

## Run the web application

Requires Node.js 22.13+ and npm.

```sh
npm ci
npm run dev
```

Open the Local URL printed by the development server. Local sign-in uses the bundled Sites development identity. On a new checkout, after opening the application once, initialize local persistence in another terminal:

```sh
npm run db:local
```

Refresh the app. Cloud deployments apply the checked-in D1 migrations automatically; `db:local` is only for the local development database. Starter policies and resources are **examples**. No live database is contacted.

## Use the CLI with the local web application

```sh
npm run build:cli
npm install -g ./public/downloads/cleopatr-cli-0.6.0.tgz
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

The deployed Sites portal has an owner-only browser access gateway. Automated CLI access requires an application deployment that accepts client bearer tokens, such as the local app. For the private hosted portal, download a signed bundle on Deploy and use:

```sh
cleo import --file ./cleopatr-bundle.json
```

The CLI still attempts its scheduled background refresh; an unreachable or authentication-gated server leaves the verified local policies active. Do not expose the control plane publicly merely to bypass this platform gateway. A production deployment needs a supported machine-authentication ingress.

### Authorize an action

```sh
cleo authorize --request examples/database-delete.json
cleo authorize --mode enforce --request examples/database-delete.json
cleo doctor
```

Use an enrolled environment matching the request (or override with `--env NAME_OR_ID`). Audit mode reports would-deny while returning success. Enforce mode blocks supported denied actions. `--audit` explicitly allows policy denials for this invocation, including inherited Enforce policies, while retaining enclave isolation and adapter limits.

The Cleo launcher authorizes only the initial executable. It preserves argv, inherited streams and TTY descriptors, forwards signals, and returns the child exit status. It does not constrain arbitrary descendants or create an OS enclave. `cleo mcp --` mediates supported stdio MCP requests. Legacy `cleo run --` remains compatible. See [CLI usage](cli/README.md).

Existing installations should upgrade to CLI **0.6.0** and run `cleo sync` to receive the latest signed policies. This version follows Environment policy modes without a flag, supports an explicit `--audit` override, and forwards HTTPS CONNECT in entirely Audit sessions. Encrypted traffic remains opaque: events describe the tunnel destination, not inner HTTPS requests. Sessions containing Enforce policies still require the unfinished HTTPS inspection adapter. It retains audit upload retries, visible upload status, complete VM event transfer, and managed VM startup deadlines. Inheritance remains non-removable in the web application and in default CLI execution, including offline caches. New snapshots still require 0.4.2; clients running code older than 0.4.2 retain their older inheritance behavior until upgraded. New enrollment files also include the client name for offline use. Previously verified policy caches remain readable, but authorizing requires a known enrolled name. Run `npm run db:local` after updating the app; it makes a local database backup before applying schema migrations. Existing published content and pending drafts are migrated on first access.

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

Cedar uses the enrolled Cleo client name as the entity ID: `Cleopatr::AgentSession::"My agent"`. Name matching is case-sensitive. Session IDs remain separate tracing metadata. The CLI takes the name from its signed, client-bound bundle or its enrollment file; action JSON cannot override it. Simulator principal input uses the same Cedar identity, allowing named-client policies to be tested before publishing. Client credentials and audit attribution still use the distinct enrollment ID.

Deploy retains every created client in the tenant's database and shows a searchable list with creation, check-in, expiration, and revocation status. New credentials do not expire unless an optional expiration is chosen; existing expiration dates are preserved. Credential plaintext is returned only at creation, while the server stores its hash. The policy editor's **Principal** selector lists the saved client names and an **Any client (wildcard)** option. Clients sharing a name share the same Cedar principal, even though their credentials and audit IDs are distinct.

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
```

The tests exercise Cedar semantics, inheritance, schema validation, signatures, tenant isolation, assignment scope, rollback and activation races, offline/304 caching, detached refresh, enforced-mode protection, process argv/exit propagation, and MCP denial before forwarding. `scripts/smoke-dev.mjs` verifies the running HTTP API. `scripts/integration.mjs` additionally creates an isolated Audit environment, published policy, and temporary client, exercises the packaged CLI and background refresh, uploads telemetry, then revokes the client and removes its temporary policy and environment; it records local audit events intentionally.

The generated Shadcn component catalog is excluded from lint because its pre-existing source does not satisfy all scaffold lint rules. Application source, shared policy code, CLI, tests, and service code are checked.

## Architecture

![Cleopatr target architecture: central Cedar policies distributed to local cleo adapters](docs/assets/cleopatr-architecture.png)

The infographic illustrates the target architecture; see the [coverage matrix](docs/IMPLEMENTATION_STATUS.md) for the current implementation. Brand assets and usage are documented in the [brand guide](docs/BRANDING.md).

- `app/`: responsive GUI and authenticated API routes.
- `core/`: canonical actions/schema, inheritance, builder, official Cedar evaluator integration, Ed25519 signing/verification.
- `control-plane/`: tenant-scoped service, persistence adapter, standalone loopback API.
- `db/` and `drizzle/`: D1/SQLite schema and versioned migrations.
- `cli/`: launcher, MCP mediation, cache/refresh, bounded audit spool.
- `runtime/`: experimental privileged Linux supervisor, Cedar-to-Landlock capability compiler, HTTP/MCP HTTP adapters and real-kernel VM tests. See [Linux harness coverage](docs/LINUX_HARNESS.md).
- `tests/`: executable authorization and integration regressions.
- `public/downloads/`: installable CLI archive.

The web service uses the official Cedar 4.12 WASM module in a Cloudflare Worker. The CLI uses the same upstream version and shared schema/evaluation code in Node. The local API adapter uses Node SQLite for direct service testing; the full GUI uses D1 through the Sites development runtime.

## Configuration

- `CLEO_SIGNING_JWK`: private Ed25519 JWK, configured as a hosted secret. Never commit this value. If absent in a local development instance, a per-workspace key is generated and stored in its development database. Production key rotation and KMS/HSM integration are not implemented.
- `CLEO_AUTHORING_ENDPOINT` and optional `CLEO_AUTHORING_TOKEN`: optional authoring provider endpoint. It accepts `{requirement, schema, resources, policies, contract}` and returns `{cedar, assumptions, testCases, model}`. Generated Cedar is server-validated, saved as a candidate only, and requires human review before publishing. No LLM runs during authorization. No provider credentials are bundled; drafting is unavailable until configured.
- `CLEO_HOME`: CLI config/cache/spool directory, default project-local `.cleo/`. Enrollment writes JSON to `.cleo/config`; set its `environment` field to an ID or unique name. Legacy `config.json` and `~/.config/cleopatr` enrollment remain readable.
- `CLEO_PORT`, `CLEO_SERVER_DATA`, `CLEO_ADMIN_TOKEN`: optional standalone loopback API settings for `npm run api:local`. This separate test instance does not share the web app’s D1 database.

The hosted workspace is isolated by authenticated user ID. Shared organizations, SSO group mapping, separate author/approver roles, two-person review, signed client enrollment flows, key rotation, and protected privileged local storage require the remaining enterprise work.

Upstream references: [Cedar source and WASM binding](https://github.com/cedar-policy/cedar/tree/main/cedar-wasm), [Cedar schema](https://docs.cedarpolicy.com/schema/json-schema.html), [authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html).

CLI 0.6 adds enclave mediation for signals, privilege attempts, file metadata, listeners, DNS, and PostgreSQL/MySQL text queries and transactions. See [enclave action setup and limits](docs/ENCLAVE_ACTIONS.md). Existing Environment policy modes apply; `--audit` retains enclave isolation.
