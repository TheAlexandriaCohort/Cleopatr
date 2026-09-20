# Cleopatr CLI

<img src="../public/brand/cleopatr-feather.png" alt="Cleopatr gold feather" width="56" />

Local authorization using the official Cedar engine, signed policy bundles, and non-blocking refresh after five minutes.

Requires Node.js 22.13+. Install the downloaded package with `npm install -g ./cleopatr-cli-0.6.0.tgz`.

CLI 0.5.0 follows effective Environment policy modes without any mode flag. `--audit` disables policy blocking for this invocation, including inherited Enforce policies, and records denied decisions as `ALLOWED_AUDIT`. It retains the Linux enclave: catalog boundaries, registered executables, protected credentials, network isolation, and supported protocol limits still apply. Since 0.5.1, opaque CONNECT tunnels are forwarded only when every effective policy is Audit, either from Environment modes or an explicit `--audit`. The client retains end-to-end TLS certificate validation. Only the destination and CONNECT attempt are observed; encrypted methods, paths, bodies, and inner protocol operations are not inspected or logged. These audit-only tunnels use the observed origin as resource identity when no catalog entry matches. Direct network bypass remains blocked. The Linux broker also preserves nonblocking socket flags; this avoids TLS stalls and truncated HTTP/2 responses. Filesystem/process grants widen within the catalog; CLI 0.6 adds per-operation signals, privilege attempts, metadata, listeners, DNS and database logging; static content/exec events remain incomplete. `--enforce` remains a compatible force-Enforce override. Conflicting mode flags are rejected. Mode is selected only by CLI flags, not `CLEO_MODE` from the caller.

Since CLI 0.4.4, Cleo uploads queued decisions independently of policy refresh: on launch, every five seconds while active, and once more on exit (including failed startup). Upload failures are reported on stderr and retain the local records; `cleo status` shows the pending count and most recent upload error. `cleo audit flush` drains up to 20 batches within a four-second network budget and reports remaining records. The server must acknowledge each batch before it is removed. VM shutdown transfers all exported records, including after errors; failed transfers retain the session directory and print its recovery path. Events recorded while offline are retried during the current or next CLI invocation. No uploader remains running after the CLI exits.

CLI 0.4.3 reports each managed VM startup stage and bounds Docker readiness/image checks to 10 seconds, image builds to 15 minutes, guest supervisor startup to 180 seconds, and container cleanup to 5 seconds. Ctrl-C cancels pending helpers, including helpers that ignore the initial signal. The startup deadline stops after the protected supervisor is ready, so long-running agents are not given an execution time limit. An unresponsive Docker daemon produces an explicit error instead of an indefinite silent wait; restart Docker Desktop before retrying. This patch does not change the signed policy contract (minimum client version remains 0.4.2).

Without an explicit CLI audit override, inherited policies remain effective and preserve any ancestor's Enforce mode through every descendant (introduced in CLI 0.4.2). Child Audit/Custom settings, duplicate assignments, and old exclusion fields cannot weaken that enforcement. Older signed caches remain readable with these stricter rules; newly signed snapshots require 0.4.2 or newer. Upgrade clients to apply the new semantics during offline evaluation.

1. In the web app, publish the relevant policies, choose environment policy modes, then create a client on Deploy.
2. Download the enrollment JSON and keep it private.
3. Run `cleo enroll --config cleopatr-enrollment.json`.
4. Run `cleo sync` against a bearer-token-accessible control plane. For the owner-private hosted portal, download the signed bundle in the UI and use `cleo import --file cleopatr-bundle.json`.
5. Enable the interactive zsh integration below, then run `cleo | your-agent`. For scripts or other shells, use `cleo -- your-agent`. Explicit adapters use `cleo authorize --request action.json`.

The default `auto` backend selects the **managed Linux VM on macOS ARM64** (Docker Desktop required), or the installed native Linux supervisor on Linux. It refuses to start an uncontained process if that backend is unavailable. First use builds a cached runtime image; later launches boot a fresh VM. Install the CLI globally, outside your agent workspace.

The protected backend adds cgroup attribution, Landlock filesystem/executable restrictions, a seccomp network broker, protected policy storage, and HTTP/MCP HTTP mediation. The managed VM boots its own Landlock-enabled kernel; Docker Desktop's kernel does not need Landlock. It runs Linux executables, mounts the current project at `/workspace`, hides `.cleo`, and keeps the actual enrollment token on the host. The bundled workload rootfs currently contains Node, curl, env, sh/bash and BusyBox. macOS binaries, native macOS modules and arbitrary host tools are not available in it.

Use `--backend cooperative` explicitly for the old initial-exec-only launcher. That mode is bypassable by same-user hostile agents. Explicit `authorize` and cooperative `mcp` remain available. Production coverage is incomplete: dynamic OS context/audit, TLS inspection, and database wire proxies remain open. See [Linux harness coverage and installation](../docs/LINUX_HARNESS.md). `cleo doctor` reports coverage, not a successful runtime probe.

## Pipe-style launch in interactive zsh

After installing or updating the CLI, enable the hook once per interactive zsh session:

```sh
eval "$(cleo init zsh)"
```

You can put that line at the end of your `.zshrc`, after plugins that replace the Enter/`accept-line` widget. Cleo does not edit shell startup files automatically. Re-run the setup after upgrading the CLI or replacing that widget.

Then enter one simple command at the prompt:

```sh
cleo | python -m my_agent
cleo --audit | ./agent-service.sh
cleo --env=PCI | npm run dev
```

New environments default to Audit. Cleo follows each environment’s Audit, Custom, or Enforce policy modes. `--enforce` strengthens all applicable policies to Enforce. `--audit` (also `--mode audit`) makes every effective policy Audit for this invocation, including inherited Enforce policies; stored Environment modes stay unchanged. For Python, `-m` takes a module name without `.py`; use `python my-agent.py` to execute a file.

The hook rewrites the line into a single Cleo launch **before** zsh starts the process. It is launcher syntax, not a Unix data pipe: the agent inherits the terminal's stdin, stdout, and stderr. Literal arguments, quoted spaces, empty arguments, and escaped characters are preserved. Shell expansion, multiple pipes, redirections, assignments before the executable, command lists, and multiline input are rejected; put such logic inside an agent script. The hook handles lines beginning with bare `cleo`, entered through zsh's `accept-line` widget. It does not intercept scripts, `zsh -c`, alternate execution widgets, aliases, or other shells.

**Without the hook, an ordinary shell starts the right-hand process independently, even if Cleo exits with an error.** Cleo cannot stop that process by failing its side of the pipe. Use the portable form in scripts, automation, and other shells:

```sh
cleo -- python -m my_agent
cleo --audit -- ./agent-service.sh
cleo --env=PCI -- npm run dev
```

The explicit cooperative launcher preserves argument boundaries, inherited standard streams, forwarded signals, and exit status. It authorizes the initial executable only. The managed VM transports agent I/O over its console; full TTY/job-control semantics are not yet supported. On a configured Linux test host, `cleo --backend linux --env PCI | python3 /workspace/agent.py` selects the native boundary instead. Full shell job control is not implemented. `cleo run -- command` remains a compatibility alias.

`--env=PCI` (also `--env PCI` or `--environment PCI`) first matches an exact environment ID, otherwise a unique case-insensitive name within the client's assigned signed policy bundle. Missing, unassigned, or ambiguous selections stop the launch; there is no fallback to a different environment. With no flag, Cleo uses an inherited `CLEO_ENVIRONMENT`, then `environment` in `.cleo/config`, then the action request environment or first enrollment assignment for legacy configurations. Environments are available immediately; publish their policies and run `cleo sync` to select a newly added environment locally. Existing launches keep the same non-blocking five-minute refresh and offline behavior.

The integration uses zsh's documented [line-editor widgets](https://zsh.sourceforge.io/Doc/Release/Zsh-Line-Editor.html); ordinary [shell pipelines](https://www.gnu.org/software/bash/manual/html_node/Pipelines) have different process semantics.

## Environment configuration

After enrollment, edit the existing `.cleo/config` and set its `environment` field to an ID copied from Cleopatr or a unique name, such as `"environment": "PCI"`. Keep the generated credential, server, and trust-key fields intact. `--env` overrides this setting for one invocation. Do not replace the full enrollment with a one-field file.

In Custom mode, enforced policies are evaluated as their own Cedar set: at least one enforced permit must match, and enforced forbids win. Audit policies record observed decisions without affecting that set. With no enforced policies, the environment audits without blocking. An empty Enforce environment denies by default.

## Principal identity

Every authorized action—including initial process launch and MCP calls—uses the enrolled client name as its Cedar principal: `Cleopatr::AgentSession::"My agent"`. Names match exactly, including capitalization. A request's `principal` value is ignored by the CLI. Session IDs remain available for tracing and audit correlation.

Online bundles carry the authenticated client ID and name under the policy signature. Offline enrollment files include `clientName`. After upgrading an older installation to 0.3.0, run `cleo sync` once to obtain its signed identity. If an older offline enrollment has no client name yet, authorization returns a configuration error until you sync or obtain a new enrollment file.

## Authorization request

```json
{
  "environmentId": "customer-platform",
  "sessionId": "agt_example",
  "action": "database.query",
  "resource": { "type": "Database", "id": "customer-db" },
  "context": {
    "operation": "DELETE",
    "tables": ["customers"],
    "confidence": "semantic"
  }
}
```

Exit codes: 0 effective allow (including Audit would-deny), 2 blocked, 3 configuration/engine failure. `--audit` and its `--mode audit` alias override policy blocking for the invocation, including inherited Enforce policies. No verified bundle means no authorization, even in Audit mode.

After five minutes since the last successful check, authorization starts a detached refresh worker and continues using the last verified bundle. HTTP requests have a four-second timeout. A lock coalesces concurrent refreshes. A failed refresh preserves the bundle and records the error locally. Successful 304 responses reset the timer. Signatures, tenant, assignments, schema, version, and monotonic sequence are checked before atomic activation. Policy rollback in the app restores previous published content as a new version and higher snapshot sequence. Bundles contain only published policies, including relevant parent assignments.

`CLEO_HOME` changes the configuration/cache path (default project-local `.cleo/`). Enrollment writes `.cleo/config` as JSON. Legacy `config.json` and home-directory enrollments remain readable when no project enrollment exists. Add `.cleo/` to your agent project’s ignore file; it holds credentials, cache, and audit spool. The managed VM masks the active in-workspace cache directory and `.cleo`, keeps signed state in protected guest storage, and uploads events from the host. The cooperative backend does not isolate same-account agents from these files. Native Linux uses root-owned supervisor storage. Keep downloaded enrollment JSON files outside the agent workspace as well.

## MCP

`cleo mcp --env=development --server support -- node support-server.js`

Configure this as the MCP server command in your agent. Tool calls, resource reads, and prompt requests are authorized before forwarding. Administrative protocol messages pass through an explicit allowlist; unknown methods are rejected. The adapter exposes only tool/server identity and integer `amount` when present. It does not fabricate arbitrary argument semantics. Resource IDs default to the MCP name/URI; use `--resource CATALOG_ID` when mediating one fixed resource. Messages use newline-delimited JSON, not Content-Length framing.

## Audit

`cleo audit flush` uploads per-policy decisions, environment ID, policy name/version, timestamp, and the exact normalized Cedar input captured at evaluation time. This includes principal, action, resource, context and entity attributes; assessed arguments and paths are preserved. It does not collect raw request bodies, file contents or headers that were never provided to Cedar. The server attributes events to the enrolled client name. The environment page shows its latest 50 received events. Background refresh also attempts a flush. The local spool is bounded at 10,000 files; allow events are removed first. If all slots contain denials, later events are dropped with a local overflow marker. Authorization does not wait for the network.

New client tokens do not expire by default; optional expiration dates are preserved. Create a new enrollment to rotate credentials. Revocation prevents future downloads/uploads, but offline last-known policies remain active by design.

Starting in CLI 0.4.1, click a decision row in Activity or Recent environment activity to expand its assessed payload and copy the JSON. Stored inputs retain the original catalog attributes even after resources are changed or removed. Earlier events have no payload and cannot be reconstructed. Inputs above 128 KiB carry an explicit size-limit marker; requests rejected before Cedar evaluation carry a separate marker. Neither case changes the authorization decision. Uploads are batched by encoded size so payloads fit the API limit.

CLI 0.6 adds enclave mediation for signals, privilege attempts, file metadata, listeners, DNS, and PostgreSQL/MySQL text queries and transactions. See [enclave action setup and limits](../docs/ENCLAVE_ACTIONS.md). Existing Environment policy modes apply; `--audit` retains enclave isolation.
