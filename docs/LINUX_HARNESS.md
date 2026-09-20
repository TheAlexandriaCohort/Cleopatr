# Linux harness implementation

The native runtime and managed macOS VM provide an **experimental kernel boundary**, not a production containment certification. CLI 0.4 selects them by default (`auto`); the older bypassable launcher requires `--backend cooperative`. The full V1 objective remains unfinished: the coverage limits below are functional requirements still to implement, not simply documentation or testing tasks.

## Managed VM on Apple Silicon

Install CLI 0.6 outside your project, start Docker Desktop, then use `cleo --env=Development -- tests/curl-agent.js`, or the equivalent pipe-style command after `eval "$(cleo init zsh)"`. First use builds a content-addressed local image containing QEMU, a Landlock-enabled Debian kernel, the supervisor, and a minimal Linux Node/curl runtime. Each launch boots a fresh VM without a privileged Docker container or host Docker socket in the workload.

Only the selected project is mounted into the workload, at `/workspace`. The private mount namespace masks `.cleo`, the standard `cleopatr-enrollment.json` file, and the selected configuration directory if it is within the workspace. The installed CLI/VM assets must be outside the shared workspace. Enrollment tokens stay on the host; verified signed bundles enter protected guest storage, and guest policy events return to the host spool for authenticated upload. Do not place extra copies of enrollment secrets or host-executed trusted code in a writable agent workspace.

CLI 0.4.3 prints its Docker check, image preparation, and supervisor startup stages. Readiness and image checks time out after 10 seconds, builds after 15 minutes, VM supervisor startup after 180 seconds, and cleanup after 5 seconds. Cancellation terminates the Docker helper process group, escalating after 0.5 seconds if necessary. The boot deadline is cleared only by the trusted guest's session-specific supervisor-ready marker; it does not limit a running agent's lifetime. If Docker stops responding, Cleo reports the failing stage and exits. Restart Docker Desktop before retrying. A cleanup failure names the container whose removal could not be confirmed; it does not claim the enclave has stopped. No cooperative fallback is used.

Policy refresh remains non-blocking with the five-minute threshold. A newer signed snapshot ends the running kernel session; relaunch to apply its new immutable OS grants. Server unavailability preserves the last verified snapshot. The runtime currently targets ARM64 and Linux Node/curl/env/sh/bash/BusyBox workloads. Native macOS executables, host package managers, arbitrary installed software, full TTY/job control and general device access are not provided. `/dev/null` is a read-only EOF fixture, not a writable device. QEMU software emulation adds startup cost.

CLI 0.5.0 follows each effective Environment policy mode by default. Add `--audit` to allow policy denials for this invocation, including inherited Enforce rules, and log them as `ALLOWED_AUDIT`. Audit retains the enclave: registered File/Process boundaries, credential masking, namespace/seccomp restrictions and protocol support limits remain. File/Process permissions widen within the catalog. CLI 0.6 additionally audits and mediates signals, privilege attempts, stat/metadata changes, listeners, DNS, and supported PostgreSQL/MySQL operations; see [action coverage and setup](ENCLAVE_ACTIONS.md). Since 0.5.1, CONNECT tunnels are forwarded in audit-only sessions, with end-to-end client TLS verification and destination-level logging. Any effective Enforce policy keeps opaque tunnels disabled; a policy denial returns 403, while a policy-allowed tunnel that needs unavailable HTTPS inspection returns 501 with an explicit reason. `--enforce` remains available to strengthen all effective policies.

Since CLI 0.4.4, Cleo retries host audit uploads independently of policy refresh, every five seconds while active and on exit. Failures retain records and print a warning; `cleo status` reports pending records and the last upload error, and `cleo audit flush` retries manually. VM shutdown drains all exported events even after a launch error, and preserves the export directory if host persistence fails. Activity refreshes its newest results every 15 seconds; viewing older pages pauses automatic refresh until Refresh is selected. Docker startup failures occur before any agent policy decision and do not create fictitious HTTP or process decision records. Per-operation kernel filesystem/process activity still has the coverage limits below.

### Why a network forbid does not permit launch

`Cleopatr::AgentSession` is the Cedar principal **type**. The enrolled name is its ID, for example `Cleopatr::AgentSession::"curl-agent"`. A rule using `principal is Cleopatr::AgentSession` already matches that client. An Enforce `process.execute` permit still requires Process catalog entries so the supervisor can build its concrete executable allowlist. Admission now reports missing entries separately from a policy denying registered executables.

Cedar is default-deny. An Enforce environment containing only a workspace-read permit and a network forbid cannot start a process. Create Process resources for the exact Linux executables the agent needs and permit `process.execute`; also permit reads of its runtime directories. Do not change this into a blanket permit merely to get past admission.

For the bundled `tests/curl-agent.js`, the required Process locators are `/workspace/tests/curl-agent.js`, `/usr/bin/env`, `/usr/local/bin/node`, `/usr/bin/curl` and the ELF interpreter `/lib/ld-linux-aarch64.so.1`. Readable File directories are `/workspace` (the existing workspace resource), `/usr`, `/bin`, `/lib`, `/etc`, and `/dev`. Assign these resources to Development or a parent. Publish permits scoped to the chosen resource IDs and client principal, alongside **Prevent network requests**. Metadata permits are also needed for loader/runtime stat calls; assign `Default - file.metadata` or a narrower compatible permit. No network permit is needed to demonstrate that forbid. Avoid overlapping File resource directories. Reviewable Cedar examples are provided: [allow the curl runtime processes](examples/allow-curl-processes.cedar) and [allow runtime reads](examples/allow-curl-runtime-reads.cedar), and [allow runtime metadata observations](examples/allow-curl-runtime-metadata.cedar). They target client `curl-agent`; change that principal if your enrollment has another name. Create one policy from each file and assign it to Development after reviewing the permissions. These files are examples only; no central permissions are changed automatically.

A real HTTPS curl attempt first sends `CONNECT www.google.com:443` to the proxy. The broad `http.request` forbid blocks that observed request and records its policy name; no encrypted GET method or search path is invented. An audit-only session forwards that connection after the two Cedar checks. A session containing any Enforce policy still requires HTTPS inspection and cannot open opaque tunnels, even if both connection checks allow it. TLS inspection remains unfinished.

Run `npm run test:runtime:vm` for the isolated signed-policy Node/curl demonstration, including host credential masking, descendant file deletion, executable denial, direct-connect denial, and named policy events. Its permissions are disposable fixtures and do not modify any central Environment.

## Components and trust boundary

`cleo --backend linux -- command` invokes the non-setuid `/usr/lib/cleopatr/cleo-supervisor launch` client. The client passes its three standard streams and a bounded launch request to a root-owned Unix socket. The service authenticates the kernel-provided `SO_PEERCRED` UID against a root-owned enrollment configuration. A caller cannot supply a worker executable, rootfs, cache path, UID, mount list or upstream proxy port.

The root supervisor:

1. Starts a protected policy worker using a fixed Node executable, cleared environment, bounded IPC and heap size. The worker verifies the signed bundle using the same Cedar implementation as the application.
2. Resolves the requested Environment against the enrollment's assigned scope, including inherited published policies and policy modes. The principal remains the enrolled client name; the session ID is separate provenance.
3. Creates a cgroup v2 session with memory and process limits. A gate keeps the child stopped until cgroup membership is established.
4. Creates private mount, PID, network, IPC and UTS namespaces. The rootfs is read-only, the explicitly configured workspace is mounted at `/workspace`, and `/tmp` is private. Each permitted executable is pinned behind a read-only bind mount; replacing or writing that executable during the session is unavailable. The host policy store and control socket are not mounted into the workload.
5. Drops supplementary groups, UID/GID and bounding capabilities, sets `no_new_privs`, and installs Landlock and a syscall allowlist before the first agent exec. A trusted namespace init reaps children. Descendants inherit the cgroup and restrictions.
6. Handles TCP connect notifications using copied socket-address facts and `SECCOMP_IOCTL_NOTIF_ADDFD`. It does **not** inspect a mutable pointer and then use `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. Protected HTTP, DNS and registered database adapters are reachable, along with policy-permitted listeners inside the private namespace. Injected sockets preserve the caller's nonblocking and close-on-exec flags, so TLS and HTTP/2 clients retain their event-loop behavior. UDP remains confined to the private namespace and protected DNS resolver; it has no external route. Raw sockets, host Unix sockets, namespace escapes, ptrace, BPF and io_uring remain unavailable.
7. Kills the whole cgroup when the initial command exits, the launcher disconnects, the policy worker fails, or a newer signed policy snapshot is activated. Updated OS grants require a new launch; they are not silently applied to an already-running Landlock domain.

The root configuration, enrollment, cached bundle and rollback high-water mark, and audit spool live outside the agent's filesystem. Root ownership and non-writable ancestry are checked. This is a different trust boundary from the same-user `.cleo` cooperative cache. A malicious host administrator, a compromised kernel, and a malicious enrolled human outside the agent's namespace are outside this backend's threat model.

The launcher deliberately inherits stdin/stdout/stderr. These are explicitly delegated file capabilities; Landlock does not retroactively mediate an already-open output file. Socket and directory descriptors are rejected as standard streams. Other inherited descriptors are closed on exec.

## Enforced and supported coverage

| Boundary | Current behavior | Limit |
| --- | --- | --- |
| Process | Kernel pre-exec Landlock grants; dynamic pidfd signal decisions and privilege-attempt assessment | No per-exec argv predicates/events; permits cannot elevate privileges or signal outside the enclave |
| Filesystem | Landlock content restrictions; dynamic stat/chmod/chown/timestamp mediation and events | Content grants still require static predicates/disjoint directories; xattrs and full content-operation telemetry remain unsupported |
| Network | Private namespace; mediated bind/listen, protected UDP/TCP DNS, registered database routes | No general external sockets, host-visible listeners, or arbitrary UDP egress |
| HTTP | HTTP/1.1 forward proxy, catalog destination matching, HTTP and network Cedar checks before forwarding, policy events with the exact normalized Cedar payload | No WebSocket upgrade or HTTP/2 inspection; opaque CONNECT is available only for entirely Audit sessions |
| HTTPS | An absolute `https://` request sent to the local HTTP proxy uses validated TLS upstream | Standard HTTPS clients use CONNECT: its observed method/host reach Cedar, so broad HTTP forbids are named and recorded. Entirely Audit sessions can forward opaque tunnels, including uncatalogued destinations represented by their origin. Sessions with any Enforce policy refuse these tunnels even if the CONNECT policy permits them. Encrypted GET/path inspection and scoped TLS trust are not implemented |
| MCP HTTP | Recognized catalog endpoints, JSON-RPC tools/resources/prompts, bounded immutable request body, typed integer `amount`, explicit administrative method allowlist | No JSON-RPC batches, arbitrary typed argument schemas, server-initiated response correlation, or discovery cache |
| MCP stdio | Existing cooperative adapter remains available | It is not yet integrated into the protected supervisor's process/pipe orchestration |
| PostgreSQL/MySQL | Wire adapters assess connect, single text queries and explicit transactions; verified upstream TLS | [Supported subset](ENCLAVE_ACTIONS.md): no prepared/extended protocol, COPY, replication, table-level SQL parser, or client-to-adapter TLS |
| Audit | HTTP/MCP plus eight new kernel/protocol actions record captured Cedar inputs in the protected spool | Static Landlock content/exec decisions are not a complete per-operation event stream |

Landlock grants combine by union. A broad parent directory grant cannot represent a denied child exception. The compiler therefore rejects overlapping File resources, and the supervisor also resolves paths inside the namespace and rejects aliases/overlaps before exec. File resources for this backend must identify directories; Process resources must identify individual files.

Landlock's rename semantics also share create/remove rights. The compiler rejects combinations that cannot preserve Cedar's decisions. Static content/exec policies still reject unsupported dynamic context. The dynamically mediated actions in [the action guide](ENCLAVE_ACTIONS.md) can use their observed context, as can HTTP/MCP. Resource locators use **sandbox paths**, such as `/workspace/project`, not host paths.

Admission also rejects explicitly scoped actions with no adapter and OS entity references outside the Environment's resource catalog. MCP resources must identify HTTP transport URLs. MCP origins are dedicated: requests to changed paths or queries are rejected instead of falling back to generic HTTP handling, which would bypass tool policies.

Endpoint resources use absolute HTTP(S) origins with optional paths; Network resources use HTTP(S) origins, TCP/UDP address-and-port locators, or `dns://hostname`. Wildcards, CIDRs and query-scoped endpoint identities are not supported by this backend and are rejected. Catalog matching and Cedar use the same decoded URI path. Ambiguous encoded separators, double encoding and repeated separators are rejected. This supplies HTTP facts, not application-specific routing or business-operation semantics.

Audit policies do not produce policy-based blocking, but the isolation floor and declared capability requirements apply in both modes. Uncatalogued filesystem paths, direct network bypass and unsupported syscalls remain unavailable. In audit-only sessions, opaque CONNECT traffic passes through the proxy after destination-level policy checks; the proxy cannot observe or govern the inner protocol. Plain HTTP/MCP still uses its catalog and protocol checks. Audit mode is not an unrestricted host process with comprehensive syscall observation.

## Requirements and building

Linux with Landlock ABI 5 or newer (Linux 6.10+ with Landlock enabled), cgroup v2 delegation with memory/pids controllers and `cgroup.kill`, seccomp user notification and FD injection, mount/PID/network namespaces, root for the service, and Node 22.13+ for the protected Cedar worker are required. The service refuses startup if required protection is absent. The unprivileged client never retries through the cooperative backend after a protected launch failure.

```sh
npm run build:runtime
cargo build --locked --release --manifest-path runtime/native/Cargo.toml
```

The JS worker and launcher are written to `dist-runtime`. The native binary is written to `runtime/native/target/release/cleo-supervisor`. Build the native program on the target Linux architecture; compiling it on macOS only produces a refusal stub, not a Linux sandbox.

For the Apple Silicon development environment, the reproducible test runner builds Linux ARM64 artifacts in Docker and places the native binary in `dist-runtime/cleo-supervisor`:

```sh
npm run test:runtime:linux
```

This boots a disposable Debian kernel in QEMU inside Docker. It does not change Docker Desktop's kernel or install a Mac kernel extension. Test logs are retained in `dist-runtime/vm`. The VM recipe currently targets ARM64; the syscall code also includes x86-64, which still needs its own end-to-end validation.

### Live terminal output and recording on macOS

Keep Docker Desktop running, then use `npm run test:runtime:linux -- --live` to stream the actual build, kernel and signed-session tests to the terminal. The session prints a `[PASS]` line after each successful assertion, including allowed reads, denied deletion/symlink writes, child-process restrictions, HTTP decisions, direct-network bypass denial and cgroup cleanup. Expected permission-denied messages are part of these tests. Logs are still saved normally.

The built-in macOS `script` utility can record and replay the terminal output with its original timing:

```sh
mkdir -p dist-runtime
script -q -r dist-runtime/cleo-tests.recording npm run test:runtime:linux -- --live
script -q -p dist-runtime/cleo-tests.recording
```

This file is a terminal replay, not a video. For a shareable screen recording, use macOS Shift–Command–5, choose **Record Selected Portion**, select the terminal, start recording, then run the live command. This demonstration uses disposable test policies and resources inside the Linux VM.

After the Linux build/tests, `npm run package:runtime` produces an architecture-labeled preview archive and SHA-256 checksum in `public/downloads`. It includes the native supervisor, JS worker/launcher, pinned Cedar WASM dependency, configuration example, service file and this guide. It does not include enrollment credentials or a workload rootfs. Node 22.13+ is still required on the Linux host.

## Installation on a test Linux host

No privileged service has been installed on the development Mac. Installation is a Linux administrator operation:

1. Install the native binary, `worker.js`, `cleo.js`, `package.json` and bundled `node_modules` under root-owned `/usr/lib/cleopatr`. Keep every code/dependency directory root-owned and not group/world writable.
2. Create root-owned `/var/lib/cleopatr` with mode `0700`. Enroll and sync using `CLEO_HOME=/var/lib/cleopatr` and the installed CLI as root. Enrollment credentials and trust configuration must not be stored in the workload workspace.
3. Provision a dedicated, root-owned rootfs containing the required interpreters, binaries, libraries and certificates. It must contain `/workspace`, `/tmp` and `/proc` mount points with mode `0755`. Its files and directories must not be group/world writable. Set the rootfs `/etc/resolv.conf` to `nameserver 127.0.0.53` for the protected resolver. Do not use the host's `/` as the rootfs.
4. Create a dedicated workspace under a protected parent directory, such as `/srv/cleopatr-workspace`, and assign its content to the enrolled UID. Define sandbox directory and executable Resources and compatible policies in Cleopatr.
5. Review `runtime/supervisor.example.json`, install it as `/etc/cleopatr/supervisor.json`, and set the enrolled UID, trusted Node/worker paths, rootfs, workspace and delegated cgroup path. The service uses a fixed configuration path; agent requests cannot override it.
6. Review and install `runtime/systemd/cleopatr-supervisor.service`. Run the native `doctor` as root before starting the service. Use a disposable host until the remaining release gates have passed.

```sh
cleo --backend linux --env PCI -- /usr/bin/python3 /workspace/agent.py

# With the existing interactive zsh integration enabled:
cleo --backend linux --env PCI | python3 /workspace/agent.py
```

The root enrollment configuration supplies the default Environment. The CLI can also forward the Environment selector from `.cleo/config` (or legacy `config.json`); it does not forward that file's credentials or trust configuration. `--env` selects an assigned ID or unique name and takes precedence. Without a mode flag, each effective policy keeps its Environment mode. `--audit` disables policy blocking for this invocation, including inherited Enforce policies. `--enforce` remains a compatible force-Enforce option. Proxy variables are set inside the workload. Other host environment variables and secrets are not inherited.

Policy refresh remains a five-minute, non-blocking background operation. A failed refresh preserves the last verified bundle. A successful new snapshot causes existing sessions to terminate and require relaunch, because Landlock permissions cannot be relaxed or replaced in place. Revocation push and immediate offline invalidation are not implemented.

## Production release gates still open

- Complete per-operation content/exec policies and audit events, including argv, xattrs, legacy metadata APIs and independent rename semantics.
- Implement session-scoped HTTPS inspection/trust, certificate pinning behavior, HTTP/2 and robust TLS failure reporting.
- Extend the PostgreSQL/MySQL text-protocol subset with database-native SQL parsing, prepared statements, richer transaction state, private-CA/client TLS support, and broader compatibility/fuzzing.
- Integrate protected MCP stdio and complete MCP HTTP discovery/argument/response handling.
- Extend DNS provenance and TCP upstream fallback, network compatibility, full terminal/job control and multi-workspace provisioning.
- Add adversarial concurrency/path replacement tests, protocol fuzzing, denial-of-service and supervisor-crash tests, x86-64 validation, performance measurements, packaging and independent privilege-boundary review.

These limits must remain visible in product claims. Passing the current kernel tests does not establish the full implementation document's definition of V1 done.

Design references: [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html), [seccomp and userspace notifications](https://docs.kernel.org/userspace-api/seccomp_filter.html), and [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).
