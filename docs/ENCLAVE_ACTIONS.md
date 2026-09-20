# Enclave actions in CLI 0.6

The managed Linux VM on macOS ARM64 and the native Linux supervisor now assess these eight additional actions. Default execution follows the Environment's effective policy modes. `--audit` records denials as `ALLOWED_AUDIT` and permits supported operations; it retains namespace isolation, read-only mounts, credential masking and the prohibition on privilege elevation.

```sh
cleo --env=Development -- node tests/curl-agent.js
cleo --audit --env=Development -- node tests/curl-agent.js
```

All decisions use the signed, enrolled client name as `Cleopatr::AgentSession`. Captured Cedar inputs appear in expandable Activity and Environment rows. A policy decision is an authorization result, not a claim that an operation succeeded: a permitted syscall can still fail because of ordinary Linux permissions, isolation restrictions or an unavailable upstream.

| Action | Mediated operations | Observed context |
| --- | --- | --- |
| `process.signal` | `kill`, `tkill`, `tgkill`; pinned process/thread identities in the same session; group requests assess every selected target before sending | `operation = "signal"`, signal number in `amount`, target executable, namespace PID in `argv` |
| `process.privilege_attempt` | UID/GID changes, supplementary groups, capabilities, unshare/setns, mount/unmount, chroot/pivot_root attempts | syscall name in `operation`, scalar arguments; resource is the calling executable |
| `file.metadata` | stat/fstat/fstatat/statx, chmod/fchmod/fchmodat, chown variants, utimensat | operation, resolved sandbox path, workspace membership; chmod mode in `amount` |
| `network.listen` | IPv4/IPv6 TCP/UDP bind and TCP listen | operation, address, port, protocol |
| `dns.query` | UDP/TCP DNS requests through `127.0.0.53`; DNS lookups performed by trusted HTTP/database adapters | query name in `host`; numeric DNS type or `LOOKUP` in `operation` |
| `database.connect` | Registered PostgreSQL/MySQL endpoint, before upstream connection | host, port, database in `server`, protocol, upstream TLS mode |
| `database.query` | PostgreSQL simple-query `Q` and MySQL `COM_QUERY` | leading command in `operation`; exact SQL as the single member of `argv` |
| `database.transaction` | Explicit `BEGIN` / `START TRANSACTION`, `COMMIT`, `ROLLBACK` | transaction command and exact SQL |

Process/File locators retain their existing sandbox-path syntax. Signal policies target the receiving executable's Process resource. Privilege policies target the caller's Process resource. Missing dynamic resources use the observed locator as the Cedar resource ID, so wildcard policies can match them; this does not add executable or file-content grants to Landlock.

Network resources additionally accept `tcp://127.0.0.1:8080` and `dns://example.com`. Listeners stay inside the private enclave network. They are not published on the host. Ports 53 and 18080 are reserved for the harness. Direct external sockets remain blocked; database connections use the registered protocol route. Unmatched DNS answers do not create general network access.

## Database configuration

Create a Database resource in the selected Environment or a parent:

```text
postgres://db.example.com:5432/app
mysql://db.example.com:3306/app
```

Use one Database resource per host/port. Do not put credentials in locators. The agent supplies its ordinary database authentication; authentication packets are relayed without adding credentials to policy/audit payloads. The client must select the catalogued database during its handshake. Database switching is rejected.

The enclave resolver maps registered database hostnames to session-local addresses. The supervisor routes those connections to the protected adapter; the adapter resolves the real upstream host. Permit `dns.query`, `network.connect`, and the desired database actions. The database's own authentication and grants remain required.

Clients speak the database's plaintext wire protocol to the private adapter endpoint; configure PostgreSQL clients with `sslmode=disable` for this local leg. The adapter requires certificate- and hostname-validated TLS upstream by default, with no plaintext fallback. `?tls=disable` is accepted only for an explicitly catalogued loopback/localhost or `host.docker.internal` development server. Private CA configuration and end-to-end client TLS to the adapter are not implemented.

Supported SQL commands are single `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `SHOW`, and the explicit transaction commands above. A trailing semicolon and ordinary comments/quoted literals are accepted. Backslash escape modes, dollar quoting, executable comments, multi-statements, prepared/extended protocols, COPY, replication, stored-program commands, database switches, compression and LOCAL INFILE are rejected. A rejected query closes the connection, allowing the database to roll back an open transaction. The adapter does not retry statements.

This is command-level mediation, not a database-native SQL parser. It does not populate `context.tables` or claim to understand permissions exercised inside functions, triggers, views or implicit database transactions. SQL query permission includes those database-side effects; use database grants for additional restrictions. The captured SQL can contain application data, so it is subject to the same access controls as other captured assessment payloads.

## Kernel and protocol limits

- Audit cannot grant root, capabilities, new namespaces, device access, writable system mounts, outside-session signal targets or host-visible listeners. Privilege-changing requests remain denied even when the policy decision is `ALLOWED_AUDIT`; no-op scalar UID/GID changes can succeed.
- Metadata mutation preserves the workload UID/GID's filesystem permissions. Special/set-ID mode bits remain prohibited. Extended attributes, legacy timestamp APIs, and every possible metadata observation are not covered; unsupported mutation syscalls remain denied. File-content operations and exec still use the existing static Landlock grants, with their documented limits.
- DNS accepts one IN question with an optional empty EDNS0 record. Compressed questions and larger/complex messages fail closed. Forwarding uses the trusted host's resolver over UDP; upstream truncation is retained rather than claiming complete TCP fallback. Enclave UDP has no external route.
- Pointer-valued syscalls are copied and emulated on pinned objects. A worker timeout or malformed/disconnected IPC terminates the session, preventing an old reply from authorizing a later operation.
- Entirely Audit sessions still allow opaque HTTP CONNECT tunnels from 0.5.1. Inner encrypted DNS/database operations in those tunnels cannot be inspected or reported as semantic decisions. Enforced/mixed sessions keep opaque tunnels disabled.

## Reproducible verification

```sh
npm test
npm run typecheck
npm run test:runtime:linux -- --live
npm run test:runtime:vm
```

The Linux suite runs all eight action checks inside a real Landlock-enabled kernel, with separate Enforce and Audit probes and recorded-payload assertions. It also verifies the previous containment checks. The managed VM suite exercises Node/curl, credential masks, filesystem policies, descendant restrictions and HTTPS Audit behavior.

Real PostgreSQL 17/MySQL 8.4 compatibility tests use disposable Docker containers and standard clients. Install the test clients outside the application if its bundled dependencies cannot be fetched from npm:

```sh
npm install --prefix /tmp/cleo-protocol-clients pg@8.16.3 mysql2@3.14.5
CLEO_TEST_CLIENTS=/tmp/cleo-protocol-clients node --import tsx runtime/tests/databases.ts
```

Protocol references: [PostgreSQL message flow](https://www.postgresql.org/docs/17/protocol-flow.html), [MySQL client/server protocol](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html), [Linux seccomp notifications](https://docs.kernel.org/userspace-api/seccomp_filter.html), and [pidfd signal API](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
