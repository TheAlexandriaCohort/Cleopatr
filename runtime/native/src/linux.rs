#[path = "mediation.rs"]
mod mediation;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{BufReader, Read, Write},
    mem::{size_of, zeroed},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const SOCKET: &str = "/run/cleopatr/supervisor.sock";
const CONFIG: &str = "/etc/cleopatr/supervisor.json";
const MAX_MESSAGE: usize = 65536;
const FS_ALL: u64 = (1 << 16) - 1;
const FS_FILE: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14) | (1 << 15);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    allowed_uids: Vec<u32>,
    worker: String,
    node: String,
    state: String,
    rootfs: String,
    workspace: String,
    #[serde(default)]
    workspace_masks: Vec<String>,
    cgroup_root: String,
    #[serde(default = "default_memory")]
    memory_max: u64,
    #[serde(default = "default_pids")]
    pids_max: u32,
}
fn default_memory() -> u64 {
    2 * 1024 * 1024 * 1024
}
fn default_pids() -> u32 {
    256
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Launch {
    argv: Vec<String>,
    environment: Option<String>,
    enforce: bool,
    #[serde(default)]
    audit: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    path: String,
    access: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Route {
    host: String,
    port: u16,
    proxy_port: u16,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ready {
    session_id: String,
    sequence: u64,
    environment_id: String,
    grants: Vec<Grant>,
    boundaries: Vec<String>,
    proxy_port: u16,
    dns_port: u16,
    routes: Vec<Route>,
}

fn c(s: &str) -> Result<CString> {
    Ok(CString::new(s)?)
}
fn syscall_ok(ret: libc::c_long) -> Result<libc::c_long> {
    if ret < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(ret)
    }
}
fn protected(path: &Path, directory: bool) -> Result<()> {
    ensure!(path.is_absolute(), "protected paths must be absolute");
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        ensure!(
            matches!(part, std::path::Component::Normal(_)),
            "invalid protected path"
        );
        current.push(part);
        let m = fs::symlink_metadata(&current)?;
        ensure!(
            !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "{} must be root-owned, not a symlink, and not writable by group/other",
            current.display()
        );
    }
    ensure!(
        fs::metadata(path)?.is_dir() == directory,
        "unexpected protected path type"
    );
    Ok(())
}
fn rootfs_tree(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0),
        "untrusted rootfs entry: {}",
        path.display()
    );
    if m.is_dir() {
        for entry in fs::read_dir(path)? {
            rootfs_tree(&entry?.path())?;
        }
    }
    Ok(())
}
fn abi() -> i64 {
    unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) }
}
fn readiness() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "the supervisor must run as root"
    );
    ensure!(
        abi() >= 5,
        "Landlock ABI 5 or newer is required; refusing degraded containment"
    );
    ensure!(
        fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")?.contains("user_notif"),
        "seccomp notification unavailable"
    );
    Ok(())
}

pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("doctor") => {
            println!(
                "{}",
                json!({"platform":"linux", "landlockAbi":abi(), "requiredLandlockAbi":5,
                "ready":readiness().is_ok(), "rootRequired":true, "seccomp":fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail").unwrap_or_default()})
            );
            Ok(())
        }
        Some("serve") => serve(),
        Some("launch") => client(&args[1..]),
        _ => bail!(
            "use doctor, serve, or launch [--env ID] [--audit|--enforce] -- /absolute/program args"
        ),
    }
}

fn send_fds(stream: &UnixStream, fds: &[RawFd]) -> Result<()> {
    unsafe {
        let mut byte = [1u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = vec![
            0usize;
            (libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize)
                .div_ceil(size_of::<usize>())
        ];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() * size_of::<usize>();
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        syscall_ok(libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) as _)?;
    }
    Ok(())
}
fn receive_fds(stream: &UnixStream, count: usize) -> Result<Vec<File>> {
    unsafe {
        let mut byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 16];
        let mut msg: libc::msghdr = zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[usize; 16]>();
        ensure!(
            libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) == 1,
            "missing file descriptors"
        );
        let mut files = Vec::new();
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let n = ((*header).cmsg_len - libc::CMSG_LEN(0) as usize) / size_of::<RawFd>();
                for i in 0..n {
                    files.push(File::from_raw_fd(
                        *libc::CMSG_DATA(header).cast::<RawFd>().add(i),
                    ));
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
        ensure!(
            msg.msg_flags & libc::MSG_CTRUNC == 0 && files.len() == count,
            "invalid file descriptors"
        );
        Ok(files)
    }
}
fn line(stream: &mut impl Read) -> Result<String> {
    let mut out = Vec::new();
    let mut byte = [0];
    loop {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            return Ok(String::from_utf8(out)?);
        }
        ensure!(out.len() < MAX_MESSAGE, "message too large");
        out.push(byte[0]);
    }
}
fn worker_line(
    stream: &mut BufReader<std::process::ChildStdout>,
    timeout: Duration,
) -> Result<String> {
    let fd = stream.get_ref().as_raw_fd();
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut byte = [0];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => bail!("policy worker disconnected"),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(String::from_utf8(out)?);
                }
                ensure!(out.len() < MAX_MESSAGE, "worker message too large");
                out.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(Instant::now() < deadline, "policy worker timed out");
                let mut fd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                syscall_ok(unsafe {
                    libc::poll(
                        &mut fd,
                        1,
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .min(1000) as i32,
                    )
                } as _)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
fn client(args: &[String]) -> Result<()> {
    let mut request = Launch {
        argv: vec![],
        environment: None,
        enforce: false,
        audit: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--enforce" => request.enforce = true,
            "--audit" => request.audit = true,
            "--env" => {
                i += 1;
                request.environment = Some(args.get(i).context("missing environment")?.clone());
            }
            "--" => {
                request.argv = args[i + 1..].to_vec();
                break;
            }
            _ => bail!("unknown launch argument"),
        }
        i += 1;
    }
    ensure!(!request.argv.is_empty(), "missing program");
    ensure!(
        !(request.enforce && request.audit),
        "conflicting execution modes"
    );
    let mut stream = UnixStream::connect(SOCKET)
        .context("Linux supervisor unavailable; refusing an uncontained launch")?;
    send_fds(&stream, &[0, 1, 2])?;
    writeln!(stream, "{}", serde_json::to_string(&request)?)?;
    let response: Value = serde_json::from_str(&line(&mut stream)?)?;
    if let Some(error) = response.get("error") {
        bail!("{error}");
    }
    std::process::exit(response["exitCode"].as_i64().unwrap_or(1) as i32);
}

fn serve() -> Result<()> {
    readiness()?;
    protected(Path::new(CONFIG), false)?;
    let config: Config = serde_json::from_slice(&fs::read(CONFIG)?)?;
    for p in [&config.state, &config.rootfs] {
        protected(Path::new(p), true)?;
    }
    for p in [&config.worker, &config.node] {
        protected(Path::new(p), false)?;
    }
    for name in ["config", "bundle.json"] {
        protected(&Path::new(&config.state).join(name), false)?;
    }
    protected(
        Path::new(&config.workspace)
            .parent()
            .context("invalid workspace")?,
        true,
    )?;
    ensure!(
        fs::symlink_metadata(&config.workspace)?.is_dir(),
        "workspace must be a real directory"
    );
    ensure!(
        fs::metadata(&config.state)?.mode() & 0o077 == 0,
        "state must have mode 0700"
    );
    ensure!(
        config.allowed_uids.iter().all(|id| *id != 0),
        "workloads cannot run as root"
    );
    rootfs_tree(Path::new(&config.rootfs))?;
    ensure!(
        Path::new(&config.cgroup_root)
            .join("cgroup.controllers")
            .exists(),
        "cgroup v2 delegation required"
    );
    let management = Path::new(&config.cgroup_root).join("supervisor");
    fs::create_dir_all(&management)?;
    fs::write(
        management.join("cgroup.procs"),
        std::process::id().to_string(),
    )?;
    fs::write(
        Path::new(&config.cgroup_root).join("cgroup.subtree_control"),
        "+memory +pids",
    )?;
    fs::create_dir_all("/run/cleopatr")?;
    fs::set_permissions("/run/cleopatr", fs::Permissions::from_mode(0o755))?;
    protected(Path::new("/run/cleopatr"), true)?;
    if Path::new(SOCKET).exists() {
        fs::remove_file(SOCKET)?;
    }
    let listener = UnixListener::bind(SOCKET)?;
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o666))?;
    // Fork before starting any threads. Each session owns its worker, cgroup and listener.
    unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
    }
    for connection in listener.incoming() {
        let mut stream = connection?;
        let mut cred: libc::ucred = unsafe { zeroed() };
        let mut size = size_of::<libc::ucred>() as u32;
        syscall_ok(unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut size,
            )
        } as _)?;
        if !config.allowed_uids.contains(&cred.uid) {
            let _ = writeln!(
                stream,
                "{}",
                json!({"error":"UID is not enrolled with this supervisor"})
            );
            continue;
        }
        let pid = unsafe { libc::fork() };
        ensure!(pid >= 0, "fork failed");
        if pid == 0 {
            drop(listener);
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                libc::signal(libc::SIGCHLD, libc::SIG_DFL);
            }
            let result = session(&config, &mut stream, cred.uid, cred.gid);
            let response = match result {
                Ok(code) => json!({"exitCode":code}),
                Err(e) => json!({"error":format!("{e:#}")}),
            };
            let _ = writeln!(stream, "{response}");
            unsafe {
                libc::_exit(0);
            }
        }
    }
    Ok(())
}

struct Group(PathBuf);
impl Drop for Group {
    fn drop(&mut self) {
        let _ = fs::write(self.0.join("cgroup.kill"), "1");
        for _ in 0..100 {
            if fs::remove_dir(&self.0).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn session(config: &Config, stream: &mut UnixStream, uid: u32, gid: u32) -> Result<i32> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let stdio = receive_fds(stream, 3)?;
    for fd in &stdio {
        let mut st: libc::stat = unsafe { zeroed() };
        syscall_ok(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } as _)?;
        ensure!(
            st.st_mode & libc::S_IFMT != libc::S_IFSOCK
                && st.st_mode & libc::S_IFMT != libc::S_IFDIR,
            "socket/directory stdio cannot cross the boundary"
        );
    }
    let request: Launch = serde_json::from_str(&line(stream)?)?;
    ensure!(
        !(request.enforce && request.audit),
        "conflicting execution modes"
    );
    ensure!(
        !request.argv.is_empty() && request.argv.len() < 1024,
        "invalid program arguments"
    );
    let mut command = Command::new(&config.node);
    command
        .arg("--max-old-space-size=128")
        // QEMU ARM64 cannot reliably tier up this Cedar WASM workload. Keep
        // baseline compilation; authorization semantics are unchanged.
        .arg("--no-wasm-tier-up")
        .arg(&config.worker)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CLEO_HOME", &config.state)
        .env("CLEO_SUPERVISOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    let mut worker = Worker(command.spawn()?);
    let mut input = worker.0.stdin.take().unwrap();
    let mut output = BufReader::new(worker.0.stdout.take().unwrap());
    let fd = output.get_ref().as_raw_fd();
    let flags = syscall_ok(unsafe { libc::fcntl(fd, libc::F_GETFL) } as _)? as i32;
    syscall_ok(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } as _)?;
    writeln!(
        input,
        "{}",
        json!({"op":"start", "request":request, "uid":uid})
    )?;
    let ready: Ready = serde_json::from_str(&worker_line(&mut output, Duration::from_secs(30))?)
        .context("policy worker refused session")?;
    ensure!(
        ready.session_id.starts_with("agt_")
            && ready
                .session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "invalid session id"
    );
    let group = Group(Path::new(&config.cgroup_root).join(&ready.session_id));
    fs::create_dir(&group.0)?;
    fs::write(group.0.join("pids.max"), config.pids_max.to_string())?;
    fs::write(group.0.join("memory.max"), config.memory_max.to_string())?;
    ensure!(
        group.0.join("cgroup.kill").exists(),
        "cgroup.kill unavailable"
    );
    let (parent, child) = UnixStream::pair()?;
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0, "fork failed");
    if pid == 0 {
        drop(parent);
        drop(input);
        drop(output);
        // Prevent the workload from inheriting the client/worker/control descriptors.
        unsafe {
            libc::close(stream.as_raw_fd());
        }
        // Keep the gate alive until a setup error has been written. Otherwise
        // the parent can see EOF and kill the cgroup before the diagnostic.
        let _diagnostic_guard = child.try_clone()?;
        if let Err(e) = sandbox(config, &request, &ready, uid, gid, &stdio, child) {
            let message = format!("cleo sandbox: {e:#}\n");
            let _ = std::io::stderr().write_all(message.as_bytes());
        }
        unsafe {
            libc::_exit(126);
        }
    }
    drop(child);
    // The child waits for this byte; no workload instruction can execute before attribution.
    fs::write(group.0.join("cgroup.procs"), pid.to_string())?;
    (&parent).write_all(&[1])?;
    parent.set_read_timeout(Some(Duration::from_secs(15)))?;
    let notifications = receive_fds(&parent, 2)?;
    let dns_socket: std::net::UdpSocket =
        std::os::fd::OwnedFd::from(notifications[1].try_clone()?).into();
    // Metadata emulation must not retain supplementary host groups.
    syscall_ok(unsafe { libc::setgroups(0, std::ptr::null()) } as _)?;
    let listener = notifications[0].as_raw_fd();
    eprintln!(
        "cleo: kernel boundary active · Landlock + seccomp · cgroup {}",
        ready.session_id
    );
    let mut check = Instant::now();
    let mut status = 0;
    loop {
        let exited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if exited == pid {
            break;
        }
        ensure!(exited >= 0, "waitpid failed");
        // A disconnected launcher terminates the entire cgroup, including daemonized descendants.
        let mut fds = [
            libc::pollfd {
                fd: listener,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLHUP | libc::POLLRDHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: dns_socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        syscall_ok(unsafe { libc::poll(fds.as_mut_ptr(), 3, 100) } as _)?;
        ensure!(
            fds[1].revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR) == 0,
            "launcher disconnected"
        );
        let mut worker_failed = false;
        let mut rpc = |request: Value| -> Result<Value> {
            let result = (|| -> Result<Value> {
                writeln!(input, "{request}")?;
                Ok(serde_json::from_str(&worker_line(
                    &mut output,
                    Duration::from_secs(5),
                )?)?)
            })();
            if result.is_err() {
                worker_failed = true;
                for _ in 0..10 {
                    if let Some(status) = worker.0.try_wait()? {
                        eprintln!("cleo-supervisor: policy worker exited: {status}");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            result
        };
        if fds[0].revents & libc::POLLIN != 0 {
            mediation::mediate(listener, &ready, &group.0, uid, gid, &mut rpc)?;
        }
        if fds[2].revents & libc::POLLIN != 0 {
            mediation::dns(&dns_socket, &mut rpc)?;
        }
        ensure!(
            !worker_failed,
            "policy worker IPC failed; terminate instead of consuming an uncorrelated reply"
        );
        if check.elapsed() >= Duration::from_secs(1) {
            ensure!(worker.0.try_wait()?.is_none(), "policy worker exited");
            writeln!(
                input,
                "{}",
                json!({"op":"check", "sequence":ready.sequence})
            )?;
            let state: Value =
                serde_json::from_str(&worker_line(&mut output, Duration::from_secs(5))?)?;
            ensure!(state["current"] == true, "policy snapshot changed; session terminated, launch again to apply new kernel rules");
            check = Instant::now();
        }
    }
    Ok(if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    })
}

fn mount(
    source: Option<&str>,
    target: &str,
    kind: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let s = source.map(c).transpose()?;
    let t = c(target)?;
    let k = kind.map(c).transpose()?;
    let d = data.map(c).transpose()?;
    syscall_ok(unsafe {
        libc::mount(
            s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            t.as_ptr(),
            k.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            d.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    } as _)?;
    Ok(())
}
fn sandbox(
    config: &Config,
    request: &Launch,
    ready: &Ready,
    uid: u32,
    gid: u32,
    stdio: &[File],
    mut gate: UnixStream,
) -> Result<()> {
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } as _)?;
    let mut byte = [0];
    gate.read_exact(&mut byte)?;
    syscall_ok(unsafe {
        libc::unshare(
            libc::CLONE_NEWNS
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWPID,
        )
    } as _)?;
    let dns_socket = mediation::resolver_socket()?;
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    mount(
        Some(&config.rootfs),
        &config.rootfs,
        None,
        libc::MS_BIND | libc::MS_REC,
        None,
    )?;
    // Rootfs is an installation artifact. No host /proc, /sys, credentials or sockets are exposed.
    mount(
        None,
        &config.rootfs,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )?;
    mount(
        Some(&config.workspace),
        &format!("{}/workspace", config.rootfs),
        None,
        libc::MS_BIND,
        None,
    )?;
    mount(
        None,
        &format!("{}/workspace", config.rootfs),
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )?;
    mount(
        Some("tmpfs"),
        &format!("{}/tmp", config.rootfs),
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=64m,mode=1777"),
    )?;
    // Enter the PID namespace; PID 1 below reaps and returns the initial command status.
    for relative in &config.workspace_masks {
        ensure!(
            !relative.is_empty()
                && Path::new(relative)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "invalid protected workspace directory"
        );
        let target = format!("{}/workspace/{}", config.rootfs, relative);
        let metadata = fs::symlink_metadata(&target)?;
        ensure!(
            (metadata.is_dir() || metadata.is_file()) && !metadata.file_type().is_symlink(),
            "protected workspace path must be a real file or directory"
        );
        ensure!(
            fs::canonicalize(&target)?
                .starts_with(fs::canonicalize(format!("{}/workspace", config.rootfs))?),
            "protected workspace path escapes workspace"
        );
        if metadata.is_dir() {
            mount(
                Some("tmpfs"),
                &target,
                Some("tmpfs"),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                Some("size=1m,mode=000"),
            )?;
        } else {
            // Mask loose enrollment files without changing the original inode.
            // NODEV makes the bound null device inaccessible to the workload.
            mount(Some("/dev/null"), &target, None, libc::MS_BIND, None)?;
            mount(
                None,
                &target,
                None,
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                None,
            )?;
        }
    }
    let inner = unsafe { libc::fork() };
    ensure!(inner >= 0, "fork failed");
    if inner != 0 {
        drop(gate);
        let mut status = 0;
        unsafe {
            libc::waitpid(inner, &mut status, 0);
            libc::_exit(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
    }
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } as _)?;
    mount(
        Some("proc"),
        &format!("{}/proc", config.rootfs),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("hidepid=2"),
    )?;
    syscall_ok(unsafe { libc::chroot(c(&config.rootfs)?.as_ptr()) } as _)?;
    std::env::set_current_dir("/workspace")?;
    // Pin each executable inode behind a read-only bind mount. In particular,
    // network filesystems may replace lookup dentries between granting and exec.
    // A Process resource always names an individual file, never a directory.
    for grant in ready.grants.iter().filter(|grant| grant.access & 1 != 0) {
        let path = fs::canonicalize(&grant.path)?;
        ensure!(
            path.is_file(),
            "Process resources must name individual executable files"
        );
        let path = path.to_str().context("invalid executable path")?;
        mount(Some(path), path, None, libc::MS_BIND, None)?;
        mount(
            None,
            path,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
    }

    let boundaries: Vec<PathBuf> = ready
        .boundaries
        .iter()
        .map(fs::canonicalize)
        .collect::<std::io::Result<_>>()?;
    for (i, path) in boundaries.iter().enumerate() {
        ensure!(
            Path::new(&ready.boundaries[i]).starts_with("/workspace")
                == path.starts_with("/workspace"),
            "File resource symlink changes workspace membership"
        );
        ensure!(path.is_dir(), "File resources for this backend must name directories; per-file remove/rename rules cannot be represented");
        ensure!(
            !boundaries
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && (path.starts_with(other) || other.starts_with(path))),
            "File resource aliases/overlaps cannot be represented by Landlock"
        );
    }
    // Only the peer's standard streams cross the boundary; no inherited runtime descriptors.
    for (i, fd) in stdio.iter().enumerate() {
        syscall_ok(unsafe { libc::dup2(fd.as_raw_fd(), i as i32) } as _)?;
    }
    let gate_fd = gate.as_raw_fd();
    syscall_ok(unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) })?; // CLOEXEC
                                                                                        // Trusted PID 1 reaps orphans; the workload is a normal process with normal signal semantics.
    let workload = unsafe { libc::fork() };
    ensure!(workload >= 0, "workload fork failed");
    if workload != 0 {
        unsafe {
            libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
        }
        loop {
            let mut status = 0;
            let exited = unsafe { libc::waitpid(-1, &mut status, 0) };
            if exited == workload {
                unsafe {
                    libc::_exit(if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        128 + libc::WTERMSIG(status)
                    });
                }
            }
            if exited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                unsafe {
                    libc::_exit(126);
                }
            }
        }
    }
    unsafe {
        libc::umask(0o077);
    }
    syscall_ok(unsafe { libc::setgroups(0, std::ptr::null()) } as _)?;
    // Drop all bounding capabilities before losing CAP_SETPCAP.
    for cap in 0..=40 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            bail!("capability drop failed");
        }
    }
    syscall_ok(unsafe { libc::setresgid(gid, gid, gid) } as _)?;
    syscall_ok(unsafe { libc::setresuid(uid, uid, uid) } as _)?;
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } as _)?;
    landlock(&ready.grants)?;
    let notify = seccomp(gate_fd)?;
    send_fds(&gate, &[notify, dns_socket.as_raw_fd()])?;
    drop(dns_socket);
    drop(gate);
    unsafe {
        libc::close(notify);
    }
    let args: Vec<CString> = request.argv.iter().map(|x| c(x)).collect::<Result<_>>()?;
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|x| x.as_ptr()).collect();
    argv.push(std::ptr::null());
    let environment = [
        "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
        "HOME=/workspace".to_string(),
        "LANG=C.UTF-8".to_string(),
        "HTTP_PROXY=http://127.0.0.1:18080".into(),
        "HTTPS_PROXY=http://127.0.0.1:18080".into(),
        "http_proxy=http://127.0.0.1:18080".into(),
        "https_proxy=http://127.0.0.1:18080".into(),
        format!("CLEO_SESSION_ID={}", ready.session_id),
        format!("CLEO_ENVIRONMENT={}", ready.environment_id),
    ];
    let env: Vec<CString> = environment.iter().map(|x| c(x)).collect::<Result<_>>()?;
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|x| x.as_ptr()).collect();
    envp.push(std::ptr::null());
    let candidates = if request.argv[0].contains('/') {
        vec![request.argv[0].clone()]
    } else {
        ["/usr/local/bin", "/usr/bin", "/bin"]
            .iter()
            .map(|path| format!("{path}/{}", request.argv[0]))
            .collect()
    };
    for candidate in candidates {
        unsafe {
            libc::execve(c(&candidate)?.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
    }
    bail!("Cannot execute {:?}: {}. Verify Process permits for the executable, shebang interpreter and ELF loader, plus File read grants for their runtime directories.", request.argv[0], std::io::Error::last_os_error())
}

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}
#[repr(C, packed)]
struct PathRule {
    allowed_access: u64,
    parent_fd: i32,
}
fn landlock(grants: &[Grant]) -> Result<()> {
    let attr = Ruleset {
        handled_access_fs: FS_ALL,
    };
    let raw = syscall_ok(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            size_of::<Ruleset>(),
            0,
        )
    })? as i32;
    let rules = unsafe { File::from_raw_fd(raw) };
    for grant in grants {
        ensure!(
            grant.path.starts_with('/') && grant.access & !FS_ALL == 0,
            "invalid filesystem grant"
        );
        let fd = syscall_ok(unsafe {
            libc::open(c(&grant.path)?.as_ptr(), libc::O_PATH | libc::O_CLOEXEC)
        } as _)
        .with_context(|| format!("grant path {} unavailable", grant.path))? as i32;
        let file = unsafe { File::from_raw_fd(fd) };
        ensure!(
            grant.access & 1 == 0 || file.metadata()?.is_file(),
            "Process resources must name individual executable files"
        );
        let mut access = grant.access;
        if !file.metadata()?.is_dir() {
            access &= FS_FILE;
        }
        if access == 0 {
            continue;
        }
        let rule = PathRule {
            allowed_access: access,
            parent_fd: fd,
        };
        syscall_ok(unsafe {
            libc::syscall(libc::SYS_landlock_add_rule, rules.as_raw_fd(), 1, &rule, 0)
        })?;
    }
    syscall_ok(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0) })?;
    Ok(())
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    }
}
fn filter(_gate_fd: RawFd) -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    let mut filter = vec![
        stmt(0x20, 4),
        jump(ARCH, 1, 0),
        stmt(0x06, 0x80000000),
        stmt(0x20, 0),
    ];
    for call in mediation::notified() {
        filter.extend([jump(call as u32, 0, 1), stmt(0x06, 0x7fc00000)]);
    }
    // clone3 cannot be inspected by classic BPF. ENOSYS asks libc to use inspectable clone.
    filter.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        stmt(0x06, 0x00050000 | libc::ENOSYS as u32),
    ]);
    let forbidden_clone = (libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_PTRACE
        | libc::CLONE_UNTRACED) as u32;
    filter.extend([
        jump(libc::SYS_clone as u32, 0, 5),
        stmt(0x20, 16),
        stmt(0x54, forbidden_clone),
        jump(0, 1, 0),
        stmt(0x06, DENY),
        stmt(0x06, ALLOW),
    ]);
    // Internet sockets stay in the private network namespace. TCP egress is
    // injected only by the broker; UDP can reach only the protected DNS socket
    // and enclave-local listeners. Raw/packet/netlink sockets remain denied.
    filter.extend([
        jump(libc::SYS_socket as u32, 0, 13),
        stmt(0x20, 16),
        jump(libc::AF_INET as u32, 1, 0),
        jump(libc::AF_INET6 as u32, 0, 9),
        stmt(0x20, 24),
        stmt(0x54, 0xf),
        jump(libc::SOCK_STREAM as u32, 1, 0),
        jump(libc::SOCK_DGRAM as u32, 0, 5),
        stmt(0x20, 32),
        jump(0, 2, 0),
        jump(libc::IPPROTO_TCP as u32, 1, 0),
        jump(libc::IPPROTO_UDP as u32, 0, 1),
        stmt(0x06, ALLOW),
        stmt(0x06, DENY),
    ]);
    // Terminal injection and device-specific ioctls are not exposed.
    filter.push(jump(libc::SYS_ioctl as u32, 0, 13));
    filter.push(stmt(0x20, 24));
    for request in [
        libc::TCGETS,
        libc::TCSETS,
        libc::TCSETSW,
        libc::TCSETSF,
        libc::TIOCGWINSZ,
        libc::TIOCSWINSZ,
        libc::FIONREAD,
        libc::FIONBIO,
        libc::TIOCGPGRP,
        libc::TIOCSPGRP,
    ] {
        filter.push(jump(request as u32, 0, 0));
    }
    // Fill the forward offsets relative to the start of the ioctl block.
    let n = filter.len();
    for (i, item) in filter[n - 10..n].iter_mut().enumerate() {
        item.jt = (10 - i) as u8;
    }
    filter.push(stmt(0x06, DENY));
    filter.push(stmt(0x06, ALLOW));
    filter.push(stmt(0x20, 0));
    let allowed = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_symlinkat,
        libc::SYS_linkat,
        libc::SYS_ftruncate,
        libc::SYS_truncate,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_sync_file_range,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigsuspend,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_umask,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrusage,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_getparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_pipe2,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_signalfd4,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_socketpair,
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_tkill,
        libc::SYS_setpgid,
        libc::SYS_getpgid,
        libc::SYS_setsid,
        libc::SYS_getsid,
    ];
    for number in allowed {
        filter.extend([jump(number as u32, 0, 1), stmt(0x06, ALLOW)]);
    }
    #[cfg(target_arch = "x86_64")]
    for number in [
        libc::SYS_open,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_symlink,
        libc::SYS_link,
        libc::SYS_dup2,
        libc::SYS_pipe,
        libc::SYS_poll,
        libc::SYS_select,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_arch_prctl,
    ] {
        filter.extend([jump(number as u32, 0, 1), stmt(0x06, ALLOW)]);
    }
    filter.push(stmt(0x06, DENY));
    filter
}
fn seccomp(gate_fd: RawFd) -> Result<RawFd> {
    let mut filter = filter(gate_fd);
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    Ok(syscall_ok(unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) })? as i32)
}

#[repr(C)]
#[derive(Default)]
struct Data {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}
#[repr(C)]
#[derive(Default)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    data: Data,
}
#[repr(C)]
struct Response {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}
#[repr(C)]
struct AddFd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}
const RECV: u64 = 0xc0502100;
const SEND: u64 = 0xc0182101;
const VALID: u64 = 0x40082102;
const ADDFD: u64 = 0x40182103;
fn descriptor_flags(pid: u32, fd: u64) -> Result<i32> {
    ensure!(fd <= i32::MAX as u64, "invalid socket descriptor");
    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
    let value = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .context("socket flags unavailable")?;
    Ok(i32::from_str_radix(value.trim(), 8)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn broker_reads_nonblocking_and_close_on_exec_flags() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let flags = || descriptor_flags(std::process::id(), socket.as_raw_fd() as u64).unwrap();
        assert_eq!(flags() & libc::O_NONBLOCK, 0);
        socket.set_nonblocking(true).unwrap();
        assert_ne!(flags() & libc::O_NONBLOCK, 0);
        assert_ne!(flags() & libc::O_CLOEXEC, 0);
        assert_eq!(
            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        assert_eq!(flags() & libc::O_CLOEXEC, 0);
    }
    #[test]
    fn launch_audit_is_explicit_and_older_requests_keep_policy_modes() {
        let old: Launch =
            serde_json::from_str(r#"{"argv":["/usr/bin/node"],"enforce":false}"#).unwrap();
        assert!(!old.audit && !old.enforce);
        let audit: Launch =
            serde_json::from_str(r#"{"argv":["/usr/bin/node"],"enforce":false,"audit":true}"#)
                .unwrap();
        assert!(audit.audit && !audit.enforce);
    }
    fn run_filter(number: libc::c_long, args: [u64; 6], wrong_arch: bool) -> u32 {
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7u32;
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003eu32;
        let mut words = vec![number as u32, if wrong_arch { 0 } else { arch }, 0, 0];
        for arg in args {
            words.push(arg as u32);
            words.push((arg >> 32) as u32);
        }
        let code = filter(99);
        let mut pc = 0;
        let mut acc = 0;
        for _ in 0..1000 {
            let instruction = &code[pc];
            pc += 1;
            match instruction.code {
                0x20 => acc = words[instruction.k as usize / 4],
                0x54 => acc &= instruction.k,
                0x15 => {
                    pc += if acc == instruction.k {
                        instruction.jt as usize
                    } else {
                        instruction.jf as usize
                    }
                }
                0x06 => return instruction.k,
                _ => panic!("unexpected BPF instruction"),
            }
        }
        panic!("filter did not terminate");
    }
    #[test]
    fn filter_rejects_alternate_abis_unknown_syscalls_and_escape_primitives() {
        for number in [
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_io_uring_setup,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_getfd,
            99999,
        ] {
            assert_eq!(
                run_filter(number, [0; 6], false),
                0x50000 | libc::EPERM as u32
            );
        }
        assert_eq!(run_filter(libc::SYS_read, [0; 6], true), 0x80000000);
        assert_eq!(run_filter(libc::SYS_read, [0; 6], false), 0x7fff0000);
        assert_eq!(run_filter(libc::SYS_execve, [0; 6], false), 0x7fff0000);
    }
    #[test]
    fn filter_handles_threads_network_and_terminal_without_branch_bypasses() {
        for family in [libc::AF_INET, libc::AF_INET6] {
            assert_eq!(
                run_filter(
                    libc::SYS_socket,
                    [family as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
                    false
                ),
                0x7fff0000
            );
            for kind in [libc::SOCK_RAW] {
                assert_eq!(
                    run_filter(
                        libc::SYS_socket,
                        [family as u64, kind as u64, 0, 0, 0, 0],
                        false
                    ),
                    0x50000 | libc::EPERM as u32
                );
            }
        }
        assert_eq!(
            run_filter(
                libc::SYS_socket,
                [libc::AF_UNIX as u64, 1, 0, 0, 0, 0],
                false
            ),
            0x50000 | libc::EPERM as u32
        );
        assert_eq!(
            run_filter(
                libc::SYS_clone,
                [libc::CLONE_THREAD as u64, 0, 0, 0, 0, 0],
                false
            ),
            0x7fff0000
        );
        assert_eq!(
            run_filter(
                libc::SYS_clone,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0],
                false
            ),
            0x50000 | libc::EPERM as u32
        );
        assert_eq!(
            run_filter(libc::SYS_clone3, [0; 6], false),
            0x50000 | libc::ENOSYS as u32
        );
        assert_eq!(run_filter(libc::SYS_connect, [0; 6], false), 0x7fc00000);
        assert_eq!(
            run_filter(libc::SYS_ioctl, [0, libc::TIOCSTI, 0, 0, 0, 0], false),
            0x50000 | libc::EPERM as u32
        );
        assert_eq!(
            run_filter(libc::SYS_ioctl, [0, libc::TCGETS, 0, 0, 0, 0], false),
            0x7fff0000
        );
    }
    fn child_result(child: impl FnOnce() -> bool) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::_exit(if child() { 0 } else { 1 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    #[test]
    fn kernel_installs_filter_and_blocks_privilege_and_raw_socket_calls() {
        child_result(|| {
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
                return false;
            }
            if seccomp(99).is_err() {
                return false;
            }
            (unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) }) == -1
                && (unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) })
                    == -1
                && (unsafe { libc::getpid() }) > 0
        });
    }
    #[test]
    fn kernel_notification_holds_connect_until_supervisor_denies_it() {
        let (parent, child) = UnixStream::pair().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(parent);
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            let listener = seccomp(child.as_raw_fd()).unwrap();
            send_fds(&child, &[listener]).unwrap();
            let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            let mut address: libc::sockaddr_in = unsafe { zeroed() };
            address.sin_family = libc::AF_INET as u16;
            address.sin_port = 80u16.to_be();
            address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let result = unsafe {
                libc::connect(
                    socket,
                    (&address as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as u32,
                )
            };
            unsafe {
                libc::_exit(
                    if result < 0
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
                    {
                        0
                    } else {
                        1
                    },
                );
            }
        }
        drop(child);
        parent
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let descriptors = receive_fds(&parent, 1).unwrap();
        let listener = descriptors[0].as_raw_fd();
        let mut poll = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
        let mut notification = Notification::default();
        assert_eq!(unsafe { libc::ioctl(listener, RECV, &mut notification) }, 0);
        assert_eq!(notification.pid, pid as u32);
        assert_eq!(notification.data.nr, libc::SYS_connect as i32);
        let response = Response {
            id: notification.id,
            val: 0,
            error: -libc::EACCES,
            flags: 0,
        };
        assert_eq!(unsafe { libc::ioctl(listener, SEND, &response) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    #[test]
    #[ignore = "requires a Linux kernel with Landlock ABI >= 5; run explicitly in the test VM"]
    fn landlock_kernel_denies_write_symlink_escape_and_unlisted_exec() {
        assert!(abi() >= 5, "Landlock ABI 5 is required");
        let path = std::env::temp_dir().join(format!("cleo-landlock-{}", std::process::id()));
        fs::create_dir_all(path.join("read")).unwrap();
        fs::write(path.join("read/data"), "test").unwrap();
        fs::create_dir_all(path.join("outside")).unwrap();
        fs::write(path.join("outside/secret"), "secret").unwrap();
        std::os::unix::fs::symlink(path.join("outside/secret"), path.join("read/link")).unwrap();
        child_result(|| {
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            }
            if landlock(&[Grant {
                path: path.join("read").to_string_lossy().to_string(),
                access: 4 | 8,
            }])
            .is_err()
            {
                return false;
            }
            fs::read(path.join("read/data")).is_ok()
                && fs::write(path.join("read/data"), "bad").is_err()
                && fs::read(path.join("read/link")).is_err()
                && fs::read(path.join("outside/secret")).is_err()
                && Command::new("/bin/sh")
                    .arg("-c")
                    .arg("exit 0")
                    .status()
                    .is_err()
        });
        assert_eq!(fs::read_to_string(path.join("read/data")).unwrap(), "test");
        fs::remove_dir_all(path).unwrap();
    }
}
