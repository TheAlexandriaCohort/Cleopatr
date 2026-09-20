//! Synchronous seccomp mediation. Pointer arguments are copied and operations
//! are emulated on pinned objects. No pointer-valued syscall is continued.
use super::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
// Linux generic syscall number on both supported 64-bit ABIs (Linux 6.5+).
const FCHMODAT2: libc::c_long = 452;

#[allow(unused_mut)] // The legacy syscall additions are x86-64 only.
pub(super) fn notified() -> Vec<libc::c_long> {
    let mut calls = vec![
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setfsuid,
        libc::SYS_setfsgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_chroot,
        libc::SYS_pivot_root,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        FCHMODAT2,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
    ];
    #[cfg(target_arch = "x86_64")]
    calls.extend([
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
    ]);
    calls
}

pub(super) fn resolver_socket() -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut interface: libc::ifreq = unsafe { zeroed() };
    interface.ifr_name[0] = b'l' as _;
    interface.ifr_name[1] = b'o' as _;
    syscall_ok(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut interface) } as _,
    )?;
    unsafe {
        interface.ifr_ifru.ifru_flags |= libc::IFF_UP as i16;
    }
    syscall_ok(unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &interface) } as _)?;
    Ok(UdpSocket::bind("127.0.0.53:53")?)
}

fn valid(listener: RawFd, event: &Notification) -> Result<()> {
    syscall_ok(unsafe { libc::ioctl(listener, VALID, &event.id) } as _)?;
    Ok(())
}
fn copy(pid: u32, address: u64, count: usize, write: bool, buffer: &mut [u8]) -> Result<()> {
    ensure!(
        count <= 65536 && buffer.len() == count,
        "memory copy exceeds limit"
    );
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: count,
    };
    let remote = libc::iovec {
        iov_base: address as *mut _,
        iov_len: count,
    };
    let result = unsafe {
        if write {
            libc::process_vm_writev(pid as i32, &local, 1, &remote, 1, 0)
        } else {
            libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0)
        }
    };
    ensure!(result == count as isize, "cannot copy syscall memory");
    Ok(())
}
fn read<T: Copy>(event: &Notification, address: u64) -> Result<T> {
    let mut value: T = unsafe { zeroed() };
    let bytes =
        unsafe { std::slice::from_raw_parts_mut((&mut value as *mut T).cast(), size_of::<T>()) };
    copy(event.pid, address, bytes.len(), false, bytes)?;
    Ok(value)
}
fn write<T>(event: &Notification, address: u64, value: &mut T) -> Result<()> {
    let bytes = unsafe { std::slice::from_raw_parts_mut((value as *mut T).cast(), size_of::<T>()) };
    copy(event.pid, address, bytes.len(), true, bytes)
}
fn string(event: &Notification, address: u64) -> Result<String> {
    let mut out = Vec::new();
    while out.len() < 4096 {
        let mut byte = [0u8];
        copy(event.pid, address + out.len() as u64, 1, false, &mut byte)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8(out)?);
        }
        out.push(byte[0]);
    }
    bail!("path exceeds limit")
}
fn member(pid: u32, group: &Path) -> Result<()> {
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .any(|line| line
                .strip_prefix("0::")
                .is_some_and(|path| Path::new(path).file_name() == group.file_name())),
        "cgroup attribution mismatch"
    );
    Ok(())
}
fn pidfd(pid: u32, thread: bool) -> Result<File> {
    let fd = syscall_ok(unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            pid,
            if thread { libc::O_EXCL } else { 0 },
        )
    })?;
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn duplicate(event: &Notification, fd: u64) -> Result<File> {
    ensure!(fd <= i32::MAX as u64, "invalid descriptor");
    // A notification identifies a TID; pidfd_getfd needs the thread-group leader.
    let status = fs::read_to_string(format!("/proc/{}/status", event.pid))?;
    let tgid: u32 = field(&status, "Tgid:")?.parse()?;
    let process = pidfd(tgid, false)?;
    let fd = syscall_ok(unsafe {
        libc::syscall(libc::SYS_pidfd_getfd, process.as_raw_fd(), fd as i32, 0)
    })?;
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn field<'a>(status: &'a str, name: &str) -> Result<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|v| v.split_whitespace().last())
        .context("process identity unavailable")
}
fn sandbox_path(pid: u32, path: PathBuf) -> Result<String> {
    let root = fs::read_link(format!("/proc/{pid}/root"))?;
    if let Ok(relative) = path.strip_prefix(root) {
        return Ok(format!("/{}", relative.to_string_lossy()));
    }
    // Kernel pseudo-files (pipes, sockets) are not catalog paths.
    ensure!(!path.is_absolute(), "descriptor outside enclave root");
    Ok(format!("fd:{}", path.to_string_lossy()))
}
fn executable(pid: u32) -> Result<String> {
    sandbox_path(pid, fs::read_link(format!("/proc/{pid}/exe"))?)
}
fn authorize(
    rpc: &mut impl FnMut(Value) -> Result<Value>,
    action: &str,
    locator: &str,
    mut context: Value,
) -> Result<()> {
    context["confidence"] = json!("kernel-observed");
    context["semanticAvailable"] = json!(true);
    ensure!(
        rpc(json!({"op":"authorize", "action":action, "locator":locator, "context":context}))?
            ["allowed"]
            == true,
        "blocked by Cleopatr policy"
    );
    Ok(())
}

// Filesystem credentials apply only to this single-threaded session supervisor.
// DAC and readonly mounts remain effective while emulating metadata mutations.
struct FsIdentity {
    uid: u32,
    gid: u32,
    parent: i32,
    death_signal: i32,
}
impl FsIdentity {
    fn enter(uid: u32, gid: u32) -> Result<Self> {
        let mut death_signal = 0i32;
        syscall_ok(
            unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death_signal, 0, 0, 0) } as _,
        )?;
        let parent = unsafe { libc::getppid() };
        unsafe {
            let old_gid = libc::setfsgid(gid);
            let old_uid = libc::setfsuid(uid);
            Ok(Self {
                uid: old_uid as u32,
                gid: old_gid as u32,
                parent,
                death_signal,
            })
        }
    }
}
impl Drop for FsIdentity {
    fn drop(&mut self) {
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
            // Linux clears PDEATHSIG on filesystem-credential changes. Restore
            // it and close the race if the service parent died during emulation.
            if libc::prctl(libc::PR_SET_PDEATHSIG, self.death_signal, 0, 0, 0) < 0
                || libc::getppid() != self.parent
            {
                libc::_exit(126);
            }
        }
    }
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn pin_path(
    event: &Notification,
    dirfd: i32,
    path: &str,
    nofollow: bool,
    uid: u32,
    gid: u32,
) -> Result<File> {
    let root = File::open(format!("/proc/{}/root", event.pid))?;
    let full = if path.starts_with('/') {
        path.to_string()
    } else {
        let directory = if dirfd == libc::AT_FDCWD {
            fs::read_link(format!("/proc/{}/cwd", event.pid))?
        } else {
            let file = duplicate(event, dirfd as u64)?;
            fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?
        };
        format!("{}/{}", sandbox_path(event.pid, directory)?, path)
    };
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 })
            as u64,
        mode: 0,
        resolve: 0x10 | 0x02,
    };
    let _identity = FsIdentity::enter(uid, gid)?;
    let fd = syscall_ok(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            c(&full)?.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    })?;
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
#[allow(unused_mut)] // Legacy x86-64 pathname syscalls adjust these locals.
fn metadata(
    event: &Notification,
    listener: RawFd,
    uid: u32,
    gid: u32,
    rpc: &mut impl FnMut(Value) -> Result<Value>,
) -> Result<i64> {
    let n = event.data.nr as libc::c_long;
    let a = event.data.args;
    let descriptor = [libc::SYS_fstat, libc::SYS_fchmod, libc::SYS_fchown].contains(&n);
    let mut directory = a[0] as i32;
    let mut pointer = a[1];
    let mut flags = 0i32;
    if n == libc::SYS_newfstatat {
        flags = a[3] as i32;
    }
    if n == libc::SYS_statx {
        flags = a[2] as i32;
    }
    if n == libc::SYS_fchownat {
        flags = a[4] as i32;
    }
    if n == FCHMODAT2 || n == libc::SYS_utimensat {
        flags = a[3] as i32;
    }
    #[cfg(target_arch = "x86_64")]
    if [
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
    ]
    .contains(&n)
    {
        directory = libc::AT_FDCWD;
        pointer = a[0];
        if n == libc::SYS_lstat || n == libc::SYS_lchown {
            flags = libc::AT_SYMLINK_NOFOLLOW;
        }
    }
    ensure!(
        flags & !(libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | 0x6000)
            == 0,
        "unsupported metadata flags"
    );
    let path = if descriptor || (n == libc::SYS_utimensat && pointer == 0) {
        String::new()
    } else {
        string(event, pointer)?
    };
    let pinned = if descriptor
        || (path.is_empty() && flags & libc::AT_EMPTY_PATH != 0)
        || (n == libc::SYS_utimensat && pointer == 0)
    {
        duplicate(event, a[0])
    } else {
        pin_path(
            event,
            directory,
            &path,
            flags & libc::AT_SYMLINK_NOFOLLOW != 0,
            uid,
            gid,
        )
    };
    let operation = if n == libc::SYS_fchmod || n == libc::SYS_fchmodat || n == FCHMODAT2 {
        "chmod"
    } else if n == libc::SYS_fchown || n == libc::SYS_fchownat {
        "chown"
    } else if n == libc::SYS_utimensat {
        "utimens"
    } else {
        "stat"
    };
    #[cfg(target_arch = "x86_64")]
    let operation = if n == libc::SYS_chmod {
        "chmod"
    } else if n == libc::SYS_chown || n == libc::SYS_lchown {
        "chown"
    } else {
        operation
    };
    let locator = match &pinned {
        Ok(file) => {
            let resolved = sandbox_path(
                event.pid,
                fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?,
            );
            match resolved {
                Ok(path) => path,
                // Delegated standard streams (and their dup() copies) may be
                // host files or terminal devices. Stat is safe on a held FD;
                // never expose the host path or emulate metadata mutation.
                Err(_)
                    if operation == "stat"
                        && (descriptor
                            || (path.is_empty() && flags & libc::AT_EMPTY_PATH != 0)) =>
                {
                    format!("inherited-fd:{}", a[0])
                }
                Err(error) => return Err(error),
            }
        }
        Err(_) => path.clone(),
    };
    let mut context = json!({"operation":operation, "path":locator, "withinWorkspace":pinned.is_ok() && (locator == "/workspace" || locator.starts_with("/workspace/"))});
    if pinned.is_ok() {
        context["resolvedPath"] = json!(locator);
    }
    let mode = if descriptor { a[1] } else { a[2] };
    #[cfg(target_arch = "x86_64")]
    let mode = if n == libc::SYS_chmod { a[1] } else { mode };
    let owner = if descriptor { a[1] } else { a[2] };
    let group = if descriptor { a[2] } else { a[3] };
    #[cfg(target_arch = "x86_64")]
    let (owner, group) = if n == libc::SYS_chown || n == libc::SYS_lchown {
        (a[1], a[2])
    } else {
        (owner, group)
    };
    let times: Option<[libc::timespec; 2]> = if operation != "utimens" || a[2] == 0 {
        None
    } else {
        Some(read(event, a[2])?)
    };
    if operation == "chmod" {
        context["amount"] = json!(mode);
    }
    if operation == "chown" {
        context["argv"] = json!([
            format!("uid={}", owner as u32),
            format!("gid={}", group as u32)
        ]);
    }
    if operation == "utimens" {
        context["argv"] = json!(times
            .as_ref()
            .map(|v| v
                .iter()
                .map(|t| format!("{}:{}", t.tv_sec, t.tv_nsec))
                .collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["now".into()]));
    }
    authorize(rpc, "file.metadata", &locator, context)?;
    let file = pinned?;
    valid(listener, event)?;
    if n == libc::SYS_statx {
        let mut value: libc::statx = unsafe { zeroed() };
        syscall_ok(unsafe {
            libc::statx(
                file.as_raw_fd(),
                c("")?.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                a[3] as u32,
                &mut value,
            )
        } as _)?;
        write(event, a[4], &mut value)?;
        return Ok(0);
    }
    if operation == "stat" {
        let mut value: libc::stat = unsafe { zeroed() };
        syscall_ok(unsafe { libc::fstat(file.as_raw_fd(), &mut value) } as _)?;
        let output = if descriptor { a[1] } else { a[2] };
        #[cfg(target_arch = "x86_64")]
        let output = if n == libc::SYS_stat || n == libc::SYS_lstat {
            a[1]
        } else {
            output
        };
        write(event, output, &mut value)?;
        return Ok(0);
    }
    // Restrict mutations to regular files/directories. Symlinks, socket FDs and
    // devices do not become a privileged path around the enclave's mount rules.
    let info = file.metadata()?;
    ensure!(
        info.is_file() || info.is_dir(),
        "metadata mutation requires a regular file or directory"
    );
    if operation == "chmod" {
        ensure!(
            mode & !0o777 == 0,
            "set-ID and special mode changes remain prohibited"
        );
        let _identity = FsIdentity::enter(uid, gid)?;
        syscall_ok(unsafe {
            libc::syscall(
                FCHMODAT2,
                file.as_raw_fd(),
                c("")?.as_ptr(),
                mode as u32,
                libc::AT_EMPTY_PATH,
            )
        })?;
    } else if operation == "chown" {
        let _identity = FsIdentity::enter(uid, gid)?;
        syscall_ok(unsafe {
            libc::fchownat(
                file.as_raw_fd(),
                c("")?.as_ptr(),
                owner as u32,
                group as u32,
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        } as _)?;
    } else {
        let _identity = FsIdentity::enter(uid, gid)?;
        syscall_ok(unsafe {
            libc::utimensat(
                file.as_raw_fd(),
                c("")?.as_ptr(),
                times.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        } as _)?;
    }
    Ok(0)
}

fn signal(
    event: &Notification,
    listener: RawFd,
    group: &Path,
    uid: u32,
    rpc: &mut impl FnMut(Value) -> Result<Value>,
) -> Result<i64> {
    let n = event.data.nr as libc::c_long;
    let a = event.data.args;
    let thread = n != libc::SYS_kill;
    let target = if n == libc::SYS_tgkill {
        a[1] as i32
    } else {
        a[0] as i32
    };
    let sig = if n == libc::SYS_tgkill {
        a[2] as i32
    } else {
        a[1] as i32
    };
    ensure!(
        (0..=64).contains(&sig) && (!thread || target > 0),
        "invalid signal"
    );
    let source_namespace = fs::metadata(format!("/proc/{}/ns/pid", event.pid))?.ino();
    let source = fs::read_to_string(format!("/proc/{}/status", event.pid))?;
    let source_group: i32 = field(&source, "NSpgid:")?.parse()?;
    let mut targets = Vec::new();
    for id in fs::read_to_string(group.join(if thread {
        "cgroup.threads"
    } else {
        "cgroup.procs"
    }))?
    .split_whitespace()
    {
        let pid: u32 = id.parse()?;
        let process = match pidfd(pid, thread) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if fs::metadata(format!("/proc/{pid}/ns/pid"))
            .map(|v| v.ino())
            .unwrap_or(0)
            != source_namespace
            || field(&status, "Uid:")?.parse::<u32>()? != uid
        {
            continue;
        }
        let ns_pid: i32 = field(&status, "NSpid:")?.parse()?;
        let ns_group: i32 = field(&status, "NSpgid:")?.parse()?;
        if !(if target > 0 {
            ns_pid == target
        } else if target == -1 {
            ns_pid > 1
        } else {
            ns_group == if target == 0 { source_group } else { -target }
        }) {
            continue;
        }
        if n == libc::SYS_tgkill && field(&status, "NStgid:")?.parse::<i32>()? != a[0] as i32 {
            continue;
        }
        member(pid, group)?;
        let exe = executable(pid)?;
        authorize(
            rpc,
            "process.signal",
            &exe,
            json!({"operation":"signal", "amount":sig, "executable":exe, "argv":[format!("pid={ns_pid}")]}),
        )?;
        targets.push(process);
    }
    ensure!(
        !targets.is_empty(),
        "signal target is outside the enclave or exited"
    );
    valid(listener, event)?;
    for target in targets {
        syscall_ok(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                target.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                if thread { 1 } else { 0 },
            )
        })?;
    }
    Ok(0)
}

fn address(
    event: &Notification,
    pointer: u64,
    length: u64,
) -> Result<(libc::sockaddr_storage, SocketAddr)> {
    ensure!(
        length == size_of::<libc::sockaddr_in>() as u64
            || length == size_of::<libc::sockaddr_in6>() as u64,
        "unsupported socket address"
    );
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            length as usize,
        )
    };
    copy(event.pid, pointer, bytes.len(), false, bytes)?;
    let parsed = parse_address(&storage)?;
    Ok((storage, parsed))
}
fn parse_address(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    if storage.ss_family == libc::AF_INET as u16 {
        let value = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(value.sin_addr.s_addr.to_ne_bytes())),
            u16::from_be(value.sin_port),
        ))
    } else if storage.ss_family == libc::AF_INET6 as u16 {
        let value = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
        ensure!(value.sin6_scope_id == 0, "scoped IPv6 unsupported");
        Ok(SocketAddr::new(
            IpAddr::V6(value.sin6_addr.s6_addr.into()),
            u16::from_be(value.sin6_port),
        ))
    } else {
        bail!("unsupported address family")
    }
}
fn network(
    event: &Notification,
    listener: RawFd,
    ready: &Ready,
    rpc: &mut impl FnMut(Value) -> Result<Value>,
) -> Result<i64> {
    let n = event.data.nr as libc::c_long;
    let a = event.data.args;
    let socket = duplicate(event, a[0])?;
    let mut kind = 0i32;
    let mut size = size_of::<i32>() as u32;
    syscall_ok(unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut size,
        )
    } as _)?;
    ensure!(
        [libc::SOCK_STREAM, libc::SOCK_DGRAM].contains(&kind),
        "unsupported socket kind"
    );
    let (storage, addr, length) = if n == libc::SYS_listen {
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        let mut length = size_of::<libc::sockaddr_storage>() as u32;
        syscall_ok(unsafe {
            libc::getsockname(
                socket.as_raw_fd(),
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } as _)?;
        let addr = parse_address(&storage)?;
        (storage, addr, length)
    } else {
        let (storage, addr) = address(event, a[1], a[2])?;
        (storage, addr, a[2] as u32)
    };
    if n == libc::SYS_connect && kind == libc::SOCK_STREAM {
        let routed = if addr.to_string() == "127.0.0.1:18080" {
            Some(ready.proxy_port)
        } else if addr.to_string() == "127.0.0.53:53" {
            Some(ready.dns_port)
        } else {
            ready
                .routes
                .iter()
                .find(|r| r.host == addr.ip().to_string() && r.port == addr.port())
                .map(|r| r.proxy_port)
        };
        if let Some(port) = routed {
            valid(listener, event)?;
            let flags = descriptor_flags(event.pid, a[0])?;
            let upstream = TcpStream::connect_timeout(
                &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
                Duration::from_secs(3),
            )?;
            upstream.set_nonblocking(flags & libc::O_NONBLOCK != 0)?;
            let add = AddFd {
                id: event.id,
                flags: 1,
                srcfd: upstream.as_raw_fd() as u32,
                newfd: a[0] as u32,
                newfd_flags: (flags & libc::O_CLOEXEC) as u32,
            };
            syscall_ok(unsafe { libc::ioctl(listener, ADDFD, &add) } as _)?;
            return Ok(0);
        }
    }
    if n == libc::SYS_connect && kind == libc::SOCK_DGRAM && addr.to_string() == "127.0.0.53:53" {
        // Every query is separately authorized by the protected DNS adapter.
    } else {
        let operation = if n == libc::SYS_connect {
            "connect"
        } else if n == libc::SYS_bind {
            "bind"
        } else {
            "listen"
        };
        authorize(
            rpc,
            if n == libc::SYS_connect {
                "network.connect"
            } else {
                "network.listen"
            },
            &format!(
                "{}://{addr}",
                if kind == libc::SOCK_STREAM {
                    "tcp"
                } else {
                    "udp"
                }
            ),
            json!({"operation":operation, "host":addr.ip().to_string(), "port":addr.port(), "protocol":if kind == libc::SOCK_STREAM { "tcp" } else { "udp" }}),
        )?;
        ensure!(
            addr.ip().is_loopback() || (n == libc::SYS_bind && addr.ip().is_unspecified()),
            "only enclave-local listeners/connections are supported outside adapters"
        );
        ensure!(
            addr.port() != 53 && addr.port() != 18080,
            "reserved enclave adapter port"
        );
    }
    valid(listener, event)?;
    let value = unsafe {
        if n == libc::SYS_listen {
            libc::listen(socket.as_raw_fd(), (a[1] as i32).clamp(0, 128))
        } else if n == libc::SYS_bind {
            libc::bind(
                socket.as_raw_fd(),
                (&storage as *const libc::sockaddr_storage).cast(),
                length,
            )
        } else {
            libc::connect(
                socket.as_raw_fd(),
                (&storage as *const libc::sockaddr_storage).cast(),
                length,
            )
        }
    };
    Ok(syscall_ok(value as _)? as i64)
}

pub(super) fn mediate(
    listener: RawFd,
    ready: &Ready,
    group: &Path,
    uid: u32,
    gid: u32,
    rpc: &mut impl FnMut(Value) -> Result<Value>,
) -> Result<()> {
    let mut event = Notification::default();
    if unsafe { libc::ioctl(listener, RECV, &mut event) } < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error().into());
    }
    let mut response = Response {
        id: event.id,
        val: 0,
        error: 0,
        flags: 0,
    };
    let result = (|| -> Result<i64> {
        member(event.pid, group)?;
        valid(listener, &event)?;
        let n = event.data.nr as libc::c_long;
        if [libc::SYS_connect, libc::SYS_bind, libc::SYS_listen].contains(&n) {
            return network(&event, listener, ready, rpc);
        }
        if [libc::SYS_kill, libc::SYS_tkill, libc::SYS_tgkill].contains(&n) {
            return signal(&event, listener, group, uid, rpc);
        }
        let privileges = [
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_setreuid,
            libc::SYS_setregid,
            libc::SYS_setresuid,
            libc::SYS_setresgid,
            libc::SYS_setfsuid,
            libc::SYS_setfsgid,
            libc::SYS_setgroups,
            libc::SYS_capset,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_chroot,
            libc::SYS_pivot_root,
        ];
        if privileges.contains(&n) {
            let names = [
                "setuid",
                "setgid",
                "setreuid",
                "setregid",
                "setresuid",
                "setresgid",
                "setfsuid",
                "setfsgid",
                "setgroups",
                "capset",
                "unshare",
                "setns",
                "mount",
                "umount2",
                "chroot",
                "pivot_root",
            ];
            let operation = names[privileges.iter().position(|call| *call == n).unwrap()];
            let exe = executable(event.pid)?;
            authorize(
                rpc,
                "process.privilege_attempt",
                &exe,
                json!({"operation":operation, "executable":exe, "amount":event.data.args[0] as i64, "argv":event.data.args.iter().map(|v|v.to_string()).collect::<Vec<_>>()}),
            )?;
            // Authorization never confers privileges. Only scalar no-op UID/GID
            // requests may proceed under the kernel's existing credential checks.
            let (identity, count) =
                if [libc::SYS_setuid, libc::SYS_setreuid, libc::SYS_setresuid].contains(&n) {
                    (
                        uid,
                        if n == libc::SYS_setuid {
                            1
                        } else if n == libc::SYS_setreuid {
                            2
                        } else {
                            3
                        },
                    )
                } else if [libc::SYS_setgid, libc::SYS_setregid, libc::SYS_setresgid].contains(&n) {
                    (
                        gid,
                        if n == libc::SYS_setgid {
                            1
                        } else if n == libc::SYS_setregid {
                            2
                        } else {
                            3
                        },
                    )
                } else {
                    (0, 0)
                };
            ensure!(
                count > 0
                    && event.data.args[..count]
                        .iter()
                        .all(|value| *value as u32 == identity
                            || (count > 1 && *value as u32 == u32::MAX)),
                "privilege elevation remains prohibited by enclave isolation"
            );
            valid(listener, &event)?;
            response.flags = 1;
            return Ok(0);
        }
        metadata(&event, listener, uid, gid, rpc)
    })();
    match result {
        Ok(value) => response.val = value,
        Err(error) => {
            response.error = -error
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                .unwrap_or(libc::EACCES);
            if response.error != -libc::ENOENT {
                eprintln!(
                    "cleo-supervisor: syscall {} denied: {error:#}",
                    event.data.nr
                );
            }
        }
    }
    if unsafe { libc::ioctl(listener, SEND, &response) } < 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn dns(socket: &UdpSocket, rpc: &mut impl FnMut(Value) -> Result<Value>) -> Result<()> {
    let mut bytes = [0u8; 4097];
    let (count, peer) = socket.recv_from(&mut bytes)?;
    if count > 4096 {
        return Ok(());
    }
    let packet: String = bytes[..count].iter().map(|v| format!("{v:02x}")).collect();
    let reply = rpc(json!({"op":"dns", "packet":packet}))?;
    let hex = reply["packet"]
        .as_str()
        .context("invalid DNS worker reply")?;
    ensure!(
        hex.len() <= 8192 && hex.len() % 2 == 0,
        "invalid DNS response length"
    );
    let response = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    socket.send_to(&response, peer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filesystem_credentials_preserve_parent_death_protection() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            let identity = FsIdentity::enter(1000, 1000).unwrap();
            drop(identity);
            let mut signal = 0i32;
            unsafe {
                libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal, 0, 0, 0);
                libc::_exit(if signal == libc::SIGKILL { 0 } else { 1 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
