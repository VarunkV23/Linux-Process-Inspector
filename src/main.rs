use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use serde::Serialize;

const RESET:   &str = "\x1b[0m";
const BOLD:    &str = "\x1b[1m";
const CYAN:    &str = "\x1b[36m";
const GREEN:   &str = "\x1b[32m";
const YELLOW:  &str = "\x1b[33m";
const RED:     &str = "\x1b[31m";
const DIM:     &str = "\x1b[2m";
const MAGENTA: &str = "\x1b[35m";

fn syscall_name(nr: u64) -> &'static str {
    match nr {
        0=>"read", 1=>"write", 2=>"open", 3=>"close", 4=>"stat",
        5=>"fstat", 6=>"lstat", 7=>"poll", 8=>"lseek", 9=>"mmap",
        10=>"mprotect", 11=>"munmap", 12=>"brk", 13=>"rt_sigaction",
        14=>"rt_sigprocmask", 16=>"ioctl", 17=>"pread64", 18=>"pwrite64",
        19=>"readv", 20=>"writev", 21=>"access", 22=>"pipe", 23=>"select",
        24=>"sched_yield", 25=>"mremap", 26=>"msync", 28=>"madvise",
        32=>"dup", 33=>"dup2", 39=>"getpid", 41=>"socket", 42=>"connect",
        43=>"accept", 44=>"sendto", 45=>"recvfrom", 46=>"sendmsg",
        47=>"recvmsg", 48=>"shutdown", 49=>"bind", 50=>"listen",
        51=>"getsockname", 52=>"getpeername", 54=>"setsockopt",
        55=>"getsockopt", 56=>"clone", 57=>"fork", 58=>"vfork",
        59=>"execve", 60=>"exit", 61=>"wait4", 62=>"kill", 63=>"uname",
        72=>"fcntl", 73=>"flock", 74=>"fsync", 76=>"truncate",
        77=>"ftruncate", 78=>"getdents", 79=>"getcwd", 80=>"chdir",
        82=>"rename", 83=>"mkdir", 84=>"rmdir", 87=>"unlink",
        88=>"symlink", 89=>"readlink", 90=>"chmod", 91=>"fchmod",
        92=>"chown", 95=>"umask", 96=>"gettimeofday", 97=>"getrlimit",
        99=>"sysinfo", 102=>"getuid", 104=>"getgid", 107=>"geteuid",
        108=>"getegid", 110=>"getppid", 112=>"setsid", 137=>"statfs",
        157=>"prctl", 158=>"arch_prctl", 160=>"setrlimit",
        162=>"nanosleep", 186=>"gettid", 202=>"futex",
        228=>"clock_gettime", 231=>"exit_group", 232=>"epoll_wait",
        233=>"epoll_ctl", 234=>"tgkill", 257=>"openat",
        262=>"newfstatat", 271=>"ppoll", 281=>"epoll_pwait",
        285=>"fallocate", 288=>"accept4", 291=>"epoll_create1",
        292=>"dup3", 293=>"pipe2", 302=>"prlimit64",
        318=>"getrandom", 319=>"memfd_create", 332=>"statx",
        _=>"unknown",
    }
}

const CAP_NAMES: &[&str] = &[
    "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER",
    "CAP_FSETID","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE","CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST",
    "CAP_NET_ADMIN","CAP_NET_RAW","CAP_IPC_LOCK","CAP_IPC_OWNER",
    "CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE",
    "CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE",
    "CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD",
    "CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP",
    "CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON","CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

fn decode_caps(hex: &str) -> Vec<&'static str> {
    let val = u64::from_str_radix(hex.trim(), 16).unwrap_or(0);
    CAP_NAMES.iter().enumerate()
        .filter(|(i, _)| val & (1u64 << i) != 0)
        .map(|(_, &name)| name)
        .collect()
}

fn tcp_state(code: &str) -> &'static str {
    match code.trim() {
        "01"=>"ESTABLISHED","02"=>"SYN_SENT","03"=>"SYN_RECV",
        "04"=>"FIN_WAIT1","05"=>"FIN_WAIT2","06"=>"TIME_WAIT",
        "07"=>"CLOSE","08"=>"CLOSE_WAIT","09"=>"LAST_ACK",
        "0A"=>"LISTEN","0B"=>"CLOSING",_=>"UNKNOWN",
    }
}

fn parse_ipv4(hex: &str) -> String {
    let n = u32::from_str_radix(hex, 16).unwrap_or(0);
    format!("{}.{}.{}.{}", n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF)
}

// ─── data structures ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProcessInfo {
    pid: u32, name: String, state: String, ppid: String,
    threads: String, uid: String, vm_rss: String, vm_size: String,
    cmdline: String, seccomp: String,
    caps_effective: Vec<&'static str>,
    caps_permitted: Vec<&'static str>,
    fds: Vec<FdInfo>, maps: Vec<MapInfo>,
    sockets: Vec<SocketInfo>, smaps: SmapsSummary,
    namespaces: Vec<NsInfo>, cgroup: Vec<String>,
}

#[derive(Serialize, Debug)]
struct FdInfo { fd: u32, target: String, kind: String }

#[derive(Serialize, Debug)]
struct MapInfo { start: String, end: String, perms: String, size_kb: u64, label: String }

#[derive(Serialize, Debug, Default)]
struct SmapsSummary {
    total_size_kb: u64, pss_kb: u64, private_dirty_kb: u64,
    shared_dirty_kb: u64, shared_clean_kb: u64, swap_kb: u64,
    regions: Vec<SmapsRegion>,
}

#[derive(Serialize, Debug)]
struct SmapsRegion {
    label: String, perms: String,
    size_kb: u64, pss_kb: u64, private_dirty_kb: u64, swap_kb: u64,
}

#[derive(Serialize, Debug)]
struct SocketInfo {
    fd: Option<u32>, protocol: String,
    local: String, remote: String, state: String, inode: u64,
}

#[derive(Serialize, Debug)]
struct NsInfo { kind: String, inode: String, isolated: bool }

// ─── /proc parsers ────────────────────────────────────────────────────────────

fn read_proc(pid: u32, file: &str) -> io::Result<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, file))
}

fn parse_status(pid: u32) -> io::Result<Vec<(String, String)>> {
    let raw = read_proc(pid, "status")?;
    Ok(raw.lines().filter_map(|l| {
        let mut p = l.splitn(2, ':');
        Some((p.next()?.trim().to_string(), p.next()?.trim().to_string()))
    }).collect())
}

fn status_field<'a>(status: &'a [(String, String)], key: &str) -> &'a str {
    status.iter().find(|(k,_)| k == key).map(|(_,v)| v.as_str()).unwrap_or("?")
}

fn parse_fds(pid: u32) -> io::Result<Vec<FdInfo>> {
    let mut fds = Vec::new();
    for entry in fs::read_dir(format!("/proc/{}/fd", pid))? {
        let entry = entry?;
        let fd: u32 = entry.file_name().to_string_lossy().parse().unwrap_or(0);
        let target = fs::read_link(entry.path())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<unreadable>".to_string());
        let kind = if target.starts_with("socket:") { "socket" }
                   else if target.starts_with("pipe:") { "pipe" }
                   else if target.starts_with('/') { "file" }
                   else { "other" }.to_string();
        fds.push(FdInfo { fd, target, kind });
    }
    fds.sort_by_key(|f| f.fd);
    Ok(fds)
}

fn parse_maps(pid: u32) -> io::Result<Vec<MapInfo>> {
    let raw = read_proc(pid, "maps")?;
    Ok(raw.lines().filter_map(|line| {
        let cols: Vec<&str> = line.splitn(6, ' ').collect();
        if cols.len() < 5 { return None; }
        let range: Vec<&str> = cols[0].splitn(2, '-').collect();
        if range.len() < 2 { return None; }
        let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
        let end   = u64::from_str_radix(range[1], 16).unwrap_or(0);
        Some(MapInfo {
            start: format!("{:016x}", start),
            end:   format!("{:016x}", end),
            perms: cols[1].to_string(),
            size_kb: (end - start) / 1024,
            label: cols.get(5).unwrap_or(&"").trim().to_string(),
        })
    }).collect())
}

fn parse_smaps(pid: u32) -> io::Result<SmapsSummary> {
    let raw = read_proc(pid, "smaps")?;
    let mut s = SmapsSummary::default();
    let mut cur: Option<SmapsRegion> = None;

    let flush = |s: &mut SmapsSummary, r: SmapsRegion| {
        s.total_size_kb    += r.size_kb;
        s.pss_kb           += r.pss_kb;
        s.private_dirty_kb += r.private_dirty_kb;
        s.swap_kb          += r.swap_kb;
        s.regions.push(r);
    };

    for line in raw.lines() {
        if line.contains('-') && !line.starts_with(' ') && !line.contains(':') {
            if let Some(r) = cur.take() { flush(&mut s, r); }
            let cols: Vec<&str> = line.splitn(6, ' ').collect();
            cur = Some(SmapsRegion {
                perms: cols.get(1).unwrap_or(&"").to_string(),
                label: cols.get(5).unwrap_or(&"").trim().to_string(),
                size_kb: 0, pss_kb: 0, private_dirty_kb: 0, swap_kb: 0,
            });
        } else if let Some(ref mut r) = cur {
            let mut p = line.splitn(2, ':');
            let key = p.next().unwrap_or("").trim();
            let val: u64 = p.next().unwrap_or("").split_whitespace()
                .next().unwrap_or("0").parse().unwrap_or(0);
            match key {
                "Size"          => r.size_kb = val,
                "Pss"           => r.pss_kb = val,
                "Private_Dirty" => r.private_dirty_kb = val,
                "Shared_Dirty"  => s.shared_dirty_kb += val,
                "Shared_Clean"  => s.shared_clean_kb += val,
                "Swap"          => r.swap_kb = val,
                _ => {}
            }
        }
    }
    if let Some(r) = cur { flush(&mut s, r); }
    Ok(s)
}

fn socket_inodes(pid: u32) -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten() {
            let fd: u32 = entry.file_name().to_string_lossy().parse().unwrap_or(0);
            if let Ok(t) = fs::read_link(entry.path()) {
                let t = t.to_string_lossy();
                if let Some(inner) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = inner.parse::<u64>() {
                        map.insert(inode, fd);
                    }
                }
            }
        }
    }
    map
}

fn parse_net_proto(pid: u32, proto: &str) -> Vec<(String, String, String, u64)> {
    let raw = fs::read_to_string(format!("/proc/{}/net/{}", pid, proto)).unwrap_or_default();
    raw.lines().skip(1).filter_map(|line| {
        let c: Vec<&str> = line.split_whitespace().collect();
        if c.len() < 10 { return None; }
        let lp: Vec<&str> = c[1].splitn(2, ':').collect();
        let rp: Vec<&str> = c[2].splitn(2, ':').collect();
        if lp.len() < 2 || rp.len() < 2 { return None; }
        let local  = format!("{}:{}", parse_ipv4(lp[0]), u16::from_str_radix(lp[1], 16).unwrap_or(0));
        let remote = format!("{}:{}", parse_ipv4(rp[0]), u16::from_str_radix(rp[1], 16).unwrap_or(0));
        let inode: u64 = c[9].parse().unwrap_or(0);
        Some((local, remote, tcp_state(c[3]).to_string(), inode))
    }).collect()
}

fn parse_sockets(pid: u32) -> Vec<SocketInfo> {
    let inodes = socket_inodes(pid);
    let mut out = Vec::new();
    for proto in &["tcp", "udp", "tcp6", "udp6"] {
        for (local, remote, state, inode) in parse_net_proto(pid, proto) {
            out.push(SocketInfo {
                fd: inodes.get(&inode).copied(),
                protocol: proto.to_string(),
                local, remote, state, inode,
            });
        }
    }
    out
}

fn all_pids() -> Vec<u32> {
    let mut pids: Vec<u32> = fs::read_dir("/proc").unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids
}

// ─── namespace / container awareness ─────────────────────────────────────────

fn ns_inode_from_link(s: &str) -> Option<u64> {
    // symlink target looks like "net:[4026531992]"
    s.split('[').nth(1)?.trim_end_matches(']').parse().ok()
}

fn parse_namespaces(pid: u32) -> Vec<NsInfo> {
    let ns_names = ["cgroup","ipc","mnt","net","pid","time","user","uts"];
    let init_ns: HashMap<String, u64> = ns_names.iter().filter_map(|ns| {
        let t = fs::read_link(format!("/proc/1/ns/{}", ns)).ok()?;
        let inode = ns_inode_from_link(&t.to_string_lossy())?;
        Some((ns.to_string(), inode))
    }).collect();

    ns_names.iter().filter_map(|ns| {
        let path = format!("/proc/{}/ns/{}", pid, ns);
        let target = fs::read_link(&path).ok()?;
        let target_str = target.to_string_lossy().to_string();
        let inode = ns_inode_from_link(&target_str).unwrap_or(0);
        let isolated = init_ns.get(*ns).map(|&i| i != inode).unwrap_or(true);
        Some(NsInfo { kind: ns.to_string(), inode: target_str, isolated })
    }).collect()
}

fn parse_cgroup(pid: u32) -> Vec<String> {
    fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

fn show_ns(pid: u32) -> io::Result<()> {
    let nss = parse_namespaces(pid);

    println!("\n{BOLD}{CYAN}Namespaces — PID {pid}{RESET}\n");
    println!("{DIM}  {:<8}  {:<30}  isolated from host?{RESET}", "type", "inode");
    for ns in &nss {
        let marker = if ns.isolated {
            format!("{GREEN}yes  ← different namespace{RESET}")
        } else {
            format!("{DIM}no (shares host namespace){RESET}")
        };
        println!("  {BOLD}{:<8}{RESET}  {DIM}{:<30}{RESET}  {}", ns.kind, ns.inode, marker);
    }

    // cgroup + container runtime detection
    let cgroups = parse_cgroup(pid);
    println!("\n{BOLD}{CYAN}Cgroups{RESET}\n");
    let mut found_runtime = false;
    for cg in &cgroups {
        let parts: Vec<&str> = cg.splitn(3, ':').collect();
        if parts.len() < 3 { continue; }
        let subsys = parts[1].trim_start_matches("name=");
        let path   = parts[2];
        let runtime = if path.contains("docker")     { Some("Docker") }
                 else if path.contains("lxc")         { Some("LXC") }
                 else if path.contains("kubepods")    { Some("Kubernetes") }
                 else if path.contains("containerd")  { Some("containerd") }
                 else if path.contains("podman")      { Some("Podman") }
                 else { None };
        if let Some(rt) = runtime {
            found_runtime = true;
            println!("  {YELLOW}[container]{RESET}  runtime={BOLD}{rt}{RESET}  subsys={DIM}{subsys}{RESET}");
            println!("             {DIM}{path}{RESET}");
        } else {
            println!("  {DIM}{:<14}  {path}{RESET}", subsys);
        }
    }
    if !found_runtime {
        println!("  {DIM}No container runtime detected (bare-metal or VM){RESET}");
    }
    Ok(())
}

// ─── diff ─────────────────────────────────────────────────────────────────────

struct ProcSnapshot {
    fd_targets: HashSet<String>,
    socket_keys: HashSet<String>,
    fd_count: usize,
    vm_rss_kb: i64,
}

fn vm_rss_kb(status: &[(String, String)]) -> i64 {
    status_field(status, "VmRSS")
        .split_whitespace().next().unwrap_or("0")
        .parse().unwrap_or(0)
}

fn take_snapshot(pid: u32) -> ProcSnapshot {
    let fds     = parse_fds(pid).unwrap_or_default();
    let sockets = parse_sockets(pid);
    let rss     = parse_status(pid).map(|s| vm_rss_kb(&s)).unwrap_or(0);
    ProcSnapshot {
        fd_count:    fds.len(),
        fd_targets:  fds.into_iter().map(|f| f.target).collect(),
        socket_keys: sockets.into_iter()
            .map(|s| format!("{}  {}  →  {}  [{}]", s.protocol, s.local, s.remote, s.state))
            .collect(),
        vm_rss_kb: rss,
    }
}

fn show_diff(pid: u32, secs: u64) -> io::Result<()> {
    println!("\n{BOLD}{CYAN}Snapshotting PID {pid}…{RESET}");
    let before = take_snapshot(pid);
    println!("  {DIM}Watching for {secs}s — interact with the process now…{RESET}\n");
    thread::sleep(Duration::from_secs(secs));

    if parse_status(pid).is_err() {
        println!("{RED}Process {pid} exited during diff window.{RESET}");
        return Ok(());
    }
    let after = take_snapshot(pid);

    header(&format!("DIFF  PID {pid}  (Δ {secs}s)"));

    // FD diff
    let new_fds:    Vec<_> = after.fd_targets.difference(&before.fd_targets).collect();
    let closed_fds: Vec<_> = before.fd_targets.difference(&after.fd_targets).collect();
    if new_fds.is_empty() && closed_fds.is_empty() {
        row("File descriptors", &format!("{DIM}no change ({} open){RESET}", after.fd_count));
    } else {
        row("File descriptors", &format!("{} → {}", before.fd_count, after.fd_count));
        for f in &new_fds    { println!("  {DIM}│{RESET}      {GREEN}+{RESET}  {f}"); }
        for f in &closed_fds { println!("  {DIM}│{RESET}      {RED}-{RESET}  {f}"); }
    }

    // Socket diff
    let new_socks:    Vec<_> = after.socket_keys.difference(&before.socket_keys).collect();
    let closed_socks: Vec<_> = before.socket_keys.difference(&after.socket_keys).collect();
    if new_socks.is_empty() && closed_socks.is_empty() {
        row("Sockets", &format!("{DIM}no change{RESET}"));
    } else {
        row("Sockets", "");
        for s in &new_socks    { println!("  {DIM}│{RESET}      {GREEN}+{RESET}  {s}"); }
        for s in &closed_socks { println!("  {DIM}│{RESET}      {RED}-{RESET}  {s}"); }
    }

    // Memory delta
    let delta = after.vm_rss_kb - before.vm_rss_kb;
    let col = if delta > 1024 { RED } else if delta < -512 { GREEN } else { DIM };
    row("VmRSS delta",
        &format!("{} KB → {} KB  ({col}{:+} KB{RESET})",
            before.vm_rss_kb, after.vm_rss_kb, delta));

    divider();
    Ok(())
}

// ─── security audit ───────────────────────────────────────────────────────────

fn show_audit(pid: u32) -> io::Result<()> {
    let status = parse_status(pid)?;
    let mut crits: Vec<String> = Vec::new();
    let mut warns: Vec<String> = Vec::new();

    let uid: u32 = status_field(&status, "Uid")
        .split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
    let cap_eff = decode_caps(status_field(&status, "CapEff"));
    let seccomp = status_field(&status, "Seccomp");

    // 1. Dangerous capabilities
    const DANGER_CAPS: &[&str] = &[
        "CAP_SYS_ADMIN","CAP_SYS_PTRACE","CAP_SYS_MODULE","CAP_SYS_RAWIO",
        "CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_NET_ADMIN","CAP_NET_RAW",
        "CAP_SETUID","CAP_SETGID","CAP_CHOWN","CAP_FOWNER",
    ];
    for &cap in &cap_eff {
        if DANGER_CAPS.contains(&cap) {
            if uid != 0 {
                crits.push(format!("{cap} held by non-root UID {uid}"));
            } else {
                warns.push(format!("{cap} active on root process"));
            }
        }
    }

    // 2. No seccomp + has caps
    if seccomp == "0" && !cap_eff.is_empty() {
        warns.push("Seccomp disabled — capabilities are unrestricted by syscall filter".into());
    }

    // 3. RWX memory pages (possible shellcode injection)
    if let Ok(maps) = parse_maps(pid) {
        for m in maps.iter().filter(|m| {
            m.perms.contains('r') && m.perms.contains('w') && m.perms.contains('x')
        }) {
            crits.push(format!(
                "RWX page @ {} label={:?}  — writable+executable region, possible shellcode",
                m.start, m.label
            ));
        }
    }

    // 4. Executable location
    let exe = fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    for prefix in &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"] {
        if exe.starts_with(prefix) {
            crits.push(format!("Binary executing from suspicious path: {exe}"));
        }
    }
    if exe.ends_with(" (deleted)") {
        crits.push(format!("On-disk binary has been deleted: {exe}"));
    }

    // 5. memfd (fileless execution)
    if let Ok(fds) = parse_fds(pid) {
        for fd in &fds {
            if fd.target.contains("memfd:") {
                crits.push(format!(
                    "memfd fd={} → {}  — anonymous in-memory executable (fileless malware pattern)",
                    fd.fd, fd.target
                ));
            }
        }
        if fds.len() > 500 {
            warns.push(format!("{} open file descriptors — abnormally high (FD leak?)", fds.len()));
        }
    }

    // 6. Established outbound connections
    let sockets = parse_sockets(pid);
    for s in &sockets {
        if s.state == "ESTABLISHED"
            && !s.remote.starts_with("127.")
            && !s.remote.starts_with("0.0.0.0")
        {
            warns.push(format!(
                "Outbound {}  {}  →  {}",
                s.protocol, s.local, s.remote
            ));
        }
    }

    // 7. Container namespace isolation check
    let nss = parse_namespaces(pid);
    let isolated_ns: Vec<_> = nss.iter().filter(|n| n.isolated).map(|n| n.kind.as_str()).collect();
    if !isolated_ns.is_empty() {
        warns.push(format!(
            "Process is in isolated namespaces: {}  — likely containerised",
            isolated_ns.join(", ")
        ));
    }

    // ── display ──────────────────────────────────────────────────────────────
    println!("\n{BOLD}{CYAN}Security Audit — PID {pid}  ({}){RESET}\n",
        status_field(&status, "Name"));

    let seccomp_label = match seccomp {
        "0" => format!("{RED}disabled{RESET}"),
        "1" => format!("{YELLOW}strict{RESET}"),
        "2" => format!("{GREEN}BPF filter{RESET}"),
        s   => s.to_string(),
    };
    println!("  Seccomp: {seccomp_label}    UID: {BOLD}{uid}{RESET}    Binary: {DIM}{exe}{RESET}\n");

    if crits.is_empty() && warns.is_empty() {
        println!("  {GREEN}✓  No anomalies detected{RESET}\n");
        return Ok(());
    }

    println!("  {RED}{} critical{RESET}   {YELLOW}{} warnings{RESET}\n",
        crits.len(), warns.len());

    for msg in &crits {
        println!("  {RED}[CRIT]{RESET}  {msg}");
    }
    for msg in &warns {
        println!("  {YELLOW}[WARN]{RESET}  {msg}");
    }
    println!();
    Ok(())
}

// ─── ptrace syscall tracer ────────────────────────────────────────────────────

fn trace_syscalls(pid: u32) -> io::Result<()> {
    use libc::*;
    let lpid = pid as pid_t;

    unsafe {
        if ptrace(PTRACE_ATTACH, lpid,
            std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>()) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut status: c_int = 0;
        waitpid(lpid, &mut status, 0);

        ptrace(PTRACE_SETOPTIONS, lpid,
            std::ptr::null_mut::<c_void>(),
            PTRACE_O_TRACESYSGOOD as *mut c_void);

        println!("{BOLD}{CYAN}Tracing PID {pid}{RESET}  (Ctrl-C to stop)\n");
        let mut in_syscall = false;

        loop {
            ptrace(PTRACE_SYSCALL, lpid,
                std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
            waitpid(lpid, &mut status, 0);

            if WIFEXITED(status) || WIFSIGNALED(status) {
                println!("\n{DIM}process exited{RESET}");
                break;
            }

            if WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP | 0x80 {
                let mut regs: user_regs_struct = std::mem::zeroed();
                ptrace(PTRACE_GETREGS, lpid,
                    std::ptr::null_mut::<c_void>(),
                    &mut regs as *mut _ as *mut c_void);

                if !in_syscall {
                    let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
                    let last = args.iter().rposition(|&a| a != 0).map(|i| i + 1).unwrap_or(0);
                    print!("{CYAN}{}{RESET}(", syscall_name(regs.orig_rax));
                    for (i, &a) in args[..last].iter().enumerate() {
                        if i > 0 { print!(", "); }
                        print!("{:#x}", a);
                    }
                    print!(")");
                    io::stdout().flush().ok();
                } else {
                    let ret = regs.rax as i64;
                    if ret < 0 { println!(" = {RED}{ret}{RESET}"); }
                    else       { println!(" = {GREEN}{ret:#x}{RESET}"); }
                }
                in_syscall = !in_syscall;
            }
        }

        ptrace(PTRACE_DETACH, lpid,
            std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
    }
    Ok(())
}

// ─── process tree ─────────────────────────────────────────────────────────────

fn print_tree_node(
    pid: u32,
    info: &HashMap<u32, (String, u32)>,
    children: &HashMap<u32, Vec<u32>>,
    prefix: &str,
    is_last: bool,
) {
    let conn = if is_last { "└─" } else { "├─" };
    let name = info.get(&pid).map(|(n,_)| n.as_str()).unwrap_or("?");
    println!("{prefix}{DIM}{conn}{RESET} {BOLD}{CYAN}{pid}{RESET} {name}");
    let next = format!("{}{}", prefix, if is_last { "  " } else { "│ " });
    if let Some(kids) = children.get(&pid) {
        for (i, &child) in kids.iter().enumerate() {
            print_tree_node(child, info, children, &next, i == kids.len() - 1);
        }
    }
}

fn show_tree() {
    let mut info: HashMap<u32, (String, u32)> = HashMap::new();
    for pid in all_pids() {
        if let Ok(status) = parse_status(pid) {
            let name = status_field(&status, "Name").to_string();
            let ppid: u32 = status_field(&status, "PPid").parse().unwrap_or(0);
            info.insert(pid, (name, ppid));
        }
    }
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut roots = Vec::new();
    for (&pid, (_, ppid)) in &info {
        if *ppid == 0 || !info.contains_key(ppid) { roots.push(pid); }
        else { children.entry(*ppid).or_default().push(pid); }
    }
    for kids in children.values_mut() { kids.sort_unstable(); }
    roots.sort_unstable();
    println!("\n{BOLD}{CYAN}Process Tree{RESET}\n");
    for (i, &root) in roots.iter().enumerate() {
        print_tree_node(root, &info, &children, "", i == roots.len() - 1);
    }
}

// ─── display helpers ──────────────────────────────────────────────────────────

fn header(t: &str) { println!("\n{BOLD}{CYAN}┌─ {t}{RESET}"); }
fn row(l: &str, v: &str) { println!("  {DIM}│{RESET}  {BOLD}{l:<22}{RESET} {v}"); }
fn divider() { println!("  {DIM}└──────────────────────────────────────────{RESET}"); }

fn perm_colour(p: &str) -> String {
    let r = if p.contains('r') { format!("{GREEN}r{RESET}") } else { format!("{DIM}-{RESET}") };
    let w = if p.contains('w') { format!("{YELLOW}w{RESET}") } else { format!("{DIM}-{RESET}") };
    let x = if p.contains('x') { format!("{RED}x{RESET}") } else { format!("{DIM}-{RESET}") };
    format!("{r}{w}{x}{}", if p.contains('p') { "p" } else { "s" })
}

fn state_col(s: &str) -> String {
    match s.chars().next().unwrap_or(' ') {
        'R' => format!("{GREEN}{s}{RESET}"),
        'S' => format!("{DIM}{s}{RESET}"),
        'D' => format!("{RED}{s}{RESET}"),
        'Z' => format!("{MAGENTA}{s}{RESET}"),
        _   => s.to_string(),
    }
}

fn sock_col(s: &str) -> String {
    match s {
        "ESTABLISHED" => format!("{GREEN}{s}{RESET}"),
        "LISTEN"      => format!("{CYAN}{s}{RESET}"),
        "TIME_WAIT"   => format!("{YELLOW}{s}{RESET}"),
        _             => format!("{DIM}{s}{RESET}"),
    }
}

fn fd_kind_col(kind: &str) -> String {
    match kind {
        "socket" => format!("{RED}socket{RESET}"),
        "pipe"   => format!("{YELLOW}pipe{RESET}  "),
        "file"   => format!("{GREEN}file{RESET}  "),
        _        => format!("{DIM}other{RESET} "),
    }
}

// ─── modes ────────────────────────────────────────────────────────────────────

fn inspect(pid: u32) -> io::Result<()> {
    let status = parse_status(pid)?;

    header("PROCESS OVERVIEW");
    row("Name",    status_field(&status, "Name"));
    row("PID",     &pid.to_string());
    row("State",   &state_col(status_field(&status, "State")));
    row("PPID",    status_field(&status, "PPid"));
    row("Threads", status_field(&status, "Threads"));
    row("UID",     status_field(&status, "Uid"));
    row("GID",     status_field(&status, "Gid"));
    divider();

    header("MEMORY (status)");
    row("VmRSS  (resident)", status_field(&status, "VmRSS"));
    row("VmSize (virtual)",  status_field(&status, "VmSize"));
    row("VmPeak",            status_field(&status, "VmPeak"));
    row("VmStk  (stack)",    status_field(&status, "VmStk"));
    row("VmData (heap+bss)", status_field(&status, "VmData"));
    divider();

    if let Ok(sm) = parse_smaps(pid) {
        header("MEMORY DETAIL (smaps)");
        row("Total mapped",  &format!("{} KB", sm.total_size_kb));
        row("PSS (actual)",  &format!("{} KB  \x1b[2m(proportional share of shared pages)\x1b[0m", sm.pss_kb));
        row("Private dirty", &format!("{} KB", sm.private_dirty_kb));
        row("Shared dirty",  &format!("{} KB", sm.shared_dirty_kb));
        row("Swap",          &format!("{} KB", sm.swap_kb));
        row("Regions",       &sm.regions.len().to_string());
        divider();
    }

    let cap_eff = decode_caps(status_field(&status, "CapEff"));
    let seccomp = match status_field(&status, "Seccomp") {
        "0" => format!("{DIM}disabled{RESET}"),
        "1" => format!("{YELLOW}strict{RESET}"),
        "2" => format!("{GREEN}BPF filter{RESET}"),
        s   => s.to_string(),
    };
    header("CAPABILITIES & SECURITY");
    row("Seccomp", &seccomp);
    if cap_eff.is_empty() {
        row("CapEff", &format!("{DIM}none{RESET}"));
    } else {
        for cap in &cap_eff { row("CapEff", &format!("{YELLOW}{cap}{RESET}")); }
    }
    divider();

    // Namespace summary inline
    let nss = parse_namespaces(pid);
    let isolated: Vec<_> = nss.iter().filter(|n| n.isolated).map(|n| n.kind.as_str()).collect();
    header("NAMESPACES");
    if isolated.is_empty() {
        row("Isolation", &format!("{DIM}host namespaces (not containerised){RESET}"));
    } else {
        row("Isolated ns", &format!("{YELLOW}{}{RESET}  {DIM}(use --ns for detail){RESET}",
            isolated.join(", ")));
    }
    divider();

    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default().replace('\0', " ");
    header("COMMAND LINE");
    println!("  {DIM}│{RESET}  {}", cmdline.trim());
    divider();

    if let Ok(fds) = parse_fds(pid) {
        header(&format!("FILE DESCRIPTORS  ({} open)", fds.len()));
        for fd in fds.iter().take(10) {
            println!("  {DIM}│{RESET}  {BOLD}{:>3}{RESET}  {}  {}", fd.fd, fd_kind_col(&fd.kind), fd.target);
        }
        if fds.len() > 10 { println!("  {DIM}│  ... {} more  (--fds){RESET}", fds.len() - 10); }
        divider();
    }

    let sockets = parse_sockets(pid);
    if !sockets.is_empty() {
        header(&format!("NETWORK SOCKETS  ({} connections)", sockets.len()));
        println!("  {DIM}│  {:<6} {:<8} {:<26} {:<26} state{RESET}", "fd", "proto", "local", "remote");
        for s in &sockets {
            let fd_s = s.fd.map(|f| f.to_string()).unwrap_or_else(|| "-".to_string());
            println!("  {DIM}│{RESET}  {:<6} {:<8} {:<26} {:<26} {}",
                fd_s, s.protocol, s.local, s.remote, sock_col(&s.state));
        }
        divider();
    }

    if let Ok(maps) = parse_maps(pid) {
        let total: u64 = maps.iter().map(|m| m.size_kb).sum();
        header(&format!("MEMORY MAP  ({} regions, {} KB total)", maps.len(), total));
        for m in maps.iter().take(14) {
            println!("  {DIM}│  {}{RESET}  {}  {YELLOW}{:>7} KB{RESET}  {}",
                m.start, perm_colour(&m.perms), m.size_kb, m.label);
        }
        if maps.len() > 14 { println!("  {DIM}│  ... {} more  (--maps){RESET}", maps.len() - 14); }
        divider();
    }

    Ok(())
}

fn show_fds(pid: u32) -> io::Result<()> {
    let fds = parse_fds(pid)?;
    println!("\n{BOLD}{CYAN}File descriptors — PID {pid}  ({} open){RESET}\n", fds.len());
    for fd in &fds {
        println!("  {BOLD}{:>3}{RESET}  {}  {}", fd.fd, fd_kind_col(&fd.kind), fd.target);
    }
    Ok(())
}

fn show_maps(pid: u32) -> io::Result<()> {
    let maps = parse_maps(pid)?;
    let total: u64 = maps.iter().map(|m| m.size_kb).sum();
    println!("\n{BOLD}{CYAN}Memory map — PID {pid}  ({} regions, {} KB){RESET}\n", maps.len(), total);
    println!("{DIM}  {:<18} {:<6} {:<10}  label{RESET}", "address", "perms", "size");
    for m in &maps {
        println!("  {DIM}{}{RESET}  {}  {YELLOW}{:>7} KB{RESET}  {}", m.start, perm_colour(&m.perms), m.size_kb, m.label);
    }
    Ok(())
}

fn show_smaps(pid: u32) -> io::Result<()> {
    let s = parse_smaps(pid)?;
    println!("\n{BOLD}{CYAN}smaps — PID {pid}{RESET}\n");
    println!("  Total mapped   {} KB", s.total_size_kb);
    println!("  PSS            {} KB  {DIM}(actual cost — proportional share of shared pages){RESET}", s.pss_kb);
    println!("  Private dirty  {} KB", s.private_dirty_kb);
    println!("  Shared dirty   {} KB", s.shared_dirty_kb);
    println!("  Shared clean   {} KB", s.shared_clean_kb);
    println!("  Swap           {} KB\n", s.swap_kb);
    println!("{DIM}  {:<42} {:<6} {:>8} {:>8} {:>9} {:>8}{RESET}",
        "region", "perms", "size KB", "pss KB", "prv-drt", "swap KB");
    for r in &s.regions {
        let label = if r.label.len() > 40 { &r.label[r.label.len()-40..] } else { &r.label };
        println!("  {:<42} {:<6} {:>8} {:>8} {:>9} {:>8}",
            label, r.perms, r.size_kb, r.pss_kb, r.private_dirty_kb, r.swap_kb);
    }
    Ok(())
}

fn show_sockets(pid: u32) -> io::Result<()> {
    let sockets = parse_sockets(pid);
    println!("\n{BOLD}{CYAN}Network sockets — PID {pid}  ({} entries){RESET}\n", sockets.len());
    println!("{DIM}  {:<6} {:<8} {:<26} {:<26} {:<14} inode{RESET}",
        "fd", "proto", "local", "remote", "state");
    for s in &sockets {
        let fd_s = s.fd.map(|f| f.to_string()).unwrap_or_else(|| "-".to_string());
        // fixed: was printing s.state raw (no colour)
        println!("  {:<6} {:<8} {:<26} {:<26} {:<14} {}",
            fd_s, s.protocol, s.local, s.remote, sock_col(&s.state), s.inode);
    }
    Ok(())
}

fn show_caps(pid: u32) -> io::Result<()> {
    let status = parse_status(pid)?;
    println!("\n{BOLD}{CYAN}Capabilities — PID {pid}  ({}){RESET}\n", status_field(&status, "Name"));
    let seccomp = match status_field(&status, "Seccomp") {
        "0" => format!("{DIM}disabled{RESET}"),
        "1" => format!("{YELLOW}strict{RESET}"),
        "2" => format!("{GREEN}BPF filter{RESET}"),
        s   => s.to_string(),
    };
    println!("  Seccomp: {seccomp}\n");
    for (field, label) in &[("CapEff","Effective"),("CapPrm","Permitted"),("CapInh","Inheritable"),("CapBnd","Bounding")] {
        let caps = decode_caps(status_field(&status, field));
        print!("  {BOLD}{label:<14}{RESET}");
        if caps.is_empty() { println!("{DIM}none{RESET}"); }
        else { println!(); for c in &caps { println!("    {YELLOW}{c}{RESET}"); } }
    }
    Ok(())
}

fn list_procs() -> io::Result<()> {
    println!("\n{BOLD}{CYAN}Running processes{RESET}\n");
    println!("{DIM}  {:>6}  {:>6}  {:<10}  name{RESET}", "PID", "PPID", "State");
    for pid in all_pids() {
        if let Ok(status) = parse_status(pid) {
            println!("  {BOLD}{:>6}{RESET}  {:>6}  {}  {}",
                pid, status_field(&status, "PPid"),
                state_col(status_field(&status, "State")),
                status_field(&status, "Name"));
        }
    }
    Ok(())
}

fn watch(pid: u32) -> io::Result<()> {
    loop {
        print!("\x1b[2J\x1b[H");
        io::stdout().flush()?;
        println!("{BOLD}{CYAN}procsnoop --watch {pid}{RESET}  (Ctrl-C to exit)\n");
        match parse_status(pid) {
            Ok(status) => {
                row("Name",    status_field(&status, "Name"));
                row("State",   &state_col(status_field(&status, "State")));
                row("VmRSS",   status_field(&status, "VmRSS"));
                row("VmSize",  status_field(&status, "VmSize"));
                row("Threads", status_field(&status, "Threads"));
                if let Ok(fds) = parse_fds(pid) { row("Open FDs", &fds.len().to_string()); }
                row("Sockets", &parse_sockets(pid).len().to_string());
            }
            Err(_) => { println!("{RED}Process {pid} exited.{RESET}"); break; }
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn show_json(pid: u32) -> io::Result<()> {
    let status = parse_status(pid)?;
    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default().replace('\0', " ");
    let info = ProcessInfo {
        pid,
        name:           status_field(&status, "Name").to_string(),
        state:          status_field(&status, "State").to_string(),
        ppid:           status_field(&status, "PPid").to_string(),
        threads:        status_field(&status, "Threads").to_string(),
        uid:            status_field(&status, "Uid").to_string(),
        vm_rss:         status_field(&status, "VmRSS").to_string(),
        vm_size:        status_field(&status, "VmSize").to_string(),
        seccomp:        status_field(&status, "Seccomp").to_string(),
        caps_effective: decode_caps(status_field(&status, "CapEff")),
        caps_permitted: decode_caps(status_field(&status, "CapPrm")),
        cmdline:        cmdline.trim().to_string(),
        fds:            parse_fds(pid).unwrap_or_default(),
        maps:           parse_maps(pid).unwrap_or_default(),
        sockets:        parse_sockets(pid),
        smaps:          parse_smaps(pid).unwrap_or_default(),
        namespaces:     parse_namespaces(pid),
        cgroup:         parse_cgroup(pid),
    };
    println!("{}", serde_json::to_string_pretty(&info)?);
    Ok(())
}

// ─── cli ──────────────────────────────────────────────────────────────────────

fn usage() {
    eprintln!("\n{BOLD}procsnoop{RESET} v0.3.0 — Linux /proc + ptrace inspector\n");
    eprintln!("Usage:");
    eprintln!("  procsnoop <pid>                  Full inspection");
    eprintln!("  procsnoop --list                 List all processes");
    eprintln!("  procsnoop --tree                 Process tree");
    eprintln!("  procsnoop --watch   <pid>        Live refresh every second");
    eprintln!("  procsnoop --fds     <pid>        Open file descriptors");
    eprintln!("  procsnoop --maps    <pid>        Memory map");
    eprintln!("  procsnoop --smaps   <pid>        Detailed memory (PSS, swap, dirty pages)");
    eprintln!("  procsnoop --sockets <pid>        Network connections");
    eprintln!("  procsnoop --caps    <pid>        Capabilities & seccomp");
    eprintln!("  procsnoop --trace   <pid>        Syscall trace (like strace)");
    eprintln!("  procsnoop --ns      <pid>        Namespaces + container runtime detection");
    eprintln!("  procsnoop --diff    <pid> [sec]  State delta over N seconds (default 5)");
    eprintln!("  procsnoop --audit   <pid>        Security anomaly detection");
    eprintln!("  procsnoop --json    <pid>        Full JSON output\n");
}

fn pid_arg(args: &[String]) -> u32 {
    args.get(2).and_then(|s| s.parse().ok()).unwrap_or_else(|| { usage(); std::process::exit(1); })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--list")    => list_procs(),
        Some("--tree")    => { show_tree(); Ok(()) }
        Some("--watch")   => watch(pid_arg(&args)),
        Some("--fds")     => show_fds(pid_arg(&args)),
        Some("--maps")    => show_maps(pid_arg(&args)),
        Some("--smaps")   => show_smaps(pid_arg(&args)),
        Some("--sockets") => show_sockets(pid_arg(&args)),
        Some("--caps")    => show_caps(pid_arg(&args)),
        Some("--trace")   => trace_syscalls(pid_arg(&args)),
        Some("--ns")      => show_ns(pid_arg(&args)),
        Some("--audit")   => show_audit(pid_arg(&args)),
        Some("--diff")    => {
            let pid  = pid_arg(&args);
            let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            show_diff(pid, secs)
        }
        Some("--json")    => show_json(pid_arg(&args)),
        Some(s) if s.parse::<u32>().is_ok() => inspect(s.parse().unwrap()),
        _ => { usage(); std::process::exit(1); }
    };
    if let Err(e) = result {
        eprintln!("{RED}Error: {e}{RESET}");
        std::process::exit(1);
    }
}
