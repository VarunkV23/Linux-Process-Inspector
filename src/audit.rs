use std::fs;
use std::io;
use crate::color::*;
use crate::proc::*;
use crate::util::decode_caps;

pub fn show_audit(pid: u32) -> io::Result<()> {
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
    let outbound: Vec<_> = sockets.iter().filter(|s| {
        s.state == "ESTABLISHED"
            && !s.remote.starts_with("127.")
            && !s.remote.starts_with("0.0.0.0")
    }).collect();
    if outbound.len() > 3 {
        warns.push(format!(
            "{} outbound ESTABLISHED connections (use --sockets for detail)",
            outbound.len()
        ));
    } else {
        for s in &outbound {
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

    //  display 
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