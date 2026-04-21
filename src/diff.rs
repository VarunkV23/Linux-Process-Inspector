use std::collections::HashSet;
use std::io;
use std::thread;
use std::time::Duration;
use crate::color::*;
use crate::display::*;
use crate::proc::*;

pub struct ProcSnapshot {
    fd_targets: HashSet<String>,
    socket_keys: HashSet<String>,
    fd_count: usize,
    vm_rss_kb: i64,
}

pub fn vm_rss_kb(status: &[(String, String)]) -> i64 {
    status_field(status, "VmRSS")
        .split_whitespace().next().unwrap_or("0")
        .parse().unwrap_or(0)
}

pub fn take_snapshot(pid: u32) -> ProcSnapshot {
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

pub fn show_diff(pid: u32, secs: u64) -> io::Result<()> {
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