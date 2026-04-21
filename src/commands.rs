use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use crate::color::*;
use crate::display::*;
use crate::proc::*;
use crate::types::*;
use crate::util::decode_caps;

//  process tree 

pub fn print_tree_node(
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

pub fn show_tree() {
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

pub fn list_procs() -> io::Result<()> {
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

pub fn watch(pid: u32) -> io::Result<()> {
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

pub fn show_ns(pid: u32) -> io::Result<()> {
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

pub fn inspect(pid: u32) -> io::Result<()> {
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

pub fn show_fds(pid: u32) -> io::Result<()> {
    let fds = parse_fds(pid)?;
    println!("\n{BOLD}{CYAN}File descriptors — PID {pid}  ({} open){RESET}\n", fds.len());
    for fd in &fds {
        println!("  {BOLD}{:>3}{RESET}  {}  {}", fd.fd, fd_kind_col(&fd.kind), fd.target);
    }
    Ok(())
}

pub fn show_maps(pid: u32) -> io::Result<()> {
    let maps = parse_maps(pid)?;
    let total: u64 = maps.iter().map(|m| m.size_kb).sum();
    println!("\n{BOLD}{CYAN}Memory map — PID {pid}  ({} regions, {} KB){RESET}\n", maps.len(), total);
    println!("{DIM}  {:<18} {:<6} {:<10}  label{RESET}", "address", "perms", "size");
    for m in &maps {
        println!("  {DIM}{}{RESET}  {}  {YELLOW}{:>7} KB{RESET}  {}", m.start, perm_colour(&m.perms), m.size_kb, m.label);
    }
    Ok(())
}

pub fn show_smaps(pid: u32) -> io::Result<()> {
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

pub fn show_sockets(pid: u32) -> io::Result<()> {
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

pub fn show_caps(pid: u32) -> io::Result<()> {
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


pub fn show_json(pid: u32) -> io::Result<()> {
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

