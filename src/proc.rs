use std::collections::HashMap;
use std::fs;
use std::io;
use crate::types::*;
use crate::util::{parse_ipv4, parse_ipv6, tcp_state};

pub fn read_proc(pid: u32, file: &str) -> io::Result<String> {
    fs::read_to_string(format!("/proc/{}/{}", pid, file))
}

pub fn parse_status(pid: u32) -> io::Result<Vec<(String, String)>> {
    let raw = read_proc(pid, "status")?;
    Ok(raw.lines().filter_map(|l| {
        let mut p = l.splitn(2, ':');
        Some((p.next()?.trim().to_string(), p.next()?.trim().to_string()))
    }).collect())
}

pub fn status_field<'a>(status: &'a [(String, String)], key: &str) -> &'a str {
    status.iter().find(|(k,_)| k == key).map(|(_,v)| v.as_str()).unwrap_or("?")
}

pub fn parse_fds(pid: u32) -> io::Result<Vec<FdInfo>> {
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

pub fn parse_maps(pid: u32) -> io::Result<Vec<MapInfo>> {
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

pub fn parse_smaps(pid: u32) -> io::Result<SmapsSummary> {
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
        if line.starts_with(|c: char| c.is_ascii_hexdigit()) && {
            // Address-range lines look like "7f3a00000000-7f3a10000000 ...".
            // Confirm the '-' comes before the first space (if any).
            let before_space = line.split(' ').next().unwrap_or("");
            before_space.contains('-')
        } {
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

pub fn socket_inodes(pid: u32) -> HashMap<u64, u32> {
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

pub fn parse_net_proto(pid: u32, proto: &str) -> Vec<(String, String, String, u64)> {
    let raw = fs::read_to_string(format!("/proc/{}/net/{}", pid, proto)).unwrap_or_default();
    let is_v6 = proto.ends_with('6');
    raw.lines().skip(1).filter_map(|line| {
        let c: Vec<&str> = line.split_whitespace().collect();
        if c.len() < 10 { return None; }
        let lp: Vec<&str> = c[1].splitn(2, ':').collect();
        let rp: Vec<&str> = c[2].splitn(2, ':').collect();
        if lp.len() < 2 || rp.len() < 2 { return None; }
        let parse_addr = |hex: &str| if is_v6 { parse_ipv6(hex) } else { parse_ipv4(hex) };
        let local  = format!("{}:{}", parse_addr(lp[0]), u16::from_str_radix(lp[1], 16).unwrap_or(0));
        let remote = format!("{}:{}", parse_addr(rp[0]), u16::from_str_radix(rp[1], 16).unwrap_or(0));
        let inode: u64 = c[9].parse().unwrap_or(0);
        Some((local, remote, tcp_state(c[3]).to_string(), inode))
    }).collect()
}

pub fn parse_sockets(pid: u32) -> Vec<SocketInfo> {
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

pub fn all_pids() -> Vec<u32> {
    let Ok(dir) = fs::read_dir("/proc") else { return Vec::new(); };
    let mut pids: Vec<u32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids
}

// namespace / container awareness 

pub fn ns_inode_from_link(s: &str) -> Option<u64> {
    // symlink target looks like "net:[4026531992]"
    s.split('[').nth(1)?.trim_end_matches(']').parse().ok()
}

pub fn parse_namespaces(pid: u32) -> Vec<NsInfo> {
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

pub fn parse_cgroup(pid: u32) -> Vec<String> {
    fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}