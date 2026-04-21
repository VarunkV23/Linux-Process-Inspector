use serde::Serialize;

#[derive(Serialize)]
pub struct ProcessInfo {
    pub pid: u32, pub name: String, pub state: String, pub ppid: String,
    pub threads: String, pub uid: String, pub vm_rss: String, pub vm_size: String,
    pub cmdline: String, pub seccomp: String,
    pub caps_effective: Vec<&'static str>,
    pub caps_permitted: Vec<&'static str>,
    pub fds: Vec<FdInfo>, pub maps: Vec<MapInfo>,
    pub sockets: Vec<SocketInfo>, pub smaps: SmapsSummary,
    pub namespaces: Vec<NsInfo>, pub cgroup: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct FdInfo { pub fd: u32, pub target: String, pub kind: String }

#[derive(Serialize, Debug)]
pub struct MapInfo { pub start: String, pub end: String, pub perms: String, pub size_kb: u64, pub label: String }

#[derive(Serialize, Debug, Default)]
pub struct SmapsSummary {
    pub total_size_kb: u64, pub pss_kb: u64, pub private_dirty_kb: u64,
    pub shared_dirty_kb: u64, pub shared_clean_kb: u64, pub swap_kb: u64,
    pub regions: Vec<SmapsRegion>,
}

#[derive(Serialize, Debug)]
pub struct SmapsRegion {
    pub label: String, pub perms: String,
    pub size_kb: u64, pub pss_kb: u64, pub private_dirty_kb: u64, pub swap_kb: u64,
}

#[derive(Serialize, Debug)]
pub struct SocketInfo {
    pub fd: Option<u32>, pub protocol: String,
    pub local: String, pub remote: String, pub state: String, pub inode: u64,
}

#[derive(Serialize, Debug)]
pub struct NsInfo { pub kind: String, pub inode: String, pub isolated: bool }