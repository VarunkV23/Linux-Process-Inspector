pub fn syscall_name(nr: u64) -> String {
    let s = match nr {
        0=>"read", 1=>"write", 2=>"open", 3=>"close", 4=>"stat",
        5=>"fstat", 6=>"lstat", 7=>"poll", 8=>"lseek", 9=>"mmap",
        10=>"mprotect", 11=>"munmap", 12=>"brk", 13=>"rt_sigaction",
        14=>"rt_sigprocmask", 15=>"rt_sigreturn", 16=>"ioctl",
        17=>"pread64", 18=>"pwrite64",
        19=>"readv", 20=>"writev", 21=>"access", 22=>"pipe", 23=>"select",
        24=>"sched_yield", 25=>"mremap", 26=>"msync", 27=>"mincore",
        28=>"madvise", 29=>"shmget", 30=>"shmat", 31=>"shmctl",
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
        425=>"io_uring_setup", 426=>"io_uring_enter", 427=>"io_uring_register",
        434=>"pidfd_open", 437=>"openat2", 438=>"pidfd_getfd",
        439=>"faccessat2", 440=>"process_madvise", 441=>"epoll_pwait2",
        442=>"mount_setattr",
        _ => return format!("syscall_{}", nr),
    };
    s.to_string()
}

pub const CAP_NAMES: &[&str] = &[
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

pub fn decode_caps(hex: &str) -> Vec<&'static str> {
    let val = u64::from_str_radix(hex.trim(), 16).unwrap_or(0);
    CAP_NAMES.iter().enumerate()
        .filter(|(i, _)| val & (1u64 << i) != 0)
        .map(|(_, &name)| name)
        .collect()
}

pub fn tcp_state(code: &str) -> &'static str {
    match code.trim() {
        "01"=>"ESTABLISHED","02"=>"SYN_SENT","03"=>"SYN_RECV",
        "04"=>"FIN_WAIT1","05"=>"FIN_WAIT2","06"=>"TIME_WAIT",
        "07"=>"CLOSE","08"=>"CLOSE_WAIT","09"=>"LAST_ACK",
        "0A"=>"LISTEN","0B"=>"CLOSING",_=>"UNKNOWN",
    }
}


pub fn parse_ipv4(hex: &str) -> String {
    let n = u32::from_str_radix(hex, 16).unwrap_or(0);
    format!("{}.{}.{}.{}", n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF)
}

/// Parse the 32-hex-char IPv6 address found in /proc/net/tcp6 and udp6.
/// The kernel stores four little-endian u32 words, so we reverse each word's
/// bytes before assembling the colon-hex representation.
pub fn parse_ipv6(hex: &str) -> String {
    if hex.len() != 32 {
        return hex.to_string();
    }
    let mut groups = [0u16; 8];
    for word_idx in 0..4 {
        let chunk = &hex[word_idx * 8 .. word_idx * 8 + 8];
        let word = u32::from_str_radix(chunk, 16).unwrap_or(0);
        // kernel stores in little-endian order → swap bytes
        let word = word.swap_bytes();
        groups[word_idx * 2]     = (word >> 16) as u16;
        groups[word_idx * 2 + 1] = (word & 0xFFFF) as u16;
    }
    // Detect ::ffff:a.b.c.d (IPv4-mapped)
    if groups[0..5] == [0, 0, 0, 0, 0] && groups[5] == 0xFFFF {
        let hi = groups[6];
        let lo = groups[7];
        return format!("::ffff:{}.{}.{}.{}",
            (hi >> 8) as u8, hi as u8,
            (lo >> 8) as u8, lo as u8);
    }
    // Find longest run of zeros for :: compression
    let (mut best_start, mut best_len, mut cur_start, mut cur_len) =
        (usize::MAX, 0usize, 0usize, 0usize);
    for i in 0..8 {
        if groups[i] == 0 {
            if cur_len == 0 { cur_start = i; }
            cur_len += 1;
            if cur_len > best_len { best_len = cur_len; best_start = cur_start; }
        } else {
            cur_len = 0;
        }
    }
    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if best_len > 1 && i == best_start {
            out.push_str(if i == 0 { "::" } else { ":" });
            i += best_len;
            if i < 8 { out.push(':'); }  // trailing colon absorbed below
            // actually rebuild correctly:
            out = rebuild_ipv6(&groups, best_start, best_len);
            return out;
        }
        if i > 0 { out.push(':'); }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    out
}

pub fn rebuild_ipv6(groups: &[u16; 8], skip_start: usize, skip_len: usize) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if i == skip_start {
            out.push_str(if i == 0 { "::" } else { ":" });
            i += skip_len;
            if i < 8 { out.push(':'); }
            // Now continue from i but we already pushed the separator
            // Re-do from i without the leading colon
            while i < 8 {
                out.push_str(&format!("{:x}", groups[i]));
                i += 1;
                if i < 8 { out.push(':'); }
            }
            return out;
        }
        if i > 0 { out.push(':'); }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    out
}