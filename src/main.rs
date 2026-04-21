use crate::audit::show_audit;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use serde::Serialize;

mod color;
mod types;
mod util;
mod proc;
mod display;
mod diff;
mod audit;
mod tracer;
mod commands;

use crate::color::*;
use crate::commands::*;
use crate::diff::show_diff;
use crate::tracer::trace_syscalls;

//  cli 

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

fn pid_arg(args: &[String]) -> Option<u32> {
    args.get(2).and_then(|s| s.parse().ok())
}

fn main() {
    // Fix 1: initialise the tty flag before any output so all Ansi statics
    // see the correct value on their first (and only) use.
    IS_TTY.get_or_init(|| unsafe { libc::isatty(1) != 0 });

    let args: Vec<String> = env::args().collect();

    // Helper closure: demand a PID argument or print usage and exit.
    let require_pid = || -> u32 {
        pid_arg(&args).unwrap_or_else(|| { usage(); std::process::exit(1); })
    };

    let result = match args.get(1).map(String::as_str) {
        Some("--list")    => list_procs(),
        Some("--tree")    => { show_tree(); Ok(()) }
        Some("--watch")   => watch(require_pid()),
        Some("--fds")     => show_fds(require_pid()),
        Some("--maps")    => show_maps(require_pid()),
        Some("--smaps")   => show_smaps(require_pid()),
        Some("--sockets") => show_sockets(require_pid()),
        Some("--caps")    => show_caps(require_pid()),
        Some("--trace")   => trace_syscalls(require_pid()),
        Some("--ns")      => show_ns(require_pid()),
        Some("--audit")   => show_audit(require_pid()),
        Some("--diff")    => {
            let pid  = require_pid();
            let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
            show_diff(pid, secs)
        }
        Some("--json")    => show_json(require_pid()),
        Some(s) if s.parse::<u32>().is_ok() => inspect(s.parse().unwrap()),
        _ => { usage(); std::process::exit(1); }
    };
    if let Err(e) = result {
        eprintln!("{RED}Error: {e}{RESET}");
        std::process::exit(1);
    }
}
