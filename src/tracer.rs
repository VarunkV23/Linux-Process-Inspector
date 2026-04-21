use std::collections::{HashMap, HashSet};
use std::io;
use std::thread;
use std::time::Duration;
use crate::color::*;
use crate::util::syscall_name;
use std::io::Write;



/// Atomic flag set by the signal handler to request a clean shutdown.
static STOP_TRACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

unsafe extern "C" fn trace_sighandler(_sig: libc::c_int) {
    STOP_TRACE.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn trace_syscalls(pid: u32) -> io::Result<()> {
    use libc::*;
    use std::sync::atomic::Ordering;

    let lpid = pid as pid_t;

    // Combined ptrace options: syscall-stop marker + follow threads/forks.
    let opts: c_int = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK;

    unsafe {
        // Install signal handlers so we always detach on Ctrl-C / SIGTERM.
        libc::signal(SIGINT,  trace_sighandler as sighandler_t);
        libc::signal(SIGTERM, trace_sighandler as sighandler_t);

        if ptrace(PTRACE_ATTACH, lpid,
            std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>()) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut status: c_int = 0;
        waitpid(lpid, &mut status, 0);

        ptrace(PTRACE_SETOPTIONS, lpid,
            std::ptr::null_mut::<c_void>(),
            opts as *mut c_void);

        println!("{BOLD}{CYAN}Tracing PID {pid}{RESET}  (Ctrl-C to stop)\n");

        // Track every pid we have attached to so we can detach all on exit.
        let mut traced: HashSet<pid_t> = HashSet::new();
        traced.insert(lpid);

        // per-pid: are we on the entry half of a syscall stop?
        let mut in_syscall: HashMap<pid_t, bool> = HashMap::new();
        in_syscall.insert(lpid, false);

        // Restart the root tracee.
        ptrace(PTRACE_SYSCALL, lpid,
            std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());

        loop {
            // Check for requested shutdown.
            if STOP_TRACE.load(Ordering::SeqCst) {
                for &tp in &traced {
                    ptrace(PTRACE_DETACH, tp,
                        std::ptr::null_mut::<c_void>(),
                        std::ptr::null_mut::<c_void>());
                }
                println!("\n{DIM}detached{RESET}");
                return Ok(());
            }

            // Wait for any traced process to stop.
            let stopped = waitpid(-1, &mut status, libc::WNOHANG);
            if stopped <= 0 {
                // No event ready; yield briefly to avoid busy-spinning.
                thread::sleep(Duration::from_micros(500));
                // Still send PTRACE_SYSCALL to all traced pids that are
                // currently running (best-effort; ignore errors).
                continue;
            }
            let cur: pid_t = stopped;

            if WIFEXITED(status) || WIFSIGNALED(status) {
                traced.remove(&cur);
                in_syscall.remove(&cur);
                if cur == lpid {
                    println!("\n{DIM}process exited{RESET}");
                    // Detach any remaining children.
                    for &tp in &traced {
                        ptrace(PTRACE_DETACH, tp,
                            std::ptr::null_mut::<c_void>(),
                            std::ptr::null_mut::<c_void>());
                    }
                    return Ok(());
                }
                // A thread/child exited — keep going.
                ptrace(PTRACE_SYSCALL, cur,
                    std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                continue;
            }

            if WIFSTOPPED(status) {
                let sig  = WSTOPSIG(status);
                let event = (status >> 16) & 0xff;

                // Handle clone/fork/vfork: attach to the new child.
                if event == PTRACE_EVENT_CLONE as i32
                    || event == PTRACE_EVENT_FORK as i32
                    || event == PTRACE_EVENT_VFORK as i32
                {
                    let mut new_pid_long: c_long = 0;
                    ptrace(PTRACE_GETEVENTMSG, cur,
                        std::ptr::null_mut::<c_void>(),
                        &mut new_pid_long as *mut c_long as *mut c_void);
                    let new_pid = new_pid_long as pid_t;
                    if new_pid > 0 && !traced.contains(&new_pid) {
                        // The new task may not have stopped yet; wait for it.
                        let mut ns: c_int = 0;
                        waitpid(new_pid, &mut ns, 0);
                        ptrace(PTRACE_SETOPTIONS, new_pid,
                            std::ptr::null_mut::<c_void>(),
                            opts as *mut c_void);
                        traced.insert(new_pid);
                        in_syscall.insert(new_pid, false);
                        ptrace(PTRACE_SYSCALL, new_pid,
                            std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                    }
                    // Resume the parent.
                    ptrace(PTRACE_SYSCALL, cur,
                        std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
                    continue;
                }

                // Syscall-stop: bit 7 of stopsig is set when TRACESYSGOOD is active.
                if sig == SIGTRAP | 0x80 {
                    let entry = in_syscall.entry(cur).or_insert(false);
                    let mut regs: user_regs_struct = std::mem::zeroed();
                    ptrace(PTRACE_GETREGS, cur,
                        std::ptr::null_mut::<c_void>(),
                        &mut regs as *mut _ as *mut c_void);

                    if !*entry {
                        // Syscall entry: print name + args.
                        let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
                        let last = args.iter().rposition(|&a| a != 0).map(|i| i + 1).unwrap_or(0);
                        if traced.len() > 1 {
                            print!("{DIM}[{cur}]{RESET} ");
                        }
                        print!("{CYAN}{}{RESET}(", syscall_name(regs.orig_rax));
                        for (i, &a) in args[..last].iter().enumerate() {
                            if i > 0 { print!(", "); }
                            print!("{:#x}", a);
                        }
                        print!(")");
                        io::stdout().flush().ok();
                    } else {
                        // Syscall exit: print return value.
                        let ret = regs.rax as i64;
                        if ret < 0 { println!(" = {RED}{ret}{RESET}"); }
                        else       { println!(" = {GREEN}{ret:#x}{RESET}"); }
                    }
                    *entry = !*entry;
                }
            }

            ptrace(PTRACE_SYSCALL, cur,
                std::ptr::null_mut::<c_void>(), std::ptr::null_mut::<c_void>());
        }
    }
}