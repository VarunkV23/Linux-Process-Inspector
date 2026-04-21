use std::io::{self, Write};
use crate::color::*;

pub fn header(t: &str) { println!("\n{BOLD}{CYAN}┌─ {t}{RESET}"); }
pub fn row(l: &str, v: &str) { println!("  {DIM}│{RESET}  {BOLD}{l:<22}{RESET} {v}"); }
pub fn divider() { println!("  {DIM}└──────────────────────────────────────────{RESET}"); }

pub fn perm_colour(p: &str) -> String {
    let r = if p.contains('r') { format!("{GREEN}r{RESET}") } else { format!("{DIM}-{RESET}") };
    let w = if p.contains('w') { format!("{YELLOW}w{RESET}") } else { format!("{DIM}-{RESET}") };
    let x = if p.contains('x') { format!("{RED}x{RESET}") } else { format!("{DIM}-{RESET}") };
    format!("{r}{w}{x}{}", if p.contains('p') { "p" } else { "s" })
}

pub fn state_col(s: &str) -> String {
    match s.chars().next().unwrap_or(' ') {
        'R' => format!("{GREEN}{s}{RESET}"),
        'S' => format!("{DIM}{s}{RESET}"),
        'D' => format!("{RED}{s}{RESET}"),
        'Z' => format!("{MAGENTA}{s}{RESET}"),
        _   => s.to_string(),
    }
}

pub fn sock_col(s: &str) -> String {
    match s {
        "ESTABLISHED" => format!("{GREEN}{s}{RESET}"),
        "LISTEN"      => format!("{CYAN}{s}{RESET}"),
        "TIME_WAIT"   => format!("{YELLOW}{s}{RESET}"),
        _             => format!("{DIM}{s}{RESET}"),
    }
}

pub fn fd_kind_col(kind: &str) -> String {
    match kind {
        "socket" => format!("{RED}socket{RESET}"),
        "pipe"   => format!("{YELLOW}pipe{RESET}  "),
        "file"   => format!("{GREEN}file{RESET}  "),
        _        => format!("{DIM}other{RESET} "),
    }
}