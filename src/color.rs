use std::sync::OnceLock;

pub static IS_TTY: OnceLock<bool> = OnceLock::new();

/// Wrapper whose Display implementation emits the escape sequence only when
/// stdout is a real terminal.
#[derive(Copy, Clone)]
pub struct Ansi(&'static str);

impl std::fmt::Display for Ansi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if IS_TTY.get().copied().unwrap_or(false) {
            f.write_str(self.0)
        } else {
            Ok(())
        }
    }
}

pub static RESET:   Ansi = Ansi("\x1b[0m");
pub static BOLD:    Ansi = Ansi("\x1b[1m");
pub static CYAN:    Ansi = Ansi("\x1b[36m");
pub static GREEN:   Ansi = Ansi("\x1b[32m");
pub static YELLOW:  Ansi = Ansi("\x1b[33m");
pub static RED:     Ansi = Ansi("\x1b[31m");
pub static DIM:     Ansi = Ansi("\x1b[2m");
pub static MAGENTA: Ansi = Ansi("\x1b[35m");