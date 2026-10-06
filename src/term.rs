//! Console presentation: ANSI colours (only when stdout is a terminal that
//! renders them) and the drag-and-drop exit pause.

use std::fmt;
use std::io::{self, IsTerminal};

#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleProcessList, GetStdHandle,
    STD_OUTPUT_HANDLE, SetConsoleMode,
};

#[derive(Debug, Clone, Copy)]
pub enum Style {
    Title,
    Muted,
    Strong,
    Decrypt,
    Encrypt,
    Success,
    Warning,
    Failure,
}

impl Style {
    /// SGR parameters understood by both Windows Terminal and conhost.
    fn sgr(self) -> &'static str {
        match self {
            Self::Title => "1;96",
            Self::Muted => "90",
            Self::Strong => "1;97",
            Self::Decrypt => "36",
            Self::Encrypt => "33",
            Self::Success => "1;92",
            Self::Warning => "1;93",
            Self::Failure => "1;91",
        }
    }
}

pub struct Painter {
    enabled: bool,
}

impl Painter {
    /// Enables colours when stdout is a terminal able to render them.
    pub fn detect() -> Self {
        Self {
            enabled: io::stdout().is_terminal() && enable_ansi(),
        }
    }

    pub fn paint<'a>(&self, style: Style, text: &'a str) -> Painted<'a> {
        Painted {
            style: self.enabled.then_some(style),
            text,
        }
    }
}

/// Styled text. Width and alignment flags apply to the visible text only.
pub struct Painted<'a> {
    style: Option<Style>,
    text: &'a str,
}

impl fmt::Display for Painted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(style) = self.style else {
            return f.pad(self.text);
        };
        write!(f, "\x1b[{}m", style.sgr())?;
        f.pad(self.text)?;
        f.write_str("\x1b[0m")
    }
}

#[cfg(windows)]
fn enable_ansi() -> bool {
    // SAFETY: `GetStdHandle` has no preconditions; `mode` is a valid out
    // pointer for `GetConsoleMode`, and `SetConsoleMode` only receives the
    // handle just queried.
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi() -> bool {
    true
}

/// Waits for Enter when this process is the only one attached to its console,
/// i.e. it was started by drag-and-drop or double-click and the window would
/// otherwise close immediately. Never blocks inside a terminal or script.
pub fn pause_if_owned_console(painter: &Painter) {
    #[cfg(windows)]
    {
        let mut processes = [0u32; 2];
        // SAFETY: `processes` is a valid, writable buffer of 2 entries and the
        // count passed matches its length.
        let attached = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), 2) };
        if attached == 1 {
            println!();
            println!("{}", painter.paint(Style::Muted, "Press Enter to exit..."));
            let _ = io::stdin().read_line(&mut String::new());
        }
    }
    #[cfg(not(windows))]
    let _ = painter;
}
