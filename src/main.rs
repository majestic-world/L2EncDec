//! Drag-and-drop toggle for Lineage II client files: every file passed on the
//! command line is decrypted if encrypted, encrypted if plain, in place.

mod codec;
mod rsa413;
mod term;
mod xor;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use codec::Operation;
use term::{Painter, Style};

const TITLE: &str = "L2 Encoder/Decoder";
const TAGLINE: &str = "By Mk (Majestic World Studio)";
const FORMATS: &str =
    "  bmp, dat, htm, ini, int, ogg, u, uax,\n  ugx, uix, ukx, unr, usk, usx, utx, xdat";
/// Width of the longest operation label (`decrypt 121`, `encrypt OGG`, ...).
const LABEL_WIDTH: usize = 11;
/// File names longer than this overflow their column instead of widening it.
const MAX_NAME_WIDTH: usize = 40;

fn main() -> ExitCode {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let painter = Painter::detect();
    println!(
        "{} {}",
        painter.paint(Style::Title, TITLE),
        painter.paint(Style::Muted, TAGLINE)
    );
    println!();

    if paths.is_empty() {
        println!(
            "{} drag & drop files onto L2Enc.exe, or run: L2Enc <file>...",
            painter.paint(Style::Strong, "Usage:")
        );
        println!(
            "{}",
            painter.paint(Style::Strong, "Supported file formats:")
        );
        println!("{FORMATS}");
        term::pause_if_owned_console(&painter);
        return ExitCode::SUCCESS;
    }

    let width = paths
        .iter()
        .map(|path| display_name(path).chars().count())
        .max()
        .unwrap_or(0)
        .min(MAX_NAME_WIDTH);
    let total = paths.len();
    let ok = paths
        .iter()
        .filter(|path| process(path, width, &painter))
        .count();

    let summary_style = match ok {
        _ if ok == total => Style::Success,
        0 => Style::Failure,
        _ => Style::Warning,
    };
    println!();
    println!(
        "{}",
        painter.paint(
            summary_style,
            &format!("Successfully processed {ok} / {total} files.")
        )
    );
    term::pause_if_owned_console(&painter);
    if ok == total {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.to_string_lossy(), OsStr::to_string_lossy)
        .into_owned()
}

/// Why a file could not be toggled, with the operation if one was chosen.
struct Failure {
    operation: Option<Operation>,
    reason: String,
}

impl Failure {
    fn new(operation: Option<Operation>, reason: impl ToString) -> Self {
        Self {
            operation,
            reason: reason.to_string(),
        }
    }
}

/// Toggles one file and prints its result row; returns whether it succeeded.
fn process(path: &Path, width: usize, painter: &Painter) -> bool {
    // The name goes out first so a slow 413 file shows what is being worked on.
    print!(
        "  {:<width$}  ",
        painter.paint(Style::Strong, &display_name(path))
    );
    let _ = io::stdout().flush();

    let result = toggle(path);
    let operation = match &result {
        Ok(operation) => Some(*operation),
        Err(failure) => failure.operation,
    };
    let (label, label_style) = match operation {
        Some(operation) if operation.is_encrypt() => (operation.label(), Style::Encrypt),
        Some(operation) => (operation.label(), Style::Decrypt),
        None => ("", Style::Muted),
    };
    print!("{:<LABEL_WIDTH$}  ", painter.paint(label_style, label));
    match result {
        Ok(_) => {
            println!("{}", painter.paint(Style::Success, "[success]"));
            true
        }
        Err(failure) => {
            println!(
                "{} {}",
                painter.paint(Style::Failure, "[fail]"),
                failure.reason
            );
            false
        }
    }
}

fn toggle(path: &Path) -> Result<Operation, Failure> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::new(None, "file name is not valid Unicode"))?;
    let data = fs::read(path).map_err(|error| Failure::new(None, error))?;
    let (operation, out) =
        codec::transform(name, &data).map_err(|error| Failure::new(None, error))?;
    write_replacing(path, &out).map_err(|error| Failure::new(Some(operation), error))?;
    Ok(operation)
}

/// Writes `bytes` to a sibling temp file, then renames it over `path`, so a
/// crash never leaves a half-written file behind.
fn write_replacing(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temp_name = path.file_name().map(OsString::from).unwrap_or_default();
    temp_name.push(".l2enc-tmp");
    let temp = path.with_file_name(temp_name);
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path).inspect_err(|_| {
        let _ = fs::remove_file(&temp);
    })
}
