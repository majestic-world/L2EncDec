//! Drag-and-drop toggle for Lineage II client files: every file passed on the
//! command line is decrypted if encrypted, encrypted if plain, in place.

mod codec;
mod progress;
mod rsa413;
mod term;
mod xor;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use codec::Operation;
use progress::Progress;
use term::{Painter, Style};

const TITLE: &str = "L2 Encoder/Decoder";
const TAGLINE: &str = "By Mk (Majestic World Studio)";
const FORMATS: &str =
    "  bmp, dat, htm, ini, int, ogg, u, uax,\n  ugx, uix, ukx, unr, usk, usx, utx, xdat";
/// Width of the longest operation label (`decrypt 121`, `encrypt OGG`, ...).
const LABEL_WIDTH: usize = 11;
/// File names longer than this overflow their column instead of widening it.
const MAX_NAME_WIDTH: usize = 40;
/// Redraw interval of the progress bar.
const PROGRESS_TICK: Duration = Duration::from_millis(50);

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

/// Toggles one file and prints its result row; returns whether it succeeded.
fn process(path: &Path, width: usize, painter: &Painter) -> bool {
    let name_cell = format!(
        "  {:<width$}  ",
        painter.paint(Style::Strong, &display_name(path))
    );
    // The name goes out first so the user sees which file is being read.
    print!("{name_cell}");
    let _ = io::stdout().flush();

    let (operation, result) = match prepare(path) {
        Ok((name, data, operation)) => {
            let row = format!("{name_cell}{}", label_cell(painter, Some(operation)));
            let result = with_progress_bar(painter, &row, operation_style(operation), |progress| {
                convert(path, name, &data, operation, progress)
            });
            (Some(operation), result)
        }
        Err(reason) => (None, Err(reason)),
    };

    if painter.is_live() {
        print!("\r{name_cell}");
    }
    print!("{}", label_cell(painter, operation));
    let succeeded = result.is_ok();
    match result {
        Ok(()) => print!("{}", painter.paint(Style::Success, "[success]")),
        Err(reason) => print!("{} {reason}", painter.paint(Style::Failure, "[fail]")),
    }
    // Wipes what is left of a longer progress bar drawn on this row.
    let erase = if painter.is_live() {
        term::ERASE_LINE_END
    } else {
        ""
    };
    println!("{erase}");
    succeeded
}

fn operation_style(operation: Operation) -> Style {
    if operation.is_encrypt() {
        Style::Encrypt
    } else {
        Style::Decrypt
    }
}

/// The operation label padded to its column, or blank padding when none was chosen.
fn label_cell(painter: &Painter, operation: Option<Operation>) -> String {
    let (label, style) = operation.map_or(("", Style::Muted), |operation| {
        (operation.label(), operation_style(operation))
    });
    format!("{:<LABEL_WIDTH$}  ", painter.paint(style, label))
}

/// Runs `work`, redrawing `row` followed by a progress bar until it returns.
/// Without a live terminal the work simply runs.
fn with_progress_bar<T>(
    painter: &Painter,
    row: &str,
    style: Style,
    work: impl FnOnce(&Progress) -> T,
) -> T {
    let progress = Progress::new();
    if !painter.is_live() {
        return work(&progress);
    }
    let finished = AtomicBool::new(false);
    thread::scope(|scope| {
        let ticker = scope.spawn(|| {
            // Retrying the second RSA key restarts the count; never move backwards.
            let mut shown = 0.0_f64;
            while !finished.load(Ordering::Acquire) {
                shown = shown.max(progress.fraction());
                print!("\r{row}{}", painter.progress_bar(style, shown));
                let _ = io::stdout().flush();
                thread::park_timeout(PROGRESS_TICK);
            }
        });
        let result = work(&progress);
        finished.store(true, Ordering::Release);
        ticker.thread().unpark();
        result
    })
}

/// Reads the file and picks the operation that toggles it.
fn prepare(path: &Path) -> Result<(&str, Vec<u8>, Operation), String> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("file name is not valid Unicode")?;
    let data = fs::read(path).map_err(|error| error.to_string())?;
    let operation = codec::select(name, &data).map_err(|error| error.to_string())?;
    Ok((name, data, operation))
}

fn convert(
    path: &Path,
    name: &str,
    data: &[u8],
    operation: Operation,
    progress: &Progress,
) -> Result<(), String> {
    let out = codec::apply(operation, name, data, progress).map_err(|error| error.to_string())?;
    write_replacing(path, &out).map_err(|error| error.to_string())
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
