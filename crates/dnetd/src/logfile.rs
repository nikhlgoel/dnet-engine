// SPDX-License-Identifier: GPL-3.0-or-later
//! T198 — the service's log file.
//!
//! A Windows service has no console, so everything the service said went nowhere: after a crash and a restart nothing
//! was left to read, and a person with a problem had only `dnetctl events`, which starts empty each time the service
//! does. This keeps what the service logs in a file the person can attach to a report.
//!
//! - **Where:** `%ProgramData%\DNet Engine\logs\dnetd.log`, in a directory only SYSTEM and Administrators can read
//!   (the same checks as the other private directories: a link or a directory someone else owns is refused).
//! - **How much:** it cannot grow without limit. When the file reaches [`DEFAULT_MAX_BYTES`] it is renamed to
//!   `dnetd.log.1` and a new one starts; older ones move up and the oldest is deleted. At most [`DEFAULT_KEEP`] old
//!   files are kept, so the whole thing stays under about 4 MB.
//! - **What is in it:** what the service already logs: what it did and why, errors, and the address of the server (the
//!   person's own). Never a credential (a test fails if a log statement names one) and never where the person goes on
//!   the network: the service does not know that, and a log of it is the thing this project refuses to make.
//! - **It never stops the service.** A directory that cannot be made, a file that cannot be written, a rename that
//!   fails: the service goes on, and the console gets what it always got.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The size at which the file is renamed and a new one started.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// How many old files are kept beside the current one.
pub const DEFAULT_KEEP: usize = 3;

/// The file name of the current log.
pub const FILE_NAME: &str = "dnetd.log";

/// A log file that rotates by size. Cheap to clone: every clone writes to the same file.
#[derive(Clone)]
pub struct RotatingLog {
    inner: std::sync::Arc<Mutex<State>>,
}

struct State {
    dir: PathBuf,
    max_bytes: u64,
    keep: usize,
    file: Option<File>,
    written: u64,
}

impl RotatingLog {
    /// Open (or start) the log in `dir`, which must already exist and be private. The current file is appended to.
    pub fn open(dir: &Path, max_bytes: u64, keep: usize) -> io::Result<Self> {
        let mut state = State {
            dir: dir.to_path_buf(),
            max_bytes: max_bytes.max(1),
            keep,
            file: None,
            written: 0,
        };
        state.start_current()?;
        Ok(Self {
            inner: std::sync::Arc::new(Mutex::new(state)),
        })
    }

    /// The path of the current file.
    #[cfg(test)]
    pub fn current_path(&self) -> PathBuf {
        let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        state.dir.join(FILE_NAME)
    }
}

impl State {
    fn path(&self, index: usize) -> PathBuf {
        if index == 0 {
            self.dir.join(FILE_NAME)
        } else {
            self.dir.join(format!("{FILE_NAME}.{index}"))
        }
    }

    /// Open the current file for appending and note how much is already in it. A link in its place is refused, not
    /// followed: the file is opened as itself (on Windows, without following a reparse point) and must be a regular
    /// file, so a planted link cannot make the service write somewhere else.
    fn start_current(&mut self) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(self.path(0))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the log file is not a regular file",
            ));
        }
        self.written = metadata.len();
        self.file = Some(file);
        Ok(())
    }

    /// Move the current file to `.1`, `.1` to `.2` and so on, delete what falls off the end, start a new current.
    /// Each step that fails is skipped: a log that cannot rotate keeps growing rather than losing the service.
    fn rotate(&mut self) {
        self.file = None; // closed, so it can be renamed
        let _ = fs::remove_file(self.path(self.keep));
        for index in (0..self.keep).rev() {
            let from = self.path(index);
            if from.exists() {
                let _ = fs::rename(&from, self.path(index + 1));
            }
        }
        if self.keep == 0 {
            let _ = fs::remove_file(self.path(0));
        }
        let _ = self.start_current();
        // The move can fail (another program holds the file open, or something is in the way). The size limit
        // still holds: a current file still over it is emptied rather than left to grow without bound.
        if self.written > self.max_bytes {
            self.file = None;
            let emptied = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(self.path(0));
            if emptied.is_ok() {
                let _ = self.start_current();
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.file.is_some()
            && self.written > 0
            && self.written + bytes.len() as u64 > self.max_bytes
        {
            self.rotate();
        }
        if self.file.is_none() {
            self.start_current()?;
        }
        let file = self.file.as_mut().expect("opened just above");
        file.write_all(bytes)?;
        self.written += bytes.len() as u64;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // A write error is reported as "written": the service must not fail, or log about failing to log, in a loop.
        let _ = state.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match state.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// What the logger writes to: the console when there is one, and the file when there is one. Neither failing stops the
/// other.
#[derive(Clone)]
pub struct Sink {
    file: Option<RotatingLog>,
}

impl Sink {
    pub fn new(file: Option<RotatingLog>) -> Self {
        Self { file }
    }
}

pub struct SinkWriter {
    file: Option<RotatingLog>,
}

/// What goes into the file: the event as it was written, except that a control character inside it (an escape
/// sequence, a carriage return, a newline that is not the one ending the event) is written as text. Whatever text
/// reaches a log line, one event stays one line and nothing in the file can move a terminal's cursor or forge a
/// second line when it is read.
pub fn neutralise(buf: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let last = buf.len().saturating_sub(1);
    let changes =
        |i: usize, b: u8| (b < 0x20 && b != b'\t' && !(b == b'\n' && i == last)) || b == 0x7f;
    if !buf.iter().enumerate().any(|(i, &b)| changes(i, b)) {
        return std::borrow::Cow::Borrowed(buf);
    }
    let mut out = Vec::with_capacity(buf.len() + 8);
    for (i, &b) in buf.iter().enumerate() {
        if changes(i, b) {
            out.extend_from_slice(format!("\\x{b:02x}").as_bytes());
        } else {
            out.push(b);
        }
    }
    std::borrow::Cow::Owned(out)
}

impl Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = io::stdout().write_all(buf);
        if let Some(file) = self.file.as_mut() {
            let _ = file.write(&neutralise(buf));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = io::stdout().flush();
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = SinkWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter {
            file: self.file.clone(),
        }
    }
}

/// The directory the log lives in: `%ProgramData%\DNet Engine\logs`.
#[cfg_attr(not(windows), allow(dead_code))] // Windows builds the sink; the tests use a folder of their own.
pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("DNet Engine").join("logs")
}

/// The sink for the real service: the console, and the log file in its private directory if that can be made. Any
/// problem is returned as text for the console, never as an error.
#[cfg(windows)]
pub fn service_sink() -> (Sink, Option<String>) {
    let dir = default_dir();
    let opened = dnet_config::write::prepare_private_dir(&dir)
        .and_then(|()| RotatingLog::open(&dir, DEFAULT_MAX_BYTES, DEFAULT_KEEP));
    match opened {
        Ok(log) => (Sink::new(Some(log)), None),
        Err(error) => (
            Sink::new(None),
            Some(format!(
                "the log file in {} could not be set up ({error}); logging to the console only",
                dir.display()
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_in(dir: &Path, max: u64, keep: usize) -> RotatingLog {
        RotatingLog::open(dir, max, keep).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn what_is_written_is_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = log_in(dir.path(), 1000, 3);
        log.write_all(b"first line\n").unwrap();
        log.write_all(b"second line\n").unwrap();
        log.flush().unwrap();
        assert_eq!(
            fs::read_to_string(log.current_path()).unwrap(),
            "first line\nsecond line\n"
        );
    }

    /// A restart opens the same file and adds to it: what was said before the crash is still there.
    #[test]
    fn a_new_run_adds_to_the_file_it_found() {
        let dir = tempfile::tempdir().unwrap();
        log_in(dir.path(), 1000, 3)
            .write_all(b"before the crash\n")
            .unwrap();
        let mut again = log_in(dir.path(), 1000, 3);
        again.write_all(b"after the restart\n").unwrap();
        assert_eq!(
            fs::read_to_string(again.current_path()).unwrap(),
            "before the crash\nafter the restart\n"
        );
    }

    #[test]
    fn a_full_file_moves_aside_and_a_new_one_starts() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = log_in(dir.path(), 20, 3);
        log.write_all(b"0123456789\n").unwrap(); // 11 bytes
        log.write_all(b"abcdefghij\n").unwrap(); // would make 22 > 20: rotates first
        assert_eq!(names(dir.path()), ["dnetd.log", "dnetd.log.1"]);
        assert_eq!(
            fs::read_to_string(dir.path().join("dnetd.log.1")).unwrap(),
            "0123456789\n"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("dnetd.log")).unwrap(),
            "abcdefghij\n"
        );
    }

    /// The disk is never filled: however much is written, the number of files and their size stay bounded.
    #[test]
    fn however_much_is_logged_the_files_stay_few_and_small() {
        let dir = tempfile::tempdir().unwrap();
        let (max, keep) = (200u64, 3usize);
        let mut log = log_in(dir.path(), max, keep);
        for n in 0..2_000 {
            log.write_all(format!("line number {n:05}\n").as_bytes())
                .unwrap();
        }
        let all = names(dir.path());
        assert_eq!(all.len(), keep + 1, "{all:?}");
        for name in &all {
            let size = fs::metadata(dir.path().join(name)).unwrap().len();
            assert!(size <= max, "{name} is {size} bytes");
        }
        // The newest line is in the current file, and the oldest kept file holds older lines than the current one.
        let current = fs::read_to_string(dir.path().join("dnetd.log")).unwrap();
        assert!(current.contains("line number 01999"), "{current}");
        let oldest = fs::read_to_string(dir.path().join(format!("dnetd.log.{keep}"))).unwrap();
        assert!(oldest.lines().next().unwrap() < current.lines().next().unwrap());
    }

    #[test]
    fn a_single_line_longer_than_the_limit_is_still_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = log_in(dir.path(), 10, 2);
        let long = format!("{}\n", "x".repeat(100));
        log.write_all(long.as_bytes()).unwrap();
        assert_eq!(fs::read_to_string(log.current_path()).unwrap(), long);
    }

    #[test]
    fn keeping_nothing_old_still_works() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = log_in(dir.path(), 20, 0);
        for n in 0..10 {
            log.write_all(format!("line {n}\n").as_bytes()).unwrap();
        }
        assert_eq!(names(dir.path()), ["dnetd.log"]);
    }

    /// If the folder vanishes under a running service, writing says it worked and the service goes on.
    #[test]
    fn a_log_that_cannot_be_written_does_not_fail_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs");
        fs::create_dir(&path).unwrap();
        let mut log = log_in(&path, 20, 2);
        log.write_all(b"one\n").unwrap();
        drop(log.inner.lock().unwrap().file.take());
        fs::remove_dir_all(&path).unwrap();
        assert_eq!(log.write(b"two\n").unwrap(), 4);
        assert!(log.flush().is_ok());
    }

    #[test]
    fn opening_in_a_folder_that_is_not_there_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        assert!(RotatingLog::open(&dir.path().join("missing"), 100, 2).is_err());
    }

    #[test]
    fn the_sink_writes_to_the_file_and_never_fails() {
        use tracing_subscriber::fmt::MakeWriter;
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path(), 1000, 2);
        let sink = Sink::new(Some(log.clone()));
        let mut writer = sink.make_writer();
        assert_eq!(writer.write(b"from the sink\n").unwrap(), 14);
        writer.flush().unwrap();
        assert!(fs::read_to_string(log.current_path())
            .unwrap()
            .contains("from the sink"));
        // No file at all: still fine.
        assert_eq!(Sink::new(None).make_writer().write(b"x").unwrap(), 1);
    }

    /// If the move aside cannot be made (here: something that is not a file is where the first old file goes), the
    /// size limit still holds instead of the file growing.
    #[test]
    fn a_rotation_that_cannot_move_the_file_still_keeps_the_size_bounded() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("dnetd.log.1")).unwrap(); // a folder cannot be replaced by a file
        let (max, keep) = (200u64, 2usize);
        let mut log = log_in(dir.path(), max, keep);
        for n in 0..1_000 {
            log.write_all(format!("line number {n:05}\n").as_bytes())
                .unwrap();
        }
        let size = fs::metadata(dir.path().join("dnetd.log")).unwrap().len();
        assert!(size <= max, "the current file is {size} bytes, over {max}");
    }

    /// A link where the log file belongs is refused, never followed to wherever it points.
    #[cfg(windows)]
    #[test]
    fn a_link_in_place_of_the_log_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere.txt");
        fs::write(&elsewhere, b"not the log\n").unwrap();
        let logs = dir.path().join("logs");
        fs::create_dir(&logs).unwrap();
        // Creating a link needs a privilege an ordinary account may not have; where it is not available, there is
        // nothing to refuse and the test says so rather than passing silently.
        if std::os::windows::fs::symlink_file(&elsewhere, logs.join(FILE_NAME)).is_err() {
            eprintln!("skipped: this account cannot create symbolic links");
            return;
        }
        assert!(RotatingLog::open(&logs, 100, 2).is_err());
        assert_eq!(fs::read(&elsewhere).unwrap(), b"not the log\n");
    }

    #[test]
    fn a_control_character_in_an_event_is_written_as_text_and_the_event_stays_one_line() {
        let plain = b"2026-11-14T09:00:00Z  INFO dnetd: a\tplain event\n";
        assert_eq!(neutralise(plain).as_ref(), plain.as_slice());
        let hostile = b"INFO x: note \x1b[2J\r\nFAKE 2026 line\nsecond\x00 \n";
        let text = String::from_utf8(neutralise(hostile).into_owned()).unwrap();
        assert_eq!(
            text,
            "INFO x: note \\x1b[2J\\x0d\\x0aFAKE 2026 line\\x0asecond\\x00 \n"
        );
        assert_eq!(text.matches('\n').count(), 1, "one event, one line");
        assert_eq!(neutralise(b"").as_ref(), b"".as_slice());
        assert_eq!(neutralise(b"\x7f").as_ref(), b"\\x7f".as_slice());
    }

    #[test]
    fn the_sink_neutralises_what_it_writes_to_the_file() {
        use tracing_subscriber::fmt::MakeWriter;
        let dir = tempfile::tempdir().unwrap();
        let log = log_in(dir.path(), 1000, 2);
        let sink = Sink::new(Some(log.clone()));
        let mut writer = sink.make_writer();
        writer.write_all(b"before\x1b[31m\nforged\n").unwrap();
        let text = fs::read_to_string(log.current_path()).unwrap();
        assert_eq!(text, "before\\x1b[31m\\x0aforged\n");
    }

    #[test]
    fn the_directory_is_under_the_programs_own_data_folder() {
        let dir = default_dir();
        assert!(
            dir.ends_with(Path::new("DNet Engine").join("logs")),
            "{dir:?}"
        );
    }
}
