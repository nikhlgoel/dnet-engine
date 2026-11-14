// SPDX-License-Identifier: GPL-3.0-or-later
//! Which program a process id is, as a path (the form application rules are written in).
//!
//! An attribution names a process id; an application rule names an executable's path. This connects them.
//! It is asked **right after** a connect is seen: process ids are reused, so the longer the gap the likelier
//! the id names a different program. A process that has already gone, or that this account may not query,
//! gives no answer, and no answer means "no application rule matched", as with every other gap in the
//! attribution (ADR-0001: best effort).
//!
//! Windows only: `QueryFullProcessImageNameW` with the least access that allows it
//! (`PROCESS_QUERY_LIMITED_INFORMATION`), which works for protected and elevated processes where a full
//! query would be refused.

use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The full path of the executable of process `pid`, if it can be read now.
pub fn image_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: `OpenProcess` returns a handle we own and close below; the buffer outlives the call and its
    // length is passed in `len`, which the call updates to the characters written.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = vec![0u16; 32_768];
        let mut len = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        ok.then(|| String::from_utf16_lossy(&buffer[..len as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_resolves_to_its_own_executable() {
        let path = image_path(std::process::id()).expect("a process can read its own path");
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            std::path::Path::new(&path)
                .file_name()
                .unwrap()
                .to_ascii_lowercase(),
            exe.file_name().unwrap().to_ascii_lowercase()
        );
        assert!(path.contains('\\'), "a full path: {path}");
    }

    #[test]
    fn a_process_that_is_not_there_gives_no_answer_not_a_guess() {
        assert_eq!(image_path(0), None);
        assert_eq!(image_path(u32::MAX), None);
        // An id no process is likely to have (ids are multiples of four).
        assert_eq!(image_path(3), None);
    }
}
