//! Small Win32 helpers shared by the Windows sandbox modules.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::System::Diagnostics::Debug::{
    FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
    FormatMessageW,
};

/// Encode a string as a NUL-terminated UTF-16 buffer for the `*W` Win32 APIs.
pub fn to_wide<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    let mut v: Vec<u16> = s.as_ref().encode_wide().collect();
    v.push(0);
    v
}

/// Quote a single Windows command-line argument following the rules used by
/// `CommandLineToArgvW`/the CRT so spaces, quotes, and backslashes survive a
/// round-trip. Matches `std::process::Command`'s Windows quoting.
pub fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty()
        || arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '"'));
    if !needs_quotes {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    let mut backslashes = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }
    if backslashes > 0 {
        quoted.push_str(&"\\".repeat(backslashes * 2));
    }
    quoted.push('"');
    quoted
}

/// Build a Windows command line for `CreateProcess`-style APIs from an argv.
pub fn argv_to_command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Produce a readable description for a Win32 error code.
pub fn format_last_error(err: u32) -> String {
    unsafe {
        let mut buf_ptr: *mut u16 = std::ptr::null_mut();
        let flags = FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS;
        let len = FormatMessageW(
            flags,
            std::ptr::null(),
            err,
            0,
            // FORMAT_MESSAGE_ALLOCATE_BUFFER expects a pointer that receives
            // the allocated buffer; windows-sys types it as `*mut u16`.
            (&mut buf_ptr as *mut *mut u16) as *mut u16,
            0,
            std::ptr::null_mut(),
        );
        if len == 0 || buf_ptr.is_null() {
            return format!("Win32 error {err}");
        }
        let slice = std::slice::from_raw_parts(buf_ptr, len as usize);
        let message = String::from_utf16_lossy(slice).trim().to_string();
        LocalFree(buf_ptr as HLOCAL);
        message
    }
}

#[cfg(test)]
mod tests {
    use super::argv_to_command_line;

    #[test]
    fn argv_to_command_line_quotes_each_argument_independently() {
        let argv = vec![
            "cmd.exe".to_string(),
            "/c".to_string(),
            "echo hello world".to_string(),
        ];
        assert_eq!(
            argv_to_command_line(&argv),
            "cmd.exe /c \"echo hello world\""
        );
    }
}
