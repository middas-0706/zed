//! Child-process creation for the Windows sandbox helper.
//!
//! The helper is already a ConPTY client: the terminal layer launched it as the
//! direct child of the pseudoconsole (it owns the `PROC_THREAD_ATTRIBUTE_
//! PSEUDOCONSOLE` slot). The sandboxed shell is the helper's child, so it
//! inherits that console at the kernel level automatically — we deliberately
//! do **not** set `STARTF_USESTDHANDLES`. That matters because in release
//! builds `zed.exe` is a GUI-subsystem binary whose CRT never initializes the
//! standard handles, so `GetStdHandle` would hand back nothing useful; natural
//! console inheritance sidesteps that entirely and is what console shells
//! (cmd/powershell/pwsh/bash) expect anyway.
//!
//! We create the child **suspended** so it can be assigned to the
//! kill-on-close Job object before it runs, then resume it.

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
};

use super::token::OwnedHandle;
use super::winutil::{argv_to_command_line, format_last_error, to_wide};

/// A suspended child process and its primary thread.
pub struct SpawnedChild {
    process: OwnedHandle,
    thread: OwnedHandle,
}

impl SpawnedChild {
    pub fn process(&self) -> HANDLE {
        self.process.raw()
    }

    /// Resume the suspended primary thread, letting the child start running.
    pub fn resume(&self) -> Result<()> {
        let res = unsafe { ResumeThread(self.thread.raw()) };
        if res == u32::MAX {
            return Err(anyhow!("ResumeThread failed: {}", unsafe {
                GetLastError()
            }));
        }
        Ok(())
    }
}

/// Spawn `argv` as a suspended child that inherits the helper's console.
///
/// When `token` is `Some`, the child is created with that (restricted) primary
/// token via `CreateProcessAsUserW`; when `None`, it uses the helper's own
/// ambient token via `CreateProcessW`. The child inherits the helper's console,
/// current directory, and environment (we pass null for the latter two).
///
/// # Safety
/// `token`, when present, must be a valid primary token handle.
pub unsafe fn spawn_suspended(token: Option<HANDLE>, argv: &[String]) -> Result<SpawnedChild> {
    let command_line = argv_to_command_line(argv);
    let mut command_line_wide = to_wide(&command_line);
    // Point lpDesktop at the interactive desktop explicitly. Without it some
    // shells (notably PowerShell) can fail with STATUS_DLL_INIT_FAILED when
    // launched under a restricted token.
    let mut desktop = to_wide(r"Winsta0\Default");

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = desktop.as_mut_ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;

    let ok = match token {
        Some(token) => unsafe {
            CreateProcessAsUserW(
                token,
                std::ptr::null(),
                command_line_wide.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1, // bInheritHandles
                creation_flags,
                std::ptr::null_mut(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        },
        None => unsafe {
            CreateProcessW(
                std::ptr::null(),
                command_line_wide.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                1, // bInheritHandles
                creation_flags,
                std::ptr::null_mut(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        },
    };

    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(anyhow!(
            "CreateProcess failed: {err} ({}) | cmd={command_line}",
            format_last_error(err)
        ));
    }

    Ok(SpawnedChild {
        process: OwnedHandle::new(pi.hProcess),
        thread: OwnedHandle::new(pi.hThread),
    })
}
