//! Job object wrapper for the Windows sandbox helper.
//!
//! The helper assigns the sandboxed child to a Job object configured with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. When the helper exits — whether it
//! finishes normally or the terminal layer kills it (timeout / cancel /
//! Stop button) — the last handle to the job closes and the kernel tears down
//! the whole child process tree. This is what stops shells from orphaning
//! grandchildren.

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

use super::token::OwnedHandle;

/// A Job object that kills all assigned processes when it (and the helper)
/// goes away.
pub struct KillOnCloseJob {
    handle: OwnedHandle,
}

impl KillOnCloseJob {
    /// Create a Job object configured to kill its processes on close.
    pub fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(anyhow!("CreateJobObjectW failed: {}", unsafe {
                GetLastError()
            }));
        }
        let job = Self {
            handle: OwnedHandle::new(handle),
        };

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                job.handle.raw(),
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(anyhow!("SetInformationJobObject failed: {}", unsafe {
                GetLastError()
            }));
        }
        Ok(job)
    }

    /// Assign a process to this job. The process should be created suspended so
    /// it can't spawn descendants outside the job before assignment.
    ///
    /// # Safety
    /// `process` must be a valid process handle with the access rights
    /// `AssignProcessToJobObject` requires.
    pub unsafe fn assign(&self, process: HANDLE) -> Result<()> {
        let ok = unsafe { AssignProcessToJobObject(self.handle.raw(), process) };
        if ok == 0 {
            return Err(anyhow!("AssignProcessToJobObject failed: {}", unsafe {
                GetLastError()
            }));
        }
        Ok(())
    }
}
