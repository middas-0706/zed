//! DACL mutation for the Windows sandbox.
//!
//! Writable roots get an inheritable allow-ACE for the per-session capability
//! SID so the `WRITE_RESTRICTED` token can write there. Because the capability
//! SID is random per session, we never need to check for an existing ACE — and
//! stale ACEs left behind by a crash are harmless (no live token references
//! that SID). We still revoke them on a clean exit ([`revoke_ace`]).
//!
//! Crucially, we set the ACE with [`SetKernelObjectSecurity`] on a handle to
//! the root **instead of** `SetNamedSecurityInfoW`. The high-level
//! `Set*SecurityInfo` APIs run Windows' automatic-inheritance algorithm, which
//! recursively rewrites every descendant's DACL to propagate the new
//! inheritable ACE — catastrophically slow on large trees (e.g. a repo with a
//! big `target/` or `node_modules/`). `SetKernelObjectSecurity` sets only the
//! root object's security descriptor; new entries created under it still
//! inherit the ACE at creation time, we just don't touch the existing tree.

use std::ffi::c_void;
use std::path::Path;

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetSecurityInfo, REVOKE_ACCESS, SET_ACCESS, SetEntriesInAclW,
    SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, InitializeSecurityDescriptor, SECURITY_DESCRIPTOR,
    SetKernelObjectSecurity, SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

use super::winutil::to_wide;

/// `SE_KERNEL_OBJECT` for `Get/SetSecurityInfo` on a file/directory handle.
const SE_KERNEL_OBJECT: i32 = 6;
const CONTAINER_INHERIT_ACE: u32 = 0x2;
const OBJECT_INHERIT_ACE: u32 = 0x1;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

const WRITE_ALLOW_MASK: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;

fn trustee_for_sid(psid: *mut c_void) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: psid as *mut u16,
    }
}

/// Open a handle to `path` (file or directory) with the rights needed to read
/// and rewrite its DACL.
unsafe fn open_for_dacl_edit(path: &Path) -> Result<windows_sys::Win32::Foundation::HANDLE> {
    let handle = unsafe {
        CreateFileW(
            to_wide(path).as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            // Required to obtain a handle to a directory; harmless for files.
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(anyhow!(
            "CreateFileW failed for {}: {}",
            path.display(),
            unsafe { GetLastError() }
        ));
    }
    Ok(handle)
}

/// Apply a single `EXPLICIT_ACCESS_W` entry to `path`'s DACL **without**
/// recursive inheritance propagation, by setting the object's security
/// descriptor directly via `SetKernelObjectSecurity`.
unsafe fn modify_dacl_no_propagate(path: &Path, explicit: &EXPLICIT_ACCESS_W) -> Result<()> {
    let handle = unsafe { open_for_dacl_edit(path)? };

    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };
    if code != ERROR_SUCCESS {
        unsafe { CloseHandle(handle) };
        return Err(anyhow!(
            "GetSecurityInfo failed for {}: {code}",
            path.display()
        ));
    }

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let merge = unsafe { SetEntriesInAclW(1, explicit, p_dacl, &mut p_new_dacl) };
    let result = if merge != ERROR_SUCCESS {
        Err(anyhow!(
            "SetEntriesInAclW failed for {}: {merge}",
            path.display()
        ))
    } else {
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let sd_ptr = &mut sd as *mut SECURITY_DESCRIPTOR as *mut c_void;
        let init = unsafe { InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) };
        if init == 0 {
            Err(anyhow!("InitializeSecurityDescriptor failed: {}", unsafe {
                GetLastError()
            }))
        } else if unsafe { SetSecurityDescriptorDacl(sd_ptr, 1, p_new_dacl, 0) } == 0 {
            Err(anyhow!("SetSecurityDescriptorDacl failed: {}", unsafe {
                GetLastError()
            }))
        } else if unsafe { SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, sd_ptr) } == 0
        {
            Err(anyhow!(
                "SetKernelObjectSecurity failed for {}: {}",
                path.display(),
                unsafe { GetLastError() }
            ))
        } else {
            Ok(())
        }
    };

    if !p_new_dacl.is_null() {
        unsafe { LocalFree(p_new_dacl as HLOCAL) };
    }
    if !p_sd.is_null() {
        unsafe { LocalFree(p_sd as HLOCAL) };
    }
    unsafe { CloseHandle(handle) };
    result
}

/// Add an inheritable allow-ACE granting write access to `psid` on `path`.
/// New entries created under `path` inherit it; existing descendants are
/// intentionally left untouched (see the module docs on propagation cost).
///
/// # Safety
/// `psid` must be a valid SID pointer and `path` must refer to an existing
/// file or directory.
pub unsafe fn add_allow_write_ace(path: &Path, psid: *mut c_void) -> Result<()> {
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: WRITE_ALLOW_MASK,
        grfAccessMode: SET_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: trustee_for_sid(psid),
    };
    unsafe { modify_dacl_no_propagate(path, &explicit) }
}

/// Remove all ACEs for `psid` from `path`'s DACL (best-effort cleanup; errors
/// are ignored because a leftover ACE for a per-session SID is harmless).
///
/// # Safety
/// `psid` must be a valid SID pointer.
pub unsafe fn revoke_ace(path: &Path, psid: *mut c_void) {
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: trustee_for_sid(psid),
    };
    let _ = unsafe { modify_dacl_no_propagate(path, &explicit) };
}

/// Grant the capability SID write access to the null device so redirections
/// like `2>NUL` work under the restricted token. Best-effort.
///
/// # Safety
/// `psid` must be a valid SID pointer.
pub unsafe fn allow_null_device(psid: *mut c_void) {
    // READ_CONTROL | WRITE_DAC to read and rewrite the device's DACL.
    let desired = READ_CONTROL | WRITE_DAC;
    let handle = unsafe {
        CreateFileW(
            to_wide(r"\\.\NUL").as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return;
    }
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };
    if code == ERROR_SUCCESS {
        let explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE,
            grfAccessMode: SET_ACCESS,
            grfInheritance: 0,
            Trustee: trustee_for_sid(psid),
        };
        let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
        let code2 = unsafe { SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl) };
        if code2 == ERROR_SUCCESS {
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    p_new_dacl,
                    std::ptr::null_mut(),
                );
            }
            if !p_new_dacl.is_null() {
                unsafe { LocalFree(p_new_dacl as HLOCAL) };
            }
        }
    }
    if !p_sd.is_null() {
        unsafe { LocalFree(p_sd as HLOCAL) };
    }
    unsafe { CloseHandle(handle) };
}
