//! DACL mutation for the Windows sandbox.
//!
//! Writable roots get an inheritable allow-ACE for the per-session capability
//! SID so the `WRITE_RESTRICTED` token can write there. Because the capability
//! SID is random per session, we never need to check for an existing ACE — and
//! stale ACEs left behind by a crash are harmless (no live token references
//! that SID). We still revoke them on a clean exit ([`revoke_ace`]).

use std::ffi::c_void;
use std::path::Path;

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, GetSecurityInfo, REVOKE_ACCESS, SET_ACCESS,
    SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use super::winutil::to_wide;

/// `SE_FILE_OBJECT` for the `Get/SetNamedSecurityInfoW` object-type argument.
const SE_FILE_OBJECT: i32 = 1;
/// `SE_KERNEL_OBJECT` for `Get/SetSecurityInfo` on a kernel handle (NUL).
const SE_KERNEL_OBJECT: i32 = 6;
const CONTAINER_INHERIT_ACE: u32 = 0x2;
const OBJECT_INHERIT_ACE: u32 = 0x1;

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

/// Add an inheritable allow-ACE granting write access to `psid` on `path`
/// (and, via inheritance, everything created under it).
///
/// # Safety
/// `psid` must be a valid SID pointer and `path` must refer to an existing
/// file or directory.
pub unsafe fn add_allow_write_ace(path: &Path, psid: *mut c_void) -> Result<()> {
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            to_wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(anyhow!(
            "GetNamedSecurityInfoW failed for {}: {code}",
            path.display()
        ));
    }

    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: WRITE_ALLOW_MASK,
        grfAccessMode: SET_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: trustee_for_sid(psid),
    };
    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = unsafe { SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl) };
    let result = if code2 != ERROR_SUCCESS {
        Err(anyhow!(
            "SetEntriesInAclW failed for {}: {code2}",
            path.display()
        ))
    } else {
        let code3 = unsafe {
            SetNamedSecurityInfoW(
                to_wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_new_dacl,
                std::ptr::null_mut(),
            )
        };
        if code3 != ERROR_SUCCESS {
            Err(anyhow!(
                "SetNamedSecurityInfoW failed for {}: {code3}",
                path.display()
            ))
        } else {
            Ok(())
        }
    };

    if !p_new_dacl.is_null() {
        unsafe {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }
    if !p_sd.is_null() {
        unsafe {
            LocalFree(p_sd as HLOCAL);
        }
    }
    result
}

/// Remove all ACEs for `psid` from `path`'s DACL. Best-effort cleanup; errors
/// are ignored because a leftover ACE for a per-session SID is harmless.
///
/// # Safety
/// `psid` must be a valid SID pointer.
pub unsafe fn revoke_ace(path: &Path, psid: *mut c_void) {
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            to_wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };
    if code != ERROR_SUCCESS {
        if !p_sd.is_null() {
            unsafe {
                LocalFree(p_sd as HLOCAL);
            }
        }
        return;
    }
    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: trustee_for_sid(psid),
    };
    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = unsafe { SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl) };
    if code2 == ERROR_SUCCESS {
        unsafe {
            SetNamedSecurityInfoW(
                to_wide(path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_new_dacl,
                std::ptr::null_mut(),
            );
        }
        if !p_new_dacl.is_null() {
            unsafe {
                LocalFree(p_new_dacl as HLOCAL);
            }
        }
    }
    if !p_sd.is_null() {
        unsafe {
            LocalFree(p_sd as HLOCAL);
        }
    }
}

/// Grant the capability SID write access to the null device so redirections
/// like `2>NUL` work under the restricted token. Best-effort.
///
/// # Safety
/// `psid` must be a valid SID pointer.
pub unsafe fn allow_null_device(psid: *mut c_void) {
    // READ_CONTROL | WRITE_DAC to read and rewrite the device's DACL.
    let desired = 0x0002_0000 | 0x0004_0000;
    let handle = unsafe {
        CreateFileW(
            to_wide(r"\\.\NUL").as_ptr(),
            desired,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
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
                unsafe {
                    LocalFree(p_new_dacl as HLOCAL);
                }
            }
        }
    }
    if !p_sd.is_null() {
        unsafe {
            LocalFree(p_sd as HLOCAL);
        }
    }
    unsafe {
        CloseHandle(handle);
    }
}
