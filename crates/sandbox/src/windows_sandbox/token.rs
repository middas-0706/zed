//! Restricted-token construction for the Windows sandbox.
//!
//! Ported from codex's unelevated `windows-sandbox-rs` backend. The key piece
//! is [`create_write_restricted_token`], which builds a `WRITE_RESTRICTED`
//! token from the current process token. Restricting SIDs on such a token are
//! consulted **only** for write-access checks, so reads keep using the user's
//! normal identity (read everywhere) while writes succeed only where the DACL
//! also grants one of the restricting SIDs.

use std::ffi::c_void;

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, LUID, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, AdjustTokenPrivileges, CopySid, CreateRestrictedToken, CreateWellKnownSid, GetLengthSid,
    GetTokenInformation, LookupPrivilegeValueW, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenDefaultDacl, TokenGroups,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::winutil::to_wide;

const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const LUA_TOKEN: u32 = 0x04;
const WRITE_RESTRICTED: u32 = 0x08;
const GENERIC_ALL: u32 = 0x1000_0000;
const WIN_WORLD_SID: i32 = 1;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;

/// Owns a Win32 `HANDLE`, closing it on drop.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Wrap a raw handle. The handle must be valid and owned by the caller.
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Owns a SID allocated by `ConvertStringSidToSidW`, releasing it with `LocalFree`.
pub struct LocalSid {
    psid: *mut c_void,
}

impl LocalSid {
    pub fn from_string(sid: &str) -> Result<Self> {
        let mut psid: *mut c_void = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(to_wide(sid).as_ptr(), &mut psid) };
        if ok == 0 || psid.is_null() {
            return Err(anyhow!("invalid SID string: {sid}"));
        }
        Ok(Self { psid })
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.psid
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.psid.is_null() {
            unsafe {
                LocalFree(self.psid as HLOCAL);
            }
        }
    }
}

/// Open a handle to the current process token with the access rights needed to
/// derive a restricted token from it.
pub fn open_current_process_token() -> Result<OwnedHandle> {
    let desired = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut handle: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), desired, &mut handle) };
    if ok == 0 {
        return Err(anyhow!("OpenProcessToken failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(OwnedHandle::new(handle))
}

/// Build a `WRITE_RESTRICTED` primary token from `base_token`, with
/// `cap_sid` plus the logon-session SID and the Everyone SID as restricting
/// SIDs. Writes then succeed only on objects whose DACL grants one of those
/// SIDs; the per-session capability SID is what we add to writable roots.
///
/// # Safety
/// `base_token` must be a valid primary token handle and `cap_sid` a valid
/// SID pointer that outlives this call. The returned handle is owned by the
/// caller.
pub unsafe fn create_write_restricted_token(
    base_token: HANDLE,
    cap_sid: *mut c_void,
) -> Result<OwnedHandle> {
    let mut logon_sid_bytes = unsafe { get_logon_sid_bytes(base_token) }?;
    let psid_logon = logon_sid_bytes.as_mut_ptr() as *mut c_void;
    let mut everyone = unsafe { world_sid() }?;
    let psid_everyone = everyone.as_mut_ptr() as *mut c_void;

    // Exact restricting-SID order: capability, logon, everyone.
    let mut entries: Vec<SID_AND_ATTRIBUTES> = vec![unsafe { std::mem::zeroed() }; 3];
    entries[0].Sid = cap_sid;
    entries[1].Sid = psid_logon;
    entries[2].Sid = psid_everyone;

    let mut new_token: HANDLE = std::ptr::null_mut();
    let flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED;
    let ok = unsafe {
        CreateRestrictedToken(
            base_token,
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            entries.len() as u32,
            entries.as_ptr(),
            &mut new_token,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CreateRestrictedToken failed: {}", unsafe {
            GetLastError()
        }));
    }
    let token = OwnedHandle::new(new_token);

    // Give the token a permissive default DACL so the sandboxed process can
    // create the pipe/IPC objects shells (notably PowerShell) rely on without
    // hitting ACCESS_DENIED.
    let dacl_sids = [psid_logon, psid_everyone, cap_sid];
    unsafe { set_default_dacl(token.raw(), &dacl_sids)? };
    unsafe { enable_single_privilege(token.raw(), "SeChangeNotifyPrivilege")? };
    Ok(token)
}

unsafe fn world_sid() -> Result<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        CreateWellKnownSid(
            WIN_WORLD_SID,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
    }
    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ok = unsafe {
        CreateWellKnownSid(
            WIN_WORLD_SID,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CreateWellKnownSid failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(buf)
}

unsafe fn get_logon_sid_bytes(h_token: HANDLE) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(h_token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(anyhow!("TokenGroups size query returned 0"));
    }
    let mut buf: Vec<u8> = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            h_token,
            TokenGroups,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        )
    };
    if ok == 0 || (needed as usize) < std::mem::size_of::<u32>() {
        return Err(anyhow!("GetTokenInformation(TokenGroups) failed"));
    }
    let group_count = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const u32) } as usize;
    // TOKEN_GROUPS layout: DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; the
    // array is aligned to pointer alignment after the 4-byte count.
    let after_count = unsafe { buf.as_ptr().add(std::mem::size_of::<u32>()) } as usize;
    let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
    let aligned = (after_count + (align - 1)) & !(align - 1);
    let groups_ptr = aligned as *const SID_AND_ATTRIBUTES;
    for i in 0..group_count {
        let entry: SID_AND_ATTRIBUTES = unsafe { std::ptr::read_unaligned(groups_ptr.add(i)) };
        if (entry.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID {
            let sid = entry.Sid;
            let sid_len = unsafe { GetLengthSid(sid) };
            if sid_len == 0 {
                return Err(anyhow!("GetLengthSid(logon) failed"));
            }
            let mut out = vec![0u8; sid_len as usize];
            if unsafe { CopySid(sid_len, out.as_mut_ptr() as *mut c_void, sid) } == 0 {
                return Err(anyhow!("CopySid(logon) failed"));
            }
            return Ok(out);
        }
    }
    Err(anyhow!("Logon SID not present on token"))
}

#[repr(C)]
struct TokenDefaultDaclInfo {
    default_dacl: *mut ACL,
}

/// Set a permissive default DACL on the token so sandboxed processes can
/// create pipes/IPC objects without ACCESS_DENIED.
unsafe fn set_default_dacl(h_token: HANDLE, sids: &[*mut c_void]) -> Result<()> {
    if sids.is_empty() {
        return Ok(());
    }
    let entries: Vec<EXPLICIT_ACCESS_W> = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: *sid as *mut u16,
            },
        })
        .collect();
    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let res = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            std::ptr::null_mut(),
            &mut p_new_dacl,
        )
    };
    if res != ERROR_SUCCESS {
        return Err(anyhow!("SetEntriesInAclW failed: {res}"));
    }
    let mut info = TokenDefaultDaclInfo {
        default_dacl: p_new_dacl,
    };
    let ok = unsafe {
        SetTokenInformation(
            h_token,
            TokenDefaultDacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<TokenDefaultDaclInfo>() as u32,
        )
    };
    let result = if ok == 0 {
        Err(anyhow!(
            "SetTokenInformation(TokenDefaultDacl) failed: {}",
            unsafe { GetLastError() }
        ))
    } else {
        Ok(())
    };
    if !p_new_dacl.is_null() {
        unsafe {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }
    result
}

unsafe fn enable_single_privilege(h_token: HANDLE, name: &str) -> Result<()> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), to_wide(name).as_ptr(), &mut luid) };
    if ok == 0 {
        return Err(anyhow!("LookupPrivilegeValueW failed: {}", unsafe {
            GetLastError()
        }));
    }
    let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    let ok2 = unsafe {
        AdjustTokenPrivileges(
            h_token,
            0,
            &tp,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok2 == 0 {
        return Err(anyhow!("AdjustTokenPrivileges failed: {}", unsafe {
            GetLastError()
        }));
    }
    Ok(())
}
