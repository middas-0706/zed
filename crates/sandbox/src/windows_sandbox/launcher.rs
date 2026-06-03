//! The Windows sandbox **helper launcher**.
//!
//! This is the entry point Zed runs when it's invoked as
//! `zed --zed-sandbox-helper <policy-file>` (see
//! [`super::SANDBOX_HELPER_FLAG`]). It plays the role `sandbox-exec` plays on
//! macOS: it reconstructs the sandbox from the policy file, spawns the real
//! command as a restricted child attached to its own (PTY) stdio, waits for it,
//! and exits with the child's exit code.
//!
//! Process-tree teardown is handled by a kill-on-close Job object: if the
//! terminal layer kills *this* helper (timeout / cancel / Stop), the job's last
//! handle closes and the kernel kills the whole child tree.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

use super::SandboxPolicy;
use super::acl;
use super::job::KillOnCloseJob;
use super::path_normalization::canonicalize_path;
use super::process::spawn_suspended;
use super::token::{
    LocalSid, OwnedHandle, create_write_restricted_token, open_current_process_token,
};

/// Exit code returned when the helper itself fails before the child runs.
const HELPER_FAILURE_EXIT_CODE: i32 = 127;
const INFINITE: u32 = u32::MAX;

/// Run the sandbox helper for the policy at `policy_path` and return the exit
/// code the helper process should exit with. Never panics.
pub fn run_sandbox_helper(policy_path: &Path) -> i32 {
    match run(policy_path) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("zed sandbox helper failed: {error:#}");
            HELPER_FAILURE_EXIT_CODE
        }
    }
}

fn run(policy_path: &Path) -> Result<i32> {
    let policy = read_policy(policy_path)?;

    let mut argv = Vec::with_capacity(policy.args.len() + 1);
    argv.push(policy.program.clone());
    argv.extend(policy.args.iter().cloned());

    // The job object tears the child tree down when the helper goes away.
    let job = KillOnCloseJob::new()?;

    // Build the write restriction unless the policy opted out. On any failure
    // we fall back to an unrestricted (ambient-token) spawn with a warning,
    // rather than failing the command outright, so a non-NTFS volume or a
    // restrictive corporate ACL policy can't make the terminal tool unusable.
    //
    // `restricted_token` and `acl_cleanup` are kept alive until after the wait:
    // the token must outlive the spawn, and the cleanup guard revokes the ACEs
    // on drop.
    let (restricted_token, acl_cleanup): (Option<OwnedHandle>, Option<AceCleanup>) =
        if policy.allow_fs_write {
            (None, None)
        } else {
            match build_write_restriction(&policy.writable_directories) {
                Ok((token, cleanup)) => (Some(token), Some(cleanup)),
                Err(error) => {
                    eprintln!(
                        "zed sandbox helper: filesystem isolation unavailable, running command \
                         without write restriction: {error:#}"
                    );
                    (None, None)
                }
            }
        };
    let token_raw = restricted_token.as_ref().map(OwnedHandle::raw);

    let child = unsafe { spawn_suspended(token_raw, &argv) }
        .with_context(|| format!("failed to launch sandboxed command: {}", policy.program))?;
    unsafe { job.assign(child.process())? };
    child.resume()?;

    let exit_code = wait_for_exit(child.process());

    // Best-effort: drop the restricted token before revoking ACEs so no live
    // token references the capability SID, then remove the ACEs we added.
    drop(restricted_token);
    drop(acl_cleanup);

    Ok(exit_code)
}

fn read_policy(policy_path: &Path) -> Result<SandboxPolicy> {
    let contents = std::fs::read_to_string(policy_path)
        .with_context(|| format!("failed to read sandbox policy {}", policy_path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse sandbox policy {}", policy_path.display()))
}

/// Build the `WRITE_RESTRICTED` token and grant the per-session capability SID
/// write access to each writable root. Returns the token plus a cleanup guard
/// that revokes the ACEs on drop.
fn build_write_restriction(writable_directories: &[PathBuf]) -> Result<(OwnedHandle, AceCleanup)> {
    let cap_sid = LocalSid::from_string(&random_capability_sid())
        .context("failed to mint sandbox capability SID")?;

    // Canonicalize and dedupe so the ACL'd paths match what the kernel checks,
    // and skip roots that don't exist (nothing to grant on).
    let mut roots: Vec<PathBuf> = Vec::new();
    for directory in writable_directories {
        let canonical = canonicalize_path(directory);
        if canonical.exists() && !roots.contains(&canonical) {
            roots.push(canonical);
        }
    }

    let base_token = open_current_process_token()?;
    let token = unsafe { create_write_restricted_token(base_token.raw(), cap_sid.as_ptr())? };

    // Allow redirections to NUL (e.g. `2>NUL`) under the restricted token.
    unsafe { acl::allow_null_device(cap_sid.as_ptr()) };

    let mut applied_roots: Vec<PathBuf> = Vec::new();
    for root in &roots {
        unsafe { acl::add_allow_write_ace(root, cap_sid.as_ptr())? };
        applied_roots.push(root.clone());
    }

    Ok((
        token,
        AceCleanup {
            cap_sid,
            roots: applied_roots,
        },
    ))
}

/// Revokes the capability-SID ACEs from each writable root when dropped.
struct AceCleanup {
    cap_sid: LocalSid,
    roots: Vec<PathBuf>,
}

impl Drop for AceCleanup {
    fn drop(&mut self) {
        for root in &self.roots {
            unsafe { acl::revoke_ace(root, self.cap_sid.as_ptr()) };
        }
    }
}

/// Wait for the child to exit and return its exit code (defaulting to a
/// failure code if the exit status can't be retrieved).
fn wait_for_exit(process: HANDLE) -> i32 {
    unsafe {
        WaitForSingleObject(process, INFINITE);
    }
    let mut code: u32 = HELPER_FAILURE_EXIT_CODE as u32;
    unsafe {
        GetExitCodeProcess(process, &mut code);
    }
    code as i32
}

/// Generate a random per-session capability SID string. Using a fresh SID for
/// each command means stale ACEs left behind by a crash reference a SID no
/// live token holds, so they're harmless.
fn random_capability_sid() -> String {
    let a: u32 = rand::random();
    let b: u32 = rand::random();
    let c: u32 = rand::random();
    let d: u32 = rand::random();
    format!("S-1-5-21-{a}-{b}-{c}-{d}")
}
