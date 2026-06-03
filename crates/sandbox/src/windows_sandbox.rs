//! Windows sandbox integration for agent terminal commands.
//!
//! macOS gets a "prefix-wrap" sandbox for free: `sandbox-exec` is a real
//! executable that applies a policy to itself and all of its descendants and
//! then `exec`s the target. Windows has no equivalent prefix command — the
//! unprivileged sandbox primitives (restricted tokens, capability SIDs, ACLs)
//! are applied *at process-creation time* via `CreateProcessAsUser`. Whoever
//! calls `CreateProcess*` must build the token and pass it in.
//!
//! To keep the existing generic PTY-spawn path untouched, this module mirrors
//! the macOS model with a Zed-owned **helper launcher**: [`wrap_invocation`]
//! rewrites a `(program, args)` pair into an invocation of the current `zed`
//! executable with a hidden `--zed-sandbox-helper <policy-file>` flag. The
//! terminal layer spawns *that* into the PTY, and the helper
//! ([`run_sandbox_helper`]) reconstructs the sandbox and spawns the real
//! command as a restricted child attached to the helper's own stdio.
//!
//! The mechanism (ported from codex's unelevated `windows-sandbox-rs`
//! backend) is:
//!
//! - Reads use the user's normal identity, so the command can read anywhere
//!   (matches macOS `(allow file-read*)`).
//! - A `WRITE_RESTRICTED` token consults a per-session **capability SID** only
//!   for *write* access checks. Writable roots get an inheritable allow-ACE
//!   for that SID; everywhere else the restricting SID is absent, so writes
//!   are denied.
//! - `allow_fs_write` skips the restriction entirely (writes go through with
//!   the agent's ambient permissions).
//!
//! Network restriction is intentionally **not** implemented here yet; the
//! `allow_network` flag is carried through the policy but currently has no
//! effect (see the implementation plan for the open design question).

mod acl;
mod job;
mod launcher;
mod path_normalization;
mod process;
mod token;
mod winutil;

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub use launcher::run_sandbox_helper;

/// The hidden flag the helper launcher is invoked with. The single argument
/// that follows is the path to the JSON [`SandboxPolicy`] file.
pub const SANDBOX_HELPER_FLAG: &str = "--zed-sandbox-helper";

/// Per-command relaxations of the default Windows sandbox.
///
/// All-false is the default, fully-sandboxed run. Setting any field requires
/// user approval before the command is launched.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SandboxPermissions {
    /// Allow network access for the command. Carried through the policy but
    /// not yet enforced by the Windows backend.
    pub allow_network: bool,
    /// Allow unrestricted filesystem writes (skips the write restriction).
    pub allow_fs_write: bool,
}

/// The serialized sandbox policy for a single command.
///
/// [`wrap_invocation`] writes this to a temporary file and the helper launcher
/// reads it back to reconstruct the sandbox. It deliberately carries the
/// original `program`/`args` too, so the only argv the terminal layer sees is
/// `zed --zed-sandbox-helper <policy-file>` — keeping the model-facing command
/// out of the host process's argv space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// The original program to launch (e.g. a shell).
    pub program: String,
    /// The original argument list for `program`.
    pub args: Vec<String>,
    /// Directory subtrees the command may write to when `allow_fs_write` is
    /// false. These are the project's worktree paths plus any per-command
    /// scratch directory — never the model-controlled working directory.
    pub writable_directories: Vec<PathBuf>,
    /// Allow unrestricted filesystem writes (skips the write restriction).
    pub allow_fs_write: bool,
    /// Allow network access (carried through; not yet enforced).
    pub allow_network: bool,
}

/// RAII guard that keeps the on-disk policy file alive for the duration of the
/// sandboxed command. The terminal layer stores it in a field whose only job
/// is to drop — and delete the temp file — when the terminal entity drops.
pub struct WindowsSandboxConfig {
    /// Kept alive so the temp file exists until the command finishes.
    _file: NamedTempFile,
}

/// Wrap a process invocation so it runs under the Windows restricted-token
/// sandbox via Zed's helper launcher.
///
/// Returns the new program and arguments to execute, along with a
/// [`WindowsSandboxConfig`] that **must** be kept alive for the duration of
/// the command (it owns the on-disk policy file the helper reads at startup).
///
/// # Arguments
/// * `program` - The program that would have been launched (typically a shell).
/// * `args` - The full argument list for `program`.
/// * `writable_directories` - Directory subtrees the command may write to when
///   `permissions.allow_fs_write` is false. Pass the project's worktree paths
///   (and any per-command scratch directory), not the model-controlled working
///   directory.
/// * `permissions` - Sandbox relaxations requested for this command.
pub fn wrap_invocation(
    program: &str,
    args: &[String],
    writable_directories: &[&Path],
    permissions: SandboxPermissions,
) -> Result<(String, Vec<String>, WindowsSandboxConfig)> {
    let policy = SandboxPolicy {
        program: program.to_string(),
        args: args.to_vec(),
        writable_directories: writable_directories
            .iter()
            .map(|path| path.to_path_buf())
            .collect(),
        allow_fs_write: permissions.allow_fs_write,
        allow_network: permissions.allow_network,
    };

    let mut file =
        NamedTempFile::new().context("failed to create temporary Windows sandbox policy file")?;
    let json =
        serde_json::to_string(&policy).context("failed to serialize Windows sandbox policy")?;
    file.write_all(json.as_bytes())
        .context("failed to write Windows sandbox policy")?;
    file.flush()
        .context("failed to flush Windows sandbox policy")?;

    let policy_path = file
        .path()
        .to_str()
        .with_context(|| {
            format!(
                "sandbox policy file path contains invalid UTF-8: {}",
                file.path().display()
            )
        })?
        .to_string();

    let helper_exe = std::env::current_exe()
        .context("failed to resolve the current executable for the sandbox helper")?;
    let helper = helper_exe
        .to_str()
        .with_context(|| {
            format!(
                "current executable path contains invalid UTF-8: {}",
                helper_exe.display()
            )
        })?
        .to_string();

    // Diagnostic breadcrumb in Zed.log (this runs in the main, logging-
    // initialized process). The helper subprocess additionally appends to
    // `<temp>/zed-sandbox-helper.log`.
    log::info!(
        "windows sandbox: wrapping `{}` ({} args); helper={helper}, policy={policy_path}, \
         writable_dirs={}, allow_fs_write={}, allow_network={}; helper log at {}",
        policy.program,
        policy.args.len(),
        policy.writable_directories.len(),
        policy.allow_fs_write,
        policy.allow_network,
        launcher::helper_log_path(std::path::Path::new(&policy_path)).display(),
    );

    Ok((
        helper,
        vec![SANDBOX_HELPER_FLAG.to_string(), policy_path],
        WindowsSandboxConfig { _file: file },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_policy_round_trips_through_json() {
        let policy = SandboxPolicy {
            program: "cmd.exe".to_string(),
            args: vec!["/c".to_string(), "echo hi".to_string()],
            writable_directories: vec![
                PathBuf::from(r"C:\Users\dev\project"),
                PathBuf::from(r"C:\Users\dev\AppData\Local\Temp\zed-abc"),
            ],
            allow_fs_write: false,
            allow_network: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.program, policy.program);
        assert_eq!(parsed.args, policy.args);
        assert_eq!(parsed.writable_directories, policy.writable_directories);
        assert_eq!(parsed.allow_fs_write, policy.allow_fs_write);
        assert_eq!(parsed.allow_network, policy.allow_network);
    }
}
