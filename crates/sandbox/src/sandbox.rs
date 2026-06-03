//! Per-OS sandbox integrations for terminal commands run on behalf of the
//! agent.
//!
//! Each supported operating system has its own module here, gated behind
//! its `target_os` cfg so callers reach for the right one explicitly and
//! non-host targets don't carry dead code.
//!
//! macOS has an integration ([`macos_seatbelt`]), wrapping Apple's
//! Seatbelt / `sandbox-exec` framework, and Windows has an integration
//! ([`windows_sandbox`]) built on a restricted-token + capability-SID +
//! ACL mechanism driven by a small helper-launcher subprocess.

#[cfg(target_os = "macos")]
pub mod macos_seatbelt;

#[cfg(target_os = "windows")]
pub mod windows_sandbox;
