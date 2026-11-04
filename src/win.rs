//! Windows-only helpers: elevation and the optional firewall rule.

use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub const FIREWALL_RULE_NAME: &str = "NTP-NTS Diagnostic Tool Peer Responder";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    format!("\"{}\"", a.replace('"', "\\\""))
}

/// Start an elevated copy of this executable via the UAC prompt.
/// Returns Ok(()) if Windows launched it (the caller should then exit).
pub fn restart_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let params: Vec<String> = std::env::args().skip(1).map(|a| quote_arg(&a)).collect();
    let (verb, file, params) = (
        wide("runas"),
        wide(&exe.to_string_lossy()),
        wide(&params.join(" ")),
    );
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc as isize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW failed (code {})", rc as isize))
    }
}

fn netsh(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("netsh")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// Create (or replace) an inbound allow rule for the responder's UDP port on the
/// Domain and Private profiles. Requires elevation.
pub fn configure_firewall_rule(port: u16) -> Result<String, String> {
    if !is_admin() {
        return Err("Administrator privileges are required to change Windows Firewall.".into());
    }
    let name = format!("name={FIREWALL_RULE_NAME}");
    // Remove an older rule of the same name so the result is deterministic.
    let _ = netsh(&["advfirewall", "firewall", "delete", "rule", &name]);
    let localport = format!("localport={port}");
    let out = netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name,
        "dir=in",
        "action=allow",
        "protocol=UDP",
        &localport,
        "profile=domain,private",
        "enable=yes",
    ])
    .map_err(|e| format!("could not run netsh: {e}"))?;
    if out.status.success() {
        Ok(format!(
            "inbound UDP/{port} allowed for Domain/Private profiles (rule: {FIREWALL_RULE_NAME})"
        ))
    } else {
        let text = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        })
        .trim()
        .to_string();
        Err(if text.is_empty() {
            "netsh returned an error".into()
        } else {
            text
        })
    }
}
