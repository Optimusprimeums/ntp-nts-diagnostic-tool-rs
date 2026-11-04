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
        match rc as isize {
            // SE_ERR_ACCESSDENIED: the user declined the UAC prompt.
            5 => Err("the UAC prompt was declined".into()),
            code => Err(format!("ShellExecuteW failed (code {code})")),
        }
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

/// The responder's inbound firewall rule as Windows reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub enabled: bool,
    pub protocol: String,
    pub local_port: String,
    pub profiles: String,
}

impl FirewallRule {
    pub fn allows_port(&self, port: u16) -> bool {
        self.enabled
            && self.protocol.eq_ignore_ascii_case("UDP")
            && (self.local_port.eq_ignore_ascii_case("Any")
                || self
                    .local_port
                    .split(',')
                    .any(|p| p.trim().parse::<u16>() == Ok(port)))
    }
}

/// Parse the first rule from `netsh advfirewall firewall show rule` output.
/// Field names are English; on other UI languages the fields may be blank.
fn parse_rule(text: &str) -> FirewallRule {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| {
                l.strip_prefix(name)
                    .map(|v| v.trim_start_matches(':').trim().to_string())
            })
            .unwrap_or_default()
    };
    FirewallRule {
        enabled: field("Enabled").eq_ignore_ascii_case("Yes"),
        protocol: field("Protocol"),
        local_port: field("LocalPort"),
        profiles: field("Profiles"),
    }
}

/// `Ok(None)` when no rule of ours exists. Reading rules does not need elevation.
pub fn firewall_rule_status() -> Result<Option<FirewallRule>, String> {
    let name = format!("name={FIREWALL_RULE_NAME}");
    let out = netsh(&["advfirewall", "firewall", "show", "rule", &name])
        .map_err(|e| format!("could not run netsh: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(parse_rule(&String::from_utf8_lossy(&out.stdout))))
}

/// Delete the responder's firewall rule. Requires elevation.
pub fn remove_firewall_rule() -> Result<String, String> {
    if !is_admin() {
        return Err("Administrator privileges are required to change Windows Firewall.".into());
    }
    let name = format!("name={FIREWALL_RULE_NAME}");
    let out = netsh(&["advfirewall", "firewall", "delete", "rule", &name])
        .map_err(|e| format!("could not run netsh: {e}"))?;
    if out.status.success() {
        Ok(format!("removed firewall rule '{FIREWALL_RULE_NAME}'"))
    } else {
        Err("no firewall rule with that name exists".into())
    }
}

/// Whether the Windows Time service (which normally owns UDP/123) is running.
pub fn w32time_running() -> Option<bool> {
    let out = Command::new("sc")
        .args(["query", "w32time"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let state = text.lines().find(|l| l.contains("STATE"))?;
    Some(state.contains("RUNNING"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_netsh_rule() {
        let text = "Rule Name:      NTP-NTS Diagnostic Tool Peer Responder\n\
                    ----------------------------------------------------------------------\n\
                    Enabled:        Yes\nDirection:      In\nProfiles:       Domain,Private\n\
                    Protocol:       UDP\nLocalPort:      123\nAction:         Allow\nOk.\n";
        let r = parse_rule(text);
        assert_eq!(
            r,
            FirewallRule {
                enabled: true,
                protocol: "UDP".into(),
                local_port: "123".into(),
                profiles: "Domain,Private".into()
            }
        );
        assert!(r.allows_port(123));
        assert!(!r.allows_port(12300));
    }
}
