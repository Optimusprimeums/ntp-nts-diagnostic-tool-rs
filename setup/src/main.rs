//! Installer and uninstaller for the NTP/NTS Diagnostic Tool. The files to
//! install are embedded, so setup is a single program. It installs for the
//! current user only, needing no administrator rights, and copies itself in to
//! serve as the uninstaller.
//!
//!   setup.exe                 install, in a window showing its progress
//!   setup.exe /S              install silently
//!   uninstall.exe /U          remove, asking first
//!   uninstall.exe /U /S       remove silently
//!
//! Saved settings and any Windows Firewall rule the tool created are left alone.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("The installer is for Windows only.");
    std::process::exit(1);
}

#[cfg(windows)]
mod window;

#[cfg(windows)]
fn main() {
    install::main();
}

#[cfg(windows)]
mod install {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};

    use windows::Win32::System::Com::*;
    use windows::Win32::System::LibraryLoader::*;
    use windows::Win32::UI::Shell::*;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::{GUID, HSTRING, Interface};
    use winreg::RegKey;
    use winreg::enums::*;

    pub const NAME: &str = "NTP/NTS Diagnostic Tool";
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const GUI: &str = "NTP-NTS-Diagnostic-Tool.exe";
    const FOLDER: &str = "NTP-NTS Diagnostic Tool";
    const UNINSTALL_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NTP-NTS-Diagnostic-Tool";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    const GUI_EXE: &[u8] = include_bytes!(env!("NTPNTS_GUI_EXE"));
    const FILES: [(&str, &[u8]); 3] = [
        (GUI, GUI_EXE),
        ("ntpnts.exe", include_bytes!(env!("NTPNTS_CLI_EXE"))),
        ("LICENSE.txt", include_bytes!("../../LICENSE")),
    ];

    /// How much installing writes, for the progress bar.
    pub fn total_bytes() -> u64 {
        let me = std::env::current_exe()
            .and_then(std::fs::metadata)
            .map_or(0, |m| m.len());
        FILES.iter().map(|f| f.1.len() as u64).sum::<u64>() + me
    }

    /// Writes `data` in pieces, saying after each how much has been written in all.
    fn write_counted(
        path: &Path,
        data: &[u8],
        done: &mut u64,
        report: &mut dyn FnMut(u64, &str),
    ) -> std::io::Result<()> {
        let name = path
            .file_name()
            .map_or(String::new(), |n| n.to_string_lossy().into_owned());
        let mut file = std::fs::File::create(path)?;
        for piece in data.chunks(512 * 1024) {
            file.write_all(piece)?;
            *done += piece.len() as u64;
            report(*done, &name);
        }
        Ok(())
    }

    /// Installs everything, saying as it goes how many bytes are written and
    /// what it's writing. Returns the program's path.
    pub fn put_files(report: &mut dyn FnMut(u64, &str)) -> Result<PathBuf, String> {
        let (Some(dir), Some(lnk)) = (install_dir(), shortcut_path()) else {
            return Err("Could not find where to install.".into());
        };
        let exe = dir.join(GUI);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Could not create the install folder.\n\n{e}"))?;
        let mut done = 0;
        // A running copy can't be overwritten, and this fails before anything
        // has changed, so an upgrade is all or nothing.
        if write_counted(&exe, GUI_EXE, &mut done, report).is_err() {
            return Err(format!(
                "The {NAME} is running, so it can't be replaced.\n\nClose it, then try again."
            ));
        }
        let rest = (|| -> Result<(), String> {
            for (name, data) in &FILES[1..] {
                write_counted(&dir.join(name), data, &mut done, report)
                    .map_err(|e| format!("{name}: {e}"))?;
            }
            let me = std::env::current_exe()
                .and_then(std::fs::read)
                .map_err(|e| format!("own copy: {e}"))?;
            write_counted(&dir.join("uninstall.exe"), &me, &mut done, report)
                .map_err(|e| format!("uninstaller: {e}"))?;
            report(done, "Start menu");
            make_shortcut(&lnk, &exe, &dir).map_err(|e| format!("shortcut: {e}"))?;
            register(&dir, &exe, &dir.join("uninstall.exe")).map_err(|e| format!("registry: {e}"))
        })();
        rest.map_err(|why| format!("Installation did not finish.\n\n{why}"))?;
        Ok(exe)
    }

    /// The version already installed, if any.
    pub fn installed_version() -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(UNINSTALL_KEY)
            .ok()?
            .get_value("DisplayVersion")
            .ok()
    }

    fn message(text: &str, style: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
        let title = HSTRING::from(format!("{NAME} Setup"));
        unsafe { MessageBoxW(None, &HSTRING::from(text), &title, style) }
    }

    pub fn complain(text: &str) {
        message(text, MB_OK | MB_ICONERROR);
    }

    fn uninstall(silent: bool) -> i32 {
        let (Some(dir), Some(lnk)) = (install_dir(), shortcut_path()) else {
            if !silent {
                complain("Could not find the install folder.");
            }
            return 1;
        };
        if !silent
            && message(
                &format!("Remove the {NAME}?\n\nYour settings are kept."),
                MB_YESNO | MB_ICONQUESTION,
            ) != IDYES
        {
            return 2;
        }
        if let Err(e) = std::fs::remove_file(dir.join(GUI))
            && e.kind() != std::io::ErrorKind::NotFound
        {
            if !silent {
                complain(&format!(
                    "Could not remove {GUI}.\n\nIf the {NAME} is running, close it and try again."
                ));
            }
            return 1;
        }
        for (name, _) in &FILES[1..] {
            let _ = std::fs::remove_file(dir.join(name));
        }
        let _ = std::fs::remove_file(lnk);
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey(UNINSTALL_KEY);
        if !silent {
            message(
                &format!(
                    "The {NAME} has been removed.\n\nIf you added its Windows Firewall rule, \
                     it is still there: remove it from Windows Defender Firewall."
                ),
                MB_OK | MB_ICONINFORMATION,
            );
        }
        // This has to be the very last thing done: the deletion only works
        // once this program has exited, and it waits a fixed time for that.
        delete_self_later(&dir);
        0
    }

    fn known_folder(id: &GUID, flags: KNOWN_FOLDER_FLAG) -> Option<PathBuf> {
        unsafe {
            let p = SHGetKnownFolderPath(id, flags, None).ok()?;
            let path = p.to_string().ok().map(PathBuf::from);
            CoTaskMemFree(Some(p.0 as *const _));
            path
        }
    }

    /// `%LOCALAPPDATA%\Programs\NTP-NTS Diagnostic Tool`
    pub fn install_dir() -> Option<PathBuf> {
        Some(known_folder(&FOLDERID_UserProgramFiles, KF_FLAG_CREATE)?.join(FOLDER))
    }

    fn shortcut_path() -> Option<PathBuf> {
        Some(known_folder(&FOLDERID_Programs, KF_FLAG_DEFAULT)?.join(format!("{FOLDER}.lnk")))
    }

    fn make_shortcut(lnk: &Path, exe: &Path, dir: &Path) -> windows::core::Result<()> {
        unsafe {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&HSTRING::from(exe.as_os_str()))?;
            link.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))?;
            link.SetDescription(&HSTRING::from("NTP and NTS server diagnostics"))?;
            let file: IPersistFile = link.cast()?;
            file.Save(&HSTRING::from(lnk.as_os_str()), true)
        }
    }

    fn register(dir: &Path, exe: &Path, uninstaller: &Path) -> std::io::Result<()> {
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey_with_flags(UNINSTALL_KEY, KEY_SET_VALUE)?;
        key.set_value("DisplayName", &NAME)?;
        key.set_value("DisplayVersion", &VERSION)?;
        key.set_value("Publisher", &"Nicholas Newman")?;
        key.set_value("DisplayIcon", &exe.display().to_string())?;
        key.set_value("InstallLocation", &dir.display().to_string())?;
        key.set_value(
            "UninstallString",
            &format!("\"{}\" /U", uninstaller.display()),
        )?;
        key.set_value(
            "QuietUninstallString",
            &format!("\"{}\" /U /S", uninstaller.display()),
        )?;
        key.set_value("NoModify", &1u32)?;
        key.set_value("NoRepair", &1u32)?;
        let kib = FILES.iter().map(|f| f.1.len()).sum::<usize>() / 1024;
        key.set_value("EstimatedSize", &(kib as u32))?;
        Ok(())
    }

    /// A running program can't delete itself, so a short-lived hidden command
    /// prompt removes uninstall.exe and the folder after this one exits. It
    /// names exactly those two things, and rmdir without /s leaves the folder
    /// alone if anything else has been put in it.
    fn delete_self_later(dir: &Path) {
        let uninstaller = dir.join("uninstall.exe");
        let Some(root) = std::env::var_os("SystemRoot") else {
            return;
        };
        let system = Path::new(&root).join("System32");
        let cmd = format!(
            "/c ping -n 3 127.0.0.1 >nul & del /f /q \"{}\" & rmdir \"{}\"",
            uninstaller.display(),
            dir.display()
        );
        let _ = std::process::Command::new(system.join("cmd.exe"))
            .raw_arg(cmd)
            .current_dir(&system)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }

    pub fn main() {
        // Only load DLLs from the system, whatever else is in Downloads.
        unsafe {
            let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        let args: Vec<String> = std::env::args().skip(1).map(|a| a.to_uppercase()).collect();
        let silent = args.iter().any(|a| a == "/S");
        let remove = args.iter().any(|a| a == "/U");
        if unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_err() {
            std::process::exit(1);
        }
        let status = if remove {
            uninstall(silent)
        } else if silent {
            match put_files(&mut |_, _| {}) {
                Ok(_) => 0,
                Err(_) => 1,
            }
        } else {
            crate::window::run()
        };
        std::process::exit(status);
    }
}
