fn main() {
    // The files to install are embedded: NTPNTS_GUI_EXE and NTPNTS_CLI_EXE name
    // the release builds of NTP-NTS-Diagnostic-Tool.exe and ntpnts.exe.
    for var in ["NTPNTS_GUI_EXE", "NTPNTS_CLI_EXE"] {
        println!("cargo:rerun-if-env-changed={var}");
        match std::env::var(var) {
            Ok(path) => println!("cargo:rerun-if-changed={path}"),
            Err(_) => panic!(
                "set {var} to the release executable to embed (see docs/wiki/Building-and-Releasing.md)"
            ),
        }
    }
    println!("cargo:rerun-if-changed=../assets/app.rc");
    println!("cargo:rerun-if-changed=../assets/app.ico");
    #[cfg(windows)]
    embed_resource::compile("../assets/app.rc", embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
