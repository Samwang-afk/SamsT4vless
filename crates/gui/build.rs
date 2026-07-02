fn main() {
    println!("cargo:rerun-if-env-changed=SS_RS_MIHOMO_PATH");
    println!("cargo:rerun-if-env-changed=SS_RS_WINTUN_PATH");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for (name, variable) in [
        ("mihomo.exe", "SS_RS_MIHOMO_PATH"),
        ("wintun.dll", "SS_RS_WINTUN_PATH"),
    ] {
        let bytes = std::env::var(variable)
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .unwrap_or_default();
        std::fs::write(out.join(name), bytes).unwrap();
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("ProductName", "SS-RS")
            .set("FileDescription", "SS-RS Global Encrypted Tunnel");
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            resource.set_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#,
            );
        }
        resource
            .compile()
            .expect("failed to embed Windows resources");
    }
}
