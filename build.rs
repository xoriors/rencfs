fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Build scripts run on the host. Select linker flags from Cargo's target
    // variables instead of cfg!, which would describe the build machine.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("Cargo must provide CARGO_CFG_TARGET_ARCH for a Windows MSVC target");
    let dll = match arch.as_str() {
        "x86_64" => "winfsp-x64.dll",
        "x86" => "winfsp-x86.dll",
        "aarch64" => "winfsp-a64.dll",
        _ => panic!("unsupported Windows MSVC target architecture: {arch}"),
    };
    println!("cargo:rustc-link-lib=dylib=delayimp");
    println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
}
