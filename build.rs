fn main() {
    if !std::env::var_os("CARGO_CFG_TARGET_OS").is_some_and(|target| target == "windows")
        || !std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|target| target == "msvc")
    {
        return;
    }

    let dll = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "winfsp-x64.dll",
        Ok("x86") => "winfsp-x86.dll",
        Ok("aarch64") => "winfsp-a64.dll",
        Ok(arch) => panic!("unsupported Windows architecture: {}", arch),
        Err(error) => panic!("CARGO_CFG_TARGET_ARCH is not set: {}", error),
    };

    println!("cargo:rustc-link-lib=dylib=delayimp");
    println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
}
