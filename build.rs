fn main() {
    // The build helper reads the target triple, so it also works when
    // cross-compiling Windows binaries from another host. It panics for
    // non-Windows targets, which do not link WinFsp.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winfsp::build::winfsp_link_delayload();
    }
}
