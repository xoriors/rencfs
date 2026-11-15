fn main() {
    // WinFsp requires delay-load linking for the winfsp DLL.
    // This must be called from build.rs at the project root level.
    winfsp::build::winfsp_link_delayload();
}
