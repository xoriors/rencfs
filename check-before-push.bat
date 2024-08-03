@echo off
set CARGO_TERM_COLOR=always
set RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

cargo build --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --all --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cd examples
cargo doc --workspace --all-features
if %errorlevel% neq 0 exit /b %errorlevel%
cd ..

cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo aur
if %errorlevel% neq 0 exit /b %errorlevel%

cargo generate-rpm
if %errorlevel% neq 0 exit /b %errorlevel%
