@echo off
set CARGO_TERM_COLOR=always
set RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

cargo fmt --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all-targets --release --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo publish --dry-run --allow-dirty --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo aur
if %errorlevel% neq 0 exit /b %errorlevel%

cargo generate-rpm
if %errorlevel% neq 0 exit /b %errorlevel%

cd java-bridge
cargo fmt --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all-targets --release --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features --no-deps --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cd ..
