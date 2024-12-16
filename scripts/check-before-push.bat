@echo off
setlocal

set CARGO_TERM_COLOR=always
gsset RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty --allow-staged
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all
if %errorlevel% neq 0 exit /b %errorlevel%

REM cargo clippy --all-targets --release
REM if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

REM cargo bench --workspace --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features --no-deps
if %errorlevel% neq 0 exit /b %errorlevel%

REM cargo publish --dry-run --allow-dirty
REM if %errorlevel% neq 0 exit /b %errorlevel%

cd java-bridge
cargo fmt --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty --allow-staged
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all-targets --release ^
    -A clippy::similar_names ^
    -A clippy::too_many_arguments ^
    -A clippy::significant_drop_tightening ^
    -A clippy::redundant_closure ^
    -A clippy::missing_errors_doc ^
    -A clippy::type_complexity
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features --no-deps
if %errorlevel% neq 0 exit /b %errorlevel%

REM cargo bench --workspace --all-targets --all-features --target x86_64-unknown-linux-gnu
if %errorlevel% neq 0 exit /b %errorlevel%

cd ..
