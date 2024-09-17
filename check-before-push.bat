@echo off
set CARGO_TERM_COLOR=always
set RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

cargo fmt --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --release --all-targets --fix --allow-dirty --allow-staged
if %errorlevel% neq 0 exit /b %errorlevel%

act --action-offline-mode -W .github/workflows/build_and_tests_reusable.yaml
if %errorlevel% neq 0 exit /b %errorlevel%
