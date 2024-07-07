cargo build --workspace --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --workspace --all-targets --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --workspace -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --workspace
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all-targets
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo publish --dry-run --allow-dirty
if %errorlevel% neq 0 exit /b %errorlevel%