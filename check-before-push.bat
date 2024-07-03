cargo build --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo build --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --all -- --check
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo publish --dry-run --allow-dirty
if %errorlevel% neq 0 exit /b %errorlevel%