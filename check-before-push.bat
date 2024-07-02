cargo build --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo fmt --check --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo check --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo clippy --all
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --all --all-features --release
if %errorlevel% neq 0 exit /b %errorlevel%
