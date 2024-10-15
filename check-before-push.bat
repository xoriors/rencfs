@echo off
setlocal

set CARGO_TERM_COLOR=always
set RUSTFLAGS=-Dwarnings
set RUSTDOCFLAGS=-Dwarnings

:: Filepath to the Cargo.toml file
set "CARGO_FILE=Cargo.toml"
set "BACKUP_FILE=Cargo_backup.txt"

:: Function to add -dryRun to the version
:add_dryrun_to_version
if exist "%CARGO_FILE%" (
    findstr /r "^version\s*=\s*\"[0-9\.]*\"" "%CARGO_FILE%" >nul
    if errorlevel 1 (
        echo No version found in the file.
        goto :eof
    )

    copy /y "%CARGO_FILE%" "%BACKUP_FILE%" >nul
    
    for /f "tokens=3 delims== " %%A in ('findstr /r "^version\s*=\s*\"[0-9\.]*\"" "%CARGO_FILE%"') do (
        set "ORIGINAL_VERSION=%%~A"
        set "MODIFIED_VERSION=%ORIGINAL_VERSION:~0,-1%-dryRun"
    )
    
    powershell -Command "(Get-Content -Raw '%CARGO_FILE%') -replace 'version = \"%ORIGINAL_VERSION%\"', 'version = \"%MODIFIED_VERSION%\"' | Set-Content '%CARGO_FILE%'"
    
    echo Version modified to: %MODIFIED_VERSION%
) else (
    echo Cargo.toml file not found!
)
goto :eof

:: Function to revert the version to its original state by restoring from backup
:revert_version
if exist "%BACKUP_FILE%" (
    copy /y "%BACKUP_FILE%" "%CARGO_FILE%" >nul
    del /f "%BACKUP_FILE%"
    echo Cargo.toml reverted to the original version.
) else (
    echo Backup file not found! Cannot revert.
)
goto :eof

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

cargo clippy --all-targets --release
if %errorlevel% neq 0 exit /b %errorlevel%

cargo test --release --all --all-features
if %errorlevel% neq 0 exit /b %errorlevel%

cargo doc --workspace --all-features --no-deps
if %errorlevel% neq 0 exit /b %errorlevel%

call :add_dryrun_to_version
if %errorlevel% neq 0 exit /b %errorlevel%

cargo publish --dry-run --allow-dirty
if %errorlevel% neq 0 exit /b %errorlevel%

call :revert_version
if %errorlevel% neq 0 exit /b %errorlevel%

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

cd ..
