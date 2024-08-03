use crate::is_debug;
use std::io;
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

#[allow(clippy::missing_panics_doc)]
pub fn log_init(level: Level) -> WorkerGuard {
    let directive = format!("rencfs={}", level.as_str())
        .parse()
        .expect("cannot parse log directive");
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .unwrap()
        .add_directive(directive);

    let (writer, guard) = tracing_appender::non_blocking(io::stdout());
    let builder = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(filter);
    // .with_max_level(level);
    if is_debug() {
        builder.pretty().init();
    } else {
        builder.init();
    }

    guard
}
