use std::io;

use tracing::level_filters::LevelFilter;
use tracing::subscriber;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Registry, fmt};

pub fn init_log(debug: bool) {
    let layer = fmt::layer()
        .pretty()
        .with_target(true)
        .with_writer(io::stderr);

    let level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let targets = Targets::new()
        .with_target("h2", LevelFilter::OFF)
        .with_default(LevelFilter::DEBUG);

    let layered = Registry::default().with(targets).with(layer).with(level);

    subscriber::set_global_default(layered).unwrap();
}
