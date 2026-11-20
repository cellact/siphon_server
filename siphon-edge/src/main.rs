//! Composing binary. siphon-sip stays upstream. This process registers the
//! HTTP addon and the WebRTC peer, then runs siphon.

use std::sync::Arc;

use clap::Parser;
use siphon::config::Config;
use siphon::SiphonServer;

mod http;
mod namespace;
mod peer;

siphon::install_allocator!();

#[derive(Parser)]
#[command(name = "siphon", about = "SIPhon edge")]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "siphon.yaml")]
    config: String,
}

fn main() {
    let cli = Cli::parse();
    let config = Config::from_file(&cli.config).unwrap_or_else(|error| {
        eprintln!("Failed to load {}: {error}", cli.config);
        std::process::exit(1);
    });

    // No `.product(...)`. The builder defaults to "SIPhon" plus siphon-sip's
    // own version. This package's version is not that version.
    let peer = namespace::PyPeer::new(Arc::new(peer::Handle::start()));
    let builder = http::register(SiphonServer::builder(), &config);
    builder
        .register_namespace("peer", peer)
        .config_path(&cli.config)
        .run();
}
