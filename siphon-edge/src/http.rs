//! HTTP addon. Same wiring as siphon-bin's `ext/http.rs`.

use siphon::config::Config;
use siphon::SiphonServer;
use siphon_http::HttpConfig;

pub fn register(builder: SiphonServer, config: &Config) -> SiphonServer {
    let Some(path) = config.extension_path("http") else {
        if config.extension_config("http").is_some() {
            eprintln!(
                "siphon: extensions.http must reference a path to an http.yaml \
                 (inline form not yet supported); HTTP disabled"
            );
        }
        return builder;
    };

    match HttpConfig::from_file(path) {
        Ok(cfg) => builder
            .register_namespace_with("http", siphon_http::namespace(cfg.clone()))
            .register_task(siphon_http::task(cfg)),
        Err(error) => {
            eprintln!(
                "siphon: http extension config {} failed to load: {error}; HTTP disabled",
                path.display()
            );
            builder
        }
    }
}
