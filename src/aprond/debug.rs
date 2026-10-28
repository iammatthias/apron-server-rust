//! main.go's debug listener: pprof and expvar under /debug/.

use rust_stdlib::expvar;
use rust_stdlib::net::{self, http};
use std::sync::Arc;

type HandlerFn = fn(&mut dyn http::ResponseWriter, &mut http::Request);

/// Reports whether a listen address binds only loopback.
pub fn loopback_addr(addr: &str) -> bool {
    let Ok((host, _)) = net::split_host_port(addr) else {
        return false;
    };
    if host == "localhost" {
        return true;
    }
    net::parse_ip(&host).is_some_and(|ip| ip.is_loopback())
}

/// Serves pprof and expvar on their own listener, so profiling is never
/// reachable through the public address.
pub fn handler() -> Arc<dyn http::Handler> {
    let mux = http::ServeMux::new();
    let routes: [(&str, HandlerFn); 5] = [
        ("/debug/pprof/", http::pprof::index),
        ("/debug/pprof/cmdline", http::pprof::cmdline),
        ("/debug/pprof/profile", http::pprof::profile),
        ("/debug/pprof/symbol", http::pprof::symbol),
        ("/debug/pprof/trace", http::pprof::trace),
    ];
    for (pattern, f) in routes {
        mux.handle_func(pattern, f).expect("fixed debug pattern");
    }
    mux.handle("/debug/vars", expvar::handler())
        .expect("fixed debug pattern");
    Arc::new(mux)
}

#[cfg(test)]
mod tests {
    use super::{handler, loopback_addr};

    #[test]
    fn test_debug_handler_registers_its_routes() {
        let _ = handler();
    }

    #[test]
    fn test_loopback_addr() {
        for (addr, want) in [
            ("127.0.0.1:6060", true),
            ("localhost:6060", true),
            ("[::1]:6060", true),
            (":6060", false),
            ("0.0.0.0:6060", false),
            ("example.com:6060", false),
            ("127.0.0.1", false),
        ] {
            assert_eq!(loopback_addr(addr), want, "{addr}");
        }
    }
}
