//! Gates that need a tool outside Cargo, such as `go` or Pebble. A missing
//! tool fails the test, so a green run proves the gate ran; setting the
//! gate's variable to `1` skips it instead. `tests/aprond.rs` includes this
//! file too.

/// Compares against the Go code; skipped with `APRON_SKIP_GO=1`.
pub const GO: Gate = Gate {
    skip_var: "APRON_SKIP_GO",
    install: "install Go 1.27 and keep the apron-server-go clone at $APRON_GO_DIR \
              (default ~/Developer/forks/apron-server-go)",
};

/// Issues certificates from Pebble; skipped with `APRON_SKIP_PEBBLE=1`.
pub const PEBBLE: Gate = Gate {
    skip_var: "APRON_SKIP_PEBBLE",
    install: "go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1 \
              github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1, \
              which installs to $(go env GOPATH)/bin; set PEBBLE_BIN_DIR for another directory",
};

pub struct Gate {
    skip_var: &'static str,
    install: &'static str,
}

impl Gate {
    /// Reports that `what` is unavailable: prints that the gate was skipped
    /// when its variable is `1`, and panics otherwise.
    pub fn unavailable(&self, what: &str) {
        if std::env::var(self.skip_var).as_deref() == Ok("1") {
            eprintln!("SKIPPED ({}=1): {what}", self.skip_var);
            return;
        }
        panic!(
            "{what}: {}, or set {}=1 to skip this gate",
            self.install, self.skip_var
        );
    }
}
