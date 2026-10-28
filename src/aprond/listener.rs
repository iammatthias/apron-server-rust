//! golang.org/x/net/netutil's `LimitListener`.

use rust_stdlib::net::{AddrRef, Conn, Listener, NetError, TlsConnectionState};
use rust_stdlib::time::Time;
use std::any::Any;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// A listener that accepts at most `n` simultaneous connections. `accept`
/// waits for a slot; closing the listener wakes it with the listener's error.
pub fn limit_listener(inner: Box<dyn Listener>, n: usize) -> Box<dyn Listener> {
    Box::new(LimitedListener {
        inner,
        slots: Arc::new(Slots {
            free: Mutex::new(n),
            freed: Condvar::new(),
        }),
        closed: AtomicBool::new(false),
    })
}

struct Slots {
    free: Mutex<usize>,
    freed: Condvar,
}

impl Slots {
    fn release(&self) {
        *self.free.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.freed.notify_one();
    }
}

struct LimitedListener {
    inner: Box<dyn Listener>,
    slots: Arc<Slots>,
    closed: AtomicBool,
}

impl Listener for LimitedListener {
    fn accept(&self) -> Result<Box<dyn Conn>, NetError> {
        {
            let mut free = self.slots.free.lock().unwrap_or_else(|e| e.into_inner());
            while *free == 0 && !self.closed.load(Ordering::SeqCst) {
                free = self
                    .slots
                    .freed
                    .wait(free)
                    .unwrap_or_else(|e| e.into_inner());
            }
            if self.closed.load(Ordering::SeqCst) {
                drop(free);
                // As Go: report the closed listener's own error, closing any
                // connection it still hands out.
                loop {
                    self.inner.accept()?.close().ok();
                }
            }
            *free -= 1;
        }
        match self.inner.accept() {
            Ok(conn) => Ok(Box::new(LimitedConn {
                inner: conn,
                slots: self.slots.clone(),
                released: AtomicBool::new(false),
            })),
            Err(e) => {
                self.slots.release();
                Err(e)
            }
        }
    }

    fn close(&self) -> Result<(), NetError> {
        let result = self.inner.close();
        self.closed.store(true, Ordering::SeqCst);
        self.slots.freed.notify_all();
        result
    }

    fn addr(&self) -> Option<AddrRef> {
        self.inner.addr()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct LimitedConn {
    inner: Box<dyn Conn>,
    slots: Arc<Slots>,
    released: AtomicBool,
}

impl LimitedConn {
    fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            self.slots.release();
        }
    }
}

impl Drop for LimitedConn {
    fn drop(&mut self) {
        // Go releases only on Close; a dropped Rust connection is closed too.
        self.release();
    }
}

impl Conn for LimitedConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        self.inner.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.inner.write(b)
    }
    fn close(&self) -> Result<(), NetError> {
        let result = self.inner.close();
        self.release();
        result
    }
    fn local_addr(&self) -> Option<AddrRef> {
        self.inner.local_addr()
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        self.inner.remote_addr()
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_deadline(t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_read_deadline(t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.inner.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn Any {
        self.inner.as_any()
    }
    fn tls_connection_state(&self) -> Option<TlsConnectionState> {
        self.inner.tls_connection_state()
    }
    fn handshake(&self) -> Result<(), NetError> {
        self.inner.handshake()
    }
}

#[cfg(test)]
mod tests {
    use super::limit_listener;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn test_limit_listener_waits_for_a_closed_connection() {
        let inner = rust_stdlib::net::listen("tcp", "127.0.0.1:0").unwrap();
        let addr = inner.addr().unwrap().to_string();
        let listener = std::sync::Arc::new(limit_listener(inner, 1));
        let _a = std::net::TcpStream::connect(&addr).unwrap();
        let _b = std::net::TcpStream::connect(&addr).unwrap();
        let first = listener.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        let l = listener.clone();
        std::thread::spawn(move || {
            let _ = tx.send(l.accept().map(|_| ()));
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a second connection was accepted past the limit"
        );
        first.close().unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
    }

    #[test]
    fn test_closing_wakes_a_waiting_accept() {
        let inner = rust_stdlib::net::listen("tcp", "127.0.0.1:0").unwrap();
        let addr = inner.addr().unwrap().to_string();
        let listener = std::sync::Arc::new(limit_listener(inner, 1));
        let _a = std::net::TcpStream::connect(&addr).unwrap();
        let _first = listener.accept().unwrap();
        let (tx, rx) = mpsc::channel();
        let l = listener.clone();
        std::thread::spawn(move || {
            let _ = tx.send(l.accept().is_err());
        });
        std::thread::sleep(Duration::from_millis(50));
        listener.close().unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }
}
