//! The test client and the checks of helpers_test.go, with the same names.
//! A failed check panics, as `t.Fatalf` does. Each module holds one kind;
//! tests import them all through this one.

mod accounts;
mod client;
mod frames;
mod rooms;
mod server;
mod uploads;

pub use accounts::*;
pub use client::*;
pub use frames::*;
pub use rooms::*;
pub use server::*;
pub use uploads::*;
