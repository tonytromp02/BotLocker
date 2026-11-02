//! Platform-agnostic detection core for Botlocker.
//!
//! Nothing in this crate touches the network, the filesystem, or a clock.
//! Adapters pass in a normalized request and the current Unix time.

pub mod behavior;
pub mod challenge;
pub mod config;
pub mod engine;
pub mod maze;
pub mod report;
pub mod request;
pub mod scoring;
pub mod signals;

pub use config::{Config, ConfigError};
pub use engine::{Classification, Engine, Reason};
pub use request::NormalizedRequest;
pub use scoring::Action;

/// Reserved path for the browser challenge and the trapped-visitor escape hatch.
pub const CHALLENGE_PATH: &str = "/.bl/challenge";

/// Endpoint the challenge page reports browser signals to.
pub const REPORT_PATH: &str = "/.bl/report";

/// Cookie set by a successful challenge.
pub const PASS_COOKIE: &str = "bl_pass";
