//! Shared types, constants, and error definitions for SeedNet.
//!
//! This crate is the foundation of the workspace: every other crate depends on it
//! for the canonical representations of a network [`Seed`], the derived
//! [`NetworkSecret`], peer identifiers, overlay addressing, and the
//! [`Error`] enum used across the stack.

pub mod constants;
pub mod error;
pub mod types;

pub use constants::*;
pub use error::Error;
pub use error::Result;
pub use types::*;
