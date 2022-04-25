#![no_std]

extern crate alloc;

// Re-export deku for downstream crates
pub use deku;
use deku::prelude::*;
use encore::prelude::*;

mod manifest;
pub use manifest::*;
mod writer;
pub use writer::*;

#[derive(displaydoc::Display, Debug)]
/// A pixie error
pub enum PixieError {
    /// `{0}`
    Deku(DekuError),
    /// `{0}
    Encore(EncoreError),
}

impl From<DekuError> for PixieError {
    fn from(e: DekuError) -> Self {
        Self::Deku(e)
    }
}

impl From<EncoreError> for PixieError {
    fn from(e: EncoreError) -> Self {
        Self::Encore(e)
    }
}
