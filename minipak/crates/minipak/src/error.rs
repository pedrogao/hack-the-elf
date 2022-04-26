use encore::prelude::*;
use pixie::{deku::DekuError, PixieError};

#[derive(displaydoc::Display, Debug)]
pub enum Error {
    Encore(EncoreError),
    Deku(DekuError),
    Pixie(PixieError),
}

impl From<EncoreError> for Error {
    fn from(e: EncoreError) -> Self {
        Self::Encore(e)
    }
}

impl From<DekuError> for Error {
    fn from(e: DekuError) -> Self {
        Self::Deku(e)
    }
}

impl From<PixieError> for Error {
    fn from(e: PixieError) -> Self {
        Self::Pixie(e)
    }
}
