use crate::X509PathFinderError;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::result;

pub type DefaultPathValidatorResult<T> = result::Result<T, DefaultPathValidatorError>;

#[derive(Debug)]
pub enum DefaultPathValidatorError {
    Error(String),
    DerError(der::Error),
    WebPkiError(webpki::Error),
}

impl Display for DefaultPathValidatorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultPathValidatorError::Error(e) => {
                write!(f, "default path validator -> error: {}", e)
            }
            DefaultPathValidatorError::DerError(e) => {
                write!(f, "default path validator -> der error: {}", e)
            }
            DefaultPathValidatorError::WebPkiError(e) => {
                write!(f, "default path validator -> webpki error: {}", e)
            }
        }
    }
}

impl Error for DefaultPathValidatorError {}

impl From<der::Error> for DefaultPathValidatorError {
    fn from(e: der::Error) -> Self {
        Self::DerError(e)
    }
}

impl From<webpki::Error> for DefaultPathValidatorError {
    fn from(e: webpki::Error) -> Self {
        Self::WebPkiError(e)
    }
}
impl From<DefaultPathValidatorError> for X509PathFinderError {
    fn from(e: DefaultPathValidatorError) -> Self {
        Self::PathValidatorError(Box::new(e))
    }
}
