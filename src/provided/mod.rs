//! Provided implementations

pub mod certificate;
#[cfg(feature = "openssl")]
pub mod openssl_common;
pub mod store;
pub mod validator;
