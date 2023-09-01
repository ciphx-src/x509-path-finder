#![doc = include_str!("../README.md")]

// mod aia;
pub mod api;
#[allow(dead_code)]
mod edge;
// mod find;
pub mod provided;
pub mod report;
mod result;
#[cfg(test)]
pub mod tests;

// pub use aia::*;
// pub use find::*;
pub use result::*;
