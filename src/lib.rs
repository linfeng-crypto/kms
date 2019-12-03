//! Tendermint Key Management System

#![forbid(unsafe_code)]
//#![deny(warnings, missing_docs, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/tmkms/0.7.0-alpha1")]

#[cfg(not(any(
    feature = "softsign",
    feature = "yubihsm-client",
    feature = "ledgertm",
    feature = "sgx"
)))]
compile_error!(
    "please enable one of the following backends with cargo's --features argument: \
     yubihsm-client, ledgertm, softsign, sgx (e.g. --features=yubihsm)"
);

#[macro_use]
extern crate abscissa_core;
extern crate prost_amino as prost;
#[cfg(feature = "sgx")]
extern crate signatory_crypto as signatory;
#[cfg(feature = "sgx")]
extern crate signatory_dalek_crypto as signatory_dalek;
pub mod application;
pub mod chain;
pub mod client;
pub mod commands;
pub mod config;
pub mod connection;
pub mod error;
pub mod keyring;
pub mod prelude;
pub mod rpc;
pub mod session;
#[cfg(feature = "sgx")]
mod sgx;
#[cfg(feature = "yubihsm-client")]
pub mod yubihsm;

pub use crate::application::KmsApplication;
