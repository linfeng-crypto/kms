//! Ed25519 signing keys

pub use signatory::ed25519::{PublicKey, Seed, Signature, PUBLIC_KEY_SIZE};

#[cfg(feature = "ledgertm")]
pub mod ledgertm;
#[cfg(feature = "sgx")]
pub mod sgx;
pub mod signer;
#[cfg(feature = "softsign")]
pub mod softsign;
#[cfg(feature = "yubihsm-client")]
pub mod yubihsm;

pub use self::signer::Signer;
