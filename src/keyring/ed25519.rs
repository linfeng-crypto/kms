//! Ed25519 signing keys

pub use signatory::ed25519::{PublicKey, Seed, Signature, PUBLIC_KEY_SIZE};

#[cfg(feature = "ledgertm")]
pub mod ledgertm;
pub mod signer;
#[cfg(feature = "softsign")]
pub mod softsign;
#[cfg(feature = "yubihsm")]
pub mod yubihsm;
#[cfg(feature="sgx")]
pub mod sgx;

pub use self::signer::Signer;
