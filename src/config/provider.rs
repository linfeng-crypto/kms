//! Cryptographic service providers: signing backends

#[cfg(feature = "ledgertm")]
pub mod ledgertm;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "softsign")]
pub mod softsign;
#[cfg(feature = "yubihsm-client")]
pub mod yubihsm;

#[cfg(feature = "ledgertm")]
use self::ledgertm::LedgerTendermintConfig;
#[cfg(feature = "sgx")]
use self::sgx::SgxTendermintConfig;
#[cfg(feature = "softsign")]
use self::softsign::SoftsignConfig;
#[cfg(feature = "yubihsm-client")]
use self::yubihsm::YubihsmConfig;
use serde::Deserialize;

/// Provider configuration
#[derive(Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Software-backed signer
    #[cfg(feature = "softsign")]
    #[serde(default)]
    pub softsign: Vec<SoftsignConfig>,

    /// Map of sgx-tm labels to their configurations
    #[cfg(feature = "sgx")]
    #[serde(default)]
    pub sgx: Vec<SgxTendermintConfig>,

    /// Map of yubihsm-connector labels to their configurations
    #[cfg(feature = "yubihsm-client")]
    #[serde(default)]
    pub yubihsm: Vec<YubihsmConfig>,

    /// Map of ledger-tm labels to their configurations
    #[cfg(feature = "ledgertm")]
    #[serde(default)]
    pub ledgertm: Vec<LedgerTendermintConfig>,
}
