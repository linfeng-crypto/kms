//! Configuration for sgx-signer

use crate::chain;
use serde::Deserialize;
use std::path::PathBuf;

/// Software signer configuration
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SgxTendermintConfig {
    /// Chains this signing key is authorized to be used from
    pub chain_ids: Vec<chain::Id>,

    /// Path to a file containing a sgx_secret key
    pub key_path: PathBuf,

    /// Sgx server address
    pub sgx_path: PathBuf,
}
