//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs

use super::Signer;
use crate::sgx;
use crate::{
    chain,
    config::provider::sgx::SgxTendermintConfig,
    error::{Error, ErrorKind::*},
    keyring::SigningProvider,
};
use signatory_crypto::public_key::PublicKeyed;
//use signatory::public_key::PublicKeyed;
use signatory_sgx::provider::SgxSigner;
use tendermint::TendermintKey;

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(
    chain_registry: &mut chain::Registry,
    configs: &[SgxTendermintConfig],
) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    // TODO(tarcieri): support for multiple softsign keys?
    if configs.len() != 1 {
        fail!(
            ConfigError,
            "expected one [softsign.provider] in config, found: {}",
            configs.len()
        );
    }

    let config = &configs[0];
    // start a sgx server
    let tx = sgx::run_sgx_server(config.sgx_path.clone());
    let provider = SgxSigner::new(tx, config.key_path.clone());
    if let Err(e) = provider.ping() {
        fail!(AccessError, "access sgx server failed: {:?}", e.what);
    }
    let public_key = provider.public_key().map_err(|_| Error::from(InvalidKey))?;

    // TODO(tarcieri): support for adding account keys into keyrings; upgrade Signatory version
    let consensus_pubkey = TendermintKey::ConsensusKey(
        tendermint::signatory::ed25519::PublicKey::from_bytes(public_key.as_bytes())
            .unwrap()
            .into(),
    );

    let signer = Signer::new(SigningProvider::Sgx, consensus_pubkey, Box::new(provider));

    for chain_id in &config.chain_ids {
        chain_registry.add_to_keyring(chain_id, signer.clone())?;
    }

    Ok(())
}
