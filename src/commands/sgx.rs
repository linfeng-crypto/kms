//! `tmkms sgxsign` CLI (sub)commands

use crate::keyring::SecretKeyEncoding;
use subtle_encoding::encoding::Encoding;
use crate::prelude::*;
use signatory_sgx::provider::SgxSigner;
use std::path::PathBuf;
use abscissa_core::{Command, Help, Runnable};

/// The `softsign` subcommand
#[derive(Command, Debug, Options, Runnable)]
pub enum SgxCommand {
    /// Show help for the `sgx` subcommand
    #[options(help = "show help for the 'yubihsm' subcommand")]
    Help(Help<Self>),

    /// Generate a software signing key
    #[options(help = "generate a sgx signing secret key")]
    Keygen(KeygenCommand),

    /// Generate a software signing key
    #[options(help = "get the sgx signing public key")]
    Pubkey(PubkeyCommand),
}


/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct KeygenCommand {
    #[options(free, help = "file path where generated secret key should be created")]
    secret_key_path: PathBuf,

    #[options(
        short = "s",
        help = "sgx server address in Ip:port format",
        default = "127.0.0.1:8888",
    )]
    sgx_server: String,
}

impl Runnable for KeygenCommand {
    fn run(&self) {
        let sgx_signer = SgxSigner::new(&self.sgx_server, &self.secret_key_path);
        if let Err(e) = sgx_signer.create_keypair() {
            error!("create key pair failed: {}", e.what());
        } else {
            info!("Wrote random sgx private key to {}", self.secret_key_path.display());
        }
    }
}

/// `pubkey` command
#[derive(Command, Debug, Default, Options)]
pub struct PubkeyCommand {
    #[options(free, help = "secrete key file path")]
    secret_key_path: PathBuf,

    #[options(
    short = "s",
    help = "sgx server address in Ip:port format",
    default = "127.0.0.1:8888",
    )]
    sgx_server: String,
}

impl Runnable for PubkeyCommand {
    fn run(&self) {
        let sgx_signer = SgxSigner::new(&self.sgx_server, &self.secret_key_path);
        match sgx_signer.get_pubkey() {
            Err(e) => {
                error!("create key pair failed: {}", e.what());
            }
            Ok(raw) => {
                let encoding = SecretKeyEncoding::default();
                println!("get public key: {}",  encoding.encode_to_string(&raw).unwrap_or("error to encode public key to a string".to_string()));
            }
        }
    }
}
