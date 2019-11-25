//! `tmkms sgxsign` CLI (sub)commands
mod runner;

use abscissa_core::{Command, Help, Runnable};
use runner::{run_sgx, write_to_buffer, SgxServer};
use signatory_sgx::error::Error as SError;
use signatory_sgx::protocol::{get_data_from_stream, Decode, Encode, KeyPair, Request, Response};
use signatory_sgx::provider::{convert_data_to_str, get_data_from_file, store_data_to_file};
use signatory_sgx::seal_signer::SealedSigner;
use std::path::Path;
use std::path::PathBuf;

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
    Publickey(PubkeyCommand),
}

/// send request to sgx enclave and get the response
fn send<P: AsRef<Path>>(request: Request, sgx_path: P) -> Result<Response, SError> {
    let mut reader = SgxServer;
    let request_rawdata = request.encode(true)?;
    let _ = write_to_buffer(&request_rawdata)?;
    run_sgx(sgx_path);
    let data = get_data_from_stream(&mut reader)?;
    Response::decode(&data)
}

/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct KeygenCommand {
    #[options(
        short = "k",
        help = "file path where generated secret key should be created"
    )]
    key_path: PathBuf,

    #[options(short = "s", help = "sgxs file path")]
    sgx_path: PathBuf,
}

impl KeygenCommand {
    fn store_key(&self, key_pair: &KeyPair) -> Result<(), SError> {
        // dangerous to use the old secret_key path
        if self.key_path.exists() {
            return Err(SError::new("secret key path already exist"));
        }
        // save private key into file
        let secret_raw_data = key_pair.sealed_privkey.encode(false)?;
        store_data_to_file(&secret_raw_data, &self.key_path)?;
        // print out the pubkey
        let pubkey_str = convert_data_to_str(&key_pair.pubkey)
            .unwrap_or_else(|e| format!("error when convert from raw data: {}", e.what()));
        println!("public key: {}", pubkey_str);
        Ok(())
    }
}

impl Runnable for KeygenCommand {
    fn run(&self) {
        let request = Request::GenerateKey;
        let response = send(request, &self.sgx_path);
        match response {
            Err(e) => println!("get response error: {:?}", e),
            Ok(r) => match r {
                Response::KeyPair(keypair) => self
                    .store_key(&keypair)
                    .unwrap_or_else(|e| println!("store key failed: {:?}", e)),
                Response::Error(s) => println!("response from sgx enclave with error: {}", s),
                e => println!("error type of response: {:?}", e),
            },
        }
    }
}

/// `pubkey` command
#[derive(Command, Debug, Default, Options)]
pub struct PubkeyCommand {
    #[options(short = "k", help = "secrete key file path")]
    key_path: PathBuf,

    #[options(short = "s", help = "sgx server address in Ip:port format")]
    sgx_path: String,
}

impl PubkeyCommand {
    fn get_pubkey(&self) -> Result<String, SError> {
        let sgx_secret_raw = get_data_from_file(&self.key_path)?;
        let sealed_signer = SealedSigner::decode(&sgx_secret_raw)?;
        let request = Request::GetPublicKey(sealed_signer);
        let response = send(request, &self.sgx_path)?;
        let pubkey_raw = match response {
            Response::PublicKey(pubkey_raw) => Ok(pubkey_raw),
            Response::Error(s) => Err(SError::new(s)),
            _ => Err(SError::new("response error")),
        }
        .unwrap();
        let pubkey_str = convert_data_to_str(&pubkey_raw)?;
        Ok(pubkey_str)
    }
}

impl Runnable for PubkeyCommand {
    fn run(&self) {
        let pubkey_str = match self.get_pubkey() {
            Err(e) => e.what().to_string(),
            Ok(s) => s,
        };
        println!("get public key: {}", pubkey_str);
    }
}
