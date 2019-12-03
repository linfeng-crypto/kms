//! `tmkms sgxsign` CLI (sub)commands
mod import;
mod keygen;
mod pubkey;

use abscissa_core::{Command, Help, Runnable};
use crossbeam_channel::unbounded;
use import::ImportCommand;
use keygen::KeygenCommand;
use pubkey::PubkeyCommand;
use signatory_sgx::provider::SgxSigner;
use signatory_sgx::server::{run_server, stop_server, C2S};
use std::path::{Path, PathBuf};
use std::thread;

/// The `sgxsign` subcommand
#[derive(Command, Debug, Options, Runnable)]
pub enum SgxCommand {
    /// Show help for the `sgxsign` subcommand
    #[options(help = "show help for the 'sgx' subcommand")]
    Help(Help<Self>),

    /// Generate a software signing key
    #[options(help = "generate a software signing key")]
    Keygen(KeygenCommand),

    /// Get the pubic key in Base64 format
    #[options(help = "get the public key in base64 format")]
    Pubkey(PubkeyCommand),

    /// Import raw secret key and get the sealed secret key
    #[options(help = "import raw secret key")]
    Import(ImportCommand),
}

pub trait RunCmd {
    fn run_cmd<P: AsRef<Path>>(&self, signer: &SgxSigner<P>);

    fn get_sgx_path(&self) -> PathBuf;

    fn get_key_path(&self) -> &Path;

    fn run_in_server(&self) {
        let (client2server_tx, client2server_rx) = unbounded::<C2S>();
        let file = self.get_sgx_path();
        let t = thread::spawn(move || {
            if let Err(e) = run_server(client2server_rx, file) {
                log::error!("error: {:?}", e);
            }
        });
        {
            let signer = SgxSigner::new(client2server_tx.clone(), self.get_key_path());
            self.run_cmd(&signer);
        }
        stop_server(client2server_tx);
        let _ = t.join().unwrap();
    }
}
