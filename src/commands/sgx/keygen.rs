use crate::commands::sgx::RunCmd;
use abscissa_core::{Command, Runnable};
use signatory_sgx::provider::SgxSigner;
use std::path::{Path, PathBuf};

/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct KeygenCommand {
    #[options(short = "p", help = "set the sgx secret key path")]
    key_path: PathBuf,

    #[options(short = "s", help = "set the sgx app file path")]
    sgx_path: PathBuf,
}

impl RunCmd for KeygenCommand {
    fn get_sgx_path(&self) -> PathBuf {
        self.sgx_path.clone()
    }

    fn get_key_path(&self) -> &Path {
        self.key_path.as_ref()
    }

    fn run_cmd<P: AsRef<Path>>(&self, signer: &SgxSigner<P>) {
        let keypair = signer.keygen().unwrap();
        let pubkey_str = signer.store_key(&keypair).unwrap();
        println!(
            "stored secret key in file: {:?}, the public key is: {}",
            self.key_path, pubkey_str
        );
    }
}

impl Runnable for KeygenCommand {
    fn run(&self) {
        self.run_in_server()
    }
}
