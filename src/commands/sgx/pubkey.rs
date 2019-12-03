use crate::commands::sgx::RunCmd;
use abscissa_core::{Command, Runnable};
use signatory_sgx::provider::{encode_to_string, SgxSigner};
use std::path::{Path, PathBuf};

/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct PubkeyCommand {
    #[options(short = "p", help = "set the sgx secret key path")]
    key_path: PathBuf,

    #[options(short = "s", help = "set the sgx app file path")]
    sgx_path: PathBuf,
}

impl RunCmd for PubkeyCommand {
    fn get_sgx_path(&self) -> PathBuf {
        self.sgx_path.clone()
    }

    fn get_key_path(&self) -> &Path {
        self.key_path.as_ref()
    }

    fn run_cmd<P: AsRef<Path>>(&self, signer: &SgxSigner<P>) {
        let pubkey_raw = signer.get_pubkey().unwrap();
        let pubkey_str = encode_to_string(&pubkey_raw).unwrap();
        println!("public key: {}", pubkey_str);
    }
}

impl Runnable for PubkeyCommand {
    fn run(&self) {
        self.run_in_server()
    }
}
