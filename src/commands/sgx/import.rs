use crate::commands::sgx::RunCmd;
use abscissa_core::{Command, Runnable};
use signatory_sgx::protocol::KeyType;
use signatory_sgx::provider::SgxSigner;
use std::path::{Path, PathBuf};

/// `keygen` command
#[derive(Command, Debug, Default, Options)]
pub struct ImportCommand {
    #[options(short = "p", help = "set the sgx secret key path")]
    key_path: PathBuf,

    #[options(short = "s", help = "set the sgx app file path")]
    sgx_path: PathBuf,

    #[options(short = "k", long = "key", help = "set the raw secret key")]
    raw_secret_key: String,

    #[options(
        short = "t",
        long = "type",
        default = "base64",
        help = "set the raw secret key type format"
    )]
    key_type: String,
}

impl RunCmd for ImportCommand {
    fn get_sgx_path(&self) -> PathBuf {
        self.sgx_path.clone()
    }

    fn get_key_path(&self) -> &Path {
        self.key_path.as_ref()
    }

    fn run_cmd<P: AsRef<Path>>(&self, signer: &SgxSigner<P>) {
        let key_type = if self.key_type.to_lowercase() == "base64".to_string() {
            KeyType::Base64
        } else {
            println!("keytype should be `base64`");
            return;
        };
        let keypair = match signer.import(key_type, &self.raw_secret_key) {
            Ok(k) => k,
            Err(e) => {
                println!("error: {:}", e.what);
                return;
            }
        };
        match signer.store_key(&keypair) {
            Err(e) => println!("error: {:?}", e.what),
            Ok(pubkey_str) => println!(
                "stored sealed secret key in file: {:?}, the public key is: {}",
                self.key_path, pubkey_str
            ),
        }
    }
}

impl Runnable for ImportCommand {
    fn run(&self) {
        self.run_in_server()
    }
}
