use crossbeam_channel::{unbounded, Sender};
use signatory_sgx::server::{run_server, C2S};
use std::path::PathBuf;
use std::thread;

pub fn run_sgx_server(sgx_file: PathBuf) -> Sender<C2S> {
    let (tx, rx) = unbounded::<C2S>();
    thread::spawn(move || {
        if let Err(e) = run_server(rx, sgx_file) {
            log::error!("sgx service crashed! {}", e);
            std::process::exit(1)
        }
    });
    tx
}
