/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use aesm_client::AesmClient;
use bytes::{Buf, BufMut};
use enclave_runner::usercalls::{SyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;
use std::cell::RefCell;
use std::io::Cursor;
use std::io::Result as IoResult;
use std::io::{Read, Write};
use std::ops::DerefMut;
use std::path::Path;

/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "cat" which actually connects the enclave application to
/// stdin and stdout of `cat` process.

pub struct SgxServer;

thread_local! {
    pub static BUFFER: RefCell<Cursor<Vec<u8>>> = RefCell::new(Cursor::new(vec![]));
}

pub fn read_from_buffer(dest: &mut [u8]) -> IoResult<usize> {
    BUFFER.with(|cell| {
        let mut cursor = cell.borrow_mut();
        let mut reader = cursor.deref_mut().reader();
        reader.read(dest)
    })
}

pub fn write_to_buffer(src: &[u8]) -> IoResult<usize> {
    BUFFER.with(|cell| {
        let mut cursor = cell.borrow_mut();
        let mut writer = cursor.get_mut().writer();
        writer.write(src)
    })
}

impl Read for SgxServer {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        read_from_buffer(buf)
    }
}

impl SyncStream for SgxServer {
    fn read(&self, dest: &mut [u8]) -> IoResult<usize> {
        read_from_buffer(dest)
    }

    fn write(&self, src: &[u8]) -> IoResult<usize> {
        write_to_buffer(src)
    }

    fn flush(&self) -> IoResult<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct ExternalService;
// Ignoring local_addr and peer_addr, as they are not relavent in the current context.
impl UsercallExtension for ExternalService {
    fn connect_stream(
        &self,
        addr: &str,
        _local_addr: Option<&mut String>,
        _peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncStream>>> {
        // If the passed address is not "sgx", we return none, whereby the passed address gets treated as
        // an IP address which is the default behavior.
        match &*addr {
            "sgx" => {
                let stream = SgxServer;
                Ok(Some(Box::new(stream)))
            }
            _ => Ok(None),
        }
    }
}

pub fn run_sgx<P: AsRef<Path>>(file: P) {
    let mut device = IsgxDevice::new()
        .expect("get sgx device failed")
        .einittoken_provider(AesmClient::new())
        .build();
    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder
        .coresident_signature()
        .expect("sign enclave failed");
    enclave_builder.usercall_extension(ExternalService);
    let enclave = enclave_builder
        .build(&mut device)
        .expect("get enclave failed");
    if let Err(e) = enclave.run() {
        println!("Error while executing SGX enclave:{}", e);
        std::process::exit(1)
    }
}
