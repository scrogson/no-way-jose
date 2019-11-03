use openssl::rsa::Rsa;
use rustler::{Binary, Env, Error, NifUnitEnum, OwnedBinary};
use std::io::Write as _;

#[derive(NifUnitEnum)]
pub enum OutputFormat {
    Der,
    Pem,
}

#[rustler::nif(name = "generate_rsa", schedule = "DirtyCpu")]
pub fn generate(env: Env, bits: u32, output: OutputFormat) -> Result<Binary, Error> {
    Rsa::generate(bits)
        .and_then(|private| match output {
            OutputFormat::Der => private.private_key_to_der(),
            OutputFormat::Pem => private.private_key_to_pem(),
        })
        .and_then(|bytes| {
            let mut binary = OwnedBinary::new(bytes.len()).unwrap();
            binary.as_mut_slice().write_all(&bytes).unwrap();

            Ok(binary.release(env))
        })
        .map_err(|_| Error::Atom("openssl_error"))
}
