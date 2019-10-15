use openssl::rsa::Rsa;
use rustler::{Encoder, Env, Error, NifUnitEnum, OwnedBinary, Term};
use std::io::Write as _;

#[derive(NifUnitEnum)]
enum OutputFormat {
    Der,
    Pem,
}

pub fn generate<'a>(env: Env<'a>, args: &[Term<'a>]) -> Result<Term<'a>, Error> {
    let bits: u32 = args[0].decode()?;
    let output: OutputFormat = args[1].decode()?;

    Rsa::generate(bits)
        .and_then(|private| match output {
            OutputFormat::Der => private.private_key_to_der(),
            OutputFormat::Pem => private.private_key_to_pem(),
        })
        .and_then(|bytes| {
            let mut binary = OwnedBinary::new(bytes.len()).unwrap();
            binary.as_mut_slice().write_all(&bytes).unwrap();

            return Ok(binary.release(env).encode(env));
        })
        .map_err(|_| Error::Atom("openssl_error"))
}
