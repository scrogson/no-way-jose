use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    RsaPrivateKey,
};
use rustler::{Error, NifUnitEnum, OwnedBinary};
use std::io::Write as _;

#[derive(NifUnitEnum)]
pub enum OutputFormat {
    Der,
    Pem,
}

#[rustler::nif(name = "generate_rsa", schedule = "DirtyCpu")]
pub fn generate(bits: usize, output: OutputFormat) -> Result<OwnedBinary, Error> {
    let mut rng = rand::thread_rng();

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|_| Error::Atom("Failed to generate RSA key"))?;

    let bytes: Vec<u8> = match output {
        OutputFormat::Der => private_key
            .to_pkcs1_der()
            .map_err(|_| Error::Atom("failed to serialize key to DER"))?
            .to_bytes()
            .to_vec(),
        OutputFormat::Pem => {
            #[cfg(unix)]
            let line_ending = LineEnding::LF;
            #[cfg(windows)]
            let line_ending = LineEnding::CRLF;

            let pem = private_key
                .to_pkcs1_pem(line_ending)
                .map_err(|_| Error::Atom("failed to serialize key to PEM"))?;
            (*pem).clone().into_bytes()
        }
    };

    let mut binary =
        OwnedBinary::new(bytes.len()).ok_or(Error::Atom("failed to allocate memory for binary"))?;
    binary
        .as_mut_slice()
        .write_all(&bytes)
        .map_err(|_| Error::Atom("failed to write to binary"))?;

    Ok(binary)
}
