use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use p384::ecdsa::SigningKey as P384SigningKey;
use rustler::{Error, NifUnitEnum, OwnedBinary};
use std::io::Write as _;

#[derive(NifUnitEnum)]
pub enum EcCurve {
    P256,
    P384,
}

#[derive(NifUnitEnum)]
pub enum OutputFormat {
    Der,
    Pem,
}

#[rustler::nif(name = "generate_ec", schedule = "DirtyCpu")]
pub fn generate(curve: EcCurve, output: OutputFormat) -> Result<OwnedBinary, Error> {
    let mut rng = rand::thread_rng();

    let bytes: Vec<u8> = match (curve, output) {
        (EcCurve::P256, OutputFormat::Der) => {
            let signing_key = P256SigningKey::random(&mut rng);
            signing_key
                .to_pkcs8_der()
                .map_err(|_| Error::Atom("failed to serialize P-256 key to DER"))?
                .to_bytes()
                .to_vec()
        }
        (EcCurve::P256, OutputFormat::Pem) => {
            let signing_key = P256SigningKey::random(&mut rng);
            signing_key
                .to_pkcs8_pem(line_ending())
                .map_err(|_| Error::Atom("failed to serialize P-256 key to PEM"))?
                .to_string()
                .into_bytes()
        }
        (EcCurve::P384, OutputFormat::Der) => {
            let signing_key = P384SigningKey::random(&mut rng);
            signing_key
                .to_pkcs8_der()
                .map_err(|_| Error::Atom("failed to serialize P-384 key to DER"))?
                .to_bytes()
                .to_vec()
        }
        (EcCurve::P384, OutputFormat::Pem) => {
            let signing_key = P384SigningKey::random(&mut rng);
            signing_key
                .to_pkcs8_pem(line_ending())
                .map_err(|_| Error::Atom("failed to serialize P-384 key to PEM"))?
                .to_string()
                .into_bytes()
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

fn line_ending() -> LineEnding {
    #[cfg(unix)]
    return LineEnding::LF;
    #[cfg(windows)]
    return LineEnding::CRLF;
}
