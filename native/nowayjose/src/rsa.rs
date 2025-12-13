use crate::key_resource::{Alg, KeyElixir, KeyInner, KeyResource};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding},
    RsaPrivateKey,
};
use rustler::types::atom::ok;
use rustler::{Encoder, Env, Error, ResourceArc, Term};

fn line_ending() -> LineEnding {
    #[cfg(unix)]
    return LineEnding::LF;
    #[cfg(windows)]
    return LineEnding::CRLF;
}

/// Generate an RSA key pair and return as KeyResource
#[rustler::nif(name = "generate_rsa_key", schedule = "DirtyCpu")]
pub fn generate_key<'a>(
    env: Env<'a>,
    alg: Alg,
    bits: usize,
    kid: Option<String>,
) -> Result<Term<'a>, Error> {
    let mut rng = rand::thread_rng();

    let private_key =
        RsaPrivateKey::new(&mut rng, bits).map_err(|_| Error::Atom("key_generation_failed"))?;
    let public_key = private_key.to_public_key();

    // Convert to PEM format
    let private_pem = private_key
        .to_pkcs1_pem(line_ending())
        .map_err(|_| Error::Atom("serialization_failed"))?;
    let public_pem = public_key
        .to_pkcs1_pem(line_ending())
        .map_err(|_| Error::Atom("serialization_failed"))?;

    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
        .map_err(|_| Error::Atom("encoding_key_failed"))?;
    let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|_| Error::Atom("decoding_key_failed"))?;

    let resource = ResourceArc::new(KeyResource::new(KeyInner::Rsa {
        encoding_key: Some(encoding_key),
        decoding_key,
        alg: alg.into(),
        kid: kid.clone(),
    }));

    let key = KeyElixir {
        kid,
        alg,
        key_use: Some("sig".to_string()),
        key_ref: resource,
    };

    Ok((ok(), key).encode(env))
}
