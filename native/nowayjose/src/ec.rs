use crate::key_resource::{Alg, KeyElixir, KeyInner, KeyResource};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p256::pkcs8::EncodePrivateKey as _;
use p256::pkcs8::EncodePublicKey as _;
use p256::pkcs8::LineEnding;
use p384::ecdsa::SigningKey as P384SigningKey;
use p384::ecdsa::VerifyingKey as P384VerifyingKey;
use rustler::types::atom::{error, ok};
use rustler::{Encoder, Env, Error, ResourceArc, Term};

fn line_ending() -> LineEnding {
    #[cfg(unix)]
    return LineEnding::LF;
    #[cfg(windows)]
    return LineEnding::CRLF;
}

/// Generate an EC key pair and return as KeyResource
#[rustler::nif(name = "generate_ec_key", schedule = "DirtyCpu")]
pub fn generate_key<'a>(env: Env<'a>, alg: Alg, kid: Option<String>) -> Result<Term<'a>, Error> {
    let mut rng = rand::thread_rng();

    // Determine curve from algorithm and generate keys
    let algorithm: Algorithm = alg.into();
    let (private_pem, public_pem): (String, String) = match algorithm {
        Algorithm::ES256 => {
            let signing_key = P256SigningKey::random(&mut rng);
            let verifying_key: &P256VerifyingKey = signing_key.verifying_key();

            let private = signing_key
                .to_pkcs8_pem(line_ending())
                .map_err(|_| Error::Atom("serialization_failed"))?
                .to_string();
            let public = verifying_key
                .to_public_key_pem(line_ending())
                .map_err(|_| Error::Atom("serialization_failed"))?;
            (private, public)
        }
        Algorithm::ES384 => {
            let signing_key = P384SigningKey::random(&mut rng);
            let verifying_key: &P384VerifyingKey = signing_key.verifying_key();

            let private = signing_key
                .to_pkcs8_pem(line_ending())
                .map_err(|_| Error::Atom("serialization_failed"))?
                .to_string();
            let public = verifying_key
                .to_public_key_pem(line_ending())
                .map_err(|_| Error::Atom("serialization_failed"))?;
            (private, public)
        }
        _ => return Ok((error(), crate::key_resource::KeyError::UnsupportedKeyType).encode(env)),
    };

    let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
        .map_err(|_| Error::Atom("encoding_key_failed"))?;
    let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
        .map_err(|_| Error::Atom("decoding_key_failed"))?;

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Ec {
            encoding_key: Some(encoding_key),
            decoding_key,
            private_pem: Some(private_pem),
            public_pem,
        },
    ));

    let key = KeyElixir {
        kid,
        alg,
        key_use: Some("sig".to_string()),
        key_ref: resource,
    };

    Ok((ok(), key).encode(env))
}
