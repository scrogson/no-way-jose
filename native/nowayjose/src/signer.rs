use crate::atoms::{error, ok};
use jsonwebtoken::{self as jwt, Algorithm, EncodingKey, Header};
use rustler::{Binary, Encoder, Env, Error, NifStruct, NifUnitEnum, Term};
use serde_json::Value;
use serde_rustler::from_term;

#[derive(Debug, NifUnitEnum)]
enum SigningError {
    InvalidToken,
    InvalidSignature,
    InvalidEcdsaKey,
    InvalidRsaKey,
    InvalidAlgorithmName,
    InvalidKeyFormat,
    InvalidBase64,
    InvalidJson,
    InvalidUtf8,
    UnknownError,
}

#[derive(Debug, NifUnitEnum)]
enum Alg {
    RS512,
}

#[derive(Debug, NifUnitEnum)]
enum Format {
    Der,
    Pem,
}

#[derive(NifStruct)]
#[module = "NoWayJose.Signer"]
struct Signer<'a> {
    alg: Alg,
    key: Binary<'a>,
    format: Format,
    kid: Option<String>,
}

pub fn sign<'a>(env: Env<'a>, args: &[Term<'a>]) -> Result<Term<'a>, Error> {
    let claims: Value = from_term(args[0])?;
    let signer: Signer = args[1].decode()?;

    let alg = match signer.alg {
        Alg::RS512 => Algorithm::RS512,
    };

    let mut header = Header::new(alg);
    if let Some(kid) = signer.kid {
        header.kid = Some(kid);
    }

    let encoder = match (signer.alg, signer.format) {
        (Alg::RS512, Format::Der) => EncodingKey::from_rsa_der(signer.key.as_slice()),
        (Alg::RS512, Format::Pem) => match EncodingKey::from_rsa_pem(signer.key.as_slice()) {
            Ok(encoder) => encoder,
            Err(err) => return Ok((error(), SigningError::from(err)).encode(env)),
        },
    };

    match jwt::encode(&header, &claims, &encoder) {
        Ok(token) => Ok((ok(), token).encode(env)),
        Err(err) => Ok((error(), SigningError::from(err)).encode(env)),
    }
}

impl From<jwt::errors::Error> for SigningError {
    fn from(err: jwt::errors::Error) -> SigningError {
        use jwt::errors::ErrorKind::*;

        match err.kind() {
            InvalidToken => SigningError::InvalidToken,
            InvalidSignature => SigningError::InvalidSignature,
            InvalidEcdsaKey => SigningError::InvalidEcdsaKey,
            InvalidRsaKey => SigningError::InvalidRsaKey,
            InvalidAlgorithmName => SigningError::InvalidAlgorithmName,
            InvalidKeyFormat => SigningError::InvalidKeyFormat,
            Base64(_) => SigningError::InvalidBase64,
            Json(_) => SigningError::InvalidJson,
            Utf8(_) => SigningError::InvalidUtf8,
            _ => SigningError::UnknownError,
        }
    }
}
