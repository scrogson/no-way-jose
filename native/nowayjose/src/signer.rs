use jsonwebtoken::{self as jwt, Algorithm, EncodingKey, Header};
use rustler::types::atom::{error, ok};
use rustler::{Binary, Decoder, Encoder, Env, Error, NifStruct, NifUnitEnum, Term};
use serde_json::Value as JsonValue;

pub struct Json(JsonValue);

impl<'a> Decoder<'a> for Json {
    fn decode(term: Term<'a>) -> Result<Self, Error> {
        let value: JsonValue = rustler::serde::from_term(term)?;
        Ok(Json(value))
    }
}

#[derive(Debug, NifUnitEnum)]
pub enum SigningError {
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

#[derive(Debug, Clone, Copy, NifUnitEnum)]
pub enum Alg {
    RS256,
    RS512,
    ES256,
    ES384,
}

#[derive(Debug, Clone, Copy, NifUnitEnum)]
pub enum Format {
    Der,
    Pem,
}

#[derive(NifStruct)]
#[module = "NoWayJose.Signer"]
pub struct Signer<'a> {
    alg: Alg,
    key: Binary<'a>,
    format: Format,
    kid: Option<String>,
}

// Legacy NIF - no longer exported (replaced by key_resource::sign)
#[allow(dead_code)]
pub fn sign_legacy<'a>(env: Env<'a>, claims: Json, signer: Signer) -> Result<Term<'a>, Error> {
    let alg = match signer.alg {
        Alg::RS256 => Algorithm::RS256,
        Alg::RS512 => Algorithm::RS512,
        Alg::ES256 => Algorithm::ES256,
        Alg::ES384 => Algorithm::ES384,
    };

    let mut header = Header::new(alg);
    if let Some(kid) = signer.kid {
        header.kid = Some(kid);
    }

    let encoder = match (signer.alg, signer.format) {
        (Alg::RS256 | Alg::RS512, Format::Der) => EncodingKey::from_rsa_der(signer.key.as_slice()),
        (Alg::RS256 | Alg::RS512, Format::Pem) => {
            match EncodingKey::from_rsa_pem(signer.key.as_slice()) {
                Ok(encoder) => encoder,
                Err(err) => return Ok((error(), (SigningError::from(err))).encode(env)),
            }
        }
        (Alg::ES256 | Alg::ES384, Format::Der) => EncodingKey::from_ec_der(signer.key.as_slice()),
        (Alg::ES256 | Alg::ES384, Format::Pem) => {
            match EncodingKey::from_ec_pem(signer.key.as_slice()) {
                Ok(encoder) => encoder,
                Err(err) => return Ok((error(), (SigningError::from(err))).encode(env)),
            }
        }
    };

    match jwt::encode(&header, &claims.0, &encoder) {
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
            InvalidRsaKey(_) => SigningError::InvalidRsaKey,
            InvalidAlgorithmName => SigningError::InvalidAlgorithmName,
            InvalidKeyFormat => SigningError::InvalidKeyFormat,
            Base64(_) => SigningError::InvalidBase64,
            Json(_) => SigningError::InvalidJson,
            Utf8(_) => SigningError::InvalidUtf8,
            _ => SigningError::UnknownError,
        }
    }
}
