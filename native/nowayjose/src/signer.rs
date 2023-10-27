use jsonwebtoken::{self as jwt, Algorithm, EncodingKey, Header};
use rustler::types::atom::{error, ok};
use rustler::{Binary, Decoder, Encoder, Env, Error, NifStruct, NifUnitEnum, Term};
use serde_json::Value as JsonValue;

pub struct Json(JsonValue);

impl<'a> Decoder<'a> for Json {
    fn decode(term: Term<'a>) -> Result<Self, Error> {
        let value: JsonValue = crate::serde::from_term(term)?;
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

#[derive(Debug, NifUnitEnum)]
pub enum Alg {
    RS512,
}

#[derive(Debug, NifUnitEnum)]
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

#[rustler::nif(schedule = "DirtyCpu")]
pub fn sign<'a>(env: Env<'a>, claims: Json, signer: Signer) -> Result<Term<'a>, Error> {
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
            Err(err) => return Ok((error(), (SigningError::from(err))).encode(env)),
        },
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

//impl From<SigningError> for Error {
//fn from(err: SigningError) -> Self {
//let error_string = format!("{:?}", err);
//let leaked_string = Box::leak(error_string.into_boxed_str());
//Error::Atom(leaked_string)
//}
//}
