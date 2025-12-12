use crate::signer::{Alg, Format};
use jsonwebtoken::{self as jwt, Algorithm, DecodingKey, Validation};
use rustler::types::atom::{error, ok};
use rustler::{Binary, Encoder, Env, Error, NifStruct, NifUnitEnum, Term};
use serde_json::Value as JsonValue;
use std::collections::HashSet;

#[derive(Debug, NifUnitEnum)]
pub enum VerificationError {
    InvalidToken,
    InvalidSignature,
    InvalidEcdsaKey,
    InvalidRsaKey,
    InvalidAlgorithmName,
    InvalidKeyFormat,
    InvalidBase64,
    InvalidJson,
    InvalidUtf8,
    ExpiredSignature,
    ImmatureSignature,
    InvalidIssuer,
    InvalidAudience,
    InvalidSubject,
    MissingRequiredClaim,
    UnknownError,
}

impl From<jwt::errors::Error> for VerificationError {
    fn from(err: jwt::errors::Error) -> VerificationError {
        use jwt::errors::ErrorKind::*;

        match err.kind() {
            InvalidToken => VerificationError::InvalidToken,
            InvalidSignature => VerificationError::InvalidSignature,
            InvalidEcdsaKey => VerificationError::InvalidEcdsaKey,
            InvalidRsaKey(_) => VerificationError::InvalidRsaKey,
            InvalidAlgorithmName => VerificationError::InvalidAlgorithmName,
            InvalidKeyFormat => VerificationError::InvalidKeyFormat,
            Base64(_) => VerificationError::InvalidBase64,
            Json(_) => VerificationError::InvalidJson,
            Utf8(_) => VerificationError::InvalidUtf8,
            ExpiredSignature => VerificationError::ExpiredSignature,
            ImmatureSignature => VerificationError::ImmatureSignature,
            InvalidIssuer => VerificationError::InvalidIssuer,
            InvalidAudience => VerificationError::InvalidAudience,
            InvalidSubject => VerificationError::InvalidSubject,
            MissingRequiredClaim(_) => VerificationError::MissingRequiredClaim,
            _ => VerificationError::UnknownError,
        }
    }
}

#[derive(NifStruct)]
#[module = "NoWayJose.Verifier"]
pub struct Verifier<'a> {
    alg: Alg,
    key: Binary<'a>,
    format: Format,
    validate_exp: bool,
    validate_nbf: bool,
    leeway: u64,
    iss: Option<Vec<String>>,
    aud: Option<Vec<String>>,
    sub: Option<String>,
    required_claims: Vec<String>,
}

#[derive(NifStruct)]
#[module = "NoWayJose.Header"]
pub struct JwtHeader {
    alg: String,
    typ: Option<String>,
    kid: Option<String>,
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify<'a>(env: Env<'a>, token: &str, verifier: Verifier) -> Result<Term<'a>, Error> {
    let alg = match verifier.alg {
        Alg::RS256 => Algorithm::RS256,
        Alg::RS512 => Algorithm::RS512,
        Alg::ES256 => Algorithm::ES256,
        Alg::ES384 => Algorithm::ES384,
    };

    // Build DecodingKey based on algorithm and format
    let decoder = match (verifier.alg, verifier.format) {
        (Alg::RS256 | Alg::RS512, Format::Der) => {
            DecodingKey::from_rsa_der(verifier.key.as_slice())
        }
        (Alg::RS256 | Alg::RS512, Format::Pem) => {
            match DecodingKey::from_rsa_pem(verifier.key.as_slice()) {
                Ok(key) => key,
                Err(err) => return Ok((error(), VerificationError::from(err)).encode(env)),
            }
        }
        (Alg::ES256 | Alg::ES384, Format::Der) => DecodingKey::from_ec_der(verifier.key.as_slice()),
        (Alg::ES256 | Alg::ES384, Format::Pem) => {
            match DecodingKey::from_ec_pem(verifier.key.as_slice()) {
                Ok(key) => key,
                Err(err) => return Ok((error(), VerificationError::from(err)).encode(env)),
            }
        }
    };

    // Build Validation struct
    let mut validation = Validation::new(alg);
    validation.validate_exp = verifier.validate_exp;
    validation.validate_nbf = verifier.validate_nbf;
    validation.leeway = verifier.leeway;

    if let Some(issuers) = verifier.iss {
        validation.iss = Some(issuers.into_iter().collect::<HashSet<_>>());
    }

    if let Some(audiences) = verifier.aud {
        validation.aud = Some(audiences.into_iter().collect::<HashSet<_>>());
    }

    if let Some(sub) = verifier.sub {
        validation.sub = Some(sub);
    }

    if !verifier.required_claims.is_empty() {
        validation.required_spec_claims = verifier.required_claims.into_iter().collect();
    }

    // Decode and verify
    match jwt::decode::<JsonValue>(token, &decoder, &validation) {
        Ok(token_data) => {
            let claims = rustler::serde::to_term(env, &token_data.claims)?;
            Ok((ok(), claims).encode(env))
        }
        Err(err) => Ok((error(), VerificationError::from(err)).encode(env)),
    }
}

#[rustler::nif]
pub fn decode_header<'a>(env: Env<'a>, token: &str) -> Result<Term<'a>, Error> {
    match jwt::decode_header(token) {
        Ok(header) => {
            let result = JwtHeader {
                alg: format!("{:?}", header.alg),
                typ: header.typ,
                kid: header.kid,
            };
            Ok((ok(), result).encode(env))
        }
        Err(err) => Ok((error(), VerificationError::from(err)).encode(env)),
    }
}
