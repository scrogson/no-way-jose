use crate::verifier::VerificationError;
use jsonwebtoken::{self as jwt, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rustler::types::atom::{error, ok};
use rustler::{Encoder, Env, Error, NifStruct, NifUnitEnum, Term};
use serde_json::Value as JsonValue;
use std::collections::HashSet;

#[derive(Debug, NifUnitEnum)]
pub enum JwksError {
    InvalidJwks,
    InvalidJwk,
    UnsupportedKeyType,
}

#[derive(NifStruct)]
#[module = "NoWayJose.Jwk"]
pub struct JwkElixir {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    key_use: Option<String>,
    raw: String,
}

/// Validation options passed from Elixir for verify_with_jwk
#[derive(NifStruct)]
#[module = "NoWayJose.ValidationOpts"]
pub struct ValidationOpts {
    validate_exp: bool,
    validate_nbf: bool,
    leeway: u64,
    iss: Option<Vec<String>>,
    aud: Option<Vec<String>>,
    sub: Option<String>,
    required_claims: Vec<String>,
}

#[rustler::nif]
pub fn parse_jwks<'a>(env: Env<'a>, json: &str) -> Result<Term<'a>, Error> {
    match serde_json::from_str::<JwkSet>(json) {
        Ok(jwks) => {
            let keys: Vec<JwkElixir> = jwks
                .keys
                .iter()
                .map(|jwk| {
                    let kty = match &jwk.algorithm {
                        jsonwebtoken::jwk::AlgorithmParameters::RSA(_) => "RSA".to_string(),
                        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(_) => {
                            "EC".to_string()
                        }
                        jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_) => "oct".to_string(),
                        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(_) => {
                            "OKP".to_string()
                        }
                    };

                    JwkElixir {
                        kid: jwk.common.key_id.clone(),
                        kty,
                        alg: jwk.common.key_algorithm.map(|a| format!("{:?}", a)),
                        key_use: jwk
                            .common
                            .public_key_use
                            .clone()
                            .map(|u| format!("{:?}", u)),
                        raw: serde_json::to_string(jwk).unwrap_or_default(),
                    }
                })
                .collect();
            Ok((ok(), keys).encode(env))
        }
        Err(_) => Ok((error(), JwksError::InvalidJwks).encode(env)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify_with_jwk<'a>(
    env: Env<'a>,
    token: &str,
    jwk_json: &str,
    opts: ValidationOpts,
) -> Result<Term<'a>, Error> {
    // Parse JWK
    let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_str(jwk_json) {
        Ok(jwk) => jwk,
        Err(_) => return Ok((error(), JwksError::InvalidJwk).encode(env)),
    };

    // Get algorithm from JWK or decode from token header
    let alg: Algorithm = match jwk.common.key_algorithm {
        Some(key_alg) => {
            // Convert KeyAlgorithm to Algorithm
            use jsonwebtoken::jwk::KeyAlgorithm;
            match key_alg {
                KeyAlgorithm::RS256 => Algorithm::RS256,
                KeyAlgorithm::RS384 => Algorithm::RS384,
                KeyAlgorithm::RS512 => Algorithm::RS512,
                KeyAlgorithm::ES256 => Algorithm::ES256,
                KeyAlgorithm::ES384 => Algorithm::ES384,
                KeyAlgorithm::PS256 => Algorithm::PS256,
                KeyAlgorithm::PS384 => Algorithm::PS384,
                KeyAlgorithm::PS512 => Algorithm::PS512,
                KeyAlgorithm::EdDSA => Algorithm::EdDSA,
                KeyAlgorithm::HS256 => Algorithm::HS256,
                KeyAlgorithm::HS384 => Algorithm::HS384,
                KeyAlgorithm::HS512 => Algorithm::HS512,
                _ => return Ok((error(), JwksError::UnsupportedKeyType).encode(env)),
            }
        }
        None => {
            // Try to get algorithm from token header
            match jwt::decode_header(token) {
                Ok(header) => header.alg,
                Err(err) => return Ok((error(), VerificationError::from(err)).encode(env)),
            }
        }
    };

    // Create DecodingKey from JWK
    let decoder = match DecodingKey::from_jwk(&jwk) {
        Ok(key) => key,
        Err(err) => return Ok((error(), VerificationError::from(err)).encode(env)),
    };

    // Build Validation struct
    let mut validation = Validation::new(alg);
    validation.validate_exp = opts.validate_exp;
    validation.validate_nbf = opts.validate_nbf;
    validation.leeway = opts.leeway;

    if let Some(issuers) = opts.iss {
        validation.iss = Some(issuers.into_iter().collect::<HashSet<_>>());
    }

    if let Some(audiences) = opts.aud {
        validation.aud = Some(audiences.into_iter().collect::<HashSet<_>>());
    }

    if let Some(sub) = opts.sub {
        validation.sub = Some(sub);
    }

    if !opts.required_claims.is_empty() {
        validation.required_spec_claims = opts.required_claims.into_iter().collect();
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
