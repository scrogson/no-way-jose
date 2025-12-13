use jsonwebtoken::{
    self as jwt, jwk::JwkSet, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rustler::types::atom::{error, ok};
use rustler::{Binary, Encoder, Env, Error, NifStruct, NifUnitEnum, Resource, ResourceArc, Term};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::sync::Arc;

/// Unified key resource that holds cryptographic keys.
/// Private key material never crosses the NIF boundary.
pub struct KeyResource {
    pub(crate) alg: Algorithm,
    pub(crate) kid: Option<String>,
    pub(crate) inner: KeyInner,
}

impl KeyResource {
    pub fn new(alg: Algorithm, kid: Option<String>, inner: KeyInner) -> Self {
        Self { alg, kid, inner }
    }

    #[allow(dead_code)]
    pub fn can_sign(&self) -> bool {
        match &self.inner {
            KeyInner::Rsa { encoding_key, .. } => encoding_key.is_some(),
            KeyInner::Ec { encoding_key, .. } => encoding_key.is_some(),
            KeyInner::Jwk { .. } => false,
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.alg
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

#[rustler::resource_impl]
impl Resource for KeyResource {}

pub enum KeyInner {
    Rsa {
        encoding_key: Option<EncodingKey>,
        decoding_key: DecodingKey,
        #[allow(dead_code)]
        private_pem: Option<String>,
        public_pem: String,
    },
    Ec {
        encoding_key: Option<EncodingKey>,
        decoding_key: DecodingKey,
        #[allow(dead_code)]
        private_pem: Option<String>,
        public_pem: String,
    },
    /// JWK keys - verification only (jsonwebtoken doesn't support EncodingKey from JWK)
    Jwk {
        #[allow(dead_code)]
        jwk: Arc<jsonwebtoken::jwk::Jwk>,
        raw_public: String,
        decoding_key: DecodingKey,
    },
}

#[derive(Debug, NifUnitEnum)]
pub enum KeyError {
    InvalidKey,
    InvalidPem,
    InvalidDer,
    InvalidJwk,
    InvalidJwks,
    InvalidAlgorithm,
    UnsupportedKeyType,
    CannotSign,
    CannotVerify,
}

#[derive(Debug, NifUnitEnum)]
pub enum VerifyError {
    InvalidToken,
    InvalidSignature,
    InvalidKey,
    ExpiredSignature,
    ImmatureSignature,
    InvalidIssuer,
    InvalidAudience,
    InvalidSubject,
    MissingRequiredClaim,
    InvalidAlgorithm,
    UnknownError,
}

impl From<jwt::errors::Error> for VerifyError {
    fn from(err: jwt::errors::Error) -> Self {
        use jwt::errors::ErrorKind::*;
        match err.kind() {
            InvalidToken => VerifyError::InvalidToken,
            InvalidSignature => VerifyError::InvalidSignature,
            InvalidEcdsaKey | InvalidRsaKey(_) => VerifyError::InvalidKey,
            ExpiredSignature => VerifyError::ExpiredSignature,
            ImmatureSignature => VerifyError::ImmatureSignature,
            InvalidIssuer => VerifyError::InvalidIssuer,
            InvalidAudience => VerifyError::InvalidAudience,
            InvalidSubject => VerifyError::InvalidSubject,
            MissingRequiredClaim(_) => VerifyError::MissingRequiredClaim,
            InvalidAlgorithmName => VerifyError::InvalidAlgorithm,
            _ => VerifyError::UnknownError,
        }
    }
}

#[derive(Debug, Clone, Copy, NifUnitEnum)]
pub enum Alg {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    PS256,
    PS384,
    PS512,
    EdDSA,
}

impl From<Alg> for Algorithm {
    fn from(alg: Alg) -> Self {
        match alg {
            Alg::RS256 => Algorithm::RS256,
            Alg::RS384 => Algorithm::RS384,
            Alg::RS512 => Algorithm::RS512,
            Alg::ES256 => Algorithm::ES256,
            Alg::ES384 => Algorithm::ES384,
            Alg::PS256 => Algorithm::PS256,
            Alg::PS384 => Algorithm::PS384,
            Alg::PS512 => Algorithm::PS512,
            Alg::EdDSA => Algorithm::EdDSA,
        }
    }
}

impl TryFrom<Algorithm> for Alg {
    type Error = ();
    fn try_from(alg: Algorithm) -> Result<Self, Self::Error> {
        match alg {
            Algorithm::RS256 => Ok(Alg::RS256),
            Algorithm::RS384 => Ok(Alg::RS384),
            Algorithm::RS512 => Ok(Alg::RS512),
            Algorithm::ES256 => Ok(Alg::ES256),
            Algorithm::ES384 => Ok(Alg::ES384),
            Algorithm::PS256 => Ok(Alg::PS256),
            Algorithm::PS384 => Ok(Alg::PS384),
            Algorithm::PS512 => Ok(Alg::PS512),
            Algorithm::EdDSA => Ok(Alg::EdDSA),
            _ => Err(()),
        }
    }
}

/// Key struct returned to Elixir
#[derive(NifStruct)]
#[module = "NoWayJose.Key"]
pub struct KeyElixir {
    pub kid: Option<String>,
    pub alg: Alg,
    pub key_use: Option<String>,
    pub key_ref: ResourceArc<KeyResource>,
}

/// Validation options
#[derive(NifStruct)]
#[module = "NoWayJose.ValidationOpts"]
pub struct ValidationOpts {
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub leeway: u64,
    pub iss: Option<Vec<String>>,
    pub aud: Option<Vec<String>>,
    pub sub: Option<String>,
    pub required_claims: Vec<String>,
}

/// JWT Header struct
#[derive(NifStruct)]
#[module = "NoWayJose.Header"]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

// ============================================================================
// Key Loading NIFs
// ============================================================================

/// Load an RSA PEM key
#[rustler::nif]
pub fn load_rsa_pem<'a>(
    env: Env<'a>,
    pem_data: Binary<'a>,
    alg: Alg,
    kid: Option<String>,
) -> Result<Term<'a>, Error> {
    let pem_bytes = pem_data.as_slice();
    let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| Error::Atom("invalid_utf8"))?;
    let algorithm: Algorithm = alg.into();

    // Try to create encoding key (private key) - may fail for public-only
    let encoding_key = EncodingKey::from_rsa_pem(pem_bytes).ok();
    let has_private = encoding_key.is_some();

    // Create decoding key (public key)
    let decoding_key = match DecodingKey::from_rsa_pem(pem_bytes) {
        Ok(key) => key,
        Err(_) => return Ok((error(), KeyError::InvalidPem).encode(env)),
    };

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Rsa {
            encoding_key,
            decoding_key,
            private_pem: if has_private {
                Some(pem_str.to_string())
            } else {
                None
            },
            public_pem: pem_str.to_string(),
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

/// Load an RSA DER key
#[rustler::nif]
pub fn load_rsa_der<'a>(
    env: Env<'a>,
    der_data: Binary<'a>,
    alg: Alg,
    kid: Option<String>,
) -> Result<Term<'a>, Error> {
    let der_bytes = der_data.as_slice();
    let algorithm: Algorithm = alg.into();

    // DER encoding key (private)
    let encoding_key = Some(EncodingKey::from_rsa_der(der_bytes));

    // DER decoding key (public)
    let decoding_key = DecodingKey::from_rsa_der(der_bytes);

    // Convert DER to PEM for storage
    let pem_str = der_to_pem(der_bytes, "RSA PRIVATE KEY");

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Rsa {
            encoding_key,
            decoding_key,
            private_pem: Some(pem_str.clone()),
            public_pem: pem_str,
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

/// Load an EC PEM key
#[rustler::nif]
pub fn load_ec_pem<'a>(
    env: Env<'a>,
    pem_data: Binary<'a>,
    alg: Alg,
    kid: Option<String>,
) -> Result<Term<'a>, Error> {
    let pem_bytes = pem_data.as_slice();
    let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| Error::Atom("invalid_utf8"))?;
    let algorithm: Algorithm = alg.into();

    // Try to create encoding key (private key)
    let encoding_key = EncodingKey::from_ec_pem(pem_bytes).ok();
    let has_private = encoding_key.is_some();

    // Try to create decoding key (public key)
    let decoding_key = DecodingKey::from_ec_pem(pem_bytes).ok();

    // At least one key type must be available
    if encoding_key.is_none() && decoding_key.is_none() {
        return Ok((error(), KeyError::InvalidPem).encode(env));
    }

    // For EC keys, we need a placeholder decoding key if we only have private key
    let decoding_key = decoding_key.unwrap_or_else(|| DecodingKey::from_ec_der(&[]));

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Ec {
            encoding_key,
            decoding_key,
            private_pem: if has_private {
                Some(pem_str.to_string())
            } else {
                None
            },
            public_pem: pem_str.to_string(),
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

/// Load an EC DER key
#[rustler::nif]
pub fn load_ec_der<'a>(
    env: Env<'a>,
    der_data: Binary<'a>,
    alg: Alg,
    kid: Option<String>,
) -> Result<Term<'a>, Error> {
    let der_bytes = der_data.as_slice();
    let algorithm: Algorithm = alg.into();

    let encoding_key = Some(EncodingKey::from_ec_der(der_bytes));
    let decoding_key = DecodingKey::from_ec_der(der_bytes);

    // Convert DER to PEM for storage
    let pem_str = der_to_pem(der_bytes, "EC PRIVATE KEY");

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Ec {
            encoding_key,
            decoding_key,
            private_pem: Some(pem_str.clone()),
            public_pem: pem_str,
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

/// Load a single JWK from JSON
#[rustler::nif]
pub fn load_jwk<'a>(env: Env<'a>, json: &str) -> Result<Term<'a>, Error> {
    let jwk: jsonwebtoken::jwk::Jwk = match serde_json::from_str(json) {
        Ok(jwk) => jwk,
        Err(_) => return Ok((error(), KeyError::InvalidJwk).encode(env)),
    };

    let kid = jwk.common.key_id.clone();
    let key_use = jwk.common.public_key_use.clone().map(|u| {
        use jsonwebtoken::jwk::PublicKeyUse;
        match u {
            PublicKeyUse::Signature => "sig".to_string(),
            PublicKeyUse::Encryption => "enc".to_string(),
            PublicKeyUse::Other(s) => s,
        }
    });

    let algorithm = extract_algorithm_from_jwk(&jwk);
    let alg = match algorithm.try_into() {
        Ok(a) => a,
        Err(_) => return Ok((error(), KeyError::UnsupportedKeyType).encode(env)),
    };

    // Create decoding key (always available for JWK)
    let decoding_key = match DecodingKey::from_jwk(&jwk) {
        Ok(key) => key,
        Err(_) => return Ok((error(), KeyError::InvalidJwk).encode(env)),
    };

    let raw_public = extract_public_json(&jwk);

    let resource = ResourceArc::new(KeyResource::new(
        algorithm,
        kid.clone(),
        KeyInner::Jwk {
            jwk: Arc::new(jwk),
            raw_public,
            decoding_key,
        },
    ));

    let key = KeyElixir {
        kid,
        alg,
        key_use,
        key_ref: resource,
    };

    Ok((ok(), key).encode(env))
}

/// Load multiple keys from JWKS JSON
#[rustler::nif]
pub fn load_jwks<'a>(env: Env<'a>, json: &str) -> Result<Term<'a>, Error> {
    let jwks: JwkSet = match serde_json::from_str(json) {
        Ok(jwks) => jwks,
        Err(_) => return Ok((error(), KeyError::InvalidJwks).encode(env)),
    };

    let mut keys = Vec::new();

    for jwk in jwks.keys {
        let kid = jwk.common.key_id.clone();
        let key_use = jwk.common.public_key_use.clone().map(|u| {
            use jsonwebtoken::jwk::PublicKeyUse;
            match u {
                PublicKeyUse::Signature => "sig".to_string(),
                PublicKeyUse::Encryption => "enc".to_string(),
                PublicKeyUse::Other(s) => s,
            }
        });

        let algorithm = extract_algorithm_from_jwk(&jwk);
        let alg = match algorithm.try_into() {
            Ok(a) => a,
            Err(_) => continue, // Skip unsupported key types
        };

        // Create decoding key
        let decoding_key = match DecodingKey::from_jwk(&jwk) {
            Ok(key) => key,
            Err(_) => continue, // Skip keys that can't be decoded
        };

        let raw_public = extract_public_json(&jwk);

        let resource = ResourceArc::new(KeyResource::new(
            algorithm,
            kid.clone(),
            KeyInner::Jwk {
                jwk: Arc::new(jwk),
                raw_public,
                decoding_key,
            },
        ));

        keys.push(KeyElixir {
            kid,
            alg,
            key_use,
            key_ref: resource,
        });
    }

    Ok((ok(), keys).encode(env))
}

// ============================================================================
// Unified Sign/Verify NIFs
// ============================================================================

/// JSON wrapper for claims
pub struct Json(JsonValue);

impl<'a> rustler::Decoder<'a> for Json {
    fn decode(term: Term<'a>) -> Result<Self, Error> {
        let value: JsonValue = rustler::serde::from_term(term)?;
        Ok(Json(value))
    }
}

/// Unified sign function - dispatches based on key type
#[rustler::nif(schedule = "DirtyCpu")]
pub fn sign<'a>(
    env: Env<'a>,
    claims: Json,
    key_ref: ResourceArc<KeyResource>,
    kid_override: Option<String>,
) -> Result<Term<'a>, Error> {
    let key_resource: &KeyResource = &key_ref;
    let alg = key_resource.algorithm();
    let kid = kid_override.or_else(|| key_resource.kid().map(String::from));

    let mut header = Header::new(alg);
    header.kid = kid;

    let result = match &key_resource.inner {
        KeyInner::Rsa {
            encoding_key: Some(key),
            ..
        } => jwt::encode(&header, &claims.0, key),
        KeyInner::Ec {
            encoding_key: Some(key),
            ..
        } => jwt::encode(&header, &claims.0, key),
        // JWKs are verification-only (jsonwebtoken limitation)
        KeyInner::Jwk { .. } => return Ok((error(), KeyError::CannotSign).encode(env)),
        _ => return Ok((error(), KeyError::CannotSign).encode(env)),
    };

    match result {
        Ok(token) => Ok((ok(), token).encode(env)),
        Err(err) => Ok((error(), VerifyError::from(err)).encode(env)),
    }
}

/// Unified verify function - dispatches based on key type
#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify<'a>(
    env: Env<'a>,
    token: &str,
    key_ref: ResourceArc<KeyResource>,
    opts: ValidationOpts,
) -> Result<Term<'a>, Error> {
    let key_resource: &KeyResource = &key_ref;
    let alg = key_resource.algorithm();

    // Build validation
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

    let result = match &key_resource.inner {
        KeyInner::Rsa { decoding_key, .. } => {
            jwt::decode::<JsonValue>(token, decoding_key, &validation)
        }
        KeyInner::Ec { decoding_key, .. } => {
            jwt::decode::<JsonValue>(token, decoding_key, &validation)
        }
        KeyInner::Jwk { decoding_key, .. } => {
            jwt::decode::<JsonValue>(token, decoding_key, &validation)
        }
    };

    match result {
        Ok(token_data) => {
            let claims = rustler::serde::to_term(env, &token_data.claims)?;
            Ok((ok(), claims).encode(env))
        }
        Err(err) => Ok((error(), VerifyError::from(err)).encode(env)),
    }
}

/// Decode JWT header
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
        Err(err) => Ok((error(), VerifyError::from(err)).encode(env)),
    }
}

/// Export public key as JWK JSON (works for all key types with encoding keys)
#[rustler::nif]
pub fn export_public<'a>(
    env: Env<'a>,
    key_ref: ResourceArc<KeyResource>,
) -> Result<Term<'a>, Error> {
    let key_resource: &KeyResource = &key_ref;
    match &key_resource.inner {
        KeyInner::Jwk { raw_public, .. } => Ok((ok(), raw_public.clone()).encode(env)),
        _ => Ok((error(), KeyError::UnsupportedKeyType).encode(env)),
    }
}

/// Export key as JWK JSON using Jwk::from_encoding_key (works for RSA/EC keys)
#[rustler::nif]
pub fn export_jwk<'a>(env: Env<'a>, key_ref: ResourceArc<KeyResource>) -> Result<Term<'a>, Error> {
    use jsonwebtoken::jwk::{Jwk, PublicKeyUse};

    let key_resource: &KeyResource = &key_ref;
    let alg = key_resource.alg;
    let kid = &key_resource.kid;

    match &key_resource.inner {
        KeyInner::Rsa {
            encoding_key: Some(enc_key),
            ..
        } => {
            let mut jwk = Jwk::from_encoding_key(enc_key, alg)
                .map_err(|_| Error::Atom("jwk_conversion_failed"))?;
            jwk.common.key_id = kid.clone();
            jwk.common.public_key_use = Some(PublicKeyUse::Signature);
            let json =
                serde_json::to_string(&jwk).map_err(|_| Error::Atom("serialization_failed"))?;
            Ok((ok(), json).encode(env))
        }
        KeyInner::Ec {
            encoding_key: Some(enc_key),
            ..
        } => {
            let mut jwk = Jwk::from_encoding_key(enc_key, alg)
                .map_err(|_| Error::Atom("jwk_conversion_failed"))?;
            jwk.common.key_id = kid.clone();
            jwk.common.public_key_use = Some(PublicKeyUse::Signature);
            let json =
                serde_json::to_string(&jwk).map_err(|_| Error::Atom("serialization_failed"))?;
            Ok((ok(), json).encode(env))
        }
        KeyInner::Jwk { raw_public, .. } => {
            // Already have public JWK JSON
            Ok((ok(), raw_public.clone()).encode(env))
        }
        _ => Ok((error(), KeyError::CannotSign).encode(env)),
    }
}

/// Export key as PEM string
#[rustler::nif]
pub fn export_pem<'a>(env: Env<'a>, key_ref: ResourceArc<KeyResource>) -> Result<Term<'a>, Error> {
    let key_resource: &KeyResource = &key_ref;

    match &key_resource.inner {
        KeyInner::Rsa { public_pem, .. } => Ok((ok(), public_pem.clone()).encode(env)),
        KeyInner::Ec { public_pem, .. } => Ok((ok(), public_pem.clone()).encode(env)),
        KeyInner::Jwk { .. } => Ok((error(), KeyError::UnsupportedKeyType).encode(env)),
    }
}

/// Export key as DER bytes
#[rustler::nif]
pub fn export_der<'a>(env: Env<'a>, key_ref: ResourceArc<KeyResource>) -> Result<Term<'a>, Error> {
    let key_resource: &KeyResource = &key_ref;

    match &key_resource.inner {
        KeyInner::Rsa { public_pem, .. } => {
            let der = pem_to_der(public_pem)?;
            let mut binary =
                rustler::OwnedBinary::new(der.len()).ok_or(Error::Atom("alloc_failed"))?;
            binary.as_mut_slice().copy_from_slice(&der);
            Ok((ok(), rustler::Binary::from_owned(binary, env)).encode(env))
        }
        KeyInner::Ec { public_pem, .. } => {
            let der = pem_to_der(public_pem)?;
            let mut binary =
                rustler::OwnedBinary::new(der.len()).ok_or(Error::Atom("alloc_failed"))?;
            binary.as_mut_slice().copy_from_slice(&der);
            Ok((ok(), rustler::Binary::from_owned(binary, env)).encode(env))
        }
        KeyInner::Jwk { .. } => Ok((error(), KeyError::UnsupportedKeyType).encode(env)),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn extract_algorithm_from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Algorithm {
    // First try explicit algorithm
    if let Some(key_alg) = jwk.common.key_algorithm {
        use jsonwebtoken::jwk::KeyAlgorithm;
        return match key_alg {
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
            _ => Algorithm::RS256, // Default fallback
        };
    }

    // Infer from key type
    match &jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::RSA(_) => Algorithm::RS256,
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ec) => {
            use jsonwebtoken::jwk::EllipticCurve;
            match ec.curve {
                EllipticCurve::P256 => Algorithm::ES256,
                EllipticCurve::P384 => Algorithm::ES384,
                EllipticCurve::P521 => Algorithm::ES384, // P-521 not fully supported, fallback
                EllipticCurve::Ed25519 => Algorithm::EdDSA,
            }
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_) => Algorithm::HS256,
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(_) => Algorithm::EdDSA,
    }
}

fn extract_public_json(jwk: &jsonwebtoken::jwk::Jwk) -> String {
    // Serialize JWK to JSON, then parse and strip private components
    let json_str = serde_json::to_string(jwk).unwrap_or_default();
    let mut json: serde_json::Map<String, JsonValue> =
        serde_json::from_str(&json_str).unwrap_or_default();

    // Remove private key components
    // RSA: d, p, q, dp, dq, qi
    // EC: d
    // Symmetric: k (but we keep it for HMAC... actually no, that's the secret)
    json.remove("d");
    json.remove("p");
    json.remove("q");
    json.remove("dp");
    json.remove("dq");
    json.remove("qi");
    json.remove("k"); // Symmetric key secret

    serde_json::to_string(&json).unwrap_or_default()
}

/// Convert DER bytes to PEM string
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b64 = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Convert PEM string to DER bytes
fn pem_to_der(pem: &str) -> Result<Vec<u8>, Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // Find the base64 content between header and footer
    let lines: Vec<&str> = pem.lines().collect();
    let mut b64 = String::new();
    let mut in_body = false;

    for line in lines {
        if line.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(line.trim());
        }
    }

    STANDARD
        .decode(&b64)
        .map_err(|_| Error::Atom("invalid_pem"))
}
