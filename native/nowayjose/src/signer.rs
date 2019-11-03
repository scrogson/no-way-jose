use crate::atoms::{error, ok};
use jsonwebtoken::{self as jwt, Algorithm::RS512, Header};
use rustler::{Atom, Binary, Error, Term};
use serde_json::Value;

#[rustler::nif(schedule = "DirtyCpu")]
pub fn sign(claims: Term, key: Binary) -> Result<(Atom, String), Error> {
    let claims: Value = serde_rustler::from_term(claims)?;
    let header = Header::new(RS512);

    match jwt::encode(&header, &claims, key.as_slice()) {
        Ok(token) => Ok((ok(), token)),
        Err(err) => Ok((error(), format!("{:?}", err))),
    }
}
