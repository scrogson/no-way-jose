use crate::atoms::{error, ok};
use jsonwebtoken::{self as jwt, Algorithm::RS512, Header};
use rustler::{Binary, Encoder, Env, Error, Term};
use serde_json::Value;
use serde_rustler::from_term;
use std::collections::HashMap;

pub fn sign<'a>(env: Env<'a>, args: &[Term<'a>]) -> Result<Term<'a>, Error> {
    let claims: HashMap<String, Value> = from_term(args[0])?;
    let key: Binary = args[1].decode()?;
    let header = Header::new(RS512);

    match jwt::encode(&header, &claims, key.as_slice()) {
        Ok(token) => Ok((ok(), token).encode(env)),
        Err(err) => Ok((error(), format!("{:?}", err)).encode(env)),
    }
}
