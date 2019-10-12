use crate::atoms::{error, ok};
use frank_jwt::Algorithm::RS512;
use rustler::{Encoder, Env, Error, Term};
use serde_json::{json, Value};
use serde_rustler::from_term;
use std::collections::HashMap;

pub fn sign<'a>(env: Env<'a>, args: &[Term<'a>]) -> Result<Term<'a>, Error> {
    let claims: HashMap<String, Value> = from_term(args[0])?;
    let key: String = from_term(args[1])?;
    let json_claims = serde_json::to_value(claims).unwrap();

    match frank_jwt::encode(json!({}), &key, &json_claims, RS512) {
        Ok(token) => Ok((ok(), token).encode(env)),
        Err(err) => Ok((error(), format!("{:?}", err)).encode(env)),
    }
}
