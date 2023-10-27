//! Constants and utilities for conversion between Rust string-likes and Elixir atoms.

use crate::serde::Error;
use rustler::{
    types::{atom as atoms, tuple},
    Atom, Binary, Decoder, Encoder, Env, Term,
};

lazy_static::lazy_static! {
    pub static ref OK: String = String::from("Ok");
    pub static ref ERROR: String = String::from("Err");
}

/**
 * Attempts to create an atom term from the provided string (if the atom already exists in the atom table). If not, returns a string term.
 */
pub fn str_to_term<'a>(env: &Env<'a>, string: &str) -> Result<Term<'a>, Error> {
    if string == "Ok" {
        Ok(ok().encode(*env))
    } else if string == "Err" {
        Ok(error().encode(*env))
    } else {
        match Atom::try_from_bytes(*env, string.as_bytes()) {
            Ok(Some(term)) => Ok(term.encode(*env)),
            Ok(None) => Err(Error::InvalidStringable),
            _ => Err(Error::InvalidStringable),
        }
    }
}

/**
 * Attempts to create a `String` from the term.
 */
pub fn term_to_string(term: &Term) -> Result<String, Error> {
    if ok().eq(term) {
        Ok(OK.to_string())
    } else if error().eq(term) {
        Ok(ERROR.to_string())
    } else if term.is_atom() {
        term.atom_to_string().or(Err(Error::InvalidAtom))
    } else {
        Err(Error::InvalidStringable)
    }
}

/// Converts an `&str` to either an existing atom or an Elixir bitstring.
pub fn str_to_term<'a>(env: &Env<'a>, string: &str) -> Result<Term<'a>, Error> {
    atoms::str_to_term(env, string).or_else(|_| Ok(string.encode(*env)))
}

/// Attempts to convert a stringable term into a `String`.
pub fn term_to_str(term: &Term) -> Result<String, Error> {
    atoms::term_to_string(term)
        .or_else(|_| term.decode())
        .or(Err(Error::ExpectedStringable))
}

pub fn is_nil(term: &Term) -> bool {
    atoms::nil().eq(term)
}

/// Parses a boolean from a Term.
pub fn parse_bool(term: &Term) -> Result<bool, Error> {
    if atoms::true_().eq(term) {
        Ok(true)
    } else if atoms::false_().eq(term) {
        Ok(false)
    } else {
        Err(Error::ExpectedBoolean)
    }
}

pub fn parse_binary(term: Term) -> Result<&[u8], Error> {
    validate_binary(&term)?;
    let binary: Binary = term.decode().or(Err(Error::ExpectedBinary))?;
    Ok(binary.as_slice())
}

pub fn parse_number<'a, T: Decoder<'a>>(term: &Term<'a>) -> Result<T, Error> {
    if !term.is_number() {
        return Err(Error::InvalidNumber);
    }

    term.decode().or(Err(Error::ExpectedNumber))
}

pub fn parse_str(term: Term) -> Result<&str, Error> {
    let bytes = parse_binary(term)?;
    std::str::from_utf8(bytes).or(Err(Error::ExpectedStringable))
}

/// Asserts that the term is an Elixir binary
pub fn validate_binary(term: &Term) -> Result<(), Error> {
    if !term.is_binary() {
        Err(Error::ExpectedBinary)
    } else {
        Ok(())
    }
}

/// Assert that the term is an Elixir tuple, and if so, return the underlying `Vec<Term>`.
pub fn validate_tuple(term: Term, len: Option<usize>) -> Result<Vec<Term>, Error> {
    if !term.is_tuple() {
        return Err(Error::ExpectedTuple);
    }

    let tuple = tuple::get_tuple(term).or(Err(Error::ExpectedTuple))?;
    match len {
        None => Ok(tuple),
        Some(len) => {
            if tuple.len() == len {
                Ok(tuple)
            } else {
                Err(Error::InvalidTuple)
            }
        }
    }
}

pub fn validate_struct<'a>(term: &Term<'a>, name: Option<&str>) -> Result<Term<'a>, Error> {
    if !term.is_map() {
        return Err(Error::ExpectedMap);
    }

    let __struct__ = atoms::__struct__().to_term(term.get_env());
    let struct_name_term = term.map_get(__struct__).or(Err(Error::ExpectedStruct))?;

    match name {
        Some(name) => {
            let name_term =
                atoms::str_to_term(&term.get_env(), name).or(Err(Error::InvalidStructName))?;

            if struct_name_term.eq(&name_term) {
                Ok(struct_name_term)
            } else {
                Err(Error::ExpectedStruct)
            }
        }
        _ => Ok(struct_name_term),
    }
}
