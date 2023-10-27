use rustler::Error as NifError;
use serde::{de, ser};
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    DeserializationError(String),
    TypeHintsRequired,
    InvalidAtom,
    InvalidBoolean,
    InvalidNumber,
    InvalidStringable,
    InvalidList,
    InvalidTuple,
    InvalidSequenceElement,
    ExpectedAtom,
    ExpectedBoolean,
    ExpectedBinary,
    ExpectedInteger,
    ExpectedFloat,
    ExpectedChar,
    ExpectedStringable,
    ExpectedNil,
    ExpectedList,
    ExpectedTuple,
    ExpectedEnum,
    ExpectedMap,
    ExpectedStruct,
    ExpectedStructName,
    ExpectedStructValue,
    ExpectedUnitVariant,
    ExpectedNewtypeStruct,
    ExpectedNewtypeVariant,
    ExpectedTupleVariant,
    ExpectedStructVariant,
    SerializationError(String),
    InvalidVariantName,
    InvalidStructName,
    InvalidBinary,
    InvalidMap,
    InvalidStruct,
    InvalidStructKey,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::DeserializationError(err) => write!(f, "{}", err),
            Error::TypeHintsRequired => {
                write!(f, "Cannot deserialize any, type hints are required")
            }
            Error::InvalidAtom => write!(f, "Failed to deserialize atom"),
            Error::InvalidBoolean => write!(f, "Failed to deserialize boolean"),
            Error::InvalidNumber => write!(f, "Failed to deserialize number"),
            Error::InvalidStringable => write!(f, "Failed to deserialize term as an &str"),
            Error::InvalidList => write!(f, "Failed to deserialize list"),
            Error::InvalidTuple => write!(f, "Failed to deserialize tuple"),
            Error::InvalidSequenceElement => write!(f, "Failed to deserialize sequence element"),
            Error::ExpectedAtom => write!(f, "Expected to deserialize atom"),
            Error::ExpectedBoolean => write!(f, "Expected to deserialize boolean"),
            Error::ExpectedBinary => write!(f, "Expected to deserialize binary"),
            Error::ExpectedInteger => write!(f, "Expected to deserialize integer"),
            Error::ExpectedFloat => write!(f, "Expected to deserialize float"),
            Error::ExpectedChar => write!(f, "Expected to deserialize char"),
            Error::ExpectedStringable => {
                write!(f, "Expected to deserialize a UTF-8 stringable term")
            }
            Error::ExpectedNil => write!(f, "Expected to deserialize nil"),
            Error::ExpectedList => write!(f, "Expected to deserialize list"),
            Error::ExpectedTuple => write!(f, "Expected to deserialize tuple"),
            Error::ExpectedEnum => write!(f, "Expected to deserialize enum"),
            Error::ExpectedMap => write!(f, "Expected to deserialize map"),
            Error::ExpectedStruct => write!(f, "Expected to deserialize struct"),
            Error::ExpectedStructName => write!(f, "Expected to deserialize struct name"),
            Error::ExpectedStructValue => write!(f, "Expected to deserialize struct value"),
            Error::ExpectedUnitVariant => write!(f, "Expected to deserialize unit variant"),
            Error::ExpectedNewtypeStruct => {
                write!(f, "Expected to deserialize newtype struct tuple")
            }
            Error::ExpectedNewtypeVariant => write!(f, "Expected to deserialize newtype variant"),
            Error::ExpectedTupleVariant => write!(f, "Expected to deserialize tuple variant"),
            Error::ExpectedStructVariant => write!(f, "Expected to deserialize struct variant"),
            Error::SerializationError(err) => write!(f, "{}", err),
            Error::InvalidVariantName => write!(f, "Failed to serialize variant to atom or string"),
            Error::InvalidStructName => {
                write!(f, "Failed to serialize struct name to atom or string")
            }
            Error::InvalidBinary => write!(f, "Failed to serialize binary"),
            Error::InvalidMap => write!(f, "Failed to serialize map to NIF map"),
            Error::InvalidStruct => write!(f, "Failed to serialize struct to NIF struct"),
            Error::InvalidStructKey => write!(f, "Failed to serialize struct key"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for NifError {
    fn from(err: Error) -> NifError {
        NifError::RaiseTerm(Box::new(err.to_string()))
    }
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Error {
        Error::SerializationError(msg.to_string())
    }
}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Error {
        Error::DeserializationError(msg.to_string())
    }
}
