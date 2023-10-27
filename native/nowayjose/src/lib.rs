mod rsa;
mod serde;
mod signer;

rustler::init!("Elixir.NoWayJose.Native", [signer::sign, rsa::generate]);
