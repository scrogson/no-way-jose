mod atoms;
mod rsa;
mod signer;

rustler::init! {
    "Elixir.NoWayJose.Native",
    [
        rsa::generate,
        signer::sign,
    ]
}
