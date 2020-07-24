use rustler::{SchedulerFlags::*, Term};

mod atoms;
mod rsa;
mod signer;

rustler::rustler_export_nifs! {
    "Elixir.NoWayJose.Native",
    [
        ("sign", 2, signer::sign, DirtyCpu),
        ("generate_rsa", 2, rsa::generate, DirtyCpu)
    ],
    None
}
