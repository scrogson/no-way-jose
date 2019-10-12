use rustler::{SchedulerFlags::*, Term};

mod atoms;
mod signer;

rustler::rustler_export_nifs! {
    "Elixir.NoWayJose.Native",
    [
        ("sign", 2, signer::sign, DirtyCpu)
    ],
    None
}
