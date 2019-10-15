use rustler::{SchedulerFlags::*, Term};

mod rsa;

rustler::rustler_export_nifs! {
    "Elixir.NoWayJose.TestUtils",
    [
        ("generate_rsa", 2, rsa::generate, DirtyCpu)
    ],
    None
}
