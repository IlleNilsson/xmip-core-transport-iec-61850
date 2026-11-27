//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// The domain of the variable a Stream travels as unless a target says
/// otherwise.
pub const STREAM_DOMAIN: &str = "XMIP";
/// The item of that variable, within [`STREAM_DOMAIN`].
pub const STREAM_ITEM: &str = "Stream";

/// Every setting a Location takes beyond its address, the server's host and
/// port, 102 by the standard: where a Location connects.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "domain",
            kind: Kind::Text,
            presence: Presence::Default(Fixed::Text(STREAM_DOMAIN)),
            meaning: "The domain of the variable that is the Stream.",
            applies: Applies::Both,
        },
        Setting {
            name: "item",
            kind: Kind::Text,
            presence: Presence::Default(Fixed::Text(STREAM_ITEM)),
            meaning: "The item of the variable that is the Stream, within its domain.",
            applies: Applies::Both,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a peer that stops mid-message is waited on; unbounded when \
             left out.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["iec61850"];
