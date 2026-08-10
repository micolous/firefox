/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Implements a subset of Noise protocol used by the CTAP caBLE/Hybrid transport.

#[cfg(feature = "xpcom")]
#[macro_use]
extern crate xpcom;

pub mod base10;
#[macro_use]
mod channel;
pub mod discovery;
mod ec;
mod error;
mod handshake;
mod hash;
mod padding;
mod symmetric_state;

use nss_rs::aead::AeadAlgorithms;
use std::fmt::Write as _;

pub use crate::{
    channel::Channel,
    error::Error,
    handshake::{Initiator, InitiatorHandshake, Responder},
    hash::Sha256,
    symmetric_state::SymmetricState,
};

pub type Result<T = ()> = std::result::Result<T, Error>;
pub const ALG: AeadAlgorithms = AeadAlgorithms::Aes256Gcm;
pub const KEY_LENGTH: usize = ALG.key_len() as usize;

/// Convert `buf` to an upper-case, base16 encoded string.
#[must_use]
fn hex<A: AsRef<[u8]>>(buf: A) -> String {
    let buf = buf.as_ref();
    let mut ret = String::with_capacity(buf.len() * 2);
    for b in buf {
        write!(&mut ret, "{b:02X}").expect("write OK");
    }
    ret
}
