/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Implementation of the Noise protocol.

extern crate nserror;
extern crate nss_rs;
extern crate sha2;
#[macro_use]
extern crate xpcom;

mod channel;
mod cipher;
mod cipher_state;
use nss_rs::aead::AeadAlgorithms;

pub use crate::{cipher_state::CipherState, channel::Channel};

pub type Result<T = ()> = std::result::Result<T, nserror::nsresult>;
pub const ALG: AeadAlgorithms = AeadAlgorithms::Aes256Gcm;
pub const KEY_LENGTH: usize = ALG.key_len() as usize;
