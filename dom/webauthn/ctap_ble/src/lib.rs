/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Provides a subset of system Bluetooth LE APIs used by the CTAP caBLE/Hybrid transport.

#[macro_use]
extern crate xpcom;
mod central;
mod error;
mod manager;

pub use crate::error::Error;

pub type Result<T = ()> = std::result::Result<T, Error>;
