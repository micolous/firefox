/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE advertisement suffix.

use crate::{Error, Result};
use serde_cbor_2::{from_slice, ser::to_vec_packed, Value};
use std::collections::BTreeMap;

/// caBLE advertisement suffix.
///
/// <https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#advertisement-suffix>
#[derive(Debug, Default, PartialEq)]
pub struct Suffix {
    /// The transport that the authenticator will use for further communication.
    pub transport_channel_identifier: Option<u32>,
}

impl Suffix {
    const KEY_TRANSPORT_CHANNEL_IDENTIFIER: Value = Value::Integer(0);

    /// Serialize [`Suffix`][] as CBOR.
    ///
    /// Returns `None` when no parameters are set.
    pub fn as_cbor(&self) -> Result<Option<Vec<u8>>> {
        let mut m = BTreeMap::new();

        if let Some(transport_channel_identifier) = self.transport_channel_identifier {
            m.insert(
                Self::KEY_TRANSPORT_CHANNEL_IDENTIFIER,
                Value::Integer(transport_channel_identifier.into()),
            );
        }

        if m.is_empty() {
            return Ok(None);
        }

        to_vec_packed(&m).map(Some).map_err(|_| Error::Internal)
    }

    /// Parse a [`Suffix`][] from CBOR.
    pub fn from_cbor(cbor: &[u8]) -> Result<Self> {
        let cbor: Value = from_slice(cbor).map_err(|_| Error::InvalidArgument)?;
        let Value::Map(map) = cbor else {
            return Err(Error::InvalidArgument);
        };

        let mut suffix = Self::default();

        if let Some(&Value::Integer(transport_channel_identifier)) =
            map.get(&Self::KEY_TRANSPORT_CHANNEL_IDENTIFIER)
        {
            suffix.transport_channel_identifier = transport_channel_identifier.try_into().ok();
        }

        Ok(suffix)
    }
}
