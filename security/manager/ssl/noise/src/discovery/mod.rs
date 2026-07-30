/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery and XPCOM bindings.

mod params;
mod service;
mod session;

use crate::{hash::Hash as _, Result, Sha256, ALG};
use nserror::NS_ERROR_FAILURE;
use nss_rs::{aead::Aead, p11, random, IntoResult as _, SECItemBorrowed, SymKey};
use pkcs11_bindings::CKA_SIGN;
use std::ptr::null_mut;

pub use self::{params::Params, service::Service, session::Session};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
enum KeyPurpose {
    EIDKey = 1,
    TunnelID = 2,
    Psk = 3,
}

#[derive(Clone)]
pub struct EIDKey {
    encryption_key: SymKey,
    signing_key: SymKey,
}

#[derive(Clone)]
pub struct SharedSecret([u8; 16]);

#[cfg_attr(feature = "test", derive(Debug, PartialEq, Eq))]
#[derive(Clone)]
pub struct TunnelID([u8; 16]);

impl KeyPurpose {
    /// Derive caBLE material for this [`KeyPurpose`][].
    pub fn derive(self, ikm: &[u8], salt: &[u8], count: usize) -> Result<Vec<u8>> {
        let info = (self as u32).to_le_bytes();
        Sha256::hkdf_bytes(salt, ikm, &info, count)
    }
}

impl SharedSecret {
    pub fn random() -> Self {
        SharedSecret(random())
    }

    pub fn to_tunnel_id(&self) -> Result<TunnelID> {
        KeyPurpose::TunnelID
            .derive(&self.0, &[], 16)?
            .try_into()
            .map(TunnelID)
            .map_err(|_| NS_ERROR_FAILURE)
    }

    /// Derive the EID key from the shared secret.
    pub fn to_eid_key(&self) -> Result<EIDKey> {
        let eid_key = KeyPurpose::EIDKey.derive(&self.0, &[], 64)?;
        let (encryption_key, signing_key) = eid_key.split_at(32);

        let encryption_key = Aead::import_key(ALG, encryption_key).map_err(|_| NS_ERROR_FAILURE)?;
        let slot = p11::Slot::internal().map_err(|_| NS_ERROR_FAILURE)?;
        let mut signing_key = SECItemBorrowed::wrap(signing_key).map_err(|_| NS_ERROR_FAILURE)?;
        let signing_key = unsafe {
            p11::PK11_ImportSymKey(
                *slot,
                Sha256::HMAC_ALGORITHM,
                p11::PK11Origin::PK11_OriginUnwrap,
                CKA_SIGN,
                signing_key.as_mut(),
                null_mut(),
            )
        }
        .into_result()
        .map_err(|_| NS_ERROR_FAILURE)?;

        Ok(EIDKey {
            encryption_key,
            signing_key,
        })
    }
}

impl AsRef<[u8; 16]> for TunnelID {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::ops::Deref for TunnelID {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Unsafe APIs that should only be used in unit tests.
#[cfg(feature = "test")]
impl From<[u8; 16]> for SharedSecret {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "test")]
impl From<[u8; 16]> for TunnelID {
    fn from(value: [u8; 16]) -> Self {
        Self(value)
    }
}
