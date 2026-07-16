/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise hash functions
//!
//! <https://noiseprotocol.org/noise.html#hash-functions>

use crate::Result;
use nserror::NS_ERROR_FAILURE;
use nss_rs::{
    SymKey,
    hash::{HashAlgorithm, hash},
    hkdf::{Hkdf, HkdfAlgorithm},
    hmac::{HmacAlgorithm, hmac},
};

const SHA256_LENGTH: usize = nss_rs::p11::SHA256_LENGTH as usize;

/// Noise Hash trait.
///
/// <https://noiseprotocol.org/noise.html#hash-functions>
pub trait Hash {
    /// A constant specifying the size in bytes of the hash output. Must be 32 or 64.
    const HASHLEN: usize;
    const HKDF_ALGORITHM: HkdfAlgorithm;

    // A constant specifying the size in bytes that the hash function uses internally to divide
    // its input for iterative processing. This is needed to use the hash function with HMAC
    // type BlockLen: ArrayLength<u8> + 'static;

    /// Hashes some arbitrary-length data with a collision-resistant cryptographic hash function
    /// and returns an output of `HASHLEN` bytes.
    fn hash(data: &[u8]) -> Result<Vec<u8>>;

    fn hmac_hash(key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}

mod internal {
    pub trait Sealed {}
    impl<T: super::Hash> Sealed for T {}
}

pub trait HashHkdf: internal::Sealed {
    fn hkdf2(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>>;
    fn hkdf3(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>>;
    // fn hkdf2_with_symkey(salt: &[u8], ikm: &Symkey) -> Result<(SymKey, SymKey)>;
}

fn hkdf<T: Hash>(salt: &[u8], ikm: &[u8], count: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::new(T::HKDF_ALGORITHM);
    let ikm = hkdf.import_secret(ikm).map_err(|_| NS_ERROR_FAILURE)?;
    hkdf_with_symkey::<T>(salt, &ikm, count)
}

fn hkdf_with_symkey<T: Hash>(salt: &[u8], ikm: &SymKey, count: usize) -> Result<Vec<u8>> {
    let len = count * T::HASHLEN;
    let hkdf = Hkdf::new(T::HKDF_ALGORITHM);
    let prk = hkdf.extract(salt, ikm).map_err(|_| NS_ERROR_FAILURE)?;
    hkdf.expand_data(&prk, &[], len)
        .map_err(|_| NS_ERROR_FAILURE)
}

impl<T: Hash> HashHkdf for T {
    fn hkdf2(chaining_key: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
        hkdf::<T>(chaining_key, ikm, 2)
    }

    fn hkdf3(chaining_key: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
        hkdf::<T>(chaining_key, ikm, 3)
    }
}

pub struct Sha256;

impl Hash for Sha256 {
    const HASHLEN: usize = SHA256_LENGTH;
    const HKDF_ALGORITHM: HkdfAlgorithm = HkdfAlgorithm::HKDF_SHA2_256;

    fn hash(data: &[u8]) -> Result<Vec<u8>> {
        hash(&HashAlgorithm::SHA2_256, data).map_err(|_| NS_ERROR_FAILURE)
    }

    fn hmac_hash(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // TODO: replace this with a bespoke version of hmac(), so that the `Vec` it returns can
        // be pre-allocated with an extra byte for hkdf.

        hmac(&HmacAlgorithm::HMAC_SHA2_256, key, data).map_err(|_| NS_ERROR_FAILURE)
    }
}
