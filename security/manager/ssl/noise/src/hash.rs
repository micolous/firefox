/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise hash functions
//!
//! <https://noiseprotocol.org/noise.html#hash-functions>

use crate::{HandshakeType, Result};
use digest::Digest;
use nserror::NS_ERROR_FAILURE;
use nss_rs::hkdf::{Hkdf, HkdfAlgorithm};
pub use sha2::Sha256;

/// [Noise Hash trait][0].
///
/// This is a wrapper for RustCrypto's [`Digest`] trait, but uses NSS for HKDF operations.
/// RustCrypto provides richer type information than `nss-rs` (so we can avoid `Vec<u8>`), and can
/// hash data incrementally.
///
/// This currently only supports SHA256.
///
/// [0]: https://noiseprotocol.org/noise.html#hash-functions
pub trait Hash: Digest {
    /// NSS HKDF algorithm for the hash.
    const HKDF_ALGORITHM: HkdfAlgorithm;

    /// A constant specifying the size in bytes of the hash output. Must be either 32 or 64 bytes.
    fn hash_len() -> usize {
        <Self as Digest>::output_size()
    }

    /// Get a Noise protocol name identifier for the handshake.
    fn protocol_name(ht: HandshakeType) -> &'static [u8];
}

impl Hash for Sha256 {
    const HKDF_ALGORITHM: HkdfAlgorithm = HkdfAlgorithm::HKDF_SHA2_256;

    fn protocol_name(ht: HandshakeType) -> &'static [u8] {
        // TODO: this doesn't allow for other ciphers, but these are the only
        // ones used by caBLE.
        match ht {
            HandshakeType::KNpsk0 => b"Noise_KNpsk0_P256_AESGCM_SHA256",
            HandshakeType::NKpsk0 => b"Noise_NKpsk0_P256_AESGCM_SHA256",
        }
    }
}

pub trait HashHkdf {
    /// Noise version of `HKDF(chaining_key, ikm, num_outputs)`.
    ///
    /// `count` is the number of keys (outputs) to derive.
    ///
    /// Returns a buffer of `Hash::HASHLEN * count` bytes.
    fn hkdf(salt: &[u8], ikm: &[u8], count: usize) -> Result<Vec<u8>>;
}

impl<HASH: Hash> HashHkdf for HASH {
    fn hkdf(salt: &[u8], ikm: &[u8], count: usize) -> Result<Vec<u8>> {
        let len = count * HASH::hash_len();
        let hkdf = Hkdf::new(HASH::HKDF_ALGORITHM);
        let ikm = hkdf.import_secret(ikm).map_err(|_| NS_ERROR_FAILURE)?;
        let prk = hkdf.extract(salt, &ikm).map_err(|_| NS_ERROR_FAILURE)?;
        let r = hkdf
            .expand_data(&prk, &[], len)
            .map_err(|_| NS_ERROR_FAILURE)?;

        if r.len() != len {
            Err(NS_ERROR_FAILURE)
        } else {
            Ok(r)
        }
    }
}
