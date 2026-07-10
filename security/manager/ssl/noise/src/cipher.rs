/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise cipher functions
//!
//! <https://noiseprotocol.org/noise.html#cipher-functions>

use crate::Result;
use nserror::NS_ERROR_FAILURE;
use nss_rs::{
    SymKey,
    aead::{Aead, AeadAlgorithms, Mode, NONCE_LEN},
};

const PADDING_MUL: usize = 32;

const fn pad_len(len: usize) -> usize {
    let o = (len + PADDING_MUL) & !(PADDING_MUL - 1);
    debug_assert!(o > len);
    o
}

/// Encrypts `plaintext` using the cipher key `k` of 32 bytes and an 8-byte unsigned integer nonce
/// `n` which must be unique for the key `k`.
///
/// Returns the ciphertext.
///
/// Encryption must be done with an "AEAD" encryption mode with the associated data `aad` (using the
/// terminology from [1]) and returns a ciphertext that is the same size as the plaintext plus 16
/// bytes for authentication data.
///
/// The entire ciphertext must be indistinguishable from random if the key is secret (note that
/// this is an additional requirement that isn't necessarily met by all AEAD schemes).
pub fn encrypt(k: &SymKey, n: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    nonce[NONCE_LEN - size_of::<u64>()..].copy_from_slice(&n.to_be_bytes());

    let mut aead = Aead::new(Mode::Encrypt, AeadAlgorithms::Aes256Gcm, k, nonce)
        .map_err(|_| NS_ERROR_FAILURE)?;

    let len = plaintext.len();
    let padded_len = pad_len(len);
    let mut pt = vec![0; padded_len];
    pt[..len].copy_from_slice(plaintext);
    pt[padded_len - 1] = (padded_len - len - 1) as u8;

    aead.encrypt(aad, &pt).map_err(|_| NS_ERROR_FAILURE)
}

/// Decrypts `ciphertext` using a cipher key `k` of 32 bytes, an 8-byte unsigned integer nonce `n`,
/// and associated data `aad`.
///
/// Returns the plaintext, unless authentication fails, in which case an error is signaled to the
/// caller.
pub fn decrypt(k: &SymKey, n: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_LEN];
    nonce[NONCE_LEN - size_of::<u64>()..].copy_from_slice(&n.to_be_bytes());

    let mut aead = Aead::new(Mode::Decrypt, AeadAlgorithms::Aes256Gcm, k, nonce)
        .map_err(|_| NS_ERROR_FAILURE)?;

    let mut pt = aead.decrypt(aad, 0, ciphertext).map_err(|_| NS_ERROR_FAILURE)?;

    let padding_len = pt.last().copied().ok_or(NS_ERROR_FAILURE)? as usize + 1;
    if padding_len > pt.len() || padding_len > PADDING_MUL {
        // Incorrect padding length
        return Err(NS_ERROR_FAILURE);
    }

    pt.truncate(pt.len() - padding_len);
    Ok(pt)
}
