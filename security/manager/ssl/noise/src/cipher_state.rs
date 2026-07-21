/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    cipher::{decrypt, encrypt},
    Result, ALG,
};
use nserror::{NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_FAILURE};
use nss_rs::{aead::Aead, SymKey};

/// [Noise `CipherState`][0] object.
///
/// [0]: https://noiseprotocol.org/noise.html#the-cipherstate-object
#[derive(Default)]
pub struct CipherState {
    k: Option<SymKey>,
    n: u64,
}

impl CipherState {
    pub fn new_with_key(key: SymKey) -> Self {
        Self { k: Some(key), n: 0 }
    }

    pub fn new_with_key_bytes(key: &[u8; 32]) -> Result<Self> {
        let key = Aead::import_key(ALG, key).map_err(|_| NS_ERROR_FAILURE)?;
        Ok(Self::new_with_key(key))
    }

    /// > Sets `k` = `key`. Sets `n` =  `0`.
    pub fn initialize_key(&mut self, key: SymKey) {
        self.k = Some(key);
        self.n = 0;
    }

    pub fn initialize_key_bytes(&mut self, key: &[u8; 32]) -> Result<()> {
        let key = Aead::import_key(ALG, key).map_err(|_| NS_ERROR_FAILURE)?;
        self.initialize_key(key);
        Ok(())
    }

    /// > Returns `true` if `k` is non-empty, `false` otherwise.
    #[inline]
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// Get the current nonce. This is only for tests.
    #[inline]
    pub fn get_nonce(&self) -> u64 {
        self.n
    }

    /// > Sets `n` = `nonce`. This function is used for handling out-of-order
    /// > transport messages...
    #[inline]
    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    /// Check that the current nonce is valid.
    ///
    /// > The maximum `n` value (2<sup>64</sup>-1) is reserved for other use.
    /// >
    /// > If incrementing `n` results in 2<sup>64</sup>-1, then any further
    /// > [`encrypt_with_ad()`][Self::encrypt_with_ad] or
    /// > [`decrypt_with_ad()`][Self::decrypt_with_ad] calls will signal an
    /// > error to the caller.
    #[inline]
    fn check_nonce(&self) -> Result {
        if self.n == u64::MAX {
            return Err(NS_ERROR_FAILURE);
        }

        Ok(())
    }

    /// > If `k` is non-empty, returns `ENCRYPT(k, n++, ad, plaintext)`.
    ///
    /// Unlike the spec, this returns an error if `k` is empty.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let Some(k) = &self.k else {
            // The spec says to return plaintext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        };

        self.check_nonce()?;
        let ciphertext = encrypt(k, self.n, ad, plaintext)?;
        self.n += 1;
        Ok(ciphertext)
    }

    /// > If `k` is non-empty returns `DECRYPT(k, n++, ad, ciphertext)`.
    /// >
    /// > If an authentication failure occurs in `DECRYPT()` then `n` is not
    /// > incremented and an error is signaled to the caller.
    ///
    /// Unlike the spec, this returns an error if `k` is empty.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(k) = &self.k else {
            // The spec says to return ciphertext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        };

        self.check_nonce()?;
        let plaintext = decrypt(k, self.n, ad, ciphertext)?;
        self.n += 1;
        Ok(plaintext)
    }
}

impl PartialEq for CipherState {
    /// Check equality between two [`CipherState`s][CipherState].
    ///
    /// ### Limitations
    ///
    /// Opaque [`SymKey`s][SymKey] are treated as unequal to each other, even if they point to the
    /// same memory address.
    fn eq(&self, other: &Self) -> bool {
        if self.n != other.n {
            return false;
        }

        match (&self.k, &other.k) {
            (None, None) => true,
            (Some(s), Some(o)) => {
                let Ok(s) = s.key_data() else {
                    return false;
                };
                let Ok(o) = o.key_data() else {
                    return false;
                };
                s == o
            }
            _ => false,
        }
    }
}
