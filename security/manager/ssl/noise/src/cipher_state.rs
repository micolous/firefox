/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    KEY_LENGTH, Result,
    cipher::{decrypt, encrypt},
};
use nserror::{NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_OK, nsresult};
use nss_rs::{
    SymKey,
    aead::{Aead, AeadAlgorithms},
};
use std::sync::{Mutex, MutexGuard};
use thin_vec::{ThinVec, thin_vec};
use xpcom::{interfaces::nsINoiseCipherState, xpcom_method};

/// [Noise `CipherState`][0] object.
///
/// [0]: https://noiseprotocol.org/noise.html#the-cipherstate-object
#[derive(Default)]
pub struct CipherState {
    pub(crate) k: Option<SymKey>,
    n: u64,
}

impl CipherState {
    pub fn new_with_key(key: SymKey) -> Self {
        Self { k: Some(key), n: 0 }
    }

    pub fn initialize_key(&mut self, key: SymKey) {
        self.k = Some(key);
        self.n = 0;
    }

    #[inline]
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    #[inline]
    pub fn get_nonce(&self) -> u64 {
        self.n
    }

    #[inline]
    pub fn set_nonce(&mut self, nonce: u64) {
        self.n = nonce;
    }

    #[inline]
    fn check_nonce(&self) -> Result {
        if self.n == u64::MAX {
            return Err(NS_ERROR_FAILURE);
        }

        Ok(())
    }

    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let Some(k) = &self.k else {
            // Return plaintext
            return Ok(Vec::from(plaintext));
        };

        self.check_nonce()?;
        let ciphertext = encrypt(k, self.n, ad, plaintext)?;
        self.n += 1;
        Ok(ciphertext)
    }

    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let Some(k) = &self.k else {
            // Return plaintext
            return Ok(Vec::from(ciphertext));
        };
        let _ = (ad, ciphertext);
        self.check_nonce()?;
        let plaintext = decrypt(k, self.n, ad, ciphertext)?;
        self.n += 1;
        Ok(plaintext)
    }
}

#[xpcom(implement(nsINoiseCipherState), atomic)]
struct NoiseCipherState {
    inner: Mutex<CipherState>,
}

impl NoiseCipherState {
    fn get_self(&self) -> Result<MutexGuard<'_, CipherState>> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    xpcom_method!(initialize_key => InitializeKey(key: *const ThinVec<u8>));
    fn initialize_key(&self, key: &ThinVec<u8>) -> Result {
        if key.len() != KEY_LENGTH {
            return Err(NS_ERROR_INVALID_ARG);
        }

        let key =
            Aead::import_key(AeadAlgorithms::Aes256Gcm, &key).map_err(|_| NS_ERROR_INVALID_ARG)?;

        let mut guard = self.get_self()?;

        guard.initialize_key(key);

        Ok(())
    }

    xpcom_method!(set_nonce => SetNonce(nonce: u64));
    fn set_nonce(&self, nonce: u64) -> Result {
        let mut guard = self.get_self()?;
        guard.n = nonce;

        Ok(())
    }

    xpcom_method!(has_key => GetHasKey() -> bool);
    fn has_key(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.has_key())
    }

    xpcom_method!(encrypt_with_ad => EncryptWithAd(ad: *const ThinVec<u8>, plaintext: *const ThinVec<u8>) -> ThinVec<u8>);
    fn encrypt_with_ad(&self, ad: &ThinVec<u8>, plaintext: &ThinVec<u8>) -> Result<ThinVec<u8>> {
        let mut guard = self.get_self()?;
        let ct = guard.encrypt_with_ad(ad, plaintext)?;
        Ok(ThinVec::from(ct))
    }

    xpcom_method!(decrypt_with_ad => DecryptWithAd(ad: *const ThinVec<u8>, ciphertext: *const ThinVec<u8>) -> ThinVec<u8>);
    fn decrypt_with_ad(&self, ad: &ThinVec<u8>, ciphertext: &ThinVec<u8>) -> Result<ThinVec<u8>> {
        let mut guard = self.get_self()?;
        let pt = guard.decrypt_with_ad(ad, ciphertext)?;
        Ok(ThinVec::from(pt))
    }
}
