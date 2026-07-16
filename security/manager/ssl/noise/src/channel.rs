/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//!

use crate::{ALG, KEY_LENGTH, Result, cipher_state::CipherState};
use nserror::{
    NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_OK, nsresult,
};
use nss_rs::{SymKey, aead::Aead};
use std::sync::{Mutex, MutexGuard};
use thin_vec::ThinVec;
use xpcom::RefPtr;

/// Channel for the transport phase of a Noise session.
pub struct Channel {
    reader: CipherState,
    writer: CipherState,
}

impl Channel {
    /// Create a new transport channel, using a pair of
    /// [`CipherState`s][CipherState]. This is used for further communication
    /// after the Noise handshake process has completed.
    pub fn new(read_key: SymKey, write_key: SymKey) -> Self {
        Self {
            reader: CipherState::new_with_key(read_key),
            writer: CipherState::new_with_key(write_key),
        }
    }

    pub fn new_with_key_bytes(read_key: &[u8; 32], write_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            reader: CipherState::new_with_key_bytes(read_key)?,
            writer: CipherState::new_with_key_bytes(write_key)?,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_keys() {
            // The spec says to return plaintext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        }

        self.writer.encrypt_with_ad(&[], plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_keys() {
            // The spec says to return ciphertext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        }

        self.reader.decrypt_with_ad(&[], ciphertext)
    }

    pub fn initialize_keys(&mut self, read_key: SymKey, write_key: SymKey) {
        self.reader.initialize_key(read_key);
        self.writer.initialize_key(write_key);
    }

    /// Returns `true` if both the reader and writer side of the channel have been initialized with
    /// keys, and can encrypt and decrypt data.
    pub fn has_keys(&self) -> bool {
        self.reader.has_key() && self.writer.has_key()
    }

    /// Get the current reader nonce. This is only for tests.
    #[inline]
    pub fn get_reader_nonce(&self) -> u64 {
        self.reader.get_nonce()
    }

    #[inline]
    pub fn set_reader_nonce(&mut self, nonce: u64) {
        self.reader.set_nonce(nonce);
    }

    /// Get the current writer nonce. This is only for tests.
    #[inline]
    pub fn get_writer_nonce(&self) -> u64 {
        self.writer.get_nonce()
    }

    #[inline]
    pub fn set_writer_nonce(&mut self, nonce: u64) {
        self.writer.set_nonce(nonce);
    }
}

/// XPCOM wrapper for [`Channel`].
#[xpcom(implement(nsINoiseChannel), atomic)]
struct NoiseChannel {
    inner: Mutex<Channel>,
}

impl NoiseChannel {
    fn get_self(&self) -> Result<MutexGuard<'_, Channel>> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    xpcom_method!(has_keys => GetHasKeys() -> bool);
    fn has_keys(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.has_keys())
    }

    xpcom_method!(initialize_keys => InitializeKeys(read_key: *const ThinVec<u8>, write_key: *const ThinVec<u8>));
    fn initialize_keys(&self, read_key: &ThinVec<u8>, write_key: &ThinVec<u8>) -> Result {
        if read_key.len() != KEY_LENGTH || write_key.len() != KEY_LENGTH {
            return Err(NS_ERROR_INVALID_ARG);
        }

        let read_key = Aead::import_key(ALG, read_key).map_err(|_| NS_ERROR_INVALID_ARG)?;
        let write_key = Aead::import_key(ALG, write_key).map_err(|_| NS_ERROR_INVALID_ARG)?;

        let mut guard = self.get_self()?;
        guard.initialize_keys(read_key, write_key);
        Ok(())
    }

    xpcom_method!(encrypt => Encrypt(plaintext: *const ThinVec<u8>) -> ThinVec<u8>);
    fn encrypt(&self, plaintext: &ThinVec<u8>) -> Result<ThinVec<u8>> {
        let mut guard = self.get_self()?;
        let ct = guard.encrypt(plaintext)?;
        Ok(ThinVec::from(ct))
    }

    xpcom_method!(decrypt => Decrypt(ciphertext: *const ThinVec<u8>) -> ThinVec<u8>);
    fn decrypt(&self, ciphertext: &ThinVec<u8>) -> Result<ThinVec<u8>> {
        let mut guard = self.get_self()?;
        let ct = guard.decrypt(ciphertext)?;
        Ok(ThinVec::from(ct))
    }
}

impl From<Channel> for RefPtr<NoiseChannel> {
    fn from(value: Channel) -> Self {
        NoiseChannel::allocate(InitNoiseChannel {
            inner: Mutex::new(value),
        })
    }
}
