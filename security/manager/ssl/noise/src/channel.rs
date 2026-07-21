/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise [Channel][] implementation and XPCOM bindings.

use crate::{cipher_state::CipherState, Result};
use nserror::{
    nsresult, NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_OK,
};
use nss_rs::SymKey;
use std::sync::{Mutex, MutexGuard};
use thin_vec::ThinVec;
use xpcom::RefPtr;

/// Noise post-handshake transport interface, built with a pair of [`CipherState`][] objects.
///
/// Messages must be decrypted in the same order that they were encrypted.
///
/// References:
///
/// * [Noise protocol: the `CipherState` object][0]
/// * [Noise protocol: the `SymmetricState` object][1]
///
/// [0]: https://noiseprotocol.org/noise.html#the-cipherstate-object
/// [1]: https://noiseprotocol.org/noise.html#the-symmetricstate-object
#[derive(Default)]
pub struct Channel {
    reader: CipherState,
    writer: CipherState,
}

impl Channel {
    /// Create a new transport channel, using a pair of [`CipherState`s][CipherState] initialized
    /// with a pair of [`SymKey`s][SymKey] derived from a Noise handshake.
    ///
    /// The keys must be imported for use with AES-256 GCM
    /// (`Aead::import_key(AeadAlgorithms::Aes256Gcm, key)`).
    pub fn new(read_key: SymKey, write_key: SymKey) -> Self {
        Self {
            reader: CipherState::new_with_key(read_key),
            writer: CipherState::new_with_key(write_key),
        }
    }

    /// Create a new transport channel, using a pair of [`CipherState`s][CipherState] initialized
    /// with a pair of keys as raw bytes derived from a Noise handshake.
    pub fn new_with_key_bytes(read_key: &[u8; 32], write_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            reader: CipherState::new_with_key_bytes(read_key)?,
            writer: CipherState::new_with_key_bytes(write_key)?,
        })
    }

    /// Initialize this channel with a `read_key` and `write_key` (derived from a Noise handshake)
    /// as [`SymKey`][], and reset both nonces to 0.
    ///
    /// The keys must be imported for use with AES-256 GCM
    /// (`Aead::import_key(AeadAlgorithms::Aes256Gcm, key)`).
    pub fn initialize_keys(&mut self, read_key: SymKey, write_key: SymKey) {
        self.reader.initialize_key(read_key);
        self.writer.initialize_key(write_key);
    }

    /// Initialize this channel with a `read_key` and `write_key` (derived from a Noise handshake)
    /// as raw bytes, and reset both nonces to 0.
    pub fn initialize_keys_bytes(
        &mut self,
        read_key: &[u8; 32],
        write_key: &[u8; 32],
    ) -> Result<()> {
        self.reader.initialize_key_bytes(read_key)?;
        self.writer.initialize_key_bytes(write_key)?;
        Ok(())
    }

    /// Returns `true` if both reader and writer keys are set, allowing this channel to encrypt and
    /// decrypt data.
    pub fn has_keys(&self) -> bool {
        self.reader.has_key() && self.writer.has_key()
    }

    /// Encrypt `plaintext` using this channel's writer key and nonce, and then increment the writer
    /// nonce.
    ///
    /// Returns an error if the channel is missing keys.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_keys() {
            // The spec says to return plaintext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        }

        self.writer.encrypt_with_ad(&[], plaintext)
    }

    /// Decrypt `ciphertext` using this channel's reader key and nonce, and then increment the
    /// reader nonce.
    ///
    /// Returns an error if the channel is missing keys, or the data cannot be decrypted.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.has_keys() {
            // The spec says to return ciphertext, but this is dangerous.
            return Err(NS_ERROR_DOM_INVALID_STATE_ERR);
        }

        self.reader.decrypt_with_ad(&[], ciphertext)
    }

    /// Get the current reader nonce. This is only for tests.
    #[inline]
    pub fn get_reader_nonce(&self) -> u64 {
        self.reader.get_nonce()
    }

    /// Set the reader nonce. See [`CipherState::set_nonce`].
    #[inline]
    pub fn set_reader_nonce(&mut self, nonce: u64) {
        self.reader.set_nonce(nonce);
    }

    /// Get the current writer nonce. This is only for tests.
    #[inline]
    pub fn get_writer_nonce(&self) -> u64 {
        self.writer.get_nonce()
    }

    /// Set the writer nonce. See [`CipherState::set_nonce`].
    #[inline]
    pub fn set_writer_nonce(&mut self, nonce: u64) {
        self.writer.set_nonce(nonce);
    }

    /// Returns `true` if this [`Channel`] is a counterparty of `other`.
    ///
    /// ie: the reader key and nonce of `self` are the same as the writer key and nonce of
    /// `other`, and vice versa.
    ///
    /// ### Limitations
    ///
    /// This only works if the [`SymKey`s][SymKey] of both channels are not opaque. Opaque
    /// [`SymKey`s][SymKey] are treated as unequal to all others, even if they point to the same
    /// memory address.
    pub fn is_counterparty(&self, other: &Channel) -> bool {
        self.reader == other.writer && self.writer == other.reader
    }
}

/// `nsINoiseChannel`-compatible XPCOM wrapper for [`Channel`][].
#[xpcom(implement(nsINoiseChannel), atomic)]
pub struct NoiseChannel {
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

    xpcom_method!(initialize_keys => InitializeKeys(aReadKey: *const ThinVec<u8>, aWriteKey: *const ThinVec<u8>));
    fn initialize_keys(&self, read_key: &ThinVec<u8>, write_key: &ThinVec<u8>) -> Result {
        let read_key = read_key
            .as_slice()
            .try_into()
            .map_err(|_| NS_ERROR_INVALID_ARG)?;
        let write_key = write_key
            .as_slice()
            .try_into()
            .map_err(|_| NS_ERROR_INVALID_ARG)?;

        let mut guard = self.get_self()?;
        guard.initialize_keys_bytes(read_key, write_key)?;
        Ok(())
    }

    xpcom_method!(encrypt => Encrypt(aPlainText: *const ThinVec<u8>) -> ThinVec<u8>);
    fn encrypt(&self, plaintext: &ThinVec<u8>) -> Result<ThinVec<u8>> {
        let mut guard = self.get_self()?;
        let ct = guard.encrypt(plaintext)?;
        Ok(ThinVec::from(ct))
    }

    xpcom_method!(decrypt => Decrypt(aCipherText: *const ThinVec<u8>) -> ThinVec<u8>);
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

/// Create a new `nsINoiseChannel`-compatible [`Channel`][], with no set keys.
#[no_mangle]
pub unsafe extern "C" fn noise_channel_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nserror::nsresult {
    if nss_rs::init().is_err() {
        return NS_ERROR_FAILURE;
    }

    let channel: RefPtr<NoiseChannel> = Channel::default().into();
    unsafe { channel.QueryInterface(iid, result) }
}
