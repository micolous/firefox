/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//!

use crate::{Result, cipher_state::CipherState};
use nss_rs::SymKey;

/// Channel for the transport phase of a Noise session.
pub struct Channel {
    reader: CipherState,
    writer: CipherState,
}

impl Channel {
    pub fn new(read_key: SymKey, write_key: SymKey) -> Self {
        Self {
            reader: CipherState::new_with_key(read_key),
            writer: CipherState::new_with_key(write_key),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.writer.encrypt_with_ad(&[], plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
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
