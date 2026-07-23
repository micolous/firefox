/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    handshake::HandshakeType,
    hash::{Hash, HashHkdf},
    Channel, CipherState, Result,
};
use sha2::{digest, Sha256};

/// [Noise `SymmetricState`][0] object.
///
/// [0]: https://noiseprotocol.org/noise.html#the-symmetric-object
#[derive(Default)]
pub struct SymmetricState<HASH: Hash> {
    cs: CipherState,
    ck: digest::Output<HASH>,
    h: digest::Output<HASH>,
}

impl<HASH: Hash> SymmetricState<HASH> {
    /// Creates a new [`SymmetricState`][] for a given `protocol`.
    pub fn initialize_symmetric(protocol: HandshakeType) -> Self {
        let name = HASH::protocol_name(protocol);
        let h = if name.len() <= HASH::hash_len() {
            // If protocol_name is less than or equal to HASHLEN bytes in length, sets h equal to
            // protocol_name with zero bytes appended to make HASHLEN bytes.
            let mut h: digest::Output<HASH> = Default::default();
            h[..name.len()].copy_from_slice(name);
            h
        } else {
            // Otherwise sets h = HASH(protocol_name).
            HASH::digest(name)
        };

        Self {
            cs: CipherState::default(),
            ck: h.clone(),
            h,
        }
    }

    pub fn mix_key(&mut self, ikm: &[u8]) -> Result<()> {
        let temp = HASH::hkdf(&self.ck, ikm, 2)?;
        let (ck, temp_k) = temp.split_at(HASH::hash_len());
        self.ck.copy_from_slice(ck);
        let temp_k = &temp_k[..32].try_into().unwrap();
        self.cs.initialize_key_bytes(temp_k)?;
        Ok(())
    }

    /// Sets `h = HASH(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = HASH::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize();
    }

    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<()> {
        let temp = HASH::hkdf(&self.ck, ikm, 3)?;
        let (ck, temp) = temp.split_at(HASH::hash_len());
        let (temp_h, temp_k) = temp.split_at(HASH::hash_len());
        self.ck.copy_from_slice(ck);
        self.mix_hash(temp_h);
        let temp_k = &temp_k[..32].try_into().unwrap();
        self.cs.initialize_key_bytes(temp_k)?;
        Ok(())
    }

    pub fn get_handshake_hash(&self) -> &digest::Output<HASH> {
        &self.h
    }

    pub fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let ct = self.cs.encrypt_with_ad(&self.h, pt)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    pub fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let pt = self.cs.decrypt_with_ad(&self.h, ct)?;
        self.mix_hash(ct);
        Ok(pt)
    }

    /// Return a [`Channel`] for encrypting transport messages.
    ///
    /// This is equivalent to [`SymmetricState.Split()`][0]
    ///
    /// [0]: https://noiseprotocol.org/noise.html#the-symmetricstate-object
    pub fn split(&self, initiator: bool) -> Result<Channel> {
        let temp = Sha256::hkdf(&self.ck, &[], 2)?;
        let (temp_k1, temp_k2) = temp.split_at(HASH::hash_len());
        let temp_k1 = temp_k1[..32].try_into().unwrap();
        let temp_k2 = temp_k2[..32].try_into().unwrap();

        if initiator {
            Channel::new_with_key_bytes(temp_k2, temp_k1)
        } else {
            Channel::new_with_key_bytes(temp_k1, temp_k2)
        }
    }
}
