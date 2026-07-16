/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{
    Channel, CipherState, Result,
    handshake::HandshakeType,
    hash::{Hash, HashHkdf, Sha256},
};

/// [Noise `SymmetricState`][0] object.
///
/// This is hard coded to use SHA256 for now.
///
/// [0]: https://noiseprotocol.org/noise.html#the-symmetric-object
#[derive(Default)]
pub struct SymmetricState
// where
//     T: Hash,
{
    cs: CipherState,
    ck: Vec<u8>,
    h: Vec<u8>,
    // _marker: PhantomData<T>,
}

impl SymmetricState {
    pub fn initialize_symmetric(protocol: HandshakeType) -> Result<Self> {
        let h = protocol.protocol_name().to_vec();
        let ck = h.clone();
        let cs = CipherState::default();

        Ok(Self {
            cs,
            ck,
            h,
            // _marker: PhantomData,
        })
    }

    pub fn mix_key(&mut self, ikm: &[u8]) -> Result<()> {
        let temp = Sha256::hkdf2(&self.ck, ikm)?;
        assert!(temp.len() >= Sha256::HASHLEN * 2);
        let (ck, temp_k) = temp.split_at(Sha256::HASHLEN);
        self.ck.copy_from_slice(ck);
        let temp_k = &temp_k[..32].try_into().unwrap();
        self.cs.initialize_key_bytes(temp_k)?;
        Ok(())
    }

    pub fn mix_hash(&mut self, data: &[u8]) -> Result<()> {
        // TODO: replace hash() with something that accepts multiple buffers as inputs
        let mut d = self.h.clone();
        d.reserve(data.len());
        d[self.h.len()..].copy_from_slice(data);
        self.h = Sha256::hash(data)?;
        Ok(())
    }

    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<()> {
        let temp = Sha256::hkdf3(&self.ck, ikm)?;
        assert!(temp.len() >= Sha256::HASHLEN * 3);
        let (ck, temp) = temp.split_at(Sha256::HASHLEN);
        let (temp_h, temp_k) = temp.split_at(Sha256::HASHLEN);
        self.ck.copy_from_slice(ck);
        self.mix_hash(temp_h)?;
        let temp_k = &temp_k[..32].try_into().unwrap();
        self.cs.initialize_key_bytes(temp_k)?;
        Ok(())
    }

    pub fn get_handshake_hash(&self) -> &Vec<u8> {
        &self.h
    }

    pub fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let ct = self.cs.encrypt_with_ad(&self.h, pt)?;
        self.mix_hash(&ct)?;
        Ok(ct)
    }

    pub fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let pt = self.cs.decrypt_with_ad(&self.h, ct)?;
        self.mix_hash(ct)?;
        Ok(pt)
    }

    pub fn split(&self) -> Result<Channel> {
        let temp = Sha256::hkdf2(&self.ck, &[])?;
        let (temp_k1, temp_k2) = temp.split_at(Sha256::HASHLEN);
        let temp_k1 = temp_k1[..32].try_into().unwrap();
        let temp_k2 = temp_k2[..32].try_into().unwrap();

        Channel::new_with_key_bytes(temp_k1, temp_k2)
    }
}
