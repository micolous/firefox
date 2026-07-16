/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise handshakes

use crate::{Channel, Result, SymmetricState, cipher::sec1_ec2_key_to_der};
use nserror::NS_ERROR_FAILURE;
use nss_rs::ec::{EcCurve, EcdhKeypair, ecdh, ecdh_keygen, import_ec_public_key_from_spki};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum HandshakeType {
    KNpsk0,
    NKpsk0,
}

impl HandshakeType {
    pub fn protocol_name(&self) -> &'static [u8; 32] {
        match self {
            Self::KNpsk0 => b"Noise_KNpsk0_P256_AESGCM_SHA256\0",
            Self::NKpsk0 => b"Noise_NKpsk0_P256_AESGCM_SHA256\0",
        }
    }
}

pub struct HandshakeState {
    ss: SymmetricState,
    local_identity: Option<EcdhKeypair>,
    ephemeral_key: EcdhKeypair,
}

impl HandshakeState {
    /// Start a Noise handshake as the initiating party.
    ///
    /// Exactly one of these parameters must be set:
    ///
    /// * `local_identity` (aka: `priv`): local private key, for `KNpsk0`
    /// * `peer_identity` (aka: `peerPub`): peer public key, for `NKpsk0`.
    ///
    /// Returns `(HandshakeState, initial_message)`. `iniital_message` is to be sent to the
    /// remote authenticator.
    pub fn initial_handshake_message(
        psk: &[u8; 32],
        local_identity: Option<EcdhKeypair>,
        peer_identity: Option<&[u8; 65]>,
    ) -> Result<(Self, Vec<u8>)> {
        assert_ne!(
            local_identity.is_some(),
            peer_identity.is_some(),
            "exactly one of local_identity or peer_identity must be given",
        );

        let mut ss = if let Some(peer_identity) = peer_identity {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::NKpsk0)?;
            ss.mix_hash(&[0])?;
            ss.mix_hash(peer_identity)?;
            ss
        } else if let Some(local_identity) = &local_identity {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::KNpsk0)?;
            ss.mix_hash(&[1])?;
            ss.mix_hash(
                &local_identity
                    .public
                    .key_data()
                    .map_err(|_| NS_ERROR_FAILURE)?,
            )?;
            ss
        } else {
            unreachable!("unexpected parameters");
        };

        ss.mix_key_and_hash(psk)?;

        let ephemeral_key = ecdh_keygen(&EcCurve::P256).map_err(|_| NS_ERROR_FAILURE)?;
        let ephemeral_key_bytes = ephemeral_key
            .public
            .key_data()
            .map_err(|_| NS_ERROR_FAILURE)?;
        ss.mix_hash(&ephemeral_key_bytes)?;
        ss.mix_key(&ephemeral_key_bytes)?;

        if let Some(peer_identity) = peer_identity {
            let peer_identity_der = sec1_ec2_key_to_der(peer_identity)?;
            let peer_identity_key =
                import_ec_public_key_from_spki(&peer_identity_der).map_err(|_| NS_ERROR_FAILURE)?;

            ss.mix_key(
                &ecdh(&ephemeral_key.private, &peer_identity_key).map_err(|_| NS_ERROR_FAILURE)?,
            )?;
        }

        let ct = ss.encrypt_and_hash(&[])?;
        let mut initial_message = Vec::with_capacity(ephemeral_key_bytes.len() + ct.len());
        initial_message.extend_from_slice(&ephemeral_key_bytes);
        initial_message.extend_from_slice(&ct);

        Ok((
            Self {
                ss,
                local_identity,
                ephemeral_key,
            },
            initial_message,
        ))
    }

    /// Respond to an authenticator as an initiator
    ///
    /// Returns a [`Channel`] and the handshake hash.
    pub fn process_handshake_response(
        mut self,
        peer_handshake_message: &[u8],
    ) -> Result<(Channel, Vec<u8>)> {
        assert!(
            peer_handshake_message.len() >= 65,
            "peer_handshake_message < 65 bytes ({})",
            peer_handshake_message.len(),
        );

        let (peer_point_bytes, ct) = peer_handshake_message.split_at(65);
        let peer_key_der = sec1_ec2_key_to_der(peer_point_bytes.try_into().unwrap())?;
        let peer_key =
            import_ec_public_key_from_spki(&peer_key_der).map_err(|_| NS_ERROR_FAILURE)?;

        self.ss.mix_hash(peer_point_bytes)?;
        self.ss.mix_key(peer_point_bytes)?;
        self.ss.mix_key(
            &ecdh(&self.ephemeral_key.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?,
        )?;

        if let Some(local_identity) = &self.local_identity {
            self.ss.mix_key(
                &ecdh(&local_identity.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?,
            )?;
        }

        let pt = self.ss.decrypt_and_hash(ct)?;
        assert!(pt.is_empty());

        let channel = self.ss.split()?;
        Ok((channel, self.ss.get_handshake_hash().clone()))
    }

    /// Start a Noise handshake as the responding party (authenticator)
    ///
    /// `message` is the value from [the initiator][Self::initial_handshake_message].
    ///
    /// Returns `(Crypter, response)`. `response` is [sent to the initiator][Self::process_handshake_response].
    pub fn build_responder(
        local_identity: Option<EcdhKeypair>,
        psk: &[u8; 32],
        peer_identity: Option<&[u8; 65]>,
        message: &[u8],
    ) -> Result<(Channel, Vec<u8>)> {
        assert_ne!(
            local_identity.is_some(),
            peer_identity.is_some(),
            "exactly one of local_identity or peer_identity must be given",
        );
        assert!(
            message.len() >= 65,
            "message < 65 bytes ({})",
            message.len(),
        );

        let (peer_point_bytes, ct) = message.split_at(65);
        let peer_key_der = sec1_ec2_key_to_der(peer_point_bytes.try_into().unwrap())?;
        let peer_key =
            import_ec_public_key_from_spki(&peer_key_der).map_err(|_| NS_ERROR_FAILURE)?;

        let mut ss = if let Some(peer_identity) = peer_identity {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::KNpsk0)?;
            ss.mix_hash(&[1])?;
            ss.mix_hash(peer_identity)?;
            ss
        } else if let Some(local_identity) = &local_identity {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::NKpsk0)?;
            ss.mix_hash(&[0])?;
            ss.mix_hash(
                &local_identity
                    .public
                    .key_data()
                    .map_err(|_| NS_ERROR_FAILURE)?,
            )?;
            ss
        } else {
            unreachable!();
        };

        ss.mix_key_and_hash(psk)?;
        ss.mix_hash(peer_point_bytes)?;
        ss.mix_key(peer_point_bytes)?;

        if let Some(local_identity) = local_identity {
            let es_key = ecdh(&local_identity.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?;
            ss.mix_key(&es_key)?;
        }

        let pt = ss.decrypt_and_hash(ct)?;
        assert!(pt.is_empty());

        let ephemeral_key = ecdh_keygen(&EcCurve::P256).map_err(|_| NS_ERROR_FAILURE)?;
        let ephemeral_key_bytes = ephemeral_key
            .public
            .key_data()
            .map_err(|_| NS_ERROR_FAILURE)?;
        ss.mix_hash(&ephemeral_key_bytes)?;
        ss.mix_key(&ephemeral_key_bytes)?;

        let shared_key_ee =
            ecdh(&ephemeral_key.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?;
        ss.mix_key(&shared_key_ee)?;

        if let Some(peer_identity) = peer_identity {
            let peer_identity_der = sec1_ec2_key_to_der(peer_identity)?;
            let peer_identity_key =
                import_ec_public_key_from_spki(&peer_identity_der).map_err(|_| NS_ERROR_FAILURE)?;

            let shared_key_se =
                ecdh(&ephemeral_key.private, &peer_identity_key).map_err(|_| NS_ERROR_FAILURE)?;
            ss.mix_key(&shared_key_se)?;
        }

        let ct = ss.encrypt_and_hash(&[])?;
        let mut response_message = Vec::with_capacity(ephemeral_key_bytes.len() + ct.len());
        response_message.extend_from_slice(&ephemeral_key_bytes);
        response_message.extend_from_slice(&ct);

        let channel = ss.split()?;

        Ok((channel, response_message))
    }
}
