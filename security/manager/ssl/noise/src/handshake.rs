/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise handshakes

use core::slice;
use std::sync::Mutex;

use crate::{
    channel::NoiseChannel, cipher::sec1_ec2_key_to_der, hash::Hash, Channel, Result, SymmetricState,
};
use nserror::{nsresult, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_ERROR_NULL_POINTER, NS_OK};
use nss_rs::ec::{
    convert_to_public, ecdh, ecdh_keygen, import_ec_private_key_pkcs8,
    import_ec_public_key_from_spki, EcCurve, EcdhKeypair,
};
use sha2::Sha256;
use thin_vec::ThinVec;
use xpcom::{
    interfaces::{nsINoiseChannel, nsINoiseHandshakeInitialMessageResult, nsINoiseHandshakeState},
    Ensure, RefPtr,
};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum HandshakeType {
    KNpsk0,
    NKpsk0,
}

pub struct HandshakeState<HASH: Hash> {
    ss: SymmetricState<HASH>,
    local_identity: Option<EcdhKeypair>,
    ephemeral_key: EcdhKeypair,
}

impl<HASH: Hash> HandshakeState<HASH> {
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
    ) -> Result<(Channel, digest::Output<HASH>)> {
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

        let channel = self.ss.split(true)?;
        Ok((channel, self.ss.get_handshake_hash().clone()))
    }

    /// Start a Noise handshake as the responding party (authenticator)
    ///
    /// `message` is the value from [the initiator][Self::initial_handshake_message].
    ///
    /// Returns `(Crypter, response)`. `response` is [sent to the initiator][Self::process_handshake_response].
    pub fn build_responder(
        psk: &[u8; 32],
        local_identity: Option<EcdhKeypair>,
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

        let mut ss: SymmetricState<HASH> = if let Some(peer_identity) = peer_identity {
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

        let channel = ss.split(false)?;

        Ok((channel, response_message))
    }
}

// #[xpcom(implement(nsINoiseHandshakeResponseResult), atomic)]
// struct NoiseHandshakeResponseResult {
//     channel: RefPtr<NoiseChannel>,
//     handshake_hash: ThinVec<u8>,
// }

// impl NoiseHandshakeResponseResult {
//     xpcom_method!(get_channel => GetChannel() -> RefPtr<NoiseChannel>);
//     fn get_channel(&self) -> Result<RefPtr<NoiseChannel>> {
//         Ok(self.channel.clone())
//     }

//     xpcom_method!(get_handshake_hash => GetHandshakeHash() -> ThinVec<u8>);
//     fn get_handshake_hash(&self) -> Result<ThinVec<u8>> {
//         Ok(self.handshake_hash.clone())
//     }
// }

/// `nsINoiseHandshakeState`-compatible XPCOM wrapper for [`HandshakeState`][].
#[xpcom(implement(nsINoiseHandshakeState), atomic)]
struct NoiseHandshakeState {
    inner: Mutex<HandshakeState<Sha256>>,
}

impl NoiseHandshakeState {
    // Manually implement xpcom_method!, because we have multiple out params
    #[allow(non_snake_case)]
    unsafe fn ProcessHandshakeResponse(
        &self,
        peer_handshake_message: *const ThinVec<u8>,
        channel: *mut *const nsINoiseChannel,
        handshake_hash: *mut ThinVec<u8>,
    ) -> nsresult {
        let peer_handshake_message: &ThinVec<u8> = match Ensure::ensure(peer_handshake_message) {
            Ok(v) => v,
            Err(r) => return r,
        };

        if channel.is_null() || handshake_hash.is_null() {
            return NS_ERROR_NULL_POINTER;
        }

        match self.process_handshake_response(peer_handshake_message) {
            Ok((c, mut h)) => {
                unsafe {
                    c.forget(&mut *channel);
                    (&mut *handshake_hash).append(&mut h);
                }

                NS_OK
            }

            Err(e) => e.into(),
        }
    }

    // xpcom_method!(
    //     process_handshake_response => ProcessHandshakeResponse(
    //         peer_handshake_message: *const ThinVec<u8>
    //     ) -> RefPtr<NoiseHandshakeInitialMessageResult>);
    fn process_handshake_response(
        &self,
        peer_handshake_message: &ThinVec<u8>,
    ) -> Result<(RefPtr<nsINoiseChannel>, ThinVec<u8>)> {
        let _ = peer_handshake_message;
        todo!()
    }
}

impl From<HandshakeState<Sha256>> for RefPtr<NoiseHandshakeState> {
    fn from(value: HandshakeState<Sha256>) -> Self {
        NoiseHandshakeState::allocate(InitNoiseHandshakeState {
            inner: Mutex::new(value),
        })
    }
}

#[xpcom(implement(nsINoiseHandshakeInitialMessageResult), atomic)]
struct NoiseHandshakeInitialMessageResult {
    state: RefPtr<nsINoiseHandshakeState>,
    initial_message: ThinVec<u8>,
}

impl NoiseHandshakeInitialMessageResult {
    xpcom_method!(get_state => GetState() -> *const nsINoiseHandshakeState);
    fn get_state(&self) -> Result<RefPtr<nsINoiseHandshakeState>> {
        Ok(self.state.clone())
    }

    xpcom_method!(get_initial_message => GetInitialMessage() -> ThinVec<u8>);
    fn get_initial_message(&self) -> Result<ThinVec<u8>> {
        Ok(self.initial_message.clone())
    }
}

// TODO: test this :)
#[no_mangle]
pub unsafe extern "C" fn NS_NoiseHandshakeInitialMessage(
    psk: *const u8,
    is_local_identity: bool,
    identity: *const u8,
    identity_length: u32,
    result: *mut *const nsINoiseHandshakeInitialMessageResult,
) -> nserror::nsresult {
    if psk.is_null() || identity.is_null() || result.is_null() {
        return NS_ERROR_NULL_POINTER;
    }

    if identity_length == 0 || identity_length > 0xffff {
        return NS_ERROR_INVALID_ARG;
    }

    let Ok(psk) = slice::from_raw_parts(psk, 32).try_into() else {
        return NS_ERROR_INVALID_ARG;
    };
    let identity = slice::from_raw_parts(identity, identity_length as usize);

    // convert types
    let mut local_identity = None;
    let mut peer_identity = None;
    if is_local_identity {
        let Ok(private) = import_ec_private_key_pkcs8(identity) else {
            return NS_ERROR_INVALID_ARG;
        };

        // TODO: verify curve

        let Ok(public) = convert_to_public(&private) else {
            return NS_ERROR_INVALID_ARG;
        };

        local_identity = Some(EcdhKeypair { public, private });
    } else {
        peer_identity = identity.try_into().ok();
        if peer_identity.is_none() {
            return NS_ERROR_INVALID_ARG;
        }
    }

    match HandshakeState::<Sha256>::initial_handshake_message(psk, local_identity, peer_identity) {
        Ok((state, initial_message)) => {
            let state: RefPtr<NoiseHandshakeState> = state.into();
            let Some(state) = state.query_interface::<nsINoiseHandshakeState>() else {
                return NS_ERROR_FAILURE;
            };
            let initial_message = ThinVec::from(initial_message);

            let r = NoiseHandshakeInitialMessageResult::allocate(
                InitNoiseHandshakeInitialMessageResult {
                    state,
                    initial_message,
                },
            );

            let Some(r) = r.query_interface::<nsINoiseHandshakeInitialMessageResult>() else {
                return NS_ERROR_FAILURE;
            };

            r.forget(&mut *result);

            NS_OK
        }

        Err(e) => e,
    }
}
