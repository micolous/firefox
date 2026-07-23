/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Noise handshakes

use crate::{
    channel::NoiseChannel,
    cipher::{sec1_ec2_key_to_der, P256_X962_LENGTH},
    hash::Hash,
    Channel, Result, SymmetricState,
};
use nserror::{
    nsresult, NS_ERROR_DOM_INVALID_STATE_ERR, NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG,
    NS_ERROR_NULL_POINTER, NS_OK,
};
use nss_rs::ec::{
    convert_to_public, ecdh, ecdh_keygen, import_ec_private_key_pkcs8,
    import_ec_public_key_from_spki, EcCurve, EcdhKeypair, EcdhPrivateKey,
};
use sha2::{digest, Sha256};
use std::sync::{Mutex, MutexGuard};
use thin_vec::ThinVec;
use xpcom::{
    interfaces::{nsINoiseChannel, nsINoiseHandshakeState},
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
    /// Start a Noise `KNpsk0` or `NKpsk0` handshake as the initiating party.
    ///
    /// # Arguments
    ///
    /// * `psk`: pre-shared key, negotiated out-of-band
    /// * `local_identity`: local keypair, required if `peer_pub` is unset
    /// * `peer_pub`: remote peer's public key
    ///
    /// If `peer_pub` is set, this performs a `NKpsk0` handshake
    /// ([CTAP: state-assisted transaction][0]). This requires prior agreement with the remote
    /// party.
    ///
    /// Otherwise, this performs a `KNpsk0` handshake, and `local_identity` must be set
    /// ([CTAP: QR-initiated transaction][1]).
    ///
    /// If neither `local_identity` nor `peer_pub` are set, this returns an error.
    ///
    /// # Return value
    ///
    /// Returns `(HandshakeState, initial_message)`. `initial_message` is to be sent to the
    /// remote peer (authenticator) [for its side of the handshake][Self::build_responder].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#hybrid-qr-initiated
    /// [1]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#hybrid-state-assisted
    pub fn initial_handshake_message(
        psk: &[u8; 32],
        local_identity: Option<EcdhKeypair>,
        peer_pub: Option<&[u8; P256_X962_LENGTH]>,
    ) -> Result<(Self, Vec<u8>)> {
        let mut ss = if let Some(peer_pub) = peer_pub {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::NKpsk0);
            ss.mix_hash(&[0]);
            ss.mix_hash(peer_pub);
            ss
        } else if let Some(local_identity) = &local_identity {
            let local_pub = local_identity
                .public
                .key_data()
                .map_err(|_| NS_ERROR_FAILURE)?;

            if local_pub.len() != P256_X962_LENGTH
                || local_pub.as_slice().first().is_none_or(|&b| b != 4)
            {
                // Doesn't look like a raw P256 public key!
                return Err(NS_ERROR_INVALID_ARG);
            }

            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::KNpsk0);
            ss.mix_hash(&[1]);
            ss.mix_hash(&local_pub);
            ss
        } else {
            // at least one of those arguments must be given
            return Err(NS_ERROR_INVALID_ARG);
        };

        ss.mix_key_and_hash(psk)?;

        let ephemeral_key = ecdh_keygen(&EcCurve::P256).map_err(|_| NS_ERROR_FAILURE)?;
        let ephemeral_key_bytes = ephemeral_key
            .public
            .key_data()
            .map_err(|_| NS_ERROR_FAILURE)?;
        ss.mix_hash(&ephemeral_key_bytes);
        ss.mix_key(&ephemeral_key_bytes)?;

        if let Some(peer_pub) = peer_pub {
            let peer_der = sec1_ec2_key_to_der(peer_pub)?;
            let peer_key =
                import_ec_public_key_from_spki(&peer_der).map_err(|_| NS_ERROR_FAILURE)?;

            ss.mix_key(&ecdh(&ephemeral_key.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?)?;
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

    /// Respond to an authenticator as an initiator.
    ///
    /// # Arguments
    ///
    /// * `peer_response_message`: [the remote peer's handshake message][Self::build_responder].
    ///   Must be at least [`P256_X962_LENGTH`] bytes.
    ///
    /// # Return value
    ///
    /// A [`Channel`] for further communication, and the handshake hash.
    pub fn process_handshake_response(
        mut self,
        peer_response_message: &[u8],
    ) -> Result<(Channel, digest::Output<HASH>)> {
        let Some((peer_point_bytes, ct)) = peer_response_message.split_at_checked(P256_X962_LENGTH)
        else {
            return Err(NS_ERROR_INVALID_ARG);
        };
        let peer_key_der = sec1_ec2_key_to_der(peer_point_bytes.try_into().unwrap())?;
        let peer_key =
            import_ec_public_key_from_spki(&peer_key_der).map_err(|_| NS_ERROR_FAILURE)?;

        self.ss.mix_hash(peer_point_bytes);
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

    /// Complete a Noise `KNpsk0` or `NKpsk0` handshake as the responding party (authenticator).
    ///
    /// # Arguments
    ///
    /// * `psk`: pre-shared key, negotiated out-of-band
    /// * `local_identity`: local keypair
    /// * `peer_pub`: remote peer's public key
    /// * `message`: [initial message from the initiator][Self::initial_handshake_message]. Must be
    ///   at least [`P256_X962_LENGTH`] bytes.
    ///
    /// If `local_identity` is set, this performs a `KNpsk0` handshake
    /// ([CTAP: state-assisted transaction][0]).
    ///
    /// Otherwise, this performs a `KNpsk0` handshake, and `peer_pub` must be set
    /// ([CTAP: QR-initiated transaction][1]).
    ///
    /// If neither `local_identity` nor `peer_pub` are set, this returns an error.
    ///
    /// # Return value
    ///
    /// Returns `(Channel, response_message)`.
    ///
    /// `response_message` is [sent to the initiator][Self::process_handshake_response].
    ///
    /// [0]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#hybrid-qr-initiated
    /// [1]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#hybrid-state-assisted
    pub fn build_responder(
        psk: &[u8; 32],
        local_identity: Option<EcdhKeypair>,
        peer_pub: Option<&[u8; P256_X962_LENGTH]>,
        message: &[u8],
    ) -> Result<(Channel, Vec<u8>)> {
        let Some((peer_point_bytes, ct)) = message.split_at_checked(P256_X962_LENGTH) else {
            return Err(NS_ERROR_INVALID_ARG);
        };

        let peer_key_der = sec1_ec2_key_to_der(peer_point_bytes.try_into().unwrap())?;
        let peer_key =
            import_ec_public_key_from_spki(&peer_key_der).map_err(|_| NS_ERROR_FAILURE)?;

        let mut ss: SymmetricState<HASH> = if let Some(local_identity) = &local_identity {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::NKpsk0);
            ss.mix_hash(&[0]);
            ss.mix_hash(
                &local_identity
                    .public
                    .key_data()
                    .map_err(|_| NS_ERROR_FAILURE)?,
            );
            ss
        } else if let Some(peer_pub) = peer_pub {
            let mut ss = SymmetricState::initialize_symmetric(HandshakeType::KNpsk0);
            ss.mix_hash(&[1]);
            ss.mix_hash(peer_pub);
            ss
        } else {
            return Err(NS_ERROR_INVALID_ARG);
        };

        ss.mix_key_and_hash(psk)?;
        ss.mix_hash(peer_point_bytes);
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
        ss.mix_hash(&ephemeral_key_bytes);
        ss.mix_key(&ephemeral_key_bytes)?;

        let shared_key_ee =
            ecdh(&ephemeral_key.private, &peer_key).map_err(|_| NS_ERROR_FAILURE)?;
        ss.mix_key(&shared_key_ee)?;

        if let Some(peer_pub) = peer_pub {
            let peer_pub_der = sec1_ec2_key_to_der(peer_pub)?;
            let peer_pub_key =
                import_ec_public_key_from_spki(&peer_pub_der).map_err(|_| NS_ERROR_FAILURE)?;

            let shared_key_se =
                ecdh(&ephemeral_key.private, &peer_pub_key).map_err(|_| NS_ERROR_FAILURE)?;
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

/// `nsINoiseHandshakeState`-compatible XPCOM wrapper for [`HandshakeState`][].
///
/// This only supports SHA-256.
///
/// This can only be used once, after which point it is "consumed".
#[xpcom(implement(nsINoiseHandshakeState), atomic)]
struct NoiseHandshakeState {
    inner: Mutex<Option<HandshakeState<Sha256>>>,
}

impl NoiseHandshakeState {
    fn get_self(&self) -> Result<MutexGuard<'_, Option<HandshakeState<Sha256>>>> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    xpcom_method!(is_consumed => GetConsumed() -> bool);
    fn is_consumed(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.is_none())
    }

    // Manually implement xpcom_method!, because we have multiple out params
    #[allow(non_snake_case)]
    unsafe fn ProcessHandshakeResponse(
        &self,
        aResponseMessage: *const ThinVec<u8>,
        aChannel: *mut *const nsINoiseChannel,
        aHandshakeHash: *mut ThinVec<u8>,
    ) -> nsresult {
        let response_message: &ThinVec<u8> = match Ensure::ensure(aResponseMessage) {
            Ok(v) => v,
            Err(r) => return r,
        };

        if aChannel.is_null() || aHandshakeHash.is_null() {
            return NS_ERROR_NULL_POINTER;
        }

        match self.process_handshake_response(response_message) {
            Ok((c, mut h)) => {
                unsafe {
                    c.forget(&mut *aChannel);
                    (&mut *aHandshakeHash).append(&mut h);
                }

                NS_OK
            }

            Err(e) => e.into(),
        }
    }

    fn process_handshake_response(
        &self,
        response_message: &ThinVec<u8>,
    ) -> Result<(RefPtr<nsINoiseChannel>, ThinVec<u8>)> {
        let mut guard = self.inner.lock().map_err(|_| NS_ERROR_FAILURE)?;
        let guard = guard.take().ok_or(NS_ERROR_DOM_INVALID_STATE_ERR)?;
        let (channel, handshake_hash) = guard.process_handshake_response(response_message)?;

        let channel: RefPtr<NoiseChannel> = channel.into();
        let channel = channel
            .query_interface::<nsINoiseChannel>()
            .ok_or(NS_ERROR_FAILURE)?;
        let handshake_hash = ThinVec::from(handshake_hash.as_slice());

        Ok((channel, handshake_hash))
    }
}

impl From<HandshakeState<Sha256>> for RefPtr<NoiseHandshakeState> {
    fn from(value: HandshakeState<Sha256>) -> Self {
        NoiseHandshakeState::allocate(InitNoiseHandshakeState {
            inner: Mutex::new(Some(value)),
        })
    }
}

/// Singleton for accessing [HandshakeState] methods
#[xpcom(implement(nsINoiseHandshakeService), atomic)]
struct NoiseHandshakeService {}

impl NoiseHandshakeService {
    // Manually implement xpcom_method!, because we have multiple out params
    #[allow(non_snake_case)]
    unsafe fn InitialKNpsk0HandshakeMessage(
        &self,
        aPsk: *const ThinVec<u8>,
        aLocalIdentity: *const ThinVec<u8>,
        aHandshakeState: *mut *const nsINoiseHandshakeState,
        aInitialMessage: *mut ThinVec<u8>,
    ) -> nsresult {
        let psk: &ThinVec<u8> = match Ensure::ensure(aPsk) {
            Ok(v) => v,
            Err(r) => return r,
        };

        let Ok(psk) = psk.as_slice().try_into() else {
            return NS_ERROR_INVALID_ARG;
        };

        let local_identity: &ThinVec<u8> = match Ensure::ensure(aLocalIdentity) {
            Ok(v) => v,
            Err(r) => return r,
        };

        if local_identity.is_empty() || local_identity.len() > 0xffff {
            return NS_ERROR_INVALID_ARG;
        }

        if aHandshakeState.is_null() || aInitialMessage.is_null() {
            return NS_ERROR_NULL_POINTER;
        }

        match self.initial_knpsk0_handshake_message(psk, local_identity) {
            Ok((s, mut m)) => {
                unsafe {
                    s.forget(&mut *aHandshakeState);
                    (&mut *aInitialMessage).append(&mut m);
                }

                NS_OK
            }

            Err(e) => e.into(),
        }
    }

    fn initial_knpsk0_handshake_message(
        &self,
        psk: &[u8; 32],
        local_identity: &[u8],
    ) -> Result<(RefPtr<nsINoiseHandshakeState>, ThinVec<u8>)> {
        // If local_identity is on the wrong curve, initial_handshake_message() will fail.
        let private =
            import_ec_private_key_pkcs8(local_identity).map_err(|_| NS_ERROR_INVALID_ARG)?;
        let local_identity = convert_to_keypair(private)?;

        let (state, initial_message) =
            HandshakeState::initial_handshake_message(psk, Some(local_identity), None)?;

        let state: RefPtr<NoiseHandshakeState> = state.into();
        let state = state
            .query_interface::<nsINoiseHandshakeState>()
            .ok_or(NS_ERROR_FAILURE)?;
        let initial_message = ThinVec::from(initial_message);

        Ok((state, initial_message))
    }

    // Manually implement xpcom_method!, because we have multiple out params
    #[allow(non_snake_case)]
    unsafe fn BuildKNpsk0Responder(
        &self,
        aPsk: *const ThinVec<u8>,
        aPeerPubKey: *const ThinVec<u8>,
        aInitialMessage: *const ThinVec<u8>,
        aChannel: *mut *const nsINoiseChannel,
        aResponseMessage: *mut ThinVec<u8>,
    ) -> nsresult {
        let psk: &ThinVec<u8> = match Ensure::ensure(aPsk) {
            Ok(v) => v,
            Err(r) => return r,
        };

        let Ok(psk) = psk.as_slice().try_into() else {
            return NS_ERROR_INVALID_ARG;
        };

        let peer_pub_key: &ThinVec<u8> = match Ensure::ensure(aPeerPubKey) {
            Ok(v) => v,
            Err(r) => return r,
        };

        let Ok(peer_pub_key) = peer_pub_key.as_slice().try_into() else {
            return NS_ERROR_INVALID_ARG;
        };

        let initial_message: &ThinVec<u8> = match Ensure::ensure(aInitialMessage) {
            Ok(v) => v,
            Err(r) => return r,
        };

        if initial_message.len() < P256_X962_LENGTH {
            return NS_ERROR_INVALID_ARG;
        }

        if aChannel.is_null() || aResponseMessage.is_null() {
            return NS_ERROR_NULL_POINTER;
        }

        match self.build_knpsk0_responder(psk, peer_pub_key, initial_message) {
            Ok((c, mut m)) => {
                unsafe {
                    c.forget(&mut *aChannel);
                    (&mut *aResponseMessage).append(&mut m);
                }

                NS_OK
            }

            Err(e) => e.into(),
        }
    }

    fn build_knpsk0_responder(
        &self,
        psk: &[u8; 32],
        peer_pub_key: &[u8; P256_X962_LENGTH],
        initial_message: &[u8],
    ) -> Result<(RefPtr<nsINoiseChannel>, ThinVec<u8>)> {
        let (channel, response_message) = HandshakeState::<Sha256>::build_responder(
            psk,
            None,
            Some(peer_pub_key),
            initial_message,
        )?;
        let channel: RefPtr<NoiseChannel> = channel.into();
        let channel = channel
            .query_interface::<nsINoiseChannel>()
            .ok_or(NS_ERROR_FAILURE)?;
        let response_message = ThinVec::from(response_message);

        Ok((channel, response_message))
    }
}

/// Convert an [`EcdhPrivateKey`] into an [`EcdhKeypair`].
fn convert_to_keypair(private: EcdhPrivateKey) -> Result<EcdhKeypair> {
    let public = convert_to_public(&private).map_err(|_| NS_ERROR_FAILURE)?;
    Ok(EcdhKeypair { private, public })
}

/// Create a [NoiseHandshakeService]-based `nsINoiseHandshakeService`.
#[no_mangle]
pub unsafe extern "C" fn noise_handshake_service_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nserror::nsresult {
    let channel: RefPtr<NoiseHandshakeService> =
        NoiseHandshakeService::allocate(InitNoiseHandshakeService {});
    unsafe { channel.QueryInterface(iid, result) }
}
