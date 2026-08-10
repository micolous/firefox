/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery service

use crate::{
    base10,
    discovery::{decode_tunnel_server_id, Eid, KeyPurpose, Params, QR_PROTOCOL},
    ec::{clone_eckeypair, ec2_pubkey_to_compressed_sec1},
    hash::Hash as _,
    hex, Error, InitiatorHandshake, Result,
};
#[cfg(feature = "xpcom")]
use crate::{handshake::CtapCableInitiatorHandshake, xpcparams_impl};
#[cfg(feature = "xpcom")]
use nserror::{nsresult, NS_OK};
use nss_rs::{
    ec::{ecdh_keygen, EcCurve, EcdhKeypair},
    p11, IntoResult as _, SECItem, SECItemBorrowed,
};
#[cfg(feature = "xpcom")]
use nsstring::{nsACString, nsCString};
use pkcs11_bindings::CKM_AES_CBC;
use serde_cbor_2::{ser::to_vec_packed, Value};
use sha2::Sha256;
#[cfg(feature = "xpcom")]
use std::sync::{Mutex, MutexGuard};
use std::{
    collections::BTreeMap,
    ffi::c_uint,
    ops::{Deref, DerefMut},
};
#[cfg(feature = "xpcom")]
use thin_vec::ThinVec;
#[cfg(feature = "xpcom")]
use xpcom::{interfaces::nsICtapCableInitiatorHandshake, RefPtr};

pub struct InitiatorSession {
    /// Request parameters, set by the initiator.
    params: Params,

    /// Random ephemeral key for initiator.
    local_identity: EcdhKeypair,

    /// Unencrypted EID from an authenticator's EID BLE advertisement.
    eid: Option<Eid>,

    websocket_url: String,

    psk: Option<[u8; 32]>,
}

impl Deref for InitiatorSession {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

impl DerefMut for InitiatorSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.params
    }
}

impl InitiatorSession {
    pub fn new() -> Result<Self> {
        Self::new_with_params(Params::new()?)
    }

    pub fn new_with_params(params: Params) -> Result<Self> {
        let local_identity = ecdh_keygen(&EcCurve::P256)?;

        Ok(Self {
            params,
            local_identity,
            eid: None,
            websocket_url: String::new(),
            psk: None,
        })
    }

    /// Returns `true` if an [`Eid`] has been decrypted, and this initiator session is ready to
    /// connect to the authenticator over its preferred transport.
    pub fn found_authenticator(&self) -> bool {
        self.eid.is_some()
    }

    /// Get the QR code URL (`FIDO:/`) for the authenticator to discover the initiator.
    pub fn qr_url(&self) -> Result<String> {
        let cbor = self.params_as_cbor()?;
        let base10 = base10::encode(&cbor);
        let base10 = str::from_utf8(&base10).map_err(|_| Error::Internal)?;
        Ok(format!("{QR_PROTOCOL}{base10}"))
    }

    /// The WebSocket URL that the initiator can connect to the authenticator on.
    ///
    /// Returns an empty string if no authenticator [has been found][Self::try_decrypt_eid], or if
    /// the [last decrypted EID][Self::try_decrypt_eid] indicates the authenticator has chosen a
    /// different transport.
    #[inline]
    pub fn websocket_url(&self) -> &str {
        &self.websocket_url
    }

    /// Try to decrypt a BLE advertisement sent by an authenticator (`trialDecrypt`).
    ///
    /// # Arguments
    ///
    /// * `eid`: Encrypted EID beacon.
    ///
    /// * `suffix`: BLE extended advertising suffix, used by the authenticator to signal which
    ///   transport channel it selected. This is a CBOR map.
    pub fn try_decrypt_eid(&mut self, encrypted_eid: &[u8; 20], suffix: Option<&[u8]>) -> bool {
        let Ok(signature) = Sha256::hmac(&self.eid_key.signing_key, &encrypted_eid[..16]) else {
            return false;
        };
        if signature[..4] != encrypted_eid[16..] {
            // Invalid signature
            return false;
        }

        const NONCE: [u8; p11::AES_BLOCK_SIZE as usize] = [0; p11::AES_BLOCK_SIZE as usize];
        let Ok(mut params) = SECItemBorrowed::wrap(&NONCE) else {
            return false;
        };
        let params_ptr: *mut SECItem = params.as_mut();

        let mut eid_bytes = [0; 16];
        let mut out_len: c_uint = 0;
        let success = unsafe {
            p11::PK11_Decrypt(
                *self.eid_key.encryption_key,
                CKM_AES_CBC,
                params_ptr,
                eid_bytes.as_mut_ptr(),
                &raw mut out_len,
                eid_bytes.len() as u32,
                encrypted_eid.as_ptr(),
                eid_bytes.len() as u32,
            )
        }
        .into_result()
        .is_ok();
        if !success {
            return false;
        }

        if out_len as usize != eid_bytes.len() {
            return false;
        }

        let Some(eid) = Eid::from_decrypted_bytes(&eid_bytes, suffix) else {
            return false;
        };

        let Some(domain) = decode_tunnel_server_id(eid.tunnel_server_id) else {
            return false;
        };

        let Ok(psk) = KeyPurpose::Psk
            .derive(&self.shared_secret.0, &eid_bytes, 32)
            .and_then(|psk| psk.try_into().map_err(|_| Error::Internal))
        else {
            return false;
        };

        let routing_id = hex(eid.routing_id);
        let tunnel_id = self.tunnel_id().encode_hex();

        self.psk = Some(psk);
        if eid.transport == Params::TRANSPORT_WEBSOCKETS {
            self.websocket_url = format!("wss://{domain}/cable/connect/{routing_id}/{tunnel_id}");
        } else {
            self.websocket_url = String::new();
        }
        self.eid = Some(eid);
        true
    }

    pub fn eid(&self) -> Option<&Eid> {
        self.eid.as_ref()
    }

    /// Serialize [Params][] and `local_identity` public key as CBOR.
    fn params_as_cbor(&self) -> Result<Vec<u8>> {
        if self.request_type.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let mut m = BTreeMap::from([
            (
                Params::KEY_PUBKEY,
                Value::Bytes(ec2_pubkey_to_compressed_sec1(&self.local_identity.public)?),
            ),
            (
                Params::KEY_SHARED_SECRET,
                Value::Bytes(self.shared_secret.0.to_vec()),
            ),
            (
                Params::KEY_KNOWN_DOMAIN_COUNT,
                Value::Integer(self.known_domain_count.into()),
            ),
            (
                Params::KEY_SUPPORTS_STATE_ASSISTED_TRANSACTIONS,
                Value::Bool(self.supports_state_assisted_transactions),
            ),
            (
                Params::KEY_REQUEST_TYPE,
                Value::Text(self.request_type.clone()),
            ),
        ]);

        if self.timestamp != 0 {
            m.insert(Params::KEY_TIMESTAMP, Value::Integer(self.timestamp.into()));
        }

        if self.supports_l2cap_transport || !self.supports_websocket_transport {
            let mut supported_transports = Vec::with_capacity(2);
            if self.supports_websocket_transport {
                supported_transports.push(Value::Integer(Params::TRANSPORT_WEBSOCKETS.into()));
            }
            if self.supports_l2cap_transport {
                supported_transports.push(Value::Integer(Params::TRANSPORT_L2CAP.into()));
            }

            if supported_transports.is_empty() {
                return Err(Error::InvalidArgument);
            }

            m.insert(
                Params::KEY_SUPPORTED_TRANSPORTS,
                Value::Array(supported_transports),
            );
        }

        to_vec_packed(&m).map_err(|_| Error::Internal)
    }

    /// Start an [`InitiatorHandshake`] from this session.
    pub fn as_handshake(&self) -> Result<InitiatorHandshake> {
        let psk = self.psk.as_ref().ok_or(Error::InvalidState)?;
        let local_identity = clone_eckeypair(&self.local_identity)?;
        InitiatorHandshake::new_qr_initiated(psk, local_identity)
    }
}

#[cfg(feature = "xpcom")]
/// `nsICtapCableInitiatorDiscoverySession`-compatible XPCOM wrapper for [`AuthenticatorSession`][].
#[xpcom(implement(nsICtapCableInitiatorDiscoverySession), atomic)]
pub struct CtapCableInitiatorDiscoverySession {
    inner: Mutex<InitiatorSession>,
}

#[cfg(feature = "xpcom")]
xpcparams_impl!(InitiatorSession, CtapCableInitiatorDiscoverySession);

#[cfg(feature = "xpcom")]
impl CtapCableInitiatorDiscoverySession {
    xpcom_method!(get_qr_url => GetQrUrl() -> nsACString);
    fn get_qr_url(&self) -> Result<nsCString> {
        let guard = self.get_self()?;
        guard.qr_url().map(nsCString::from)
    }

    xpcom_method!(try_decrypt_eid => TryDecryptEID(
        aEncryptedEID: *const ThinVec<u8>,
        aExtendedAdvertisingSuffix: *const ThinVec<u8>
    ) -> bool);
    fn try_decrypt_eid(
        &self,
        encrypted_eid: &ThinVec<u8>,
        suffix: Option<&ThinVec<u8>>,
    ) -> Result<bool> {
        let mut guard = self.get_self()?;
        let Ok(encrypted_eid) = encrypted_eid.as_slice().try_into() else {
            // Incorrect length shouldn't error.
            return Ok(false);
        };

        Ok(guard.try_decrypt_eid(encrypted_eid, suffix.map(ThinVec::as_slice)))
    }

    xpcom_method!(get_found_authenticator => GetFoundAuthenticator() -> bool);
    fn get_found_authenticator(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.found_authenticator())
    }

    xpcom_method!(get_websocket_url => GetWebSocketUrl() -> nsACString);
    fn get_websocket_url(&self) -> Result<nsCString> {
        let guard = self.get_self()?;
        Ok(nsCString::from(guard.websocket_url()))
    }

    xpcom_method!(handshake => Handshake() -> *const nsICtapCableInitiatorHandshake);
    fn handshake(&self) -> Result<RefPtr<nsICtapCableInitiatorHandshake>> {
        let guard = self.get_self()?;
        let responder = guard.as_handshake()?;
        let responder: RefPtr<CtapCableInitiatorHandshake> = responder.into();
        let responder = responder
            .query_interface::<nsICtapCableInitiatorHandshake>()
            .ok_or(Error::Internal)?;

        Ok(responder)
    }
}

#[cfg(feature = "xpcom")]
impl From<InitiatorSession> for RefPtr<CtapCableInitiatorDiscoverySession> {
    fn from(value: InitiatorSession) -> Self {
        CtapCableInitiatorDiscoverySession::allocate(InitCtapCableInitiatorDiscoverySession {
            inner: Mutex::new(value),
        })
    }
}
