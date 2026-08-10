/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery service

use crate::{
    base10,
    discovery::{Eid, KeyPurpose, Params, SharedSecret},
    ec::import_compressed_ec2_pubkey,
    hash::Hash,
    Error, Responder, Result,
};
#[cfg(feature = "xpcom")]
use crate::{handshake::CtapCableResponder, xpcparams_impl};
#[cfg(feature = "xpcom")]
use nserror::{nsresult, NS_OK};
use nss_rs::{ec::EcdhPublicKey, p11, IntoResult as _, SECItem, SECItemBorrowed};
#[cfg(feature = "xpcom")]
use nsstring::nsACString;
use pkcs11_bindings::CKM_AES_CBC;
use serde_cbor_2::{from_slice, Value};
use sha2::Sha256;
#[cfg(feature = "xpcom")]
use std::sync::{Mutex, MutexGuard};
use std::{
    ffi::c_uint,
    ops::{Deref, DerefMut},
};
#[cfg(feature = "xpcom")]
use thin_vec::ThinVec;
#[cfg(feature = "xpcom")]
use xpcom::{interfaces::nsICtapCableResponder, RefPtr};

const QR_PROTOCOL: &str = "FIDO:/";

pub struct AuthenticatorSession {
    /// Request parameters, set by the initiator.
    params: Params,

    /// Unencrypted EID for an authenticator's EID BLE advertisement.
    eid: Option<Eid>,

    peer_identity: EcdhPublicKey,

    psk: Option<[u8; 32]>,
}

impl AuthenticatorSession {
    pub fn new_with_qr_url<A: AsRef<[u8]>>(url: A) -> Result<Self> {
        let url = url.as_ref();

        if !url.starts_with(QR_PROTOCOL.as_bytes()) {
            return Err(Error::InvalidArgument);
        }
        let url = &url[QR_PROTOCOL.len()..];

        if url.is_empty() {
            // Empty string is valid for base10, but not valid for this.
            return Err(Error::InvalidArgument);
        }

        let decoded = base10::decode(url)?;
        let cbor: Value = from_slice(&decoded).map_err(|_| Error::InvalidArgument)?;
        let Value::Map(map) = cbor else {
            return Err(Error::InvalidArgument);
        };

        let shared_secret = map
            .get(&Params::KEY_SHARED_SECRET)
            .ok_or(Error::InvalidArgument)?;
        let Value::Bytes(shared_secret) = shared_secret else {
            return Err(Error::InvalidArgument);
        };
        let shared_secret = SharedSecret(
            shared_secret
                .clone()
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let mut params = Params::new_with_shared_secret(shared_secret)?;

        let peer_identity = map.get(&Params::KEY_PUBKEY).ok_or(Error::InvalidArgument)?;
        let Value::Bytes(peer_identity) = peer_identity else {
            return Err(Error::InvalidArgument);
        };
        let peer_identity = peer_identity
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        let peer_identity = import_compressed_ec2_pubkey(&peer_identity)?;

        let known_domain_count = map
            .get(&Params::KEY_KNOWN_DOMAIN_COUNT)
            .ok_or(Error::InvalidArgument)?;
        let &Value::Integer(known_domain_count) = known_domain_count else {
            return Err(Error::InvalidArgument);
        };
        params.known_domain_count = known_domain_count
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;

        if let Some(&Value::Integer(timestamp)) = map.get(&Params::KEY_TIMESTAMP) {
            if let Ok(timestamp) = timestamp.try_into() {
                params.timestamp = timestamp;
            }
        }

        if let Some(&Value::Bool(supports_state_assisted_transactions)) =
            map.get(&Params::KEY_SUPPORTS_STATE_ASSISTED_TRANSACTIONS)
        {
            params.supports_state_assisted_transactions = supports_state_assisted_transactions;
        }

        let request_type = map
            .get(&Params::KEY_REQUEST_TYPE)
            .ok_or(Error::InvalidArgument)?;
        let Value::Text(request_type) = request_type else {
            return Err(Error::InvalidArgument);
        };
        params.request_type = request_type.clone();

        // Chromium pre-CTAP 2.2 used this as a flag for whether it supported non-discoverable
        // MakeCredential, but it didn't land in the final spec. CTAP 2.3 made this supported transports.
        let mut seen_transport = false;
        if let Some(Value::Array(supported_transports)) = map.get(&Params::KEY_SUPPORTED_TRANSPORTS)
        {
            for transport in supported_transports {
                let &Value::Integer(transport) = transport else {
                    // Unexpected type
                    break;
                };

                let Ok(transport) = transport.try_into() else {
                    // Unexpected size
                    break;
                };

                seen_transport = true;
                match transport {
                    Params::TRANSPORT_WEBSOCKETS => params.supports_websocket_transport = true,
                    Params::TRANSPORT_L2CAP => params.supports_l2cap_transport = true,
                    _ => (),
                }
            }
        }

        if !seen_transport {
            // There was no supported transports key, it was empty, or it contained unexpected data;
            // treat it as the default.
            params.supports_websocket_transport = true;
        }

        Ok(Self {
            params,
            eid: None,
            peer_identity,
            psk: None,
        })
    }

    /// Encrypt the [`Eid`], add it to this session's state, and return the encrypted form.
    ///
    /// The first 20 bytes is a regular BLE advertisement. Additional bytes are for extended
    /// advertisements.
    pub fn encrypt_eid(&mut self, eid: Eid) -> Result<Vec<u8>> {
        if !self.params.supports_transport(eid.transport)? {
            return Err(Error::InvalidArgument);
        }

        let b = eid.to_decrypted_bytes()?;
        let (main, suffix) = b.split_at_checked(16).ok_or(Error::Internal)?;

        // Derive PSK
        let psk = KeyPurpose::Psk
            .derive(&self.shared_secret.0, main, 32)?
            .try_into()
            .map_err(|_| Error::Internal)?;

        // Encrypt main part
        const NONCE: [u8; p11::AES_BLOCK_SIZE as usize] = [0; p11::AES_BLOCK_SIZE as usize];
        let mut params = SECItemBorrowed::wrap(&NONCE)?;
        let params_ptr: *mut SECItem = params.as_mut();

        let mut encrypted_eid = [0; 16];
        let mut out_len: c_uint = 0;
        unsafe {
            p11::PK11_Encrypt(
                *self.eid_key.encryption_key,
                CKM_AES_CBC,
                params_ptr,
                encrypted_eid.as_mut_ptr(),
                &raw mut out_len,
                encrypted_eid.len() as u32,
                main.as_ptr(),
                main.len() as u32,
            )
            .into_result()?;
        }

        // Sign main part
        let signature = Sha256::hmac(&self.eid_key.signing_key, &encrypted_eid)?;

        let mut o = Vec::with_capacity(b.len() + 4);
        o.extend_from_slice(&encrypted_eid);
        o.extend_from_slice(&signature[..4]);
        o.extend_from_slice(suffix);

        self.psk = Some(psk);
        self.eid = Some(eid);
        Ok(o)
    }

    pub fn eid(&self) -> Option<&Eid> {
        self.eid.as_ref()
    }

    pub fn as_responder(&self, message: &[u8]) -> Result<Responder> {
        let psk = self.psk.as_ref().ok_or(Error::InvalidState)?;

        Responder::new_qr_initiated(psk, &self.peer_identity, message)
    }
}

impl Deref for AuthenticatorSession {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

// TODO: make readonly xpcom params
impl DerefMut for AuthenticatorSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.params
    }
}

#[cfg(feature = "xpcom")]
/// `nsICtapCableAuthenticatorDiscoverySession`-compatible XPCOM wrapper for
/// [`AuthenticatorSession`][].
#[xpcom(implement(nsICtapCableAuthenticatorDiscoverySession), atomic)]
pub struct CtapCableAuthenticatorDiscoverySession {
    inner: Mutex<AuthenticatorSession>,
}

#[cfg(feature = "xpcom")]
xpcparams_impl!(AuthenticatorSession, CtapCableAuthenticatorDiscoverySession);

#[cfg(feature = "xpcom")]
impl CtapCableAuthenticatorDiscoverySession {
    xpcom_method!(generate_encrypted_eid => GenerateEncryptedEID(
        aTunnelServerID: u16,
        aRoutingID: *const ThinVec<u8>,
        aTransport: u32
    ) -> ThinVec<u8>);
    fn generate_encrypted_eid(
        &self,
        tunnel_server_id: u16,
        routing_id: &ThinVec<u8>,
        transport: u32,
    ) -> Result<ThinVec<u8>> {
        let routing_id = routing_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        let eid =
            Eid::new(tunnel_server_id, routing_id, transport).ok_or(Error::InvalidArgument)?;

        let mut guard = self.get_self()?;
        let encrypted_eid = guard.encrypt_eid(eid)?;

        Ok(ThinVec::from(encrypted_eid))
    }

    xpcom_method!(handshake => Handshake(aInitialMessage: *const ThinVec<u8>) -> *const nsICtapCableResponder);
    fn handshake(&self, initial_message: &ThinVec<u8>) -> Result<RefPtr<nsICtapCableResponder>> {
        let guard = self.get_self()?;
        let responder = guard.as_responder(initial_message)?;
        let responder: RefPtr<CtapCableResponder> = responder.into();
        let responder = responder
            .query_interface::<nsICtapCableResponder>()
            .ok_or(Error::Internal)?;

        Ok(responder)
    }
}

#[cfg(feature = "xpcom")]
impl From<AuthenticatorSession> for RefPtr<CtapCableAuthenticatorDiscoverySession> {
    fn from(value: AuthenticatorSession) -> Self {
        CtapCableAuthenticatorDiscoverySession::allocate(
            InitCtapCableAuthenticatorDiscoverySession {
                inner: Mutex::new(value),
            },
        )
    }
}
