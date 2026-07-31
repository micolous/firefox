/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery parameters

#[cfg(feature = "xpcom")]
use super::params::CtapCableDiscoveryParams;
use crate::{
    base10,
    discovery::{decode_tunnel_server_id, hex, Eid, Params},
    Error, Result,
};
#[cfg(feature = "xpcom")]
use nserror::{nsresult, NS_OK};
use nss_rs::ec::{ecdh_keygen, EcCurve, EcdhKeypair};
#[cfg(feature = "xpcom")]
use nsstring::{nsACString, nsCString};
use std::ops::{Deref, DerefMut};
#[cfg(feature = "xpcom")]
use std::sync::Mutex;
#[cfg(feature = "xpcom")]
use thin_vec::ThinVec;
#[cfg(feature = "xpcom")]
use xpcom::{interfaces::nsICtapCableDiscoveryParams, RefPtr};

const QR_PROTOCOL: &[u8; 6] = b"FIDO:/";

pub struct Session {
    /// Request parameters, set by the initiator.
    params: Params,
}

pub struct InitiatorSession {
    session: Session,

    /// Random ephemeral key for initiator.
    local_identity: EcdhKeypair,

    /// Unencrypted EID from an authenticator's EID BLE advertisement.
    eid: Option<Eid>,

    /// QR code URL.
    url: String,

    websocket_url: String,
}

pub struct AuthenticatorSession {
    session: Session,

    /// Authenticator-generated random nonce, sent to the initator in the EID BLE advertisement.
    nonce: [u8; 10],
}

impl Session {
    pub fn params(&self) -> &Params {
        &self.params
    }
}

impl Deref for Session {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

impl Deref for InitiatorSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl InitiatorSession {
    pub fn new(params: Params) -> Result<Self> {
        let local_identity = ecdh_keygen(&EcCurve::P256)?;
        // TODO
        let url = "TODO:/".to_string();

        Ok(Self {
            session: Session { params },
            local_identity,
            eid: None,
            websocket_url: String::new(),
            url,
        })
    }

    pub fn found_authenticator(&self) -> bool {
        self.eid.is_some()
    }

    #[inline]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[inline]
    pub fn websocket_url(&self) -> &str {
        &self.websocket_url
    }

    /// Try to decrypt a BLE advertisement sent by an authenticator.
    ///
    /// # Arguments
    ///
    /// * `eid`: Encrypted EID beacon.
    ///
    /// * `suffix`: BLE extended advertising suffix, used by the authenticator to signal which
    ///   transport channel it selected. This is a CBOR map.
    pub fn try_decrypt_eid(&mut self, encrypted_eid: &[u8; 20], suffix: Option<&[u8]>) -> bool {
        let Some(eid) = self.params.try_decrypt_eid_bytes(encrypted_eid, suffix) else {
            return false;
        };

        let Some(domain) = decode_tunnel_server_id(eid.tunnel_server_id) else {
            return false;
        };

        let routing_id = hex(&eid.routing_id);
        let tunnel_id = self.params.tunnel_id().encode_hex();
        self.websocket_url = format!("wss://{domain}/cable/connect/{routing_id}/{tunnel_id}");
        self.eid = Some(eid);
        true
    }

    pub fn eid(&self) -> Option<&Eid> {
        self.eid.as_ref()
    }
}

impl DerefMut for InitiatorSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

impl AuthenticatorSession {
    pub fn new_with_qr_url<A: AsRef<[u8]>>(url: A) -> Result<Self> {
        let url = url.as_ref();

        if !url.starts_with(QR_PROTOCOL) {
            return Err(Error::InvalidArgument);
        }
        let url = &url[QR_PROTOCOL.len()..];

        if url.is_empty() {
            // Empty string is valid for base10, but not valid for this.
            return Err(Error::InvalidArgument);
        }

        let _decoded = base10::decode(url)?;

        Err(Error::NotImplemented)
    }
}

impl Deref for AuthenticatorSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl DerefMut for AuthenticatorSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
    }
}

#[cfg(feature = "xpcom")]
/// Implement `nsICtapCableDiscoverySession` on a type that dereferences to [`Channel`][].
macro_rules! xpcsession_impl {
    ($base:ty, $xpc:ty) => {
        impl $xpc {
            fn get_self(&self) -> crate::Result<std::sync::MutexGuard<'_, $base>> {
                self.inner.lock().map_err(|_| crate::Error::Internal)
            }

            xpcom_method!(get_params => GetParams() -> *const nsICtapCableDiscoveryParams);
            fn get_params(&self) -> Result<RefPtr<nsICtapCableDiscoveryParams>> {
                let guard = self.get_self()?;
                let params = guard.params().clone();
                let params: RefPtr<CtapCableDiscoveryParams> = params.into();

                params.query_interface::<nsICtapCableDiscoveryParams>().ok_or(crate::Error::Internal)
            }
        }
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
xpcsession_impl!(AuthenticatorSession, CtapCableAuthenticatorDiscoverySession);

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

        let guard = self.get_self()?;
        let eid = guard.encrypt_eid(&eid)?;

        Ok(ThinVec::from(eid))
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

#[cfg(feature = "xpcom")]
/// `nsICtapCableInitiatorDiscoverySession`-compatible XPCOM wrapper for [`AuthenticatorSession`][].
#[xpcom(implement(nsICtapCableInitiatorDiscoverySession), atomic)]
pub struct CtapCableInitiatorDiscoverySession {
    inner: Mutex<InitiatorSession>,
}

#[cfg(feature = "xpcom")]
xpcsession_impl!(InitiatorSession, CtapCableInitiatorDiscoverySession);

#[cfg(feature = "xpcom")]
impl CtapCableInitiatorDiscoverySession {
    xpcom_method!(get_url => GetUrl() -> nsACString);
    fn get_url(&self) -> Result<nsCString> {
        let guard = self.get_self()?;

        Ok(nsCString::from(guard.url()))
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
        let encrypted_eid = encrypted_eid
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;

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
}

#[cfg(feature = "xpcom")]
impl From<InitiatorSession> for RefPtr<CtapCableInitiatorDiscoverySession> {
    fn from(value: InitiatorSession) -> Self {
        CtapCableInitiatorDiscoverySession::allocate(InitCtapCableInitiatorDiscoverySession {
            inner: Mutex::new(value),
        })
    }
}
