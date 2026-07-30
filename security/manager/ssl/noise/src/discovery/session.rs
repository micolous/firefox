/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery parameters

use crate::{
    discovery::{params::XPCParams, Params},
    Result,
};
use nserror::{NS_ERROR_FAILURE, NS_ERROR_INVALID_ARG, NS_ERROR_NOT_IMPLEMENTED, NS_OK, nsresult};
use nss_rs::ec::{ecdh_keygen, EcCurve, EcdhKeypair};
use nsstring::{nsACString, nsCString};
use std::{
    ops::{Deref, DerefMut},
    sync::Mutex,
};
use thin_vec::ThinVec;
use xpcom::{interfaces::nsICtapCableDiscoveryParams, RefPtr};

pub struct Session {
    /// Request parameters, set by the initiator.
    params: Params,
}

pub struct InitiatorSession {
    session: Session,

    /// Random ephemeral key for initiator.
    local_identity: EcdhKeypair,

    /// Tunnel server ID from an authenticator's EID BLE advertisement.
    ///
    /// 255 = invalid / unknown
    tunnel_server_id: u16,

    /// Routing ID from an authenticator's EID BLE advertisement.
    routing_id: [u8; 3],

    /// Authenticator-generated random nonce, sent to the initator in the EID BLE advertisement.
    nonce: [u8; 10],

    /// The transport selected by the authenticator.
    transport: u32,

    /// QR code URL.
    url: String,
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
    /// Invalid tunnel server ID, used as a default to indicate whether we have found an authenticator.
    const INVALID_TUNNEL_SERVER_ID: u16 = 255;

    pub fn new(params: Params) -> Result<Self> {
        let local_identity = ecdh_keygen(&EcCurve::P256).map_err(|_| NS_ERROR_FAILURE)?;
        // TODO
        let url = "TODO:/".to_string();

        Ok(Self {
            session: Session { params },
            local_identity,
            tunnel_server_id: Self::INVALID_TUNNEL_SERVER_ID,
            routing_id: [0; 3],
            nonce: [0; 10],
            transport: 0,
            url,
        })
    }

    pub fn found_authenticator(&self) -> bool {
        self.tunnel_server_id != Self::INVALID_TUNNEL_SERVER_ID
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Try to decrypt a BLE advertisement sent by an authenticator.
    /// 
    /// # Arguments
    /// 
    /// * `eid`: Encrypted EID beacon.
    ///
    /// * `suffix`: BLE extended advertising suffix, used by the authenticator to signal which
    ///   transport channel it selected. This is a CBOR map.
    pub fn try_decrypt_eid(&mut self, encrypted_eid: &[u8; 20], suffix: Option<&[u8]>) -> Result<bool> {
        let _ = encrypted_eid;
        let _ = suffix;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }
}

impl DerefMut for InitiatorSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session
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

/// Implement `nsICtapCableDiscoverySession` on a type that dereferences to [`Channel`][].
macro_rules! xpcsession_impl {
    ($base:ty, $xpc:ty) => {
        impl $xpc {
            fn get_self(&self) -> crate::Result<std::sync::MutexGuard<'_, $base>> {
                self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
            }

            xpcom_method!(get_params => GetParams() -> *const nsICtapCableDiscoveryParams);
            fn get_params(&self) -> Result<RefPtr<nsICtapCableDiscoveryParams>> {
                let guard = self.get_self()?;
                let params = guard.params().clone();
                let params: RefPtr<XPCParams> = params.into();

                params.query_interface::<nsICtapCableDiscoveryParams>().ok_or(NS_ERROR_FAILURE)
            }
        }
    }
}

/// `nsICtapCableAuthenticatorDiscoverySession`-compatible XPCOM wrapper for
/// [`AuthenticatorSession`][].
#[xpcom(implement(nsICtapCableAuthenticatorDiscoverySession), atomic)]
pub struct XPCAuthenticatorSession {
    inner: Mutex<AuthenticatorSession>,
}

xpcsession_impl!(AuthenticatorSession, XPCAuthenticatorSession);

impl XPCAuthenticatorSession {
    xpcom_method!(generate_encrypted_eid => GenerateEncryptedEID(
        aTunnelServerID: u16,
        aRoutingID: u32,
        aTransport: u32
    ) -> ThinVec<u8>);
    fn generate_encrypted_eid(
        &self,
        tunnel_server_id: u16,
        routing_id: u32,
        transport: u32,
    ) -> Result<ThinVec<u8>> {
        let _ = routing_id;
        let _ = tunnel_server_id;
        let _ = transport;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }
}

impl From<AuthenticatorSession> for RefPtr<XPCAuthenticatorSession> {
    fn from(value: AuthenticatorSession) -> Self {
        XPCAuthenticatorSession::allocate(InitXPCAuthenticatorSession {
            inner: Mutex::new(value),
        })
    }
}

/// `nsICtapCableInitiatorDiscoverySession`-compatible XPCOM wrapper for [`AuthenticatorSession`][].
#[xpcom(implement(nsICtapCableInitiatorDiscoverySession), atomic)]
pub struct XPCInitiatorSession {
    inner: Mutex<InitiatorSession>,
}

xpcsession_impl!(InitiatorSession, XPCInitiatorSession);

impl XPCInitiatorSession {
    xpcom_method!(get_url => GetUrl() -> nsACString);
    fn get_url(&self) -> Result<nsCString> {
        let guard = self.get_self()?;

        Ok(nsCString::from(guard.url()))
    }

    xpcom_method!(try_decrypt_eid => TryDecryptEID(
        aEncryptedEID: *const ThinVec<u8>,
        aExtendedAdvertisingSuffix: *const ThinVec<u8>
    ) -> bool);
    fn try_decrypt_eid(&self, encrypted_eid: &ThinVec<u8>, suffix: Option<&ThinVec<u8>>) -> Result<bool> {
        let mut guard = self.get_self()?;
        let encrypted_eid = encrypted_eid.as_slice().try_into().map_err(|_| NS_ERROR_INVALID_ARG)?;

        guard.try_decrypt_eid(encrypted_eid, suffix.map(ThinVec::as_slice))
    }
}

impl From<InitiatorSession> for RefPtr<XPCInitiatorSession> {
    fn from(value: InitiatorSession) -> Self {
        XPCInitiatorSession::allocate(InitXPCInitiatorSession {
            inner: Mutex::new(value),
        })
    }
}
