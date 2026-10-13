/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery parameters

use crate::{
    discovery::{EidKey, SharedSecret, TunnelID, KNOWN_TUNNEL_SERVER_DOMAINS},
    Error, Result,
};
#[cfg(feature = "xpcom")]
use nserror::{nsresult, NS_ERROR_FAILURE, NS_OK};
#[cfg(feature = "xpcom")]
use nsstring::nsACString;
use serde_cbor_2::Value;
#[cfg(feature = "xpcom")]
use std::sync::{Mutex, MutexGuard};
#[cfg(feature = "system-time")]
use std::time::SystemTime;
#[cfg(feature = "xpcom")]
use thin_vec::ThinVec;
#[cfg(feature = "xpcom")]
use xpcom::RefPtr;

#[derive(Clone)]
pub struct Params {
    pub(super) shared_secret: SharedSecret,
    tunnel_id: TunnelID,
    pub(super) eid_key: EidKey,

    pub known_domain_count: u16,
    pub supports_state_assisted_transactions: bool,
    pub timestamp: u64,
    pub request_type: String,

    /// `true` if the initiator supports WebSockets as a transport channel.
    pub supports_websocket_transport: bool,

    /// `true` if the initiator supports BLE L2CAP as a transport channel.
    pub supports_l2cap_transport: bool,
}

impl Params {
    pub const TRANSPORT_WEBSOCKETS: u32 = 0;
    pub const TRANSPORT_L2CAP: u32 = 1;

    pub(super) const KEY_PUBKEY: Value = Value::Integer(0);
    pub(super) const KEY_SHARED_SECRET: Value = Value::Integer(1);
    pub(super) const KEY_KNOWN_DOMAIN_COUNT: Value = Value::Integer(2);
    pub(super) const KEY_TIMESTAMP: Value = Value::Integer(3);
    pub(super) const KEY_SUPPORTS_STATE_ASSISTED_TRANSACTIONS: Value = Value::Integer(4);
    pub(super) const KEY_REQUEST_TYPE: Value = Value::Integer(5);
    pub(super) const KEY_SUPPORTED_TRANSPORTS: Value = Value::Integer(6);

    /// Create new caBLE discovery parameters with a random shared secret.
    ///
    /// This is the primary entrypoint for initiators.
    pub fn new() -> Result<Self> {
        let mut o = Self::new_with_shared_secret(SharedSecret::random())?;
        o.known_domain_count = KNOWN_TUNNEL_SERVER_DOMAINS
            .len()
            .try_into()
            .map_err(|_| Error::Internal)?;
        o.supports_websocket_transport = true;

        #[cfg(feature = "system-time")]
        {
            o.timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| Error::Internal)?
                .as_secs();
        }

        Ok(o)
    }

    /// Create new caBLE discovery parameters with a specific shared secret.
    ///
    /// **This should not be used externally.**
    ///
    /// Authenticators should use [`AuthenticatorSession::new_with_qr_url`] instead.
    ///
    /// [`AuthenticatorSession::new_with_qr_url`]: super::AuthenticatorSession::new_with_qr_url
    pub(super) fn new_with_shared_secret(shared_secret: SharedSecret) -> Result<Self> {
        let tunnel_id = shared_secret.to_tunnel_id()?;
        let eid_key = shared_secret.to_eid_key()?;

        Ok(Self {
            shared_secret,
            tunnel_id,
            eid_key,
            known_domain_count: 0,
            timestamp: 0,
            supports_state_assisted_transactions: false,
            request_type: String::new(),
            supports_websocket_transport: false,
            supports_l2cap_transport: false,
        })
    }

    pub fn tunnel_id(&self) -> &TunnelID {
        &self.tunnel_id
    }

    /// Returns `true` if this [`Params`] supports the indicated transport channel identifier.
    pub fn supports_transport(&self, transport: u32) -> Result<bool> {
        match transport {
            Params::TRANSPORT_WEBSOCKETS => Ok(self.supports_websocket_transport),
            Params::TRANSPORT_L2CAP => Ok(self.supports_l2cap_transport),
            _ => Err(Error::InvalidArgument),
        }
    }
}

#[cfg(feature = "xpcom")]
/// `nsICtapCableDiscoveryParams`-compatible XPCOM wrapper for [`Params`][].
#[xpcom(implement(nsICtapCableDiscoveryParams), atomic)]
pub struct CtapCableDiscoveryParams {
    inner: Mutex<Params>,
}

#[cfg(feature = "xpcom")]
#[macro_export]
/// Implement `nsICtapCableDiscoverySession` on a type that dereferences to [`Params`][].
macro_rules! xpcparams_impl {
    ($base:ty, $xpc:ty) => {
        impl $xpc {
            pub fn get_self(&self) -> Result<MutexGuard<'_, $base>> {
                self.inner.lock().map_err(|_| Error::Internal)
            }

            xpcom_method!(get_known_domain_count => GetKnownDomainCount() -> u16);
            fn get_known_domain_count(&self) -> Result<u16> {
                let guard = self.get_self()?;
                Ok(guard.known_domain_count)
            }

            xpcom_method!(set_known_domain_count => SetKnownDomainCount(v: u16));
            fn set_known_domain_count(&self, v: u16) -> Result {
                let mut guard = self.get_self()?;
                guard.known_domain_count = v;
                Ok(())
            }

            xpcom_method!(get_timestamp => GetTimestamp() -> u64);
            fn get_timestamp(&self) -> Result<u64> {
                let guard = self.get_self()?;
                Ok(guard.timestamp)
            }

            xpcom_method!(set_timestamp => SetTimestamp(v: u64));
            fn set_timestamp(&self, v: u64) -> Result {
                let mut guard = self.get_self()?;
                guard.timestamp = v;
                Ok(())
            }

            xpcom_method!(get_supports_state_assisted_transactions =>
                GetSupportsStateAssistedTransactions() -> bool);
            fn get_supports_state_assisted_transactions(&self) -> Result<bool> {
                let guard = self.get_self()?;
                Ok(guard.supports_state_assisted_transactions)
            }

            xpcom_method!(set_supports_state_assisted_transactions =>
                SetSupportsStateAssistedTransactions(v: bool));
            fn set_supports_state_assisted_transactions(&self, v: bool) -> Result {
                let mut guard = self.get_self()?;
                guard.supports_state_assisted_transactions = v;
                Ok(())
            }

            xpcom_method!(get_request_type => GetRequestType() -> nsACString);
            fn get_request_type(&self) -> Result<nsstring::nsCString> {
                let guard = self.get_self()?;
                Ok(guard.request_type.as_str().into())
            }

            xpcom_method!(set_request_type => SetRequestType(v: *const nsstring::nsACString));
            fn set_request_type(&self, v: &nsstring::nsACString) -> Result {
                let mut guard = self.get_self()?;
                guard.request_type = v.to_string();
                Ok(())
            }

            xpcom_method!(get_supports_websocket_transport => GetSupportsWebSocketTransport() -> bool);
            fn get_supports_websocket_transport(&self) -> Result<bool> {
                let guard = self.get_self()?;
                Ok(guard.supports_websocket_transport)
            }

            xpcom_method!(set_supports_websocket_transport => SetSupportsWebSocketTransport(v: bool));
            fn set_supports_websocket_transport(&self, v: bool) -> Result {
                let mut guard = self.get_self()?;
                guard.supports_websocket_transport = v;
                Ok(())
            }

            xpcom_method!(get_supports_l2cap_transport => GetSupportsL2CAPTransport() -> bool);
            fn get_supports_l2cap_transport(&self) -> Result<bool> {
                let guard = self.get_self()?;
                Ok(guard.supports_l2cap_transport)
            }

            xpcom_method!(set_supports_l2cap_transport => SetSupportsL2CAPTransport(v: bool));
            fn set_supports_l2cap_transport(&self, v: bool) -> Result {
                let mut guard = self.get_self()?;
                guard.supports_l2cap_transport = v;
                Ok(())
            }

            xpcom_method!(get_tunnel_id => GetTunnelID() -> ThinVec<u8>);
            fn get_tunnel_id(&self) -> Result<ThinVec<u8>> {
                let guard = self.get_self()?;
                Ok(ThinVec::from(guard.tunnel_id().as_slice()))
            }
        }
    }
}

#[cfg(feature = "xpcom")]
xpcparams_impl!(Params, CtapCableDiscoveryParams);

#[cfg(feature = "xpcom")]
impl From<Params> for RefPtr<CtapCableDiscoveryParams> {
    fn from(value: Params) -> Self {
        CtapCableDiscoveryParams::allocate(InitCtapCableDiscoveryParams {
            inner: Mutex::new(value),
        })
    }
}

#[cfg(feature = "xpcom")]
/// Create a new `nsICtapCableDiscoveryParams`-compatible [`Params`][].
#[no_mangle]
pub unsafe extern "C" fn ctap_cable_discovery_params_constructor(
    iid: *const xpcom::nsIID,
    result: *mut *mut xpcom::reexports::libc::c_void,
) -> nsresult {
    if nss_rs::init().is_err() {
        return NS_ERROR_FAILURE;
    }

    let params: RefPtr<CtapCableDiscoveryParams> = match Params::new() {
        Ok(p) => p.into(),
        Err(e) => return e.into(),
    };

    unsafe { params.QueryInterface(iid, result) }
}
