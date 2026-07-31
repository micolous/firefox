/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery parameters

use crate::{
    discovery::{Eid, EidKey, SharedSecret, TunnelID},
    hash::Hash as _,
    Error, Result,
};
#[cfg(feature = "xpcom")]
use nserror::{nsresult, NS_ERROR_FAILURE, NS_OK};
use nss_rs::{p11, IntoResult as _, SECItem, SECItemBorrowed};
#[cfg(feature = "xpcom")]
use nsstring::{nsACString, nsCString};
use pkcs11_bindings::CKM_AES_CBC;
use sha2::Sha256;
#[cfg(feature = "xpcom")]
use std::sync::{Mutex, MutexGuard};
use std::{collections::HashSet, ffi::c_uint};
#[cfg(feature = "xpcom")]
use thin_vec::ThinVec;
#[cfg(feature = "xpcom")]
use xpcom::RefPtr;

#[derive(Clone)]
pub struct Params {
    shared_secret: SharedSecret,
    tunnel_id: TunnelID,
    eid_key: EidKey,

    pub known_domain_count: u16,
    pub supports_state_assisted_transactions: bool,
    pub timestamp: u64,
    pub request_type: String,

    // TODO: consider replacing this with something smaller, as there are currently
    // two supported values defined by the spec.
    pub supported_transports: HashSet<u32>,
}

impl Params {
    pub const TRANSPORT_WEBSOCKETS: u32 = 0;
    pub const TRANSPORT_L2CAP: u32 = 1;

    /// Create new caBLE discovery parameters with a random shared secret.
    ///
    /// This is the primary entrypoint for initiators.
    pub fn new() -> Result<Self> {
        Self::new_with_shared_secret(SharedSecret::random())
    }

    #[cfg(test)]
    #[inline]
    /// Create new caBLE discovery parameters with a specific shared secret.
    ///
    /// This is only intended for tests.
    pub fn new_with_shared_secret_for_tests(shared_secret: SharedSecret) -> Result<Self> {
        Self::new_with_shared_secret(shared_secret)
    }

    fn new_with_shared_secret(shared_secret: SharedSecret) -> Result<Self> {
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
            supported_transports: HashSet::new(),
        })
    }

    /// `true` if the initiator supports WebSockets as a transport channel.
    pub fn supports_websocket_transport(&self) -> bool {
        self.supported_transports.is_empty()
            || self
                .supported_transports
                .contains(&Self::TRANSPORT_WEBSOCKETS)
    }

    /// `true` if the initiator supports BLE L2CAP as a transport channel.
    pub fn supports_l2cap_transport(&self) -> bool {
        self.supported_transports.contains(&Self::TRANSPORT_L2CAP)
    }

    pub fn tunnel_id(&self) -> &TunnelID {
        &self.tunnel_id
    }

    /// Try to decrypt a BLE advertisement sent by an authenticator (`trialDecrypt`).
    ///
    /// # Arguments
    ///
    /// * `eid`: Encrypted EID beacon.
    ///
    /// * `suffix`: BLE extended advertising suffix, used by the authenticator to signal which
    ///   transport channel it selected. This is a CBOR map.
    pub(super) fn try_decrypt_eid_bytes(
        &self,
        encrypted_eid: &[u8; 20],
        suffix: Option<&[u8]>,
    ) -> Option<Eid> {
        let signature = Sha256::hmac(&self.eid_key.signing_key, &encrypted_eid[..16]).ok()?;
        if &signature[..4] != &encrypted_eid[16..] {
            // Invalid signature
            return None;
        }

        const NONCE: [u8; p11::AES_BLOCK_SIZE as usize] = [0; p11::AES_BLOCK_SIZE as usize];
        let mut params = SECItemBorrowed::wrap(&NONCE).ok()?;
        let params_ptr: *mut SECItem = params.as_mut();

        let mut eid = [0; 16];
        let mut out_len: c_uint = 0;
        unsafe {
            p11::PK11_Decrypt(
                *self.eid_key.encryption_key,
                CKM_AES_CBC,
                params_ptr,
                eid.as_mut_ptr(),
                &raw mut out_len,
                eid.len() as u32,
                encrypted_eid.as_ptr(),
                eid.len() as u32,
            )
            .into_result()
            .ok()?;
        }

        if out_len as usize != eid.len() {
            return None;
        }

        Eid::from_decrypted_bytes(&eid, suffix)
    }

    pub(super) fn encrypt_eid(&self, eid: &Eid) -> Result<Vec<u8>> {
        let _ = eid;
        Err(Error::NotImplemented)
    }
}

#[cfg(feature = "xpcom")]
/// `nsICtapCableDiscoveryParams`-compatible XPCOM wrapper for [`Params`][].
#[xpcom(implement(nsICtapCableDiscoveryParams), atomic)]
pub struct CtapCableDiscoveryParams {
    inner: Mutex<Params>,
}

#[cfg(feature = "xpcom")]
impl CtapCableDiscoveryParams {
    fn get_self(&self) -> Result<MutexGuard<'_, Params>> {
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
    fn get_request_type(&self) -> Result<nsCString> {
        let guard = self.get_self()?;
        Ok(guard.request_type.as_str().into())
    }

    xpcom_method!(set_request_type => SetRequestType(v: *const nsACString));
    fn set_request_type(&self, v: &nsACString) -> Result {
        let mut guard = self.get_self()?;
        guard.request_type = v.to_string();
        Ok(())
    }

    xpcom_method!(get_supported_transports => GetSupportedTransports() -> ThinVec<u32>);
    fn get_supported_transports(&self) -> Result<ThinVec<u32>> {
        let guard = self.get_self()?;
        Ok(guard.supported_transports.iter().copied().collect())
    }

    xpcom_method!(set_supported_transports => SetSupportedTransports(v: *const ThinVec<u32>));
    fn set_supported_transports(&self, v: &ThinVec<u32>) -> Result {
        let mut guard = self.get_self()?;
        guard.supported_transports = HashSet::from_iter(v.iter().copied());
        Ok(())
    }

    xpcom_method!(get_supports_websocket_transport => GetSupportsWebSocketTransport() -> bool);
    fn get_supports_websocket_transport(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.supports_websocket_transport())
    }

    xpcom_method!(get_supports_l2cap_transport => GetSupportsL2CAPTransport() -> bool);
    fn get_supports_l2cap_transport(&self) -> Result<bool> {
        let guard = self.get_self()?;
        Ok(guard.supports_l2cap_transport())
    }

    xpcom_method!(get_tunnel_id => GetTunnelID() -> ThinVec<u8>);
    fn get_tunnel_id(&self) -> Result<ThinVec<u8>> {
        let guard = self.get_self()?;
        Ok(ThinVec::from(guard.tunnel_id().as_slice()))
    }
}

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
