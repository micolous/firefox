/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! caBLE discovery parameters

use crate::{cable_discovery::Params, Result};
use nserror::{nsresult, NS_ERROR_FAILURE, NS_ERROR_NOT_IMPLEMENTED, NS_ERROR_NULL_POINTER, NS_OK};
use nss_rs::SymKey;
use nsstring::nsACString;
use std::sync::{Mutex, MutexGuard};
use thin_vec::ThinVec;
use xpcom::{interfaces::nsICableDiscoveryParams, Ensure, RefPtr};

pub enum SessionType {
    Initiator,
    Authenticator,
}

pub struct Session {
    /// Request parameters, set by the initiator.
    params: Params,

    session_type: SessionType,

    /// Random ephemeral key for initiator.
    ///
    /// Unset for authenticator.
    local_identity: SymKey,

    /// Authenticator-generated random nonce, sent to the initator in the EID BLE advertisement.
    ///
    /// Initiator starts out with this set to `None`.
    nonce: Option<[u8; 10]>,
}

impl Session {}

/// `nsICableDiscoverySession`-compatible XPCOM wrapper for [`Session`][].
#[xpcom(implement(nsICableDiscoverySession), atomic)]
pub struct CableDiscoverySession {
    inner: Mutex<Session>,
}

impl CableDiscoverySession {
    fn _get_self(&self) -> Result<MutexGuard<'_, Session>> {
        self.inner.lock().map_err(|_| NS_ERROR_FAILURE)
    }

    xpcom_method!(get_params => GetParams() -> *const nsICableDiscoveryParams);
    fn get_params(&self) -> Result<RefPtr<nsICableDiscoveryParams>> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(get_url => GetUrl() -> nsACString);
    fn get_url(&self) -> Result<nsACString> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(get_tunnel_id => GetTunnelID() -> ThinVec<u8>);
    fn get_tunnel_id(&self) -> Result<ThinVec<u8>> {
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    xpcom_method!(generate_encrypted_eid =>
        GenerateEncryptedEID(aTunnelServerID: u16, aRoutingID: u32) -> ThinVec<u8>);
    fn generate_encrypted_eid(
        &self,
        tunnel_server_id: u16,
        routing_id: u32,
    ) -> Result<ThinVec<u8>> {
        let _ = routing_id;
        let _ = tunnel_server_id;
        Err(NS_ERROR_NOT_IMPLEMENTED)
    }

    // Manually implement xpcom_method!, because we have multiple out params
    #[allow(non_snake_case)]
    unsafe fn TryDecryptEID(
        &self,
        aEncryptedEID: *const ThinVec<u8>,
        aTunnelServerID: *mut u16,
        aRoutingID: *mut u32,
        retval: *mut bool,
    ) -> nsresult {
        let encrypted_eid: &ThinVec<u8> = match Ensure::ensure(aEncryptedEID) {
            Ok(v) => v,
            Err(r) => return r,
        };

        if aTunnelServerID.is_null() || aRoutingID.is_null() || retval.is_null() {
            return NS_ERROR_NULL_POINTER;
        }

        let _ = encrypted_eid;

        NS_ERROR_NOT_IMPLEMENTED
    }
}

impl From<Session> for RefPtr<CableDiscoverySession> {
    fn from(value: Session) -> Self {
        CableDiscoverySession::allocate(InitCableDiscoverySession {
            inner: Mutex::new(value),
        })
    }
}
